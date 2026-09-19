from __future__ import annotations

from typing import Any

from .conditions import matches_all
from .model import SystemModel, data_sensitivity
from .scoring import clamp_score, priority


def analyze_system(
    system_data: dict[str, Any],
    rules: list[dict[str, Any]],
) -> dict[str, Any]:
    model = SystemModel.from_dict(system_data)
    threats: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()

    for rule in rules:
        for context in build_contexts(model, rule.get("scope", "flow_component_actor")):
            if not matches_all(rule.get("when", []), context, model):
                continue

            threat = build_threat(rule, context)
            key = (
                threat["rule_id"],
                threat.get("component_id", ""),
                threat.get("actor_id", ""),
            )
            if key in seen:
                continue
            seen.add(key)
            threats.append(threat)

    scenarios = build_cumulative_scenarios(threats)
    return {
        "system": model.name,
        "system_model": {
            "components": model.components,
            "flows": model.flows,
            "actors": model.actors,
            "controls": sorted(model.controls),
            "external_findings": model.external_findings,
        },
        "threat_count": len(threats),
        "threats": threats,
        "cumulative_scenarios": scenarios,
        "summary": summarize(threats, scenarios),
    }


def build_contexts(model: SystemModel, scope: str) -> list[dict[str, Any]]:
    contexts: list[dict[str, Any]] = []

    if scope == "component":
        return [{"component": component} for component in model.components]

    if scope == "component_actor":
        for component in model.components:
            for actor in model.actors:
                contexts.append({"component": component, "actor": actor})
        return contexts

    if scope == "flow_component":
        for component in model.components:
            for flow in model.flows_touching(str(component.get("id"))):
                contexts.append({"component": component, "flow": flow})
        return contexts

    if scope == "external_finding":
        return [{"finding": finding} for finding in model.external_findings]

    for component in model.components:
        for flow in model.flows_touching(str(component.get("id"))):
            for actor in model.actors:
                contexts.append({"component": component, "flow": flow, "actor": actor})
    return contexts


def build_threat(rule: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    flow = context.get("flow", {})
    component = context.get("component", {})
    actor = context.get("actor", {})
    data_categories = flow.get("data_categories", component.get("data_categories", []))

    impact = clamp_score(int(rule.get("impact", data_sensitivity(data_categories))))
    manageability = clamp_score(int(rule.get("manageability", 2)))

    return {
        "rule_id": rule["id"],
        "title": render_template(rule["title"], context),
        "description": render_template(rule.get("description", ""), context),
        "levels": rule.get("levels", []),
        "dimensions": {
            "lifecycle": rule.get("dimensions", {}).get(
                "lifecycle",
                flow.get("lifecycle_stage"),
            ),
            "llm_role": rule.get("dimensions", {}).get(
                "llm_role",
                component.get("llm_roles", component.get("involvement", [])),
            ),
            "adversary": rule.get("dimensions", {}).get(
                "adversary",
                actor.get("type"),
            ),
            "vulnerability_properties": {
                "impact": impact,
                "manageability": manageability,
            },
        },
        "priority": priority(impact, manageability),
        "component_id": str(component.get("id", "")),
        "flow_id": str(flow.get("id", "")),
        "actor_id": str(actor.get("id", "")),
        "recommended_controls": rule.get("recommended_controls", []),
        "evidence": evidence(context),
        "cumulative": bool(rule.get("cumulative", False)),
    }


def render_template(template: str, context: dict[str, Any]) -> str:
    values = {
        "component.id": context.get("component", {}).get("id", ""),
        "component.name": context.get("component", {}).get("name", ""),
        "actor.id": context.get("actor", {}).get("id", ""),
        "actor.type": context.get("actor", {}).get("type", ""),
        "flow.id": context.get("flow", {}).get("id", ""),
    }
    result = template
    for key, value in values.items():
        result = result.replace("{" + key + "}", str(value))
    return result


def evidence(context: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in ("component", "flow", "actor", "finding"):
        if key in context:
            item = context[key]
            result[key] = item.get("id", item)
    return result


def build_cumulative_scenarios(threats: list[dict[str, Any]]) -> list[dict[str, Any]]:
    scenarios: list[dict[str, Any]] = []
    for threat in threats:
        if threat.get("cumulative"):
            scenarios.append(
                {
                    "title": f"Кумулятивный сценарий: {threat['title']}",
                    "source_threat": threat["rule_id"],
                    "levels": threat.get("levels", []),
                    "priority": threat.get("priority"),
                    "rationale": (
                        "Угроза связывает данные, поведение модели и операционные "
                        "процессы, поэтому контроль отдельных событий может не "
                        "обнаружить всю цепочку."
                    ),
                }
            )
    return scenarios


def summarize(
    threats: list[dict[str, Any]],
    scenarios: list[dict[str, Any]],
) -> dict[str, Any]:
    by_priority: dict[str, int] = {}
    for threat in threats:
        by_priority[threat["priority"]] = by_priority.get(threat["priority"], 0) + 1
    return {
        "by_priority": by_priority,
        "cross_level_count": sum(1 for threat in threats if len(threat["levels"]) > 1),
        "cumulative_scenario_count": len(scenarios),
    }
