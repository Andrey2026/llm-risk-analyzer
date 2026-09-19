from __future__ import annotations

from typing import Any

from .model import SystemModel


def get_path(context: dict[str, Any], path: str) -> Any:
    current: Any = context
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def matches_condition(
    condition: dict[str, Any],
    context: dict[str, Any],
    model: SystemModel,
) -> bool:
    op = condition.get("op", "eq")
    left = condition.get("left")
    actual = get_path(context, left) if left else None
    expected = condition.get("value")

    if op == "eq":
        return actual == expected
    if op == "neq":
        return actual != expected
    if op == "contains":
        return expected in as_list(actual)
    if op == "contains_any":
        return bool(set(as_list(actual)) & set(as_list(expected)))
    if op == "missing_control":
        return expected not in model.controls
    if op == "has_control":
        return expected in model.controls
    if op == "actor_can_reach_component":
        actor = context.get("actor", {})
        component = context.get("component", {})
        return model.actor_can_reach(actor, str(component.get("id")))
    if op == "flow_touches_component":
        component_id = context.get("component", {}).get("id")
        flow = context.get("flow", {})
        return flow.get("from") == component_id or flow.get("to") == component_id
    if op == "exists":
        return actual is not None

    raise ValueError(f"Unsupported condition operation: {op}")


def matches_all(
    conditions: list[dict[str, Any]],
    context: dict[str, Any],
    model: SystemModel,
) -> bool:
    return all(matches_condition(condition, context, model) for condition in conditions)
