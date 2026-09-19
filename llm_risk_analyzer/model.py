from __future__ import annotations

from dataclasses import dataclass
from typing import Any


SENSITIVE_DATA = {
    "personal_data",
    "medical_data",
    "financial_data",
    "trade_secret",
    "credentials",
    "source_code",
}


@dataclass(frozen=True)
class SystemModel:
    name: str
    components: list[dict[str, Any]]
    flows: list[dict[str, Any]]
    actors: list[dict[str, Any]]
    controls: set[str]
    external_findings: list[dict[str, Any]]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SystemModel":
        return cls(
            name=str(data.get("system", "Unnamed system")),
            components=list(data.get("components", [])),
            flows=list(data.get("flows", [])),
            actors=list(data.get("actors", [])),
            controls=set(data.get("controls", [])),
            external_findings=list(data.get("external_findings", [])),
        )

    def flows_touching(self, component_id: str) -> list[dict[str, Any]]:
        return [
            flow
            for flow in self.flows
            if flow.get("from") == component_id or flow.get("to") == component_id
        ]

    def actor_can_reach(self, actor: dict[str, Any], component_id: str) -> bool:
        access = set(actor.get("access_to", []))
        if component_id in access:
            return True
        reachable = set(access)
        changed = True
        while changed:
            changed = False
            for flow in self.flows:
                source = flow.get("from")
                target = flow.get("to")
                if source in reachable and target not in reachable:
                    reachable.add(target)
                    changed = True
                if target in reachable and source not in reachable:
                    reachable.add(source)
                    changed = True
        return component_id in reachable


def data_sensitivity(data_categories: list[str]) -> int:
    categories = set(data_categories)
    if "medical_data" in categories or "credentials" in categories:
        return 4
    if categories & SENSITIVE_DATA:
        return 3
    if categories:
        return 2
    return 1
