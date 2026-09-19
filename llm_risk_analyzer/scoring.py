from __future__ import annotations


def priority(impact: int, manageability: int) -> str:
    if impact >= 3 and manageability >= 3:
        return "P1"
    if impact >= 4 and manageability <= 2:
        return "P2"
    return "P3"


def clamp_score(value: int) -> int:
    return min(4, max(1, value))
