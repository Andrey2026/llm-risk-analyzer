from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_json(path: str | Path) -> dict[str, Any]:
    file_path = Path(path)
    with file_path.open("r", encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, dict):
        raise ValueError(f"{file_path} must contain a JSON object")
    return data


def load_rules(path: str | Path) -> list[dict[str, Any]]:
    data = load_json(path)
    rules = data.get("rules")
    if not isinstance(rules, list):
        raise ValueError(f"{path} must contain a 'rules' list")
    return rules
