from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


def write_report(result: dict[str, Any], output: str | Path, output_format: str) -> None:
    path = Path(output)
    if output_format == "json":
        path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        return
    if output_format == "csv":
        write_csv(result, path)
        return
    path.write_text(render_markdown(result), encoding="utf-8")


def render_markdown(result: dict[str, Any]) -> str:
    lines = [
        f"# Анализ рисков LLM-системы: {result['system']}",
        "",
        f"Найдено угроз: {result['threat_count']}",
        "",
        "## Сводка",
        "",
        f"- Кросс-уровневые угрозы: {result['summary']['cross_level_count']}",
        f"- Кумулятивные сценарии: {result['summary']['cumulative_scenario_count']}",
        "",
        "## Описание входной системы",
        "",
        *render_system_model(result.get("system_model", {})),
        "",
        "## Матрица угроз",
        "",
        "| Приоритет | Угроза | Уровни | Жизненный цикл | Роль LLM | Противник | Ущерб | Управляемость |",
        "|---|---|---|---|---|---|---:|---:|",
    ]

    for threat in result["threats"]:
        props = threat["dimensions"]["vulnerability_properties"]
        lines.append(
            "| {priority} | {title} | {levels} | {lifecycle} | {llm_role} | "
            "{adversary} | {impact} | {manageability} |".format(
                priority=threat["priority"],
                title=threat["title"],
                levels=format_value(threat["levels"]),
                lifecycle=format_value(threat["dimensions"]["lifecycle"]),
                llm_role=format_value(threat["dimensions"]["llm_role"]),
                adversary=format_value(threat["dimensions"]["adversary"]),
                impact=props["impact"],
                manageability=props["manageability"],
            )
        )

    if result["cumulative_scenarios"]:
        lines.extend(["", "## Кумулятивные сценарии", ""])
        for scenario in result["cumulative_scenarios"]:
            lines.append(f"- **{scenario['priority']}** {scenario['title']}")

    return "\n".join(lines) + "\n"


def write_csv(result: dict[str, Any], path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "priority",
                "title",
                "levels",
                "lifecycle",
                "llm_role",
                "adversary",
                "impact",
                "manageability",
            ],
        )
        writer.writeheader()
        for threat in result["threats"]:
            props = threat["dimensions"]["vulnerability_properties"]
            writer.writerow(
                {
                    "priority": threat["priority"],
                    "title": threat["title"],
                    "levels": ", ".join(threat["levels"]),
                    "lifecycle": format_value(threat["dimensions"]["lifecycle"]),
                    "llm_role": format_value(threat["dimensions"]["llm_role"]),
                    "adversary": format_value(threat["dimensions"]["adversary"]),
                    "impact": props["impact"],
                    "manageability": props["manageability"],
                }
            )


def render_system_model(system_model: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    components = system_model.get("components", [])
    flows = system_model.get("flows", [])
    actors = system_model.get("actors", [])
    controls = system_model.get("controls", [])
    findings = system_model.get("external_findings", [])

    if components:
        lines.extend(
            [
                "### Компоненты",
                "",
                "| ID | Название | Тип | Роль LLM | Данные |",
                "|---|---|---|---|---|",
            ]
        )
        for component in components:
            lines.append(
                "| {id} | {name} | {type} | {roles} | {data} |".format(
                    id=component.get("id", ""),
                    name=component.get("name", ""),
                    type=format_value(component.get("type")),
                    roles=format_value(component.get("llm_roles", "")),
                    data=format_value(component.get("data_categories", "")),
                )
            )
        lines.append("")

    if flows:
        lines.extend(
            [
                "### Потоки данных",
                "",
                "| ID | Откуда | Куда | Этап жизненного цикла | Категории данных |",
                "|---|---|---|---|---|",
            ]
        )
        for flow in flows:
            lines.append(
                "| {id} | {source} | {target} | {stage} | {data} |".format(
                    id=flow.get("id", ""),
                    source=flow.get("from", ""),
                    target=flow.get("to", ""),
                    stage=format_value(flow.get("lifecycle_stage")),
                    data=format_value(flow.get("data_categories", "")),
                )
            )
        lines.append("")

    if actors:
        lines.extend(
            [
                "### Роли и доступ",
                "",
                "| ID | Тип | Доступ к компонентам | Повторные запросы |",
                "|---|---|---|---|",
            ]
        )
        for actor in actors:
            lines.append(
                "| {id} | {type} | {access} | {repeated} |".format(
                    id=actor.get("id", ""),
                    type=format_value(actor.get("type")),
                    access=format_value(actor.get("access_to", "")),
                    repeated=format_bool(actor.get("can_make_repeated_queries")),
                )
            )
        lines.append("")

    if controls:
        lines.extend(["### Меры защиты", ""])
        lines.extend(f"- {format_value(control)}" for control in controls)
        lines.append("")

    if findings:
        lines.extend(
            [
                "### Внешние результаты проверок",
                "",
                "| ID | Источник | Категория | Результат |",
                "|---|---|---|---|",
            ]
        )
        for finding in findings:
            lines.append(
                "| {id} | {source} | {category} | {result} |".format(
                    id=finding.get("id", ""),
                    source=finding.get("source", ""),
                    category=format_value(finding.get("category")),
                    result=format_value(finding.get("result")),
                )
            )
        lines.append("")

    return lines


def format_bool(value: Any) -> str:
    if value is True:
        return "да"
    if value is False:
        return "нет"
    return ""


def format_value(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(format_value(item) for item in value)
    return "" if value is None else TRANSLATIONS.get(str(value), str(value))


TRANSLATIONS = {
    "data": "данные",
    "model": "модель",
    "process": "процессы",
    "processing": "обработка",
    "generation": "генерация",
    "storage": "хранение",
    "fine_tuning": "дообучение",
    "active_generation": "активная генерация",
    "rag": "RAG",
    "insider": "инсайдер",
    "external_attacker": "внешний противник",
    "supply_chain_operator": "участник цепочки поставок",
    "interface": "интерфейс",
    "storage": "хранение",
    "data_store": "хранилище",
    "llm": "LLM",
    "training_pipeline": "конвейер дообучения",
    "medical_data": "медицинские данные",
    "personal_data": "персональные данные",
    "financial_data": "финансовые данные",
    "trade_secret": "коммерческая тайна",
    "generated_annotations": "сгенерированные аннотации",
    "human_review": "проверка человеком",
    "api_rate_limit": "ограничение частоты API-запросов",
    "audit_log": "журнал аудита",
    "behavioral_monitoring": "поведенческий мониторинг",
    "prompt_injection": "инъекция запроса",
    "failed": "проверка не пройдена",
}
