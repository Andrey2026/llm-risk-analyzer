from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.append(str(Path(__file__).resolve().parents[1]))
    from llm_risk_analyzer.engine import analyze_system
    from llm_risk_analyzer.loader import load_json, load_rules
    from llm_risk_analyzer.report import render_markdown, write_report
else:
    from .engine import analyze_system
    from .loader import load_json, load_rules
    from .report import render_markdown, write_report


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="llm-risk-analyzer",
        description="Analyze LLM-system risks from JSON architecture and JSON rules.",
    )
    parser.add_argument("system", help="Path to system JSON description")
    parser.add_argument(
        "--rules",
        default="rules/core-rules.json",
        help="Path to rules JSON file",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json", "csv"],
        default="markdown",
        help="Output format",
    )
    parser.add_argument("--output", help="Write report to file")
    args = parser.parse_args()

    system = load_json(args.system)
    rules = load_rules(args.rules)
    result = analyze_system(system, rules)

    if args.output:
        write_report(result, Path(args.output), args.format)
        return

    if args.format == "json":
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif args.format == "markdown":
        markdown = render_markdown(result)
        print(markdown, end="")
        output_path = default_report_path(result["system"])
        write_report(result, output_path, "markdown")
        print(f"\nMarkdown-отчет сохранен: {output_path}")
    else:
        raise SystemExit("CSV output requires --output")


def default_report_path(system_name: str) -> Path:
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", system_name).strip("-").lower()
    return reports_dir / f"{slug or 'system'}-analysis.md"


if __name__ == "__main__":
    main()
