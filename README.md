# llm-risk-analyzer

`llm-risk-analyzer` is a small rule-based prototype for analyzing security and
privacy risks in LLM-integrated information systems.

The prototype implements a reproducible version of a four-dimensional threat
analysis approach:

- data lifecycle stage;
- LLM involvement role;
- adversary model;
- vulnerability properties, including impact and manageability.

The analyzer does not replace expert judgment. It transforms a structured JSON
description of a system into a threat matrix by applying an extensible JSON rule
base.

## Why this prototype exists

Existing tools such as OWASP LLM Top 10, MITRE ATLAS, garak, and PyRIT provide
useful threat categories, techniques, and test findings. This project uses such
inputs as evidence, then relates them to a concrete system architecture:
components, data flows, actors, controls, and LLM roles.

The goal is to identify not only isolated vulnerabilities, but also cross-level
and cumulative scenarios that connect data, model behavior, and operational
processes.

## Input

The input is a JSON model of an LLM-enabled system:

```json
{
  "system": "MedDocAssistant",
  "components": [
    {
      "id": "llm_annotator",
      "type": "llm",
      "name": "LLM annotation module",
      "llm_roles": ["active_generation"]
    }
  ],
  "flows": [
    {
      "id": "f1",
      "from": "ehr_database",
      "to": "llm_annotator",
      "lifecycle_stage": "processing",
      "data_categories": ["medical_data", "personal_data"]
    }
  ],
  "actors": [
    {
      "id": "clinician",
      "type": "insider",
      "access_to": ["web_ui"],
      "can_make_repeated_queries": true
    }
  ],
  "controls": ["human_review", "api_rate_limit"]
}
```

## Rules

Rules are stored separately from the Python code:

```json
{
  "id": "cumulative_inference_by_repeated_queries",
  "scope": "flow_component_actor",
  "when": [
    {"left": "component.type", "op": "eq", "value": "llm"},
    {"left": "actor.can_make_repeated_queries", "op": "eq", "value": true},
    {"op": "missing_control", "value": "behavioral_monitoring"}
  ],
  "levels": ["data", "model", "process"],
  "impact": 4,
  "manageability": 1
}
```

This keeps the engine generic. New threat knowledge can be added by extending
the rule base instead of rewriting the analyzer.

## Usage

```bash
python -m llm_risk_analyzer.cli examples/meddocassistant.json
```

Save a report:

```bash
python -m llm_risk_analyzer.cli examples/meddocassistant.json --output reports/meddocassistant.md
```

When Markdown output is printed to the console without `--output`, the analyzer
also saves a Markdown report to `reports/<system>-analysis.md`.

JSON output:

```bash
python -m llm_risk_analyzer.cli examples/meddocassistant.json --format json
```

## Example output

For the included `MedDocAssistant` example, the analyzer identifies:

- prompt injection against an LLM annotation module;
- memorization risk caused by fine-tuning on operational data;
- cumulative inference via repeated legitimate queries;
- training data poisoning risk.

Each threat is mapped to analysis levels, framework dimensions, impact,
manageability, priority, and recommended controls.

## Development

Run tests:

```bash
python -m unittest discover -s tests
```
