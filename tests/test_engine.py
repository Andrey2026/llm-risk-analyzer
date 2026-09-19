import unittest

from llm_risk_analyzer.engine import analyze_system
from llm_risk_analyzer.loader import load_json, load_rules


class EngineTest(unittest.TestCase):
    def test_meddocassistant_detects_core_threats(self) -> None:
        system = load_json("examples/meddocassistant.json")
        rules = load_rules("rules/core-rules.json")

        result = analyze_system(system, rules)
        rule_ids = {threat["rule_id"] for threat in result["threats"]}

        self.assertIn("llm_prompt_injection_sensitive_generation", rule_ids)
        self.assertIn("llm_memorization_from_operational_finetuning", rule_ids)
        self.assertIn("cumulative_inference_by_repeated_queries", rule_ids)
        self.assertIn("training_data_poisoning", rule_ids)
        self.assertGreaterEqual(result["summary"]["cross_level_count"], 4)
        self.assertGreaterEqual(result["summary"]["cumulative_scenario_count"], 1)

    def test_priority_mapping(self) -> None:
        system = load_json("examples/meddocassistant.json")
        rules = load_rules("rules/core-rules.json")

        result = analyze_system(system, rules)
        priorities = {threat["rule_id"]: threat["priority"] for threat in result["threats"]}

        self.assertEqual(priorities["llm_memorization_from_operational_finetuning"], "P2")
        self.assertEqual(priorities["cumulative_inference_by_repeated_queries"], "P2")
        self.assertEqual(priorities["training_data_poisoning"], "P3")


if __name__ == "__main__":
    unittest.main()
