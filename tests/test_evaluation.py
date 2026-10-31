"""Offline evaluation tests on synthetic, explicitly labeled scenarios."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ops_sentinel.evaluation import LabeledScenario, _scores, evaluate, load_scenarios

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "evaluation_cases.json"


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.scenarios = load_scenarios(SAMPLE)

    def test_dataset_contains_positive_negative_and_policy_gap(self):
        self.assertEqual(len(self.scenarios), 13)
        self.assertEqual(len({scenario.scenario_id for scenario in self.scenarios}), 13)
        self.assertTrue(any(not scenario.expected_rules for scenario in self.scenarios))
        self.assertTrue(any("AFTER_HOURS_PRIVILEGED" in scenario.expected_rules for scenario in self.scenarios))

    def test_precision_recall_confusion_counts(self):
        report = evaluate(self.scenarios, repeats=1, recovery_trials=1)
        overall = report["detection"]["overall"]
        self.assertEqual((overall["tp"], overall["fp"], overall["fn"], overall["tn"]),
                         (6, 1, 0, 32))
        self.assertEqual(overall["precision"], round(6/7, 4))
        self.assertEqual(overall["recall"], 1.0)
        self.assertEqual(overall["false_positive_rate"], round(1/33, 4))
        self.assertEqual(report["case_exact_match_rate"], round(12/13, 4))

    def test_authorized_evening_login_exposes_false_positive(self):
        report = evaluate(self.scenarios, repeats=1, recovery_trials=1)
        example = next(s for s in report["scenarios"]
                       if s["id"] == "approved_evening_maintenance_false_alert")
        self.assertFalse(example["match"])
        self.assertEqual(example["expected_rules"], [])
        self.assertEqual(example["predicted_rules"], ["AFTER_HOURS_PRIVILEGED"])
        self.assertEqual(report["detection"]["per_rule"]["AFTER_HOURS_PRIVILEGED"]["fp"], 1)

    def test_investigation_guardrails_and_evidence_traceability(self):
        report = evaluate(self.scenarios, repeats=1, recovery_trials=1)
        investigation = report["investigation_checks"]
        self.assertEqual(investigation["generated_cases"], 7)
        self.assertGreater(investigation["evidence_records"], 0)
        self.assertEqual(investigation["grounded_evidence_rate"], 1.0)
        self.assertEqual(investigation["approval_guardrail_rate"], 1.0)
        self.assertEqual(investigation["allowlisted_trace_rate"], 1.0)
        self.assertEqual(investigation["warnings"], [])

    def test_recovery_is_bounded_and_resumable(self):
        report = evaluate(self.scenarios, repeats=1, recovery_trials=2)
        self.assertEqual(report["recovery"]["trials"], 2)
        self.assertEqual(report["recovery"]["successful_recoveries"], 2)
        self.assertEqual(report["recovery"]["recovery_rate"], 1.0)

    def test_latency_has_positive_bounded_measurements(self):
        report = evaluate(self.scenarios, repeats=3, recovery_trials=1)
        latency = report["latency"]
        self.assertEqual(latency["repeats"], 3)
        self.assertGreaterEqual(latency["median_ms"], latency["min_ms"])
        self.assertGreaterEqual(latency["max_ms"], latency["p95_ms"])
        self.assertIn("offline", latency["scope"])

    def test_empty_denominator_has_explicit_null_rates(self):
        count = _scores(0, 0, 0, 0)
        self.assertIsNone(count["precision"])
        self.assertIsNone(count["recall"])
        self.assertIsNone(count["false_positive_rate"])
        self.assertIsNone(count["accuracy"])

    def test_empty_no_alert_fixture_has_no_investigation_denominators(self):
        no_alert = next(s for s in self.scenarios if s.scenario_id == "privileged_business_hours")
        report = evaluate([no_alert], repeats=1, recovery_trials=1)
        self.assertEqual(report["investigation_checks"]["generated_cases"], 0)
        self.assertIsNone(report["investigation_checks"]["grounded_evidence_rate"])
        self.assertIsNone(report["investigation_checks"]["approval_guardrail_rate"])
        self.assertEqual(report["detection"]["overall"]["tp"], 0)

    def test_offline_evaluation_never_calls_external_model(self):
        with patch("ops_sentinel.narration.request.urlopen",
                   side_effect=AssertionError("unexpected network call")):
            report = evaluate(self.scenarios, repeats=1, recovery_trials=1)
        self.assertEqual(report["scenario_count"], 13)

    def test_invalid_benchmark_configurations(self):
        for repeats, trials in [(0, 1), (101, 1), (True, 1), (1, 0),
                                (1, 21), (1, True)]:
            with self.subTest(repeats=repeats, trials=trials):
                with self.assertRaises(ValueError):
                    evaluate(self.scenarios, repeats=repeats, recovery_trials=trials)
        with self.assertRaises(ValueError):
            evaluate([], repeats=1, recovery_trials=1)

    def test_invalid_labels_rejected(self):
        data = json.loads(SAMPLE.read_text(encoding="utf-8"))
        data["scenarios"][0]["expected_rules"] = ["NON_EXISTENT_RULE"]
        with self.assertRaisesRegex(ValueError, "labels"):
            self._load_custom(data)

    def test_duplicate_ids_rejected(self):
        data = json.loads(SAMPLE.read_text(encoding="utf-8"))
        data["scenarios"][1]["id"] = data["scenarios"][0]["id"]
        with self.assertRaisesRegex(ValueError, "IDs"):
            self._load_custom(data)

    def test_naive_timestamps_rejected(self):
        data = json.loads(SAMPLE.read_text(encoding="utf-8"))
        data["scenarios"][0]["events"][0]["timestamp"] = "2026-10-30T19:00:00"
        with self.assertRaisesRegex(ValueError, "timezone"):
            self._load_custom(data)

    def test_boolean_field_and_unknown_fields_rejected(self):
        data = json.loads(SAMPLE.read_text(encoding="utf-8"))
        data["scenarios"][0]["events"][0]["privileged"] = "true"
        with self.assertRaisesRegex(ValueError, "boolean"):
            self._load_custom(data)
        data = json.loads(SAMPLE.read_text(encoding="utf-8"))
        data["scenarios"][0]["events"][0]["shell_command"] = "rm -rf /"
        with self.assertRaisesRegex(ValueError, "fields"):
            self._load_custom(data)

    def test_manifest_requires_structure_and_bounded_events(self):
        data = json.loads(SAMPLE.read_text(encoding="utf-8"))
        data["scenarios"] = []
        with self.assertRaisesRegex(ValueError, "bounded"):
            self._load_custom(data)
        data = json.loads(SAMPLE.read_text(encoding="utf-8"))
        data["scenarios"][0]["events"] *= 251
        with self.assertRaisesRegex(ValueError, "event list"):
            self._load_custom(data)

    def _load_custom(self, value):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "cases.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            return load_scenarios(path)


if __name__ == "__main__":
    unittest.main()
