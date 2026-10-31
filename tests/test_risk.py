"""Risk scoring tests use synthetic rule context only."""
import unittest

from ops_sentinel.risk import assess_risk, classify_severity


class RiskTests(unittest.TestCase):
    def test_severity_boundaries(self):
        for score, level in [(0, "low"), (39, "low"), (40, "medium"),
                             (69, "medium"), (70, "high"), (89, "high"),
                             (90, "critical"), (100, "critical")]:
            with self.subTest(score=score):
                self.assertEqual(classify_severity(score), level)

    def test_invalid_score_rejected(self):
        for score in (-1, 101, 2.5, True):
            with self.subTest(score=score):
                with self.assertRaises(ValueError):
                    classify_severity(score)

    def test_base_legacy_scores_preserved(self):
        cases = [("AFTER_HOURS_PRIVILEGED", 75, "high", 0),
                 ("UNJUSTIFIED_PRIVILEGED_CHANGE", 85, "high", 0),
                 ("FAILED_LOGIN_BURST", 60, "medium", 3)]
        for rule, score, level, attempts in cases:
            with self.subTest(rule=rule):
                assessment = assess_risk(rule, failed_attempts=attempts)
                self.assertEqual((assessment.score, assessment.severity), (score, level))

    def test_weekend_and_overnight_explain_bonuses(self):
        result = assess_risk("AFTER_HOURS_PRIVILEGED", weekend=True, overnight=True)
        self.assertEqual((result.score, result.severity), (90, "critical"))
        self.assertEqual([f.code for f in result.factors], ["RULE_BASE", "WEEKEND", "OVERNIGHT"])
        self.assertEqual(sum(f.points for f in result.factors), result.score)

    def test_failed_privileged_account_prioritized(self):
        ordinary = assess_risk("FAILED_LOGIN_BURST", failed_attempts=3)
        privileged = assess_risk("FAILED_LOGIN_BURST", failed_attempts=3, privileged=True)
        self.assertEqual((ordinary.score, privileged.score), (60, 75))
        self.assertIn("PRIVILEGED_ACCOUNT", [f.code for f in privileged.factors])

    def test_failure_count_bounded(self):
        self.assertEqual(assess_risk("FAILED_LOGIN_BURST", failed_attempts=3).score, 60)
        self.assertEqual(assess_risk("FAILED_LOGIN_BURST", failed_attempts=5).score, 70)
        self.assertEqual(assess_risk("FAILED_LOGIN_BURST", failed_attempts=20).score, 70)

    def test_capped_to_100(self):
        risk = assess_risk("UNJUSTIFIED_PRIVILEGED_CHANGE", weekend=True, overnight=True)
        self.assertEqual((risk.score, risk.severity), (100, "critical"))
        self.assertEqual(sum(f.points for f in risk.factors), 100)
        high = assess_risk("FAILED_LOGIN_BURST", failed_attempts=20,
                           privileged=True, weekend=True, overnight=True)
        self.assertEqual(high.score, 100)
        self.assertEqual(sum(f.points for f in high.factors), 100)

    def test_unknown_rule_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unknown detection rule"):
            assess_risk("IMAGINARY_RULE")

    def test_invalid_attempts_rejected(self):
        for attempts in (-1, 1, True):
            with self.subTest(attempts=attempts):
                with self.assertRaises(ValueError):
                    assess_risk("FAILED_LOGIN_BURST", failed_attempts=attempts)
        with self.assertRaises(ValueError):
            assess_risk("AFTER_HOURS_PRIVILEGED", failed_attempts=3)

    def test_scoring_is_deterministic(self):
        first = assess_risk("FAILED_LOGIN_BURST", failed_attempts=4, privileged=True)
        second = assess_risk("FAILED_LOGIN_BURST", failed_attempts=4, privileged=True)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
