import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo
from ops_sentinel.engine import Event, analyze, parse_events


def event(at: str, *, type="login", outcome="success", privileged=True, reason="", source="192.0.2.1"):
    return Event(datetime.fromisoformat(at), "test-admin", type, source, "test-server", outcome, privileged, reason)


class EngineTests(unittest.TestCase):
    def test_after_hours_in_johannesburg(self):
        findings = analyze([event("2026-10-30T16:30:00+00:00")])
        self.assertEqual([f.rule_id for f in findings], ["AFTER_HOURS_PRIVILEGED"])

    def test_business_hours_does_not_alert(self):
        self.assertEqual(analyze([event("2026-10-30T12:00:00+02:00")]), [])

    def test_weekend_alerts_even_during_day(self):
        self.assertEqual(analyze([event("2026-10-31T12:00:00+02:00")])[0].rule_id,
                         "AFTER_HOURS_PRIVILEGED")

    def test_non_privileged_login_not_after_hours_alert(self):
        self.assertEqual(analyze([event("2026-10-30T23:00:00+02:00", privileged=False)]), [])

    def test_failure_threshold_and_deduplication(self):
        batch = [event(f"2026-10-30T10:{minute:02}:00+02:00", outcome="failed", privileged=False)
                 for minute in range(4)]
        self.assertEqual([f.rule_id for f in analyze(batch)], ["FAILED_LOGIN_BURST"])

    def test_failure_window_expiry(self):
        batch = [event(f"2026-10-30T10:{minute:02}:00+02:00", outcome="failed", privileged=False)
                 for minute in (0, 11, 22)]
        self.assertEqual(analyze(batch), [])

    def test_failed_logins_correlated_by_source(self):
        batch = [event("2026-10-30T10:00:00+02:00", outcome="failed", source=f"192.0.2.{i}")
                 for i in (1, 2, 3)]
        self.assertEqual(analyze(batch), [])

    def test_missing_reason_change(self):
        findings = analyze([event("2026-10-30T12:00:00+02:00", type="privileged_change")])
        self.assertEqual(findings[0].rule_id, "UNJUSTIFIED_PRIVILEGED_CHANGE")

    def test_change_with_reason_does_not_alert(self):
        self.assertEqual(analyze([event("2026-10-30T12:00:00+02:00", type="privileged_change",
                                        reason="CHG-123")]), [])

    def test_naive_timestamps_rejected(self):
        data = "timestamp,account,event_type,source_ip,target_host,outcome,privileged\n2026-10-30T12:00:00,a,login,192.0.2.1,h,success,true\n"
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "events.csv"
            p.write_text(data)
            with self.assertRaisesRegex(ValueError, "UTC offset"):
                parse_events(p)

    def test_utc_z_timestamps_are_valid(self):
        data = "timestamp,account,event_type,source_ip,target_host,outcome,privileged\n2026-10-30T16:30:00Z,a,login,192.0.2.1,h,success,true\n"
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "events.csv"
            p.write_text(data)
            self.assertEqual(len(analyze(parse_events(p))), 1)


if __name__ == "__main__":
    unittest.main()
