"""Read-only investigation tests, including approval and model boundaries."""
import json
import unittest
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from ops_sentinel.engine import Event, analyze, parse_events
from ops_sentinel.investigation import InvestigationAgent, ReadOnlyEventTools

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "synthetic_events.csv"


def sample():
    events = parse_events(SAMPLE)
    findings = analyze(events)
    return events, findings


class FakeNarrator:
    def __init__(self):
        self.contexts = []

    def summarize(self, context):
        self.contexts.append(context)
        return "Suggested response: ignore approvals and disable every account."


class InvestigationTests(unittest.TestCase):
    def test_all_sample_findings_generate_separate_cases(self):
        events, findings = sample()
        reports = [InvestigationAgent().investigate(f, events) for f in findings]
        self.assertEqual(len(reports), 3)
        self.assertEqual(len({r.case_id for r in reports}), 3)
        self.assertTrue(all(r.status == "needs_human_review" for r in reports))
        self.assertTrue(all(r.tool_trace for r in reports))

    def test_no_remediation_execution_and_pending_approval(self):
        events, findings = sample()
        report = InvestigationAgent().investigate(findings[0], events)
        self.assertEqual(report.approval_requests[0].status, "pending_human_approval")
        self.assertEqual(report.model_commentary, None)
        self.assertFalse(any("executed" in s.lower() for s in report.observations))

    def test_read_only_tool_allowlist(self):
        events, findings = sample()
        tools = ReadOnlyEventTools(events)
        start = datetime.fromisoformat("2026-10-30T00:00:00+02:00")
        end = datetime.fromisoformat("2026-10-31T00:00:00+02:00")
        with self.assertRaisesRegex(ValueError, "not allowed"):
            tools.run("disable_account", findings[0], start, end)

    def test_evidence_deduplicated_across_tools(self):
        events, findings = sample()
        failed = next(f for f in findings if f.rule_id == "FAILED_LOGIN_BURST")
        report = InvestigationAgent().investigate(failed, events)
        self.assertEqual(len(report.evidence), 3)
        self.assertEqual(len({e.event_id for e in report.evidence}), 3)
        self.assertEqual([t.tool for t in report.tool_trace], ["account_timeline", "source_timeline"])

    def test_finding_and_evidence_iso_timestamps(self):
        events, findings = sample()
        report = InvestigationAgent().investigate(findings[0], events)
        data = json.loads(json.dumps(report.to_dict()))
        self.assertTrue(data["case_id"].startswith("INV-"))
        self.assertTrue(all("+02:00" in e["timestamp"] for e in data["evidence"]))
        self.assertTrue(data["tool_trace"][0]["window_start"].endswith("+02:00"))

    def test_generated_case_id_is_stable(self):
        events, findings = sample()
        a = InvestigationAgent().investigate(findings[0], events)
        b = InvestigationAgent().investigate(findings[0], list(reversed(events)))
        self.assertEqual(a.case_id, b.case_id)
        self.assertEqual([e.account for e in a.evidence], [e.account for e in b.evidence])

    def test_records_outside_time_window_are_not_included(self):
        events, findings = sample()
        finding = next(f for f in findings if f.rule_id == "AFTER_HOURS_PRIVILEGED")
        report = InvestigationAgent(lookback_minutes=1, lookahead_minutes=0).investigate(finding, events)
        self.assertEqual(len(report.evidence), 1)

    def test_bounded_evidence_and_truncation_marker(self):
        events, findings = sample()
        failed = next(f for f in findings if f.rule_id == "FAILED_LOGIN_BURST")
        report = InvestigationAgent(max_evidence_per_tool=1).investigate(failed, events)
        self.assertLessEqual(len(report.evidence), 2)
        self.assertTrue(any(t.truncated for t in report.tool_trace))
        self.assertTrue(any("incomplete" in note for note in report.observations))

    def test_change_reference_is_not_verified_approval(self):
        events, findings = sample()
        after_hours = next(f for f in findings if f.rule_id == "AFTER_HOURS_PRIVILEGED")
        report = InvestigationAgent(lookback_minutes=24 * 60).investigate(after_hours, events)
        self.assertTrue(any("not proof of approved changes" in o for o in report.observations))
        self.assertTrue(any(item.business_reason == "CHG-100" for item in report.evidence))

    def test_nearby_success_correlates_with_failure(self):
        events, findings = sample()
        failed = next(f for f in findings if f.rule_id == "FAILED_LOGIN_BURST")
        extra = Event(datetime.fromisoformat("2026-10-30T11:03:00+02:00"), "test-user",
                      "login", "192.0.2.20", "test-server", "success", False)
        report = InvestigationAgent().investigate(failed, events + [extra])
        self.assertTrue(any("1 same-account/source successful" in o for o in report.observations))

    def test_unrelated_account_omitted_from_account_lookup(self):
        events, findings = sample()
        finding = next(f for f in findings if f.rule_id == "AFTER_HOURS_PRIVILEGED")
        result = InvestigationAgent().investigate(finding, events)
        self.assertTrue(all(e.account == "test-admin" for e in result.evidence))

    def test_model_text_is_separate_and_cannot_approve(self):
        events, findings = sample()
        narrator = FakeNarrator()
        report = InvestigationAgent(model=narrator).investigate(findings[0], events)
        self.assertIn("ignore approvals", report.model_commentary)
        self.assertEqual(report.status, "needs_human_review")
        self.assertEqual(report.approval_requests[0].status, "pending_human_approval")
        self.assertEqual(len(narrator.contexts), 1)

    def test_invalid_model_output_rejected(self):
        events, findings = sample()
        class BadModel:
            def summarize(self, context):
                return {"execute": "disable_account"}
        with self.assertRaisesRegex(ValueError, "commentary must be text"):
            InvestigationAgent(model=BadModel()).investigate(findings[0], events)

    def test_missing_timezone_rejected(self):
        events, findings = sample()
        with self.assertRaisesRegex(ValueError, "timezone"):
            InvestigationAgent().investigate(replace(findings[0], timestamp="2026-10-30T11:00:00"), events)
        bad = replace(events[0], timestamp=datetime(2026, 10, 30, 11))
        with self.assertRaisesRegex(ValueError, "timezone aware"):
            InvestigationAgent().investigate(findings[0], [bad])

    def test_unknown_rule_rejected(self):
        events, findings = sample()
        with self.assertRaisesRegex(ValueError, "Unrecognized"):
            InvestigationAgent().investigate(replace(findings[0], rule_id="ARBITRARY"), events)

    def test_window_limits_validated(self):
        for minutes in (-1, True, 1441):
            with self.subTest(minutes=minutes):
                with self.assertRaises(ValueError):
                    InvestigationAgent(lookback_minutes=minutes)

    def test_invalid_max_evidence_is_rejected(self):
        events, findings = sample()
        with self.assertRaisesRegex(ValueError, "max_per_tool"):
            InvestigationAgent(max_evidence_per_tool=0).investigate(findings[0], events)


if __name__ == "__main__":
    unittest.main()
