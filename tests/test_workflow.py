"""Synthetic-only tests of workflow planning, persistence, retries and audit."""
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from ops_sentinel.engine import Event, parse_events
from ops_sentinel.workflow import (
    AuditIntegrityError, DEFAULT_PLAN, FixedReadOnlyTools, LocalCheckpoint,
    RetryableStepError, StepSpec, WorkflowOrchestrator, WorkflowPlan,
)

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "synthetic_events.csv"


class SpyTools(FixedReadOnlyTools):
    def __init__(self):
        self.calls = []

    def execute(self, name, events, outputs):
        self.calls.append(name)
        return super().execute(name, events, outputs)


class TransientTools(SpyTools):
    def __init__(self, fail_count=1):
        super().__init__()
        self.remaining = fail_count

    def execute(self, name, events, outputs):
        if name == "investigate_findings" and self.remaining:
            self.remaining -= 1
            self.calls.append("transient:" + name)
            raise RetryableStepError("synthetic temporary problem")
        return super().execute(name, events, outputs)


class BrokenTools(SpyTools):
    def execute(self, name, events, outputs):
        self.calls.append(name)
        raise RuntimeError("sensitive value must not be persisted")


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.events = parse_events(SAMPLE)
        self.folder = Path(self.temp.name)

    def test_default_plan_is_explicit_and_ordered(self):
        self.assertEqual([s.name for s in DEFAULT_PLAN.steps],
                         ["detect", "investigate", "summarize"])
        self.assertEqual(DEFAULT_PLAN.steps[-1].depends_on, ("detect", "investigate"))

    def test_unsafe_tool_rejected(self):
        with self.assertRaisesRegex(ValueError, "not allowed"):
            WorkflowPlan((StepSpec("bad", "disable_account"),))

    def test_missing_dependency_and_cycle_rejected(self):
        with self.assertRaisesRegex(ValueError, "dependencies"):
            WorkflowPlan((StepSpec("a", "detect_events", ("b",)),
                          StepSpec("b", "summarize_cases", ("a",))))
        with self.assertRaisesRegex(ValueError, "dependencies"):
            WorkflowPlan((StepSpec("self", "detect_events", ("self",)),))

    def test_duplicate_step_names_rejected(self):
        with self.assertRaisesRegex(ValueError, "unique"):
            WorkflowPlan((StepSpec("x", "detect_events"), StepSpec("x", "summarize_cases")))

    def test_invalid_attempt_budget_rejected(self):
        for value in (0, 6, True):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "max_attempts"):
                    WorkflowPlan((StepSpec("step", "detect_events", max_attempts=value),))

    def test_happy_path_three_cases_and_approval_pending(self):
        state = WorkflowOrchestrator(self.folder).run(self.events, run_id="demo")
        self.assertEqual(state["status"], "completed")
        self.assertEqual(state["steps"]["detect"]["output"]["records_analyzed"], 6)
        cases = state["steps"]["investigate"]["output"]["investigations"]
        self.assertEqual(len(cases), 3)
        self.assertTrue(all(c["status"] == "needs_human_review" for c in cases))
        self.assertTrue(all(c["approval_requests"][0]["status"] == "pending_human_approval" for c in cases))
        summary = state["steps"]["summarize"]["output"]
        self.assertEqual(summary["investigations_count"], 3)
        self.assertEqual(summary["approval_requests_pending"], 3)
        self.assertFalse(summary["automated_remediation_executed"])
        self.assertEqual(summary["review_status"], "needs_human_review")

    def test_resume_skips_completed_steps(self):
        tools = SpyTools()
        runner = WorkflowOrchestrator(self.folder, tools=tools)
        first = runner.run(self.events, run_id="resume")
        self.assertEqual(len(tools.calls), 3)
        audit = LocalCheckpoint(self.folder, "resume")
        audit_len = len(audit.verify_audit())
        second = runner.run(self.events, run_id="resume")
        self.assertEqual(first, second)
        self.assertEqual(len(tools.calls), 3)
        self.assertEqual(len(audit.verify_audit()), audit_len)

    def test_default_run_id_is_deterministic(self):
        a = WorkflowOrchestrator(self.folder).run(self.events)
        b = WorkflowOrchestrator(self.folder).run(list(reversed(self.events)))
        self.assertEqual(a["run_id"], b["run_id"])
        self.assertEqual(b["status"], "completed")

    def test_retry_only_explicit_transient_errors(self):
        tools = TransientTools(fail_count=1)
        delays = []
        state = WorkflowOrchestrator(self.folder, tools=tools, sleep=delays.append,
                                     retry_delay_seconds=0.25).run(self.events, run_id="retry")
        self.assertEqual(state["status"], "completed")
        self.assertEqual(state["steps"]["investigate"]["attempts"], 2)
        self.assertEqual(delays, [0.25])
        events = [entry["event"] for entry in LocalCheckpoint(self.folder, "retry").verify_audit()]
        self.assertIn("step_retryable_error", events)

    def test_retry_budget_exhaustion_is_terminal(self):
        tools = TransientTools(fail_count=10)
        state = WorkflowOrchestrator(self.folder, tools=tools, sleep=lambda _: None).run(self.events, run_id="exhaust")
        self.assertEqual(state["status"], "failed")
        self.assertEqual(state["steps"]["investigate"]["attempts"], 2)
        self.assertEqual(state["steps"]["summarize"]["status"], "pending")
        WorkflowOrchestrator(self.folder, tools=tools).run(self.events, run_id="exhaust")
        self.assertEqual(state["steps"]["investigate"]["attempts"], 2)

    def test_unexpected_tool_error_is_not_retried_or_logged_with_secret(self):
        tools = BrokenTools()
        state = WorkflowOrchestrator(self.folder, tools=tools).run(self.events, run_id="broken")
        self.assertEqual(state["status"], "failed")
        self.assertEqual(state["steps"]["detect"]["attempts"], 1)
        self.assertEqual(len(tools.calls), 1)
        self.assertNotIn("sensitive value", json.dumps(state))
        self.assertNotIn("sensitive value", (self.folder / "broken.audit.jsonl").read_text())

    def test_audit_chain_detects_modified_record(self):
        WorkflowOrchestrator(self.folder).run(self.events, run_id="tampered")
        audit = LocalCheckpoint(self.folder, "tampered")
        self.assertTrue(audit.verify_audit())
        text = audit.audit_path.read_text()
        audit.audit_path.write_text(text.replace("run_started", "run_hacked"))
        with self.assertRaisesRegex(AuditIntegrityError, "integrity"):
            WorkflowOrchestrator(self.folder).run(self.events, run_id="tampered")

    def test_checkpoint_requires_matching_input(self):
        WorkflowOrchestrator(self.folder).run(self.events, run_id="bound")
        changed = replace(self.events[0], account="different")
        with self.assertRaisesRegex(AuditIntegrityError, "mismatch"):
            WorkflowOrchestrator(self.folder).run([changed, *self.events[1:]], run_id="bound")

    def test_checkpoint_requires_matching_plan(self):
        WorkflowOrchestrator(self.folder).run(self.events, run_id="plan")
        shorter = WorkflowPlan((StepSpec("detect", "detect_events"),))
        with self.assertRaisesRegex(AuditIntegrityError, "mismatch"):
            WorkflowOrchestrator(self.folder, plan=shorter).run(self.events, run_id="plan")

    def test_damaged_checkpoint_fails_closed(self):
        WorkflowOrchestrator(self.folder).run(self.events, run_id="broken-json")
        (self.folder / "broken-json.state.json").write_text("{")
        with self.assertRaisesRegex(AuditIntegrityError, "invalid checkpoint"):
            WorkflowOrchestrator(self.folder).run(self.events, run_id="broken-json")

    def test_missing_audit_fails_closed(self):
        WorkflowOrchestrator(self.folder).run(self.events, run_id="missing-audit")
        (self.folder / "missing-audit.audit.jsonl").unlink()
        with self.assertRaisesRegex(AuditIntegrityError, "without audit"):
            WorkflowOrchestrator(self.folder).run(self.events, run_id="missing-audit")

    def test_invalid_run_ids_rejected(self):
        for run_id in ("../escape", "x/y", "..", "", "a" * 65):
            with self.subTest(run_id=run_id):
                with self.assertRaisesRegex(ValueError, "run ID"):
                    WorkflowOrchestrator(self.folder).run(self.events, run_id=run_id)

    def test_naive_event_timestamp_rejected(self):
        bad = replace(self.events[0], timestamp=datetime(2026, 10, 30, 11))
        with self.assertRaisesRegex(ValueError, "aware timestamps"):
            WorkflowOrchestrator(self.folder).run([bad, *self.events[1:]], run_id="naive")

    def test_no_model_or_external_call_in_default_workflow(self):
        tools = FixedReadOnlyTools()
        self.assertEqual(set(["detect_events", "investigate_findings", "summarize_cases"]),
                         set(__import__("ops_sentinel.workflow", fromlist=["TOOL_ALLOWLIST"]).TOOL_ALLOWLIST))
        state = WorkflowOrchestrator(self.folder, tools=tools).run(self.events, run_id="offline")
        self.assertEqual(state["status"], "completed")
        self.assertTrue(all(report["model_commentary"] is None for report in
                            state["steps"]["investigate"]["output"]["investigations"]))


if __name__ == "__main__":
    unittest.main()
