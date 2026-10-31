"""Offline benchmark suite for deterministic Ops Sentinel detection and investigation.

Synthetic labels assess rule matches at the scenario/rule level, not whether
any real account has been compromised. No external AI service is evaluated.
"""

from __future__ import annotations

import json
import math
import statistics
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from time import perf_counter
from typing import Sequence

from .engine import Event, analyze
from .investigation import InvestigationAgent
from .risk import BASE_SCORES
from .workflow import FixedReadOnlyTools, LocalCheckpoint, RetryableStepError, WorkflowOrchestrator

RULE_IDS = tuple(sorted(BASE_SCORES))
REQUIRED_EVENT_KEYS = frozenset({"timestamp", "event_type", "outcome", "privileged"})
OPTIONAL_EVENT_KEYS = frozenset({"account", "source_ip", "target_host", "business_reason"})
MAX_SCENARIOS = 100
MAX_EVENTS_PER_SCENARIO = 250


@dataclass(frozen=True)
class LabeledScenario:
    scenario_id: str
    events: tuple[Event, ...]
    expected_rules: frozenset[str]


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def _scores(tp: int, fp: int, fn: int, tn: int) -> dict:
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    fpr = _ratio(fp, fp + tn)
    f1 = _ratio(2 * tp, 2 * tp + fp + fn)
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1,
        "false_positive_rate": fpr,
        "accuracy": _ratio(tp + tn, tp + tn + fp + fn),
    }


def load_scenarios(path: str | Path) -> tuple[LabeledScenario, ...]:
    """Validate a bounded synthetic JSON fixture without executing its data."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) != {"dataset", "scenarios"} or not isinstance(data["dataset"], str):
        raise ValueError("invalid evaluation manifest")
    records = data["scenarios"]
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_SCENARIOS:
        raise ValueError("evaluation scenarios must be a nonempty bounded list")
    seen: set[str] = set()
    scenarios = []
    for number, item in enumerate(records, start=1):
        if not isinstance(item, dict) or set(item) != {"id", "expected_rules", "events"}:
            raise ValueError(f"invalid scenario definition: {number}")
        sid, labels, raw_events = item["id"], item["expected_rules"], item["events"]
        if not isinstance(sid, str) or not sid or len(sid) > 80 or sid in seen:
            raise ValueError("scenario IDs must be distinct nonempty strings")
        seen.add(sid)
        if (not isinstance(labels, list) or any(not isinstance(label, str) or label not in RULE_IDS for label in labels)
                or len(set(labels)) != len(labels)):
            raise ValueError(f"invalid expected detection labels in {sid}")
        if not isinstance(raw_events, list) or not 1 <= len(raw_events) <= MAX_EVENTS_PER_SCENARIO:
            raise ValueError(f"invalid event list in {sid}")
        events = []
        for row in raw_events:
            if (not isinstance(row, dict) or not REQUIRED_EVENT_KEYS <= set(row)
                    or not set(row) <= REQUIRED_EVENT_KEYS | OPTIONAL_EVENT_KEYS):
                raise ValueError(f"invalid event fields in {sid}")
            ts = row["timestamp"]
            if not isinstance(ts, str):
                raise ValueError("timestamp must be an ISO 8601 string")
            try:
                parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError(f"invalid event timestamp in {sid}") from exc
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError("event timestamps must be timezone aware")
            for field in ("event_type", "outcome"):
                if not isinstance(row[field], str) or not row[field].strip():
                    raise ValueError(f"invalid {field} in {sid}")
            if type(row["privileged"]) is not bool:
                raise ValueError("privileged must be a boolean")
            for field in OPTIONAL_EVENT_KEYS:
                if field in row and not isinstance(row[field], str):
                    raise ValueError(f"invalid {field} in {sid}")
            events.append(Event(
                timestamp=parsed,
                account=row.get("account", "synthetic-admin"),
                event_type=row["event_type"],
                source_ip=row.get("source_ip", "192.0.2.1"),
                target_host=row.get("target_host", "synthetic-host"),
                outcome=row["outcome"],
                privileged=row["privileged"],
                business_reason=row.get("business_reason", ""),
            ))
        scenarios.append(LabeledScenario(sid, tuple(events), frozenset(labels)))
    return tuple(scenarios)


def _evidence_key(event: Event) -> tuple:
    return (event.timestamp.isoformat(), event.account, event.event_type,
            event.outcome, event.source_ip, event.target_host,
            event.privileged, event.business_reason)


def _report_evidence_key(evidence) -> tuple:
    return (evidence.timestamp, evidence.account, evidence.event_type,
            evidence.outcome, evidence.source_ip, evidence.target_host,
            evidence.privileged, evidence.business_reason)


class _FailOnceTools(FixedReadOnlyTools):
    def __init__(self):
        self.fired = False
        self.calls = 0

    def execute(self, name, events, outputs):
        self.calls += 1
        if name == "investigate_findings" and not self.fired:
            self.fired = True
            raise RetryableStepError("synthetic transient failure")
        return super().execute(name, events, outputs)


def _recovery_benchmark(events: Sequence[Event], trials: int) -> dict:
    passed = 0
    for index in range(trials):
        with tempfile.TemporaryDirectory() as folder:
            tools = _FailOnceTools()
            orchestrator = WorkflowOrchestrator(folder, tools=tools, sleep=lambda _: None)
            run_id = f"eval-recovery-{index}"
            state = orchestrator.run(events, run_id=run_id)
            checkpoint = LocalCheckpoint(folder, run_id)
            before = len(checkpoint.verify_audit())
            calls = tools.calls
            resumed = orchestrator.run(events, run_id=run_id)
            after = len(checkpoint.verify_audit())
            if (state["status"] == "completed" and resumed == state
                    and state["steps"]["investigate"]["attempts"] == 2
                    and tools.calls == calls and after == before):
                passed += 1
    return {"trials": trials, "successful_recoveries": passed,
            "recovery_rate": _ratio(passed, trials),
            "fault": "one synthetic transient investigation-tool error per trial"}


def evaluate(
    scenarios: Sequence[LabeledScenario], *,
    repeats: int = 5, recovery_trials: int = 3,
) -> dict:
    """Evaluate rule-level classification, investigation safeguards and recovery.

    Detection confusion-matrix units are (scenario, rule) pairs. Timing numbers
    are measurements from this runtime, not universal performance guarantees.
    """
    if not scenarios:
        raise ValueError("at least one labeled scenario is required")
    if type(repeats) is not int or not 1 <= repeats <= 100:
        raise ValueError("repeats must be between 1 and 100")
    if type(recovery_trials) is not int or not 1 <= recovery_trials <= 20:
        raise ValueError("recovery_trials must be between 1 and 20")

    counts = {rule: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for rule in RULE_IDS}
    observed = []
    expected_matches = []
    predicted_matches = []
    investigated_cases = 0
    evidence_total = 0
    evidence_grounded = 0
    trace_valid = 0
    guarded = 0
    case_errors = []
    agent = InvestigationAgent(model=None)

    for scenario in scenarios:
        findings = analyze(list(scenario.events))
        predicted = {f.rule_id for f in findings}
        expected_matches.append(sorted(scenario.expected_rules))
        predicted_matches.append(sorted(predicted))
        observed.append({"id": scenario.scenario_id,
                         "expected_rules": sorted(scenario.expected_rules),
                         "predicted_rules": sorted(predicted),
                         "match": predicted == scenario.expected_rules})
        for rule in RULE_IDS:
            truth, found = rule in scenario.expected_rules, rule in predicted
            key = "tp" if truth and found else "fp" if found else "fn" if truth else "tn"
            counts[rule][key] += 1

        available = {_evidence_key(event) for event in scenario.events}
        for finding in findings:
            report = agent.investigate(finding, scenario.events)
            investigated_cases += 1
            evidence_total += len(report.evidence)
            evidence_grounded += sum(_report_evidence_key(ev) in available for ev in report.evidence)
            if report.tool_trace and all(trace.tool in {
                "account_timeline", "source_timeline", "recorded_change_references"
            } and trace.returned_events <= trace.matched_events for trace in report.tool_trace):
                trace_valid += 1
            if (report.status == "needs_human_review" and report.model_commentary is None
                    and bool(report.approval_requests)
                    and all(r.status == "pending_human_approval" for r in report.approval_requests)):
                guarded += 1
            if not report.evidence:
                case_errors.append(f"{scenario.scenario_id}: no supporting records in selected time window")

    totals = {key: sum(item[key] for item in counts.values()) for key in ("tp", "fp", "fn", "tn")}
    durations = []
    for _ in range(repeats):
        start = perf_counter()
        for scenario in scenarios:
            findings = analyze(list(scenario.events))
            for finding in findings:
                agent.investigate(finding, scenario.events)
        durations.append((perf_counter() - start) * 1000)
    ordered = sorted(durations)
    timings = {
        "repeats": repeats,
        "median_ms": round(statistics.median(ordered), 3),
        "p95_ms": round(ordered[math.ceil(len(ordered) * 0.95) - 1], 3),
        "min_ms": round(ordered[0], 3),
        "max_ms": round(ordered[-1], 3),
        "scope": "full synthetic suite: detection + offline investigation",
    }

    return {
        "methodology": "scenario-level labels per detection rule; synthetic cases, not real-world validated",
        "scenario_count": len(scenarios),
        "event_count": sum(len(s.events) for s in scenarios),
        "case_exact_match_rate": _ratio(sum(row["match"] for row in observed), len(observed)),
        "detection": {"overall": _scores(**totals),
                      "per_rule": {rule: _scores(**count) for rule, count in counts.items()}},
        "investigation_checks": {
            "generated_cases": investigated_cases,
            "evidence_records": evidence_total,
            "grounded_evidence_rate": _ratio(evidence_grounded, evidence_total),
            "allowlisted_trace_rate": _ratio(trace_valid, investigated_cases),
            "approval_guardrail_rate": _ratio(guarded, investigated_cases),
            "limitations": "structural tests only; cannot establish narrative correctness or real threat detection",
            "warnings": case_errors,
        },
        "recovery": _recovery_benchmark(scenarios[0].events, recovery_trials),
        "latency": timings,
        "scenarios": observed,
    }
