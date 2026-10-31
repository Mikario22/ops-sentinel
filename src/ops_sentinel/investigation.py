"""Read-only, evidence-grounded investigation agent (no remediation executor).

This deliberately treats CSV events and optional model commentary as untrusted.
A future LLM can generate a separate narrative without changing evidence,
risk scores, approval requirements, or the allowed tools.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol, Sequence

from .engine import Event, Finding

# An explicit allowlist: there is no tool that can modify identities or hosts.
ALLOWED_TOOLS = frozenset({"account_timeline", "source_timeline", "recorded_change_references"})
RULE_TOOLS = {
    "AFTER_HOURS_PRIVILEGED": ("account_timeline", "recorded_change_references"),
    "FAILED_LOGIN_BURST": ("account_timeline", "source_timeline"),
    "UNJUSTIFIED_PRIVILEGED_CHANGE": ("account_timeline", "recorded_change_references"),
}
PROPOSED_ACTIONS = {
    "AFTER_HOURS_PRIVILEGED": "consider_temporarily_restricting_account",
    "FAILED_LOGIN_BURST": "consider_account_lockout_or_source_block",
    "UNJUSTIFIED_PRIVILEGED_CHANGE": "consider_reverting_privileged_change",
}


@dataclass(frozen=True)
class EventEvidence:
    event_id: str
    timestamp: str
    account: str
    event_type: str
    outcome: str
    source_ip: str
    target_host: str
    privileged: bool
    business_reason: str


@dataclass(frozen=True)
class ToolTrace:
    tool: str
    matched_events: int
    returned_events: int
    truncated: bool
    window_start: str
    window_end: str


@dataclass(frozen=True)
class ApprovalRequest:
    action: str
    status: str
    reason: str


@dataclass(frozen=True)
class InvestigationReport:
    case_id: str
    rule_id: str
    account: str
    risk_score: int
    severity: str
    status: str
    summary: str
    observations: tuple[str, ...]
    evidence: tuple[EventEvidence, ...]
    tool_trace: tuple[ToolTrace, ...]
    approval_requests: tuple[ApprovalRequest, ...]
    model_commentary: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class NarrativeModel(Protocol):
    """Optional model adapter; must return text only, never commands or tool calls."""

    def summarize(self, context: dict) -> str:
        """Generate a narrative from the supplied bounded, local evidence."""


def _aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


def _timestamp(text: str) -> datetime:
    try:
        value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("finding timestamp must be valid ISO 8601") from exc
    if not _aware(value):
        raise ValueError("finding timestamp must have timezone information")
    return value


def _event_id(event: Event, index: int) -> str:
    record = [index, event.timestamp.astimezone(timezone.utc).isoformat(), event.account,
              event.event_type, event.source_ip, event.target_host, event.outcome,
              event.privileged, event.business_reason]
    return hashlib.sha256(json.dumps(record, separators=(",", ":")).encode()).hexdigest()[:16]


def _case_id(finding: Finding) -> str:
    fingerprint = json.dumps([finding.rule_id, finding.timestamp, finding.account.casefold(),
                              finding.source_ip, finding.target_host], separators=(",", ":"))
    return "INV-" + hashlib.sha256(fingerprint.encode()).hexdigest()[:12].upper()


class ReadOnlyEventTools:
    """Fixed local tools; no network, shell, database writes, or dynamic execution."""

    def __init__(self, events: Sequence[Event], *, max_per_tool: int = 50):
        if isinstance(max_per_tool, bool) or not isinstance(max_per_tool, int) or not 1 <= max_per_tool <= 500:
            raise ValueError("max_per_tool must be between 1 and 500")
        if any(not _aware(event.timestamp) for event in events):
            raise ValueError("event timestamps must be timezone aware")
        ordered = sorted(events, key=lambda event: (
            event.timestamp, event.account, event.event_type, event.source_ip,
            event.target_host, event.outcome, event.privileged, event.business_reason,
        ))
        self._events = tuple(enumerate(ordered))
        self._limit = max_per_tool

    def run(self, name: str, finding: Finding, start: datetime, end: datetime) -> tuple[tuple[EventEvidence, ...], ToolTrace]:
        if name not in ALLOWED_TOOLS:
            raise ValueError(f"Tool not allowed: {name}")
        if not _aware(start) or not _aware(end) or start > end:
            raise ValueError("tool window must be timezone-aware and ordered")
        matched: list[tuple[int, Event]] = []
        for index, event in self._events:
            if not start <= event.timestamp <= end:
                continue
            same_account = event.account.casefold() == finding.account.casefold()
            if name == "account_timeline" and same_account:
                matched.append((index, event))
            elif name == "source_timeline" and event.source_ip == finding.source_ip:
                matched.append((index, event))
            elif name == "recorded_change_references" and same_account and event.business_reason:
                matched.append((index, event))
        chosen = matched[: self._limit]
        evidence = tuple(EventEvidence(
            _event_id(event, index), event.timestamp.isoformat(), event.account,
            event.event_type, event.outcome, event.source_ip, event.target_host,
            event.privileged, event.business_reason,
        ) for index, event in chosen)
        trace = ToolTrace(name, len(matched), len(chosen), len(matched) > len(chosen),
                          start.isoformat(), end.isoformat())
        return evidence, trace


class InvestigationAgent:
    """Bounded multi-step, read-only investigations with human approval requests.

    A supplied model can add commentary only. Deterministic observations, risk,
    actions, approval status and evidence cannot be overridden by model output.
    """

    def __init__(self, *, lookback_minutes: int = 60, lookahead_minutes: int = 15,
                 max_evidence_per_tool: int = 50, model: NarrativeModel | None = None):
        if any(isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1440
               for value in (lookback_minutes, lookahead_minutes)):
            raise ValueError("investigation window minutes must be integers between 0 and 1440")
        self.lookback = timedelta(minutes=lookback_minutes)
        self.lookahead = timedelta(minutes=lookahead_minutes)
        self.max_evidence_per_tool = max_evidence_per_tool
        self.model = model

    def investigate(self, finding: Finding, events: Sequence[Event]) -> InvestigationReport:
        if finding.rule_id not in RULE_TOOLS:
            raise ValueError(f"Unrecognized finding rule: {finding.rule_id}")
        stamp = _timestamp(finding.timestamp)
        start, end = stamp - self.lookback, stamp + self.lookahead
        tools = ReadOnlyEventTools(events, max_per_tool=self.max_evidence_per_tool)
        trace: list[ToolTrace] = []
        collected: dict[str, EventEvidence] = {}
        by_tool: dict[str, tuple[EventEvidence, ...]] = {}
        for tool in RULE_TOOLS[finding.rule_id]:
            evidence, result = tools.run(tool, finding, start, end)
            trace.append(result)
            by_tool[tool] = evidence
            for item in evidence:
                collected[item.event_id] = item
        ordered = tuple(sorted(collected.values(), key=lambda e: (_timestamp(e.timestamp), e.event_id)))
        observations = [f"{len(ordered)} distinct event record(s) returned by read-only tools."]
        if not ordered:
            observations.append("No corroborating event records were found in this window; verify the input dataset.")
        if any(step.truncated for step in trace):
            observations.append("At least one tool result was truncated; evidence is incomplete.")
        if finding.rule_id == "FAILED_LOGIN_BURST":
            failures = [item for item in by_tool["account_timeline"] if item.event_type == "login"
                        and item.outcome == "failed" and item.source_ip == finding.source_ip]
            successes = [item for item in by_tool["account_timeline"] if item.event_type == "login"
                         and item.outcome == "success" and item.source_ip == finding.source_ip]
            observations.append(f"{len(failures)} same-account/source failed login record(s) visible in the window.")
            observations.append(f"{len(successes)} same-account/source successful login record(s) visible in the window.")
        else:
            refs = sorted({e.business_reason for e in by_tool["recorded_change_references"]
                           if e.business_reason})
            observations.append(f"{len(refs)} distinct business reason/reference value(s) recorded in nearby events.")
            observations.append("Recorded references are not proof of approved changes; verify externally.")
        observations.append("These records alone cannot establish intent or confirm compromise.")
        summary = (f"Review {finding.rule_id} for {finding.account}: "
                   f"{finding.severity} triage priority ({finding.risk_score}/100); "
                   f"{len(ordered)} related event record(s) collected.")
        approval = ApprovalRequest(
            PROPOSED_ACTIONS[finding.rule_id], "pending_human_approval",
            "Proposal only; a separate authorized human decision is required. This agent cannot execute it.",
        )
        commentary: str | None = None
        if self.model is not None:
            context = {"rule_id": finding.rule_id, "score": finding.risk_score,
                       "severity": finding.severity, "observations": list(observations),
                       "evidence": [asdict(item) for item in ordered]}
            # Model sees bounded, already selected evidence. It cannot call tools.
            result = self.model.summarize(context)
            if not isinstance(result, str) or len(result) > 4000:
                raise ValueError("model commentary must be text with at most 4000 characters")
            commentary = result
        return InvestigationReport(
            _case_id(finding), finding.rule_id, finding.account, finding.risk_score,
            finding.severity, "needs_human_review", summary, tuple(observations), ordered,
            tuple(trace), (approval,), commentary,
        )
