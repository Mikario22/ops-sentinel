"""Resumable, auditable orchestration of Ops Sentinel's read-only agents.

This is a single-writer, local prototype. It cannot execute commands, change
accounts, or approve remediation. Only the three built-in tool names are valid.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

from .engine import Event, Finding, analyze
from .investigation import InvestigationAgent

TOOL_ALLOWLIST = frozenset({"detect_events", "investigate_findings", "summarize_cases"})
RUN_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
ZERO_HASH = "0" * 64
SCHEMA_VERSION = 1


class WorkflowError(RuntimeError):
    """Invalid plan, state, or orchestration operation."""


class RetryableStepError(WorkflowError):
    """Explicit transient error: the only exception class eligible for retry."""


class AuditIntegrityError(WorkflowError):
    """Audit or checkpoint evidence does not validate."""


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(value: Any) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class StepSpec:
    name: str
    tool: str
    depends_on: tuple[str, ...] = ()
    max_attempts: int = 2


@dataclass(frozen=True)
class WorkflowPlan:
    steps: tuple[StepSpec, ...]

    def __post_init__(self) -> None:
        if not self.steps or len(self.steps) > 16:
            raise ValueError("plan must contain 1–16 steps")
        seen: set[str] = set()
        for step in self.steps:
            if not isinstance(step.name, str) or not RUN_ID_PATTERN.fullmatch(step.name):
                raise ValueError("invalid step name")
            if step.name in seen:
                raise ValueError("step names must be unique")
            if step.tool not in TOOL_ALLOWLIST:
                raise ValueError(f"tool not allowed: {step.tool}")
            if isinstance(step.max_attempts, bool) or not isinstance(step.max_attempts, int) or not 1 <= step.max_attempts <= 5:
                raise ValueError("max_attempts must be 1–5")
            if len(set(step.depends_on)) != len(step.depends_on) or any(dep not in seen for dep in step.depends_on):
                raise ValueError("dependencies must be unique and precede their step")
            seen.add(step.name)

    def fingerprint(self) -> str:
        return _digest([asdict(step) for step in self.steps])


DEFAULT_PLAN = WorkflowPlan((
    StepSpec("detect", "detect_events", (), 2),
    StepSpec("investigate", "investigate_findings", ("detect",), 2),
    StepSpec("summarize", "summarize_cases", ("detect", "investigate"), 2),
))


class FixedReadOnlyTools:
    """Only allowlisted local operations. No shell, network or write tools."""

    def execute(self, name: str, events: Sequence[Event], outputs: dict[str, dict]) -> dict:
        if name not in TOOL_ALLOWLIST:
            raise ValueError(f"tool not allowed: {name}")
        if name == "detect_events":
            return {"records_analyzed": len(events),
                    "findings": [item.to_dict() for item in analyze(list(events))]}
        if name == "investigate_findings":
            detected = outputs["detect"]["findings"]
            agent = InvestigationAgent(model=None)
            return {"investigations": [
                agent.investigate(Finding(**finding), events).to_dict()
                for finding in detected
            ]}
        cases = outputs["investigate"]["investigations"]
        levels = Counter(case["severity"] for case in cases)
        return {
            "investigations_count": len(cases),
            "case_ids": [case["case_id"] for case in cases],
            "severity_breakdown": {level: levels[level]
                                   for level in ("low", "medium", "high", "critical")},
            "review_status": "needs_human_review",
            "approval_requests_pending": sum(
                request["status"] == "pending_human_approval"
                for case in cases for request in case["approval_requests"]
            ),
            "automated_remediation_executed": False,
        }


class LocalCheckpoint:
    """Atomic JSON checkpoint + hash-linked JSONL audit, for one writer only.

    The two files are *not* an atomic transaction. Interrupted writes require
    manual verification; corrupted or inconsistent records fail closed.
    """

    def __init__(self, directory: str | Path, run_id: str):
        if not isinstance(run_id, str) or not RUN_ID_PATTERN.fullmatch(run_id) or run_id in {".", ".."}:
            raise ValueError("invalid run ID")
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.state_path = self.directory / f"{run_id}.state.json"
        self.audit_path = self.directory / f"{run_id}.audit.jsonl"

    def load(self) -> dict | None:
        if not self.state_path.exists():
            return None
        if self.state_path.is_symlink():
            raise AuditIntegrityError("symlinked checkpoint is not allowed")
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise AuditIntegrityError("invalid checkpoint JSON") from exc
        if not isinstance(state, dict):
            raise AuditIntegrityError("checkpoint must be a JSON object")
        return state

    def save(self, state: dict) -> None:
        temp_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=self.directory,
                                             prefix=".checkpoint-", suffix=".tmp",
                                             delete=False) as stream:
                temp_name = stream.name
                stream.write(json.dumps(state, indent=2, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temp_name, 0o600)
            os.replace(temp_name, self.state_path)
        finally:
            if temp_name and os.path.exists(temp_name):
                os.unlink(temp_name)

    def verify_audit(self) -> list[dict]:
        if not self.audit_path.exists():
            return []
        if self.audit_path.is_symlink():
            raise AuditIntegrityError("symlinked audit is not allowed")
        try:
            lines = self.audit_path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise AuditIntegrityError("audit unreadable") from exc
        previous = ZERO_HASH
        result: list[dict] = []
        for index, line in enumerate(lines):
            try:
                row = json.loads(line)
                if not isinstance(row, dict) or set(row) != {
                    "sequence", "previous_hash", "event", "step", "details", "hash"
                }:
                    raise ValueError("invalid audit shape")
                payload = {key: row[key] for key in row if key != "hash"}
                if row["sequence"] != index or row["previous_hash"] != previous or row["hash"] != _digest(payload):
                    raise ValueError("invalid audit chain")
            except (TypeError, ValueError, KeyError) as exc:
                raise AuditIntegrityError(f"audit integrity failure at record {index}") from exc
            previous = row["hash"]
            result.append(row)
        return result

    def append_audit(self, event: str, step: str = "", details: dict | None = None) -> None:
        records = self.verify_audit()
        payload = {
            "sequence": len(records),
            "previous_hash": records[-1]["hash"] if records else ZERO_HASH,
            "event": event,
            "step": step,
            "details": details or {},
        }
        record = dict(payload, hash=_digest(payload))
        # Audit details are intentionally metadata only, not source event contents.
        with self.audit_path.open("a", encoding="utf-8") as stream:
            stream.write(_json(record) + "\n")
            stream.flush()
            os.fsync(stream.fileno())


class WorkflowOrchestrator:
    """Execute a validated dependency plan with bounded explicit retries.

    All built-in operations are read-only. The injected tools seam is intended
    for tests or trusted application code, never for user-supplied tool names.
    """

    def __init__(self, directory: str | Path, *, plan: WorkflowPlan = DEFAULT_PLAN,
                 tools: FixedReadOnlyTools | None = None,
                 sleep: Callable[[float], None] = time.sleep,
                 retry_delay_seconds: float = 0.0):
        if not isinstance(plan, WorkflowPlan):
            raise TypeError("plan must be a WorkflowPlan")
        if isinstance(retry_delay_seconds, bool) or not isinstance(retry_delay_seconds, (int, float)) or not 0 <= retry_delay_seconds <= 10:
            raise ValueError("retry delay must be between 0 and 10 seconds")
        self.directory = Path(directory)
        self.plan = plan
        self.tools = tools if tools is not None else FixedReadOnlyTools()
        self.sleep = sleep
        self.retry_delay_seconds = retry_delay_seconds

    @staticmethod
    def input_digest(events: Sequence[Event]) -> str:
        rows = []
        for event in events:
            if event.timestamp.tzinfo is None or event.timestamp.utcoffset() is None:
                raise ValueError("workflow events must have aware timestamps")
            row = asdict(event)
            row["timestamp"] = event.timestamp.isoformat()
            rows.append(row)
        return _digest(sorted(rows, key=_json))

    def run(self, events: Sequence[Event], *, run_id: str | None = None) -> dict:
        frozen_events = tuple(events)
        input_hash = self.input_digest(frozen_events)
        run_id = run_id if run_id is not None else f"RUN-{input_hash[:12]}"
        checkpoint = LocalCheckpoint(self.directory, run_id)
        state = checkpoint.load()
        records = checkpoint.verify_audit()
        if state is None:
            if records:
                raise AuditIntegrityError("audit exists without checkpoint; manual reconciliation required")
            state = {
                "schema_version": SCHEMA_VERSION,
                "run_id": run_id,
                "plan_digest": self.plan.fingerprint(),
                "input_digest": input_hash,
                "status": "running",
                "steps": {step.name: {
                    "status": "pending", "attempts": 0, "output": None, "error": None
                } for step in self.plan.steps},
            }
            checkpoint.save(state)
            checkpoint.append_audit("run_started", details={"steps": len(self.plan.steps)})
        else:
            if not records:
                raise AuditIntegrityError("checkpoint exists without audit; manual reconciliation required")
            if (state.get("schema_version") != SCHEMA_VERSION
                    or state.get("run_id") != run_id
                    or state.get("plan_digest") != self.plan.fingerprint()
                    or state.get("input_digest") != input_hash):
                raise AuditIntegrityError("checkpoint plan or input mismatch")
            if not isinstance(state.get("steps"), dict) or set(state["steps"]) != {step.name for step in self.plan.steps}:
                raise AuditIntegrityError("checkpoint step structure mismatch")
            for step in self.plan.steps:
                value = state["steps"][step.name]
                if not isinstance(value, dict) or value.get("status") not in {
                    "pending", "running", "retrying", "completed", "failed"
                } or type(value.get("attempts")) is not int or not 0 <= value["attempts"] <= step.max_attempts:
                    raise AuditIntegrityError("checkpoint step is invalid")
                if value["status"] == "completed" and not isinstance(value.get("output"), dict):
                    raise AuditIntegrityError("completed step has no output")
            if state.get("status") not in {"running", "completed", "failed"}:
                raise AuditIntegrityError("checkpoint run status is invalid")
            if state["status"] in {"completed", "failed"}:
                return state

        for step in self.plan.steps:
            record = state["steps"][step.name]
            if record["status"] == "completed":
                continue
            if record["status"] == "failed":
                state["status"] = "failed"
                checkpoint.save(state)
                return state
            if not all(state["steps"][name]["status"] == "completed" for name in step.depends_on):
                raise AuditIntegrityError("step dependencies were not completed")
            while record["attempts"] < step.max_attempts:
                record["attempts"] += 1
                record["status"] = "running"
                checkpoint.save(state)
                checkpoint.append_audit("step_started", step.name, {"attempt": record["attempts"]})
                outputs = {key: item["output"] for key, item in state["steps"].items()
                           if item["status"] == "completed"}
                try:
                    result = self.tools.execute(step.tool, frozen_events, outputs)
                    if not isinstance(result, dict):
                        raise TypeError("tool returned non-object result")
                    # Also enforce JSON serializability before checkpointing.
                    result = json.loads(_json(result))
                except RetryableStepError:
                    record["status"] = "retrying"
                    record["error"] = "retryable_step_error"
                    checkpoint.save(state)
                    checkpoint.append_audit("step_retryable_error", step.name, {"attempt": record["attempts"]})
                    if record["attempts"] < step.max_attempts:
                        self.sleep(min(10.0, self.retry_delay_seconds * (2 ** (record["attempts"] - 1))))
                    continue
                except Exception as exc:
                    record["status"] = "failed"
                    record["error"] = f"tool_error:{type(exc).__name__}"
                    checkpoint.save(state)
                    checkpoint.append_audit("step_failed", step.name, {"error_type": type(exc).__name__})
                    break
                record.update(status="completed", output=result, error=None)
                checkpoint.save(state)
                checkpoint.append_audit("step_completed", step.name, {"attempts": record["attempts"]})
                break
            if record["status"] != "completed":
                record["status"] = "failed"
                record["error"] = record["error"] or "attempt_budget_exhausted"
                state["status"] = "failed"
                checkpoint.save(state)
                checkpoint.append_audit("run_failed", step.name)
                return state

        state["status"] = "completed"
        checkpoint.save(state)
        checkpoint.append_audit("run_completed", details={"steps": len(self.plan.steps)})
        return state
