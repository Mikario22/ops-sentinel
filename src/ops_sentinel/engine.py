"""Pure, deterministic security analytics; all example input is synthetic."""

from __future__ import annotations

import csv
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

LOCAL_ZONE = ZoneInfo("Africa/Johannesburg")


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    account: str
    event_type: str
    source_ip: str
    target_host: str
    outcome: str
    privileged: bool
    business_reason: str = ""


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    account: str
    timestamp: str
    source_ip: str
    target_host: str
    risk_score: int
    evidence: str
    recommended_action: str

    def to_dict(self) -> dict:
        return asdict(self)


def parse_events(path: str | Path) -> list[Event]:
    """Read an explicit CSV schema, rejecting missing and ambiguous timestamps."""
    required = {"timestamp", "account", "event_type", "source_ip", "target_host", "outcome", "privileged"}
    events: list[Event] = []
    with open(path, newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Missing CSV columns: {', '.join(sorted(missing))}")
        for number, row in enumerate(reader, start=2):
            try:
                ts = datetime.fromisoformat((row["timestamp"] or "").strip().replace("Z", "+00:00"))
                if ts.tzinfo is None or ts.utcoffset() is None:
                    raise ValueError("timestamp must include UTC offset or Z")
                for key in required - {"timestamp", "privileged"}:
                    if not (row[key] or "").strip():
                        raise ValueError(f"{key} must not be blank")
                flag = (row["privileged"] or "").strip().lower()
                if flag not in {"true", "false"}:
                    raise ValueError("privileged must be true or false")
                events.append(Event(
                    timestamp=ts, account=row["account"].strip(),
                    event_type=row["event_type"].strip().lower(),
                    source_ip=row["source_ip"].strip(),
                    target_host=row["target_host"].strip(),
                    outcome=row["outcome"].strip().lower(),
                    privileged=(flag == "true"),
                    business_reason=(row.get("business_reason") or "").strip(),
                ))
            except (ValueError, TypeError, KeyError) as exc:
                raise ValueError(f"Invalid CSV row {number}: {exc}") from exc
    return events


def analyze(events: list[Event], *, zone: ZoneInfo = LOCAL_ZONE, failure_threshold: int = 3,
            failure_window_minutes: int = 10) -> list[Finding]:
    """Return evidence-backed findings; time comparisons use aware datetimes."""
    if failure_threshold < 2 or failure_window_minutes <= 0:
        raise ValueError("failure_threshold >= 2 and failure_window_minutes > 0 required")
    findings: list[Finding] = []
    failed_logins: dict[tuple[str, str], deque[Event]] = defaultdict(deque)
    tripped: dict[tuple[str, str], bool] = defaultdict(bool)
    window = timedelta(minutes=failure_window_minutes)
    for event in sorted(events, key=lambda e: e.timestamp):
        local = event.timestamp.astimezone(zone)
        stamp = event.timestamp.isoformat()
        if (event.event_type == "login" and event.outcome == "success" and event.privileged
                and (local.weekday() >= 5 or local.hour < 7 or local.hour >= 18)):
            findings.append(Finding(
                "AFTER_HOURS_PRIVILEGED", "high", event.account, stamp, event.source_ip,
                event.target_host, 75,
                f"Privileged login at {local:%Y-%m-%d %H:%M %Z} outside Mon-Fri 07:00-18:00",
                "Confirm authorized activity and correlate with approved change or ticket.",
            ))
        if event.event_type == "privileged_change" and event.outcome == "success" and not event.business_reason:
            findings.append(Finding(
                "UNJUSTIFIED_PRIVILEGED_CHANGE", "high", event.account, stamp,
                event.source_ip, event.target_host, 85,
                "Successful privileged change has no recorded business reason",
                "Request change reference and verify owner approval before closing.",
            ))
        if event.event_type == "login" and event.outcome == "failed":
            key = (event.account.casefold(), event.source_ip)
            recent = failed_logins[key]
            recent.append(event)
            while recent and event.timestamp - recent[0].timestamp > window:
                recent.popleft()
            if len(recent) < failure_threshold:
                tripped[key] = False
            if len(recent) >= failure_threshold and not tripped[key]:
                findings.append(Finding(
                    "FAILED_LOGIN_BURST", "medium", event.account, stamp,
                    event.source_ip, event.target_host, 60,
                    f"{len(recent)} failures for same account/source within {failure_window_minutes} minutes",
                    "Review source legitimacy, account lockout activity, and related successful logins.",
                ))
                tripped[key] = True
    return findings
