"""Deterministic, explainable risk scoring for security findings.

Scores are heuristic triage priorities, not probabilities of compromise.
"""

from __future__ import annotations

from dataclasses import dataclass


BASE_SCORES: dict[str, int] = {
    "AFTER_HOURS_PRIVILEGED": 75,
    "FAILED_LOGIN_BURST": 45,
    "UNJUSTIFIED_PRIVILEGED_CHANGE": 85,
}


@dataclass(frozen=True)
class RiskFactor:
    code: str
    points: int
    explanation: str


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    severity: str
    factors: tuple[RiskFactor, ...]


def classify_severity(score: int) -> str:
    """Apply ordered, inclusive triage thresholds to an integer score of 0–100."""
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
        raise ValueError("score must be an integer between 0 and 100")
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def assess_risk(
    rule_id: str,
    *,
    privileged: bool = False,
    weekend: bool = False,
    overnight: bool = False,
    failed_attempts: int = 0,
) -> RiskAssessment:
    """Calculate an auditable triage priority from rule and event context.

    Overnight is 00:00–05:59 in the analysis timezone. Weekend and overnight
    adjustments are independent. The total is capped at 100.
    """
    if rule_id not in BASE_SCORES:
        raise ValueError(f"Unknown detection rule: {rule_id}")
    if isinstance(failed_attempts, bool) or not isinstance(failed_attempts, int) or failed_attempts < 0:
        raise ValueError("failed_attempts must be a non-negative integer")
    if rule_id == "FAILED_LOGIN_BURST":
        if failed_attempts < 2:
            raise ValueError("FAILED_LOGIN_BURST requires at least two failed attempts")
    elif failed_attempts:
        raise ValueError("failed_attempts only applies to FAILED_LOGIN_BURST")

    factors: list[RiskFactor] = [
        RiskFactor("RULE_BASE", BASE_SCORES[rule_id], f"Base priority for {rule_id}"),
    ]
    if rule_id == "FAILED_LOGIN_BURST":
        count_points = min(failed_attempts * 5, 25)
        factors.append(RiskFactor(
            "REPEATED_FAILURES", count_points,
            f"{failed_attempts} failed attempts, five points each (maximum 25)",
        ))
        if privileged:
            factors.append(RiskFactor("PRIVILEGED_ACCOUNT", 15, "Affected account is privileged"))
    if weekend:
        factors.append(RiskFactor("WEEKEND", 10, "Event occurred on Saturday or Sunday"))
    if overnight:
        factors.append(RiskFactor("OVERNIGHT", 5, "Event occurred between 00:00 and 05:59 local time"))

    total = min(100, sum(factor.points for factor in factors))
    return RiskAssessment(total, classify_severity(total), tuple(factors))
