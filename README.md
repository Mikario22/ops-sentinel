# Ops Sentinel

An **explainable security-event correlation engine** built as a personal engineering portfolio project. It demonstrates event parsing, timezone-aware algorithms, rule-based detection, explainable context-based risk scoring, evidence generation, automated tests, and GitHub CI.

> **Important:** The included dataset is synthetic. Never commit company logs, credentials, employee details, endpoint identifiers, or customer data.

## Problem

Security teams receive many authentication and administrative events. Finding **privileged access outside business hours**, **bursts of failed logins**, and **unjustified privileged changes** manually takes time and leads to inconsistent investigations.

## Architecture

`CSV events -> strict input validation -> deterministic correlation/detection -> evidence-rich JSON findings -> human review`

The engine is **not an LLM agent** and does **not take remediation actions**. A future, permission-controlled investigation agent can consume findings, request approval, and propose actions. Its policy and evidence should be testable separately from the model.

## Quick start

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install -e .
python -m ops_sentinel analyze samples/synthetic_events.csv --output findings.json
python -m unittest discover -s tests -v
```

Python 3.11+ required. All core logic is stdlib-only. The timestamps in the CSV **must** contain a UTC offset or `Z`. All after-hours checks are converted to `Africa/Johannesburg`. Current business hours are **Monday–Friday 07:00 to 18:00**; these are illustrative policy defaults, not production company rules.

## Detection rules

| Rule | Conditions | Baseline score |
|---|---|---|
| `AFTER_HOURS_PRIVILEGED` | Successful privileged login outside weekday business hours | 75 |
| `FAILED_LOGIN_BURST` | 3+ failed logins by same account and source within 10 min | 60 (for 3 attempts) |
| `UNJUSTIFIED_PRIVILEGED_CHANGE` | Successful privileged change with missing business reason | 85 |

## Explainable risk scoring

Each finding includes `risk_score` (0–100), `severity`, and a machine-readable
`risk_factors` list with factor codes, point values, and explanations. The rule
baseline and contextual adjustments are deterministic:

- **Failed-login bursts:** 45 base points plus 5 per failed attempt (maximum 25), and 15 more if the account is privileged.
- **After-hours privileged login:** 75 base points.
- **Unjustified privileged change:** 85 base points.
- **Weekend context:** +10 points (Saturday or Sunday in `Africa/Johannesburg`).
- **Overnight context:** +5 points (00:00–05:59 in `Africa/Johannesburg`).
- **Severity:** low 0–39, medium 40–69, high 70–89, critical 90–100. Scores are capped at 100; the factor values may sum above the cap.

For example, an after-hours privileged login on Saturday at 02:30 local time
scores **90 / critical** (75 rule baseline + 10 weekend + 5 overnight).
The scores are illustrative *triage priorities*, **not calibrated probabilities
of compromise**. They must be evaluated against real-world ground truth before
production use. Alerts require analyst review; the system takes no automated
remediation actions. A burst emits one finding at first threshold crossing, not
an updated finding for every subsequent failure. This is a batch prototype,
not a full production SIEM.

## Roadmap

- [x] Parse synthetic event data and validate timezones
- [x] Implement auditable correlation algorithms
- [x] Unit tests and CI
- [x] Explainable risk scoring with severity thresholds and contextual factors
- [ ] Add threshold configuration and suppression policy
- [ ] Add alert evaluation metrics and benchmarks
- [ ] Add a read-only investigation agent with human approval gates
- [ ] Add a dashboard using synthetic data

Use meaningful commits tied to working code, not artificial daily commits.
