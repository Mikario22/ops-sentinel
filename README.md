# Ops Sentinel

An **explainable security-event correlation engine** built as a personal engineering portfolio project. It demonstrates event parsing, timezone-aware algorithms, rule-based detection, evidence generation, automated tests, and GitHub CI.

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

| Rule | Conditions | Score |
|---|---|---|
| `AFTER_HOURS_PRIVILEGED` | Successful privileged login outside weekday business hours | 75 |
| `FAILED_LOGIN_BURST` | 3+ failed logins by same account and source within 10 min | 60 |
| `UNJUSTIFIED_PRIVILEGED_CHANGE` | Successful privileged change with missing business reason | 85 |

Scores are demonstrative fixed rule weights, **not statistically calibrated risks**. Alerts are for analyst review only. A burst produces one finding while its window remains above threshold. This is a batch prototype, not a full production SIEM.

## Roadmap

- [x] Parse synthetic event data and validate timezones
- [x] Implement auditable correlation algorithms
- [x] Unit tests and CI
- [ ] Add threshold configuration and suppression policy
- [ ] Add alert evaluation metrics and benchmarks
- [ ] Add a read-only investigation agent with human approval gates
- [ ] Add a dashboard using synthetic data

## Suggested first commits

1. `feat: add explainable security detection engine`
2. `test: cover timezone boundaries and login correlation`
3. `ci: validate analyzer across Python versions`

Use meaningful commits tied to working code, not artificial daily commits.
