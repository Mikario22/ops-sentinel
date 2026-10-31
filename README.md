# Ops Sentinel

An **explainable security-event correlation engine** built as a personal engineering portfolio project. It demonstrates event parsing, timezone-aware algorithms, rule-based detection, explainable context-based risk scoring, evidence generation, a read-only investigation agent, resumable workflow orchestration, automated tests, and GitHub CI.

> **Important:** The included dataset is synthetic. Never commit company logs, credentials, employee details, endpoint identifiers, or customer data.

## Problem

Security teams receive many authentication and administrative events. Finding **privileged access outside business hours**, **bursts of failed logins**, and **unjustified privileged changes** manually takes time and leads to inconsistent investigations.

## Architecture

`CSV events -> validation -> detection and risk scoring -> read-only investigation tools -> JSON cases -> human review`

The investigation agent uses deterministic, read-only tools. An optional OpenAI Responses API narrator can add model-generated commentary **only after explicit opt-in**. Neither mode can approve or execute remediation. Model-generated text is clearly separated from evidence and approval status.

## Quick start

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install -e .
python -m ops_sentinel analyze samples/synthetic_events.csv --output findings.json
python -m ops_sentinel investigate samples/synthetic_events.csv --output investigations.json
python -m ops_sentinel workflow samples/synthetic_events.csv --output workflow-summary.json
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

## Read-only Investigation Agent (Commit 3)

Use `python -m ops_sentinel investigate samples/synthetic_events.csv --output investigations.json`.
For each finding, the agent produces a stable case ID, risk and severity,
bounded evidence, read-only tool traces, correlation observations and a
**pending human-approval request** for any potentially disruptive response.
There is no remediation executor. Offline operation needs no API key.

The fixed tool allowlist contains:

- `account_timeline`: time-bounded history of the affected account.
- `source_timeline`: events with the same source IP.
- `recorded_change_references`: nearby events with stated business reasons.
  **A stated change reference is not verified approval.**

Events are deduplicated by stable IDs, results are capped per tool (default
50), and truncated evidence is marked. Investigation context defaults to 60
minutes before and 15 minutes after the finding. Adjust with
`--lookback-minutes`, `--lookahead-minutes`, and `--max-evidence`. The
reports are triage aids, not proof of compromise. All proposed actions are
**pending_human_approval**; the project cannot approve or execute them.

### Optional AI commentary — explicit opt-in only

Using this option sends the selected event evidence to the OpenAI API and may
incur API charges. **Do not send real company data or personal data without
explicit organizational authorization and a data-sharing review.** The
default offline mode never calls an external model; CI uses no real API calls.

```powershell
$env:OPENAI_API_KEY = '<your-own-key>'
$env:OPS_SENTINEL_OPENAI_MODEL = '<available-model-in-your-API-project>'
python -m ops_sentinel investigate samples/synthetic_events.csv --output investigations.json --narrator openai --allow-external-data-transfer
```

Never commit keys or secret values. The model can append untrusted commentary
only; it cannot change evidence, risk scores, approval status or tool calls.


## Workflow Orchestrator (Commit 4)

A resumable **read-only** workflow now coordinates three explicit steps:

```text
detect_events ──> investigate_findings ──> summarize_cases
       \______________________________________^
```

The planner validates step names, tool allowlisting, dependency ordering and
maximum retry attempts before any work starts. A retry happens **only** for
`RetryableStepError`, with bounded attempts and configurable backoff. Ordinary
errors stop execution without retrying or leaking exception messages into the
audit. There is **no** command executor, external connector, account modification,
or automated approval function.

Run the complete pipeline offline with the synthetic example:

```powershell
python -m ops_sentinel workflow samples/synthetic_events.csv --state-dir .ops-sentinel-state --output workflow-summary.json
```

The default run ID derives from a digest of the input events. Running the same
command again automatically **resumes** completed work without re-executing the
tools. To run a separate case, use `--run-id demo-2`. The local state folder
contains `<run-id>.state.json` with checkpointed investigation data and
`<run-id>.audit.jsonl` with a SHA-256 hash-linked event trail. Hash links help
detect accidental edits; they are **not** cryptographic signatures and should
not be treated as proof against a malicious administrator.

The summary includes investigation counts, severity levels and the number of
**pending human approval requests**. The workflow does not fulfill, approve, or
execute those requests. State files can contain event details: use only
synthetic or explicitly approved data, keep the directory access-controlled,
and never commit state files. For production use, add multi-process locking,
transactional storage, authenticated reviewers, audit export and idempotency
controls for any future side-effecting tools. The checkpoint and audit files
are not one atomic transaction; interrupted writes may require manual recovery.


## Roadmap

- [x] Parse synthetic event data and validate timezones
- [x] Implement auditable correlation algorithms
- [x] Unit tests and CI
- [x] Explainable risk scoring with severity thresholds and contextual factors
- [ ] Add threshold configuration and suppression policy
- [ ] Add alert evaluation metrics and benchmarks
- [x] Add a read-only investigation agent with human approval gates
- [x] Add optional opt-in LLM commentary with immutable approval controls
- [x] Build a local read-only workflow engine with planning, retries, resume and audit
- [ ] Add a dashboard using synthetic data

Use meaningful commits tied to working code, not artificial daily commits.
