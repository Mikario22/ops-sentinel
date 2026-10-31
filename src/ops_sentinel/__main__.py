"""Command line entrypoint for detection, investigation and read-only workflows."""
import argparse
import json
from pathlib import Path

from .engine import analyze, parse_events
from .evaluation import evaluate, load_scenarios
from .investigation import InvestigationAgent
from .narration import OpenAIResponsesNarrator
from .workflow import LocalCheckpoint, WorkflowOrchestrator


def main() -> None:
    parser = argparse.ArgumentParser(description="Explainable security event analyzer")
    parser.add_argument("command", choices=["analyze", "investigate", "workflow", "evaluate"])
    parser.add_argument("csv", type=Path, help="CSV with timestamp, account and event fields")
    parser.add_argument("--output", "-o", type=Path, help="Optional JSON output path")
    parser.add_argument("--lookback-minutes", type=int, default=60, help="Investigation lookback (0–1440)")
    parser.add_argument("--lookahead-minutes", type=int, default=15, help="Investigation lookahead (0–1440)")
    parser.add_argument("--max-evidence", type=int, default=50, help="Maximum events returned per tool (1–500)")
    parser.add_argument("--narrator", choices=["none", "openai"], default="none",
                        help="Optional LLM text commentary (disabled by default)")
    parser.add_argument("--allow-external-data-transfer", action="store_true",
                        help="Explicitly permit sending selected evidence to the OpenAI API")
    parser.add_argument("--state-dir", type=Path, default=Path(".ops-sentinel-state"),
                        help="Local workflow checkpoint/audit folder (workflow only)")
    parser.add_argument("--run-id", help="Optional safe workflow ID for resume (workflow only)")
    parser.add_argument("--retry-delay", type=float, default=0,
                        help="Seconds between eligible workflow retries (0–10)")
    parser.add_argument("--repeats", type=int, default=5, help="Evaluation latency repetitions (1–100)")
    parser.add_argument("--recovery-trials", type=int, default=3, help="Synthetic recovery trials (1–20)")
    args = parser.parse_args()
    if args.narrator == "openai" and args.command != "investigate":
        parser.error("--narrator openai requires the investigate command")
    if args.command == "workflow" and args.allow_external_data_transfer:
        parser.error("workflow does not support external data transfer")
    if args.command == "evaluate":
        if args.allow_external_data_transfer:
            parser.error("evaluate does not support external data transfer")
        payload = evaluate(load_scenarios(args.csv), repeats=args.repeats,
                           recovery_trials=args.recovery_trials)
        output = json.dumps(payload, indent=2)
        if args.output:
            args.output.write_text(output + "\n", encoding="utf-8")
            print(f"Wrote evaluation report for {payload['scenario_count']} synthetic cases to {args.output}")
        else:
            print(output)
        return
    events = parse_events(args.csv)
    if args.command == "workflow":
        runner = WorkflowOrchestrator(args.state_dir, retry_delay_seconds=args.retry_delay)
        state = runner.run(events, run_id=args.run_id)
        paths = LocalCheckpoint(args.state_dir, state["run_id"])
        payload = {
            "run_id": state["run_id"],
            "status": state["status"],
            "state_path": str(paths.state_path),
            "audit_path": str(paths.audit_path),
            "steps": {key: {"status": step["status"], "attempts": step["attempts"],
                            "error": step["error"]} for key, step in state["steps"].items()},
            "summary": (state["steps"]["summarize"]["output"]
                        if state["steps"]["summarize"]["status"] == "completed" else None),
        }
    else:
        findings = analyze(events)
        if args.command == "investigate":
            narrator = (OpenAIResponsesNarrator(allow_external_data_transfer=args.allow_external_data_transfer)
                        if args.narrator == "openai" else None)
            agent = InvestigationAgent(model=narrator, lookback_minutes=args.lookback_minutes,
                                       lookahead_minutes=args.lookahead_minutes,
                                       max_evidence_per_tool=args.max_evidence)
            reports = [agent.investigate(finding, events) for finding in findings]
            payload = {"records_analyzed": len(events), "investigations_count": len(reports),
                       "investigations": [report.to_dict() for report in reports]}
        else:
            payload = {"records_analyzed": len(events), "findings_count": len(findings),
                       "findings": [item.to_dict() for item in findings]}
    output = json.dumps(payload, indent=2)
    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
        if args.command == "workflow":
            print(f"Workflow {state['run_id']}: {state['status']} ({args.output})")
        else:
            key = "investigations" if args.command == "investigate" else "findings"
            print(f"Wrote {len(findings)} {key} to {args.output}")
    else:
        print(output)
    if args.command == "workflow" and state["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
