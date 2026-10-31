"""Command line entrypoint for detection and read-only investigation."""
import argparse
import json
from pathlib import Path

from .engine import analyze, parse_events
from .investigation import InvestigationAgent
from .narration import OpenAIResponsesNarrator


def main() -> None:
    parser = argparse.ArgumentParser(description="Explainable security event analyzer")
    parser.add_argument("command", choices=["analyze", "investigate"])
    parser.add_argument("csv", type=Path, help="CSV with timestamp, account and event fields")
    parser.add_argument("--output", "-o", type=Path, help="Optional JSON output path")
    parser.add_argument("--lookback-minutes", type=int, default=60, help="Investigation lookback (0–1440)")
    parser.add_argument("--lookahead-minutes", type=int, default=15, help="Investigation lookahead (0–1440)")
    parser.add_argument("--max-evidence", type=int, default=50, help="Maximum events returned per tool (1–500)")
    parser.add_argument("--narrator", choices=["none", "openai"], default="none",
                        help="Optional LLM text commentary (disabled by default)")
    parser.add_argument("--allow-external-data-transfer", action="store_true",
                        help="Explicitly permit sending selected evidence to the OpenAI API")
    args = parser.parse_args()
    if args.narrator == "openai" and args.command != "investigate":
        parser.error("--narrator openai requires the investigate command")
    events = parse_events(args.csv)
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
        noun = "investigations"
    else:
        payload = {"records_analyzed": len(events), "findings_count": len(findings),
                   "findings": [item.to_dict() for item in findings]}
        noun = "findings"
    output = json.dumps(payload, indent=2)
    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
        print(f"Wrote {len(findings)} {noun} to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
