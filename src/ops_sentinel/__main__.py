"""Command line entrypoint: python -m ops_sentinel analyze <csv> [--output path]."""
import argparse
import json
from pathlib import Path
from .engine import analyze, parse_events


def main() -> None:
    parser = argparse.ArgumentParser(description="Explainable security event analyzer")
    parser.add_argument("command", choices=["analyze"])
    parser.add_argument("csv", type=Path, help="CSV with timestamp, account and event fields")
    parser.add_argument("--output", "-o", type=Path, help="Optional JSON output path")
    args = parser.parse_args()
    events = parse_events(args.csv)
    findings = analyze(events)
    payload = {"records_analyzed": len(events), "findings_count": len(findings),
               "findings": [item.to_dict() for item in findings]}
    output = json.dumps(payload, indent=2)
    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
        print(f"Wrote {len(findings)} findings to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
