from __future__ import annotations
import argparse
import sys
from pathlib import Path

from injexpose.parse_sqlmap import parse_sqlmap_output
from injexpose.triage import assign_severity_and_impact
from injexpose.report_terminal import render_terminal_report


def _read_input(input_path: str) -> str:
    if input_path == "-" or input_path.strip() == "":
        return sys.stdin.read()

    p = Path(input_path)
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    return p.read_text(encoding="utf-8", errors="replace")


def cmd_report(args: argparse.Namespace) -> int:
    raw = _read_input(args.input)
    findings = parse_sqlmap_output(raw, default_url=args.url)

    triaged = [assign_severity_and_impact(f) for f in findings]

    target = args.url or "UNKNOWN_TARGET"
    report = render_terminal_report(triaged, target=target, run_label=args.label or "manual")
    print(report)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="injexpose",
        description="InjeXpose triage reporter (sqlmap output -> Vulnerabilities/Impact/Severity).",
    )
    sub = p.add_subparsers(dest="command", required=True)

    rpt = sub.add_parser("report", help="Generate triage report from sqlmap output text.")
    rpt.add_argument("--input", "-i", required=True, help="Path to sqlmap output text file, or '-' for stdin.")
    rpt.add_argument("--url", help="Target URL (if not present in output).")
    rpt.add_argument("--label", help="Optional run label for display.")
    rpt.set_defaults(func=cmd_report)

    return p


def main() -> int:
    try:
        parser = build_parser()
        args = parser.parse_args()
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
