import argparse
import json
import sys
from pathlib import Path

from ast_auditor.scanner import scan_source


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan Python source for potentially dangerous calls."
    )
    parser.add_argument(
        "file",
        type=Path,
        help="Python source file to scan",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text)",
    )
    args = parser.parse_args()

    try:
        source = args.file.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        print(f"Error: cannot read {args.file}: {exc}", file=sys.stderr)
        return 2

    try:
        findings = scan_source(source)
    except SyntaxError as exc:
        print(
            f"Error: invalid Python syntax at line {exc.lineno}: {exc.msg}",
            file=sys.stderr,
        )
        return 2

    if args.format == "json":
        report = {
            "tool": "AST Auditor",
            "target": str(args.file),
            "findings_count": len(findings),
            "findings": [
                {
                    "rule_id": finding.rule_id,
                    "severity": finding.severity,
                    "line": finding.line,
                    "message": finding.message,
                }
                for finding in findings
            ],
        }
        print(json.dumps(report, indent=2))
    elif not findings:
        print(f"No findings: {args.file}")
    else:
        for finding in findings:
            print(
                f"{args.file}:{finding.line}: "
                f"{finding.severity} {finding.rule_id} - {finding.message}"
            )

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
