import argparse
import json
import sys
from pathlib import Path

from ast_auditor.scanner import scan_source

RULES = {
    "PY001": {
        "name": "DangerousEval",
        "shortDescription": {"text": "Potentially dangerous eval() call"},
        "fullDescription": {
            "text": "eval() can execute dynamically supplied Python expressions."
        },
        "defaultConfiguration": {"level": "error"},
    },
    "PY002": {
        "name": "DangerousExec",
        "shortDescription": {"text": "Potentially dangerous exec() call"},
        "fullDescription": {
            "text": "exec() can execute dynamically supplied Python statements."
        },
        "defaultConfiguration": {"level": "error"},
    },
    "PY003": {
        "name": "UnsafePickleDeserialization",
        "shortDescription": {
            "text": "Potentially unsafe pickle deserialization"
        },
        "fullDescription": {
            "text": "Loading untrusted pickle data can execute arbitrary code."
        },
        "defaultConfiguration": {"level": "error"},
    },
    "PY004": {
        "name": "ShellCommandExecution",
        "shortDescription": {
            "text": "Potentially unsafe shell command execution"
        },
        "fullDescription": {
            "text": (
                "Shell execution can enable command injection when commands "
                "contain untrusted input."
            )
        },
        "defaultConfiguration": {"level": "error"},
    },
    "PY005": {
        "name": "UnsafeYamlLoad",
        "shortDescription": {
            "text": "Potentially unsafe YAML deserialization"
        },
        "fullDescription": {
            "text": (
                "yaml.load() without a recognized safe loader may deserialize "
                "untrusted data unsafely."
            )
        },
        "defaultConfiguration": {"level": "error"},
    },
}


def build_sarif(target: str, findings: list) -> dict:
    """Convert scanner findings into a SARIF 2.1.0 report."""
    results = []

    for finding in findings:
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": "error" if finding.severity == "HIGH" else "warning",
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": target},
                            "region": {"startLine": finding.line},
                        }
                    }
                ],
            }
        )

    return {
        "$schema": (
            "https://json.schemastore.org/"
            "sarif-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AST Auditor",
                        "version": "0.1.0",
                        "informationUri": (
                            "https://github.com/"
                            "Parakh-Shinde/ast-auditor"
                        ),
                        "rules": [
                            {"id": rule_id, **rule}
                            for rule_id, rule in RULES.items()
                        ],
                    }
                },
                "results": results,
            }
        ],
    }


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
        choices=("text", "json", "sarif"),
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
    elif args.format == "sarif":
        report = build_sarif(str(args.file), findings)
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
