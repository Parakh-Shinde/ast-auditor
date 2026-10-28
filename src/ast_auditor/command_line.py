"""Command-line interface for AST Auditor."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import quote

from ast_auditor import __version__
from ast_auditor.repository_scanner import scan_project
from ast_auditor.rules import RULE_PACK_VERSION, list_rules
from ast_auditor.security_scanner import Finding, scan_source


def _sarif_rule(rule) -> dict:
    level = "error" if rule.severity == "HIGH" else "warning"
    return {
        "id": rule.rule_id,
        "name": rule.name,
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.description},
        "help": {"text": rule.remediation},
        "helpUri": rule.references[0] if rule.references else None,
        "defaultConfiguration": {"level": level},
        "properties": {
            "category": rule.category,
            "confidence": rule.confidence.lower(),
            "security-severity": rule.security_score,
            "tags": ["security", f"external/cwe/{rule.cwe.lower()}", rule.category],
            "cwe": rule.cwe,
            "references": list(rule.references),
            "rulePackVersion": RULE_PACK_VERSION,
        },
    }


def build_sarif(target: str, findings: list[Finding]) -> dict:
    """Convert findings to SARIF 2.1.0 with registered rule metadata."""
    results = []
    for finding in findings:
        rule = next(item for item in list_rules() if item.rule_id == finding.rule_id)
        location_path = finding.file or target
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": "error" if finding.severity == "HIGH" else "warning",
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": quote(
                                    location_path.replace(os.sep, "/"), safe="/:"
                                )
                            },
                            "region": {"startLine": finding.line},
                        }
                    }
                ],
                "properties": {
                    "severity": rule.severity,
                    "confidence": rule.confidence,
                    "cwe": rule.cwe,
                    "remediation": rule.remediation,
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AST Auditor",
                        "version": __version__,
                        "informationUri": "https://github.com/Parakh-Shinde/ast-auditor",
                        "rules": [_sarif_rule(rule) for rule in list_rules()],
                    }
                },
                "results": results,
            }
        ],
    }


def _json_report(
    target: str,
    findings: list[Finding],
    files_scanned: int | None = None,
    errors: list[dict[str, str]] | None = None,
    skipped: int = 0,
) -> dict:
    report = {
        "tool": "AST Auditor",
        "tool_version": __version__,
        "rule_pack_version": RULE_PACK_VERSION,
        "target": target,
        "findings_count": len(findings),
        "findings": [],
    }
    for item in findings:
        rule = next(rule for rule in list_rules() if rule.rule_id == item.rule_id)
        report["findings"].append(
            {
                "rule_id": item.rule_id,
                "rule_name": rule.name,
                "severity": item.severity,
                "confidence": rule.confidence,
                "cwe": rule.cwe,
                "category": rule.category,
                "line": item.line,
                "message": item.message,
                "remediation": rule.remediation,
                "references": list(rule.references),
                **({"file": item.file} if item.file is not None else {}),
            }
        )
    if files_scanned is not None:
        report["files_scanned"] = files_scanned
        report["files_skipped_size_limit"] = skipped
        report["errors"] = errors or []
    return report


def _print_rules() -> None:
    print(
        json.dumps(
            {
                "tool": "AST Auditor",
                "tool_version": __version__,
                "rule_pack_version": RULE_PACK_VERSION,
                "rules": [
                    {
                        "id": rule.rule_id,
                        "name": rule.name,
                        "title": rule.title,
                        "severity": rule.severity,
                        "confidence": rule.confidence,
                        "cwe": rule.cwe,
                        "category": rule.category,
                        "description": rule.description,
                        "remediation": rule.remediation,
                        "references": list(rule.references),
                    }
                    for rule in list_rules()
                ],
            },
            indent=2,
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan Python files for selected security risks without executing them."
    )
    parser.add_argument(
        "path", nargs="?", type=Path, help="Python file or repository directory to scan"
    )
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument(
        "--jobs",
        type=int,
        default=None,
        help="Parallel workers for directory scans (default: up to 8 CPU workers)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="Exclude a repository-relative path glob; may be repeated",
    )
    parser.add_argument(
        "--max-file-bytes",
        type=int,
        default=2_000_000,
        help="Skip larger files (default: 2000000 bytes)",
    )
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="Print the versioned security rule registry and exit",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"AST Auditor {__version__} (rule pack {RULE_PACK_VERSION})",
    )
    args = parser.parse_args()

    if args.list_rules:
        _print_rules()
        return 0
    if args.path is None:
        parser.error("path is required unless --list-rules is used")
    if args.jobs is not None and args.jobs < 1:
        parser.error("--jobs must be at least 1")
    if args.max_file_bytes < 1:
        parser.error("--max-file-bytes must be positive")

    target = str(args.path)
    if args.path.is_dir():
        try:
            file_results = scan_project(
                args.path,
                jobs=args.jobs,
                excludes=tuple(args.exclude),
                max_file_bytes=args.max_file_bytes,
            )
        except (OSError, ValueError, NotADirectoryError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2
        findings = [finding for result in file_results for finding in result.findings]
        findings.sort(key=lambda item: (item.file or "", item.line, item.rule_id))
        errors = [
            {"file": result.path, "error": result.error}
            for result in file_results
            if result.error
        ]
        skipped = sum(result.skipped for result in file_results)
        scanned = len(file_results) - len(errors) - skipped
        report = _json_report(target, findings, scanned, errors, skipped)
    else:
        try:
            source = args.path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            print(f"Error: cannot read {args.path}: {exc}", file=sys.stderr)
            return 2
        try:
            findings = scan_source(source)
        except SyntaxError as exc:
            print(
                f"Error: invalid Python syntax at line {exc.lineno}: {exc.msg}",
                file=sys.stderr,
            )
            return 2
        report = _json_report(target, findings)

    if args.format == "json":
        print(json.dumps(report, indent=2))
    elif args.format == "sarif":
        print(json.dumps(build_sarif(target, findings), indent=2))
    elif not findings:
        print(f"No findings: {target}")
        if args.path.is_dir():
            print(
                f"Scanned {report['files_scanned']} Python files; "
                f"skipped {report['files_skipped_size_limit']} oversized files; "
                f"{len(report['errors'])} read/parse errors."
            )
    else:
        for finding in findings:
            location = (
                f"{finding.file}:{finding.line}"
                if finding.file
                else f"{target}:{finding.line}"
            )
            print(
                f"{location}: {finding.severity} {finding.rule_id} - {finding.message}"
            )
        if args.path.is_dir():
            print(
                f"Scanned {report['files_scanned']} Python files; "
                f"skipped {report['files_skipped_size_limit']} oversized files; "
                f"{len(report['errors'])} read/parse errors."
            )

    if args.path.is_dir() and report.get("errors") and args.format == "text":
        for error in report["errors"]:
            print(f"Warning: {error['file']}: {error['error']}", file=sys.stderr)
    return 1 if findings else (2 if args.path.is_dir() and report.get("errors") else 0)
