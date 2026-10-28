# AST Auditor — Security review and release checklist

## Scope

This document describes the supplied project archive and the v0.3.0 changes. It is not a third-party certification, a complete security audit, or evidence that the scanner is equivalent to any company's internal tooling.

## v0.3.0 engineering changes

- Added `rules.py` as a central registry with rule-pack version, stable IDs, severity, confidence, CWE, category, remediation, references, and SARIF metadata.
- Added `--list-rules` and `--version` CLI options.
- JSON findings include registry-backed triage metadata.
- SARIF rule metadata is generated from the same registry to reduce drift between detections and reports.
- Renamed implementation, test, benchmark, and documentation files to describe their purpose more clearly. Standard Python/GitHub names were retained where tooling expects them.
- Added registry tests and retained existing scanner regression coverage.

## Confirm before release

- Run the full test suite and Ruff on the target operating system and supported Python versions.
- Validate JSON and SARIF with a schema validator or code-scanning consumer, not only a JSON parser.
- Review every rule's true-positive and safe-negative examples.
- Run benchmarks on representative repositories; synthetic tests alone are insufficient for scale claims.
- Check dependency and build artifacts before publishing a release.
- Compare changes against the user's original working tree and preserve local backups before any merge.

## Known limitations

- Five rules only; coverage is intentionally limited.
- AST inspection and lightweight alias tracking do not provide general taint or interprocedural data-flow analysis.
- Static findings can be false positives and do not prove exploitability.
- The repository scanner returns a sorted list of results, so total result memory is not yet bounded by streaming output.
- No million-file performance claim is made.
- No external repository, GitHub settings, profile, or published release has been changed by this archive.
