# Changelog

Notable changes to AST Auditor are recorded here. Package releases follow
semantic-versioning principles where practical. The security rule-pack version
is tracked separately from the package version.

## 0.4.0 — TLS verification detection and evaluation tooling

### Security detection

- Added PY006 to detect literal `verify=False` in recognized module-level
  `requests` and `httpx` HTTP request functions.
- Added positive and negative regression coverage for module aliases, imported
  functions, function aliases, and non-matching calls.
- Documented detection boundaries: client-instance methods, dynamic
  verification values, and custom wrappers are not resolved.

### Evaluation and packaging

- Added a labelled detection corpus and baseline evaluation report to support
  reproducible, scoped detection evaluation.
- Added `scripts/evaluate_detection.py` for running the evaluation workflow.
- Included evaluation JSON and JSONL assets in the source distribution.
- Strengthened CI checks to verify required source-distribution assets and
  essential wheel modules.
- Evaluation results are limited to the documented corpus and methodology;
  they should not be interpreted as a universal detection-accuracy guarantee.

### Versioning

- Set the Python package version to `0.4.0`.
- Set the security rule-pack version to `2026.2`.

## 0.3.0 — Rule registry and maintainable project layout

- Added a central registry for five security rules, including stable IDs,
  severity, confidence, CWE, category, remediation, and public references.
- Added a separate rule-pack version (`2026.1`) and CLI commands for
  `--version` and `--list-rules`.
- Added registry-backed metadata to JSON findings and SARIF results and rule
  definitions.
- Renamed implementation, tests, benchmark, examples, and review documents to
  make their purpose easier to understand.
- Added registry-focused tests and expanded CLI metadata assertions.
- Improved Ruff compatibility in the repository scanner and branch-alias merge
  logic.
- Documented limitations and a measured, evidence-first scaling roadmap.

## 0.2.0 — Repository scanning foundation

- Added directory scanning, process workers, bounded pending tasks,
  deterministic results, exclusions, file-size limits, and per-file errors.
- Added a synthetic throughput benchmark.

## 0.1.0 — Initial scanner

- Added AST-based detection for selected dangerous Python APIs, text, JSON, and
  SARIF output, and the initial regression suite.
