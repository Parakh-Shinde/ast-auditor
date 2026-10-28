# Changelog

Notable changes to AST Auditor are recorded here. Versions follow semantic-versioning principles where practical; the rule-pack version is tracked separately from the package version.

## 0.4.0 — TLS verification rule

- Added PY006 for literal `verify=False` in recognized module-level `requests` and `httpx` HTTP request functions.
- Added positive and negative regression coverage for module aliases, imported functions, function aliases, and non-matching calls.
- Bumped the package version to `0.4.0` and rule-pack version to `2026.2`.
- Detection is intentionally limited: client-instance methods, dynamic verification values, and custom wrappers are not resolved.

## 0.3.0 — Rule registry and maintainable project layout

- Added a central registry for five security rules, including stable IDs, severity, confidence, CWE, category, remediation, and public references.
- Added a separate rule-pack version (`2026.1`) and CLI commands for `--version` and `--list-rules`.
- Added registry-backed metadata to JSON findings and SARIF results/rule definitions.
- Renamed implementation, tests, benchmark, examples, and review documents to make their purpose easier to understand.
- Added registry-focused tests and expanded CLI metadata assertions.
- Improved Ruff compatibility in the repository scanner and branch-alias merge logic.
- Documented limitations and a measured, evidence-first scaling roadmap.

## 0.2.0 — Repository scanning foundation

- Added directory scanning, process workers, bounded pending tasks, deterministic results, exclusions, file-size limits, and per-file errors.
- Added a synthetic throughput benchmark.

## 0.1.0 — Initial scanner

- Added AST-based detection for selected dangerous Python APIs, text/JSON/SARIF output, and the initial regression suite.
