# AST Auditor — Security review and release checklist

## Scope

This is a maintainer-authored engineering review of the current project, not a third-party audit, certification, or proof of equivalence to proprietary security tooling. It documents design boundaries and the checks required before a release.

## Current implementation

- Six curated Python rules (PY001–PY006), driven by a central registry.
- AST parsing; scanned source is not imported or executed.
- Lightweight alias tracking for selected APIs; this is not general semantic, taint, or interprocedural analysis.
- CLI output in text, JSON, and SARIF 2.1.0.
- Repository scanning with exclusions, per-file size limits, process-based parallelism, and bounded in-flight work.
- CI coverage for Python 3.10–3.14, Ruff, regression tests, JSON/SARIF output checks, official SARIF schema validation, and source/wheel distribution inspection.
- Project metadata and repository links declared in `pyproject.toml`; Dependabot configured for weekly pip and GitHub Actions update checks.

## Rule-specific boundaries

- **PY001 / PY002:** detect selected dynamic `eval` / `exec` call patterns; reflective access and arbitrary dynamic dispatch may evade detection.
- **PY003:** covers selected `pickle` deserialization APIs, not every unsafe serialization format or wrapper.
- **PY004:** covers selected shell-execution APIs and patterns; it does not prove whether input is attacker-controlled.
- **PY005:** covers selected potentially unsafe `yaml.load()` patterns and recognized safe-loader forms; behavior in custom wrappers or dynamic aliases may not be resolved.
- **PY006:** recognizes literal `verify=False` in selected module-level `requests` and `httpx` request calls; client-instance methods, dynamic values, and custom wrappers are not resolved.

A finding is a review lead, not proof of exploitability. False positives and false negatives are expected for a deliberately narrow AST scanner.

## Release checklist

Before publishing a release:

- [ ] Run tests and Ruff on the supported Python matrix and on a clean checkout.
- [ ] Validate JSON and SARIF output, including official SARIF schema validation and declared rule IDs.
- [ ] Inspect source archive and wheel contents, then install the built wheel in a clean environment and smoke-test the CLI.
- [ ] Review positive and safe-negative tests for every rule.
- [ ] Check package metadata, changelog, version, and rule-pack version for consistency.
- [ ] Run benchmarks on representative repositories and publish environment, workload, elapsed time, throughput, peak memory, and errors before making performance claims.
- [ ] Inspect dependency/build artifacts and review pending dependency updates.
- [ ] Confirm the release tag and artifact provenance before publishing.
- [ ] Preserve the user's local changes and backups; do not merge or publish without explicit approval.

## Known limitations

- Six rules only; this is not a complete SAST engine.
- No general taint analysis, interprocedural data flow, or comprehensive symbol resolution.
- No incremental cache, baseline comparison, governed suppressions, or streaming output yet.
- Results are retained in memory; very large finding volumes may require additional resource controls.
- Synthetic benchmarks do not demonstrate production throughput or million-file performance.
- This independent project uses public security guidance and does not claim access to proprietary company-internal rules.
