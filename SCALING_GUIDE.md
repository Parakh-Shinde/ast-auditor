# Scaling guide

## What is implemented in v0.4.0

- Single-file and repository-directory scans.
- Process-based parallel analysis with bounded in-flight work.
- Stable, sorted output; common generated/dependency directory exclusions; configurable glob excludes and file-size limits.
- Per-file parse/read error reporting and file-specific JSON/SARIF findings.
- A central rule registry with stable IDs, a versioned rule pack, CWE mapping, severity, confidence, remediation, and references.
- Six curated rules, including detection of literal `verify=False` in recognized module-level `requests` and `httpx` calls.
- Registry-driven JSON/SARIF metadata and `--list-rules` output.
- Regression tests and a synthetic benchmark harness.

## What is not yet implemented

- Incremental content-hash cache.
- General taint/data-flow analysis or interprocedural analysis.
- Finding baselines, stable finding fingerprints, and governed suppressions.
- Streaming reports for enormous finding volumes.
- Distributed workers, tenant isolation, job cancellation, and service-level observability.
- A large representative benchmark corpus with precision/recall measurements.

## A practical enterprise-oriented roadmap

1. **Rule quality:** require positive and negative fixtures, documented rationale, confidence, references, and regression tests for every new rule.
2. **Quality metrics:** maintain a labeled public benchmark corpus and measure precision/recall per rule; do not invent a single scanner accuracy score.
3. **Stable findings:** add normalized fingerprints, baseline comparison, expiry-aware suppressions, and CI diff mode.
4. **Incremental scans:** cache by content hash, scanner version, and rule-pack version; invalidate on all three.
5. **Data flow:** add explicit sources, sinks, sanitizers, scope-aware symbol resolution, and conservative confidence levels.
6. **Output at scale:** stream JSONL/SARIF, bound finding memory, and support artifact partitioning.
7. **Operational safety:** enforce file-size, CPU, memory, and time limits when scanning untrusted repositories; never import or execute scanned code.
8. **Benchmark honestly:** measure representative projects at increasing sizes and publish environment, elapsed time, throughput, peak memory, and errors. Millions of files should remain a goal until directly measured.
9. **CI and supply chain:** test supported Python versions, audit dependencies, build reproducibly, and sign release artifacts when the release process is mature.

## Important boundaries

AST Auditor is an independent project inspired by public secure-coding guidance. It does not include or claim access to proprietary Google, Meta, or other company-internal rules. The current implementation has six curated Python rules and is not a complete SAST engine.
