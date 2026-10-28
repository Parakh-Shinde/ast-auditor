# AST Auditor

[![CI](https://github.com/Parakh-Shinde/ast-auditor/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Parakh-Shinde/ast-auditor/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**AST Auditor** is an independent, rule-registry-driven Python static application security testing (SAST) tool. It parses source code without executing the scanned program and reports a curated set of potentially dangerous patterns.

The project emphasizes reviewable detections, regression tests, stable rule IDs, machine-readable output, and explicit limitations. It is an engineering project—not a claim of equivalence to proprietary security tooling or a complete SAST product.

## At a glance

- **Python support:** 3.10 and newer
- **Runtime dependencies:** none
- **Output:** terminal text, JSON, and SARIF 2.1.0
- **Scanning:** individual files or repository directories, with configurable exclusions and file-size limits
- **Parallelism:** process-based workers with bounded in-flight work
- **Rule metadata:** central registry with severity, confidence, CWE mapping, remediation, and references
- **Validation:** CI test matrix for Python 3.10–3.14, linting, JSON checks, SARIF schema validation, and distribution inspection

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate        # Windows PowerShell: .venv\\Scripts\\Activate.ps1
python -m pip install -e ".[dev]"
python -m pytest -q
python -m ruff check src tests scripts
```

## Use it

```bash
# Print package and rule-pack versions
ast-auditor --version

# Inspect registered rules
ast-auditor --list-rules

# Scan one Python file
ast-auditor examples/vulnerable_python.py

# Scan a repository and emit JSON
ast-auditor . --jobs 4 --format json

# Emit SARIF for compatible CI/code-scanning workflows
ast-auditor . --jobs 4 --format sarif > security-findings.sarif

# Exclude generated code and cap individual file size
ast-auditor . --exclude '**/generated/**' --max-file-bytes 2000000
```

**Exit codes:** `0` means no findings, `1` means findings were reported, and `2` means a file read or syntax error occurred. A finding is a signal for human review, not proof of exploitability.

## Rule catalog

| Rule | Detection | CWE | Severity | Confidence |
|---|---|---|---|---|
| PY001 | Dynamic `eval()` | CWE-95 | HIGH | MEDIUM |
| PY002 | Dynamic `exec()` | CWE-94 | HIGH | MEDIUM |
| PY003 | Selected `pickle` deserialization APIs | CWE-502 | HIGH | MEDIUM |
| PY004 | Selected shell-command APIs | CWE-78 | HIGH | MEDIUM |
| PY005 | Potentially unsafe `yaml.load()` | CWE-502 | HIGH | MEDIUM |
| PY006 | Literal `verify=False` in recognized `requests` / `httpx` module-level calls | CWE-295 | HIGH | MEDIUM |

Rule definitions live in `src/ast_auditor/rules.py`; detection logic lives in `src/ast_auditor/security_scanner.py`. Package versioning and rule-pack versioning are tracked separately.

## Architecture

```text
Python source
    |
    v
Repository discovery + resource limits
    |
    v
AST-based rule visitor
    |
    v
Central rule registry
    |
    v
Text / JSON / SARIF reports
```

| Path | Responsibility |
|---|---|
| `src/ast_auditor/security_scanner.py` | AST visitor and detection logic |
| `src/ast_auditor/rules.py` | Rule metadata and registry |
| `src/ast_auditor/repository_scanner.py` | File discovery and bounded parallel scanning |
| `src/ast_auditor/command_line.py` | CLI, JSON output, and SARIF generation |
| `tests/` | Rule, CLI, output, and repository-scanning regression tests |
| `examples/vulnerable_python.py` | Intentionally vulnerable test fixture; do not use as application code |
| `scripts/benchmark_repository_scan.py` | Synthetic local benchmark harness |
| `SCALING_GUIDE.md` | Implemented capabilities and scaling roadmap |
| `SECURITY_REVIEW.md` | Scope, limitations, and release checklist |
| `CONTRIBUTING.md` | Development and rule-contribution guidance |
| `SECURITY.md` | Security issue reporting guidance |
| `CHANGELOG.md` | Version history |

## Validate locally

```bash
python -m pytest -q
python -m ruff check src tests scripts
python -m compileall -q src tests scripts
python -m ast_auditor --list-rules
python scripts/benchmark_repository_scan.py --files 10000 --jobs 4
```

Benchmarks generate synthetic Python files. Record the machine, Python version, worker count, source size, elapsed time, peak memory, and error/finding counts when comparing results. Synthetic results are not evidence of production throughput or a million-file service-level objective.

## Security and trust boundaries

- Scanned source is parsed, not imported or executed.
- Detection is intentionally narrow and can miss indirect calls, reflection, custom wrappers, data flow, and vulnerabilities outside the six registered rules.
- PY006 currently recognizes literal `verify=False` only in selected module-level `requests` and `httpx` request calls; client-instance methods and dynamic values are not resolved.
- Findings can be false positives and require contextual review.
- This tool does not replace dependency auditing, secret scanning, dynamic testing, code review, or a comprehensive security assessment.
- Repository scanning returns results in memory; very large finding volumes will need streaming output and incremental caching.
- The project uses public security guidance and independently written detection logic. It does not claim access to proprietary company-internal rules.

See [SCALING_GUIDE.md](SCALING_GUIDE.md), [SECURITY_REVIEW.md](SECURITY_REVIEW.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
