# AST Auditor

**AST Auditor** is an independent Python static application security testing (SAST) project. It parses source code without executing the scanned program and reports a curated set of potentially dangerous patterns.

This project is designed as a credible, testable foundation for security-engineering work: a central rule registry, stable rule IDs, regression tests, JSON/SARIF output, and bounded parallel repository scanning. It does **not** claim to use proprietary Google, Meta, or other company-internal rules, and it has not yet demonstrated million-file production performance.

## Quick start

Requires Python 3.10 or newer.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m pytest -q
python -m ruff check src tests scripts
```

## Scan code

```bash
# Show the scanner version and rule-pack version
ast-auditor --version

# Print all rule metadata as JSON
ast-auditor --list-rules

# Scan one Python file
ast-auditor examples/vulnerable_python.py

# Scan a repository; output machine-readable JSON
ast-auditor . --jobs 4 --format json

# Generate SARIF 2.1.0 for CI/code-scanning integrations
ast-auditor . --jobs 4 --format sarif > security-findings.sarif

# Exclude generated code and cap individual file size
ast-auditor . --exclude '**/generated/**' --max-file-bytes 2000000
```

A scan with findings returns exit code `1`. A file read or syntax error returns `2`. A clean scan returns `0`.

## Curated rules

The registry is in `src/ast_auditor/rules.py`. Detection implementations are in `src/ast_auditor/security_scanner.py`.

| Rule | Risk | CWE | Severity | Confidence |
|---|---|---|---|---|
| PY001 | Dynamic `eval()` | CWE-95 | HIGH | MEDIUM |
| PY002 | Dynamic `exec()` | CWE-94 | HIGH | MEDIUM |
| PY003 | Selected `pickle` deserialization APIs | CWE-502 | HIGH | MEDIUM |
| PY004 | Selected shell-command APIs | CWE-78 | HIGH | MEDIUM |
| PY005 | Potentially unsafe `yaml.load()` | CWE-502 | HIGH | MEDIUM |
| PY006 | Disabled TLS certificate verification (`verify=False`) in recognized `requests` / `httpx` calls | CWE-295 | HIGH | MEDIUM |

The registry stores each rule's stable ID, title, description, severity, confidence, CWE mapping, category, remediation, references, and SARIF metadata. The rule-pack version is separate from the package version so rule changes can be tracked explicitly.

## Project map

| Path | Purpose |
|---|---|
| `src/ast_auditor/security_scanner.py` | AST visitor and detection logic |
| `src/ast_auditor/rules.py` | Versioned rule metadata and registry |
| `src/ast_auditor/repository_scanner.py` | Safe file discovery and bounded parallel scanning |
| `src/ast_auditor/command_line.py` | CLI, JSON output, and SARIF generation |
| `src/ast_auditor/__main__.py` | Standard `python -m ast_auditor` entry point |
| `tests/test_security_scanner.py` | Rule behavior and false-positive regression tests |
| `tests/test_command_line.py` | CLI, JSON, SARIF, and repository scan tests |
| `examples/vulnerable_python.py` | Intentionally vulnerable scanner fixture; never use as application code |
| `examples/alias_tracking_demo.py` | Demonstration of supported alias cases |
| `scripts/benchmark_repository_scan.py` | Synthetic local throughput benchmark |
| `SCALING_GUIDE.md` | Scale limitations and next-stage roadmap |
| `SECURITY_REVIEW.md` | Review notes and known limitations |
| `CONTRIBUTING.md` | How to add rules and run quality checks |
| `CHANGELOG.md` | Version history |

Files such as `pyproject.toml`, `LICENSE`, `.gitignore`, `.github/workflows/ci.yml`, `__init__.py`, and `__main__.py` retain conventional names because Python and GitHub tooling expect or commonly use them.

## Validate and benchmark

```bash
python -m pytest -q
python -m ruff check src tests scripts
python -m compileall -q src scripts
python scripts/benchmark_repository_scan.py --files 10000 --jobs 4
```

Benchmarks generate synthetic Python files. Record hardware, Python version, worker count, source size, elapsed time, peak memory, and findings before comparing runs. A synthetic benchmark is not evidence of production throughput or a million-file SLO.

## Engineering principles

- Add a rule only with positive examples, safe/negative examples, regression tests, rationale, and known limitations.
- Prefer conservative claims. A static finding is a lead for investigation, not proof of exploitability.
- Do not execute scanned source code.
- Do not claim precision/recall or enterprise scale without a representative, reproducible benchmark corpus.
- Use public security guidance and independently written detection logic; do not imply access to proprietary company rules.

## Current limitations

This scanner uses AST inspection and lightweight alias tracking, not full semantic analysis or general taint tracking. It can miss reflective calls, custom wrappers, indirect data flow, complex control flow, and vulnerabilities outside the six curated rules. It currently detects literal `verify=False` only for recognized module-level `requests` and `httpx` request functions; it does not resolve client-instance methods, dynamic values, or arbitrary wrappers. It does not replace dependency scanning, secret scanning, dynamic testing, code review, or a comprehensive security assessment. Repository scanning uses process workers and bounded pending work, but final results are retained in memory; very large finding volumes will need streaming output and incremental caching.

See [SCALING_GUIDE.md](SCALING_GUIDE.md), [SECURITY_REVIEW.md](SECURITY_REVIEW.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [CHANGELOG.md](CHANGELOG.md).

## License

MIT. See [LICENSE](LICENSE).
