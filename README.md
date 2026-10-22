# AST Auditor

AST Auditor is a lightweight, AST-based static security scanner for Python source code. It parses source files without executing them and identifies potentially dangerous calls to `eval()` and `exec()`, plus selected unsafe deserialization calls.

## Features

- Detects direct calls to `eval()` with rule PY001.
- Detects direct calls to `exec()` with rule PY002.
- Detects calls to `pickle.load()` and `pickle.loads()` with rule PY003, including common import aliases.
- Detects `subprocess` calls with literal `shell=True` and `os.system()` with rule PY004, including common import aliases.
- Detects potentially unsafe `yaml.load()` calls with rule PY005, including supported import and alias patterns.
- Tracks simple and chained aliases in supported cases.
- Reports severity and source line numbers.
- Supports text, JSON, and SARIF 2.1.0 output.
- Includes automated scanner and CLI tests.

## Requirements

- Python 3.10 or newer.
- pip.

## Installation

From the repository root, install the project and its development dependencies:

    python -m pip install -e ".[dev]"

## Usage

Show CLI options:

    ast-auditor --help

Scan a file:

    ast-auditor samples/vulnerable_example.py

Generate JSON:

    ast-auditor samples/vulnerable_example.py --format json

Generate SARIF:

    ast-auditor samples/vulnerable_example.py --format sarif

You can also run the module directly:

    python -m ast_auditor samples/vulnerable_example.py

## Exit codes

- 0: No findings.
- 1: One or more findings detected.
- 2: File read or Python parsing error.

## Tests and lint

Run tests:

    python -m pytest

Run lint:

    ruff check src tests

## Limitations

The scanner detects potentially dangerous calls using AST inspection and lightweight alias tracking. Alias tracking does not perform complete Python scope, control-flow, or data-flow analysis. It may miss indirect calls, dynamically resolved functions, and other classes of Python security vulnerabilities. PY003 targets the standard-library `pickle` API and does not cover every unsafe deserialization library or custom wrapper. PY004 detects selected standard-library subprocess APIs when `shell=True` is explicitly written as a literal, plus `os.system()`; it does not perform taint analysis and may miss indirect or dynamically configured shell execution. PY005 flags `yaml.load()` when the scanner cannot establish that a recognized safe loader is used. It is not a complete YAML security analysis and may not recognize every custom or indirect loader configuration. Findings are potential risks, not proof of exploitability.

A finding indicates potentially dangerous code, not proof of exploitability. This early-stage tool is not a substitute for a comprehensive security audit.

## License

MIT
