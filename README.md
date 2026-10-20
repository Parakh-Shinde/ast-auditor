# AST Auditor

AST Auditor is a lightweight, AST-based static security scanner for Python source code. It parses source files without executing them and identifies potentially dangerous direct calls to `eval()` and `exec()`.

## Features

- Detects direct calls to `eval()` with rule PY001.
- Detects direct calls to `exec()` with rule PY002.
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

The scanner detects direct calls to eval() and exec(), along with simple aliases and chained aliases in supported cases. Alias tracking is intentionally lightweight and does not perform complete Python scope, control-flow, or data-flow analysis. It may miss indirect calls, dynamically resolved functions, and other classes of Python security vulnerabilities.

A finding indicates potentially dangerous code, not proof of exploitability. This early-stage tool is not a substitute for a comprehensive security audit.

## License

MIT
