# Contributing to AST Auditor

Thanks for helping improve AST Auditor. The project prioritizes trustworthy findings, transparent limitations, and reproducible tests over rule count.

## Before adding a rule

Every rule proposal should include:

1. A stable rule ID and a concise, human-readable name.
2. A clear threat model and why the pattern is risky.
3. At least one positive fixture that should be detected.
4. Safe/negative fixtures that should not be detected.
5. A CWE mapping when a relevant CWE exists, severity rationale, confidence, remediation, and public references.
6. Documented blind spots, alias limitations, and known false-positive risks.
7. Tests for text/JSON/SARIF metadata and deterministic behavior where relevant.

Do not claim precision, recall, or coverage without a labeled test corpus and a repeatable measurement method.

## Development checks

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
python -m ruff check src tests scripts
python -m compileall -q src tests scripts
python -m ast_auditor --list-rules
```

For a report-format change, validate JSON and SARIF output and check that every finding's rule ID is declared in the SARIF driver metadata.

## Safe-analysis boundary

Do not import or execute scanned project code. Tests should use inert source strings or temporary fixture files. Repository scanning must remain bounded by configurable resource limits where possible.

## Rule registry

Add metadata to `src/ast_auditor/rules.py` and detection behavior to `src/ast_auditor/security_scanner.py`. Keep stable rule IDs; do not silently repurpose an existing ID for different behavior. If rule semantics materially change, document the change and consider a rule-pack version bump.

## Project naming

Use descriptive names for new modules, tests, examples, and documentation. Keep standard ecosystem filenames such as `pyproject.toml`, `README.md`, `LICENSE`, `__init__.py`, `__main__.py`, and `.github/workflows/ci.yml` where tools expect or conventionally use them.
