"""Ensure the original scanner import path remains supported."""

from ast_auditor.scanner import Finding, SecurityVisitor, scan_source


def test_legacy_scanner_imports_remain_available() -> None:
    assert Finding is not None
    assert SecurityVisitor is not None
    assert scan_source('eval("untrusted")')[0].rule_id == "PY001"
