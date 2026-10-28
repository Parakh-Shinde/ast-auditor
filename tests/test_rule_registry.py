from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from ast_auditor import __version__
from ast_auditor.rules import RULE_PACK_VERSION, RULES, get_rule, list_rules

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_package_and_rule_pack_versions_are_explicit() -> None:
    assert __version__ == "0.4.0"
    assert RULE_PACK_VERSION == "2026.2"


def test_registry_has_unique_stable_rule_ids_and_complete_metadata() -> None:
    rules = list_rules()
    ids = [rule.rule_id for rule in rules]

    assert ids == sorted(ids)
    assert len(ids) == len(set(ids)) == 6
    for rule in rules:
        assert rule.name
        assert rule.title
        assert rule.description
        assert rule.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        assert rule.confidence in {"HIGH", "MEDIUM", "LOW"}
        assert rule.cwe.startswith("CWE-")
        assert rule.remediation
        assert rule.references
        assert rule.security_score


def test_get_rule_returns_registered_definition() -> None:
    assert get_rule("PY001").cwe == "CWE-95"


def test_get_rule_rejects_unknown_rule_id() -> None:
    try:
        get_rule("PY999")
    except KeyError as error:
        assert "Unregistered" in str(error)
    else:
        raise AssertionError("unknown rule ID should be rejected")


def test_cli_lists_rules_as_machine_readable_json() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "ast_auditor", "--list-rules"],
        cwd=PROJECT_ROOT,
        env={**__import__("os").environ, "PYTHONPATH": str(PROJECT_ROOT / "src")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    report = json.loads(result.stdout)
    assert report["rule_pack_version"] == RULE_PACK_VERSION
    assert {rule["id"] for rule in report["rules"]} == set(RULES)


def test_cli_version_includes_package_and_rule_pack_versions() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "ast_auditor", "--version"],
        cwd=PROJECT_ROOT,
        env={**__import__("os").environ, "PYTHONPATH": str(PROJECT_ROOT / "src")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "0.3.0" in result.stdout
    assert RULE_PACK_VERSION in result.stdout
