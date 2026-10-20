import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ast_auditor", *args],
        cwd=PROJECT_ROOT,
        env={
            **__import__("os").environ,
            "PYTHONPATH": str(PROJECT_ROOT / "src"),
        },
        capture_output=True,
        text=True,
        check=False,
    )


def test_json_report_contains_eval_finding(tmp_path: Path) -> None:
    source_file = tmp_path / "vulnerable.py"
    source_file.write_text("result = eval(user_input)\n", encoding="utf-8")

    result = run_cli("--format", "json", str(source_file))

    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["tool"] == "AST Auditor"
    assert report["findings_count"] == 1
    assert report["findings"][0]["rule_id"] == "PY001"
    assert report["findings"][0]["severity"] == "HIGH"
    assert report["findings"][0]["line"] == 1


def test_clean_file_returns_zero(tmp_path: Path) -> None:
    source_file = tmp_path / "clean.py"
    source_file.write_text('print("hello")\n', encoding="utf-8")

    result = run_cli(str(source_file))

    assert result.returncode == 0
    assert "No findings" in result.stdout


def test_invalid_python_returns_two(tmp_path: Path) -> None:
    source_file = tmp_path / "invalid.py"
    source_file.write_text("if true print('invalid')\n", encoding="utf-8")

    result = run_cli(str(source_file))

    assert result.returncode == 2
    assert "invalid Python syntax" in result.stderr


def test_missing_file_returns_two(tmp_path: Path) -> None:
    missing_file = tmp_path / "does_not_exist.py"

    result = run_cli(str(missing_file))

    assert result.returncode == 2
    assert "cannot read" in result.stderr

def test_sarif_report_contains_eval_finding(tmp_path):
    source_file = tmp_path / "vulnerable.py"
    source_file.write_text(
        "result = eval(user_input)\n",
      encoding="utf-8",
    )

    result = run_cli(
        "--format",
        "sarif",
        str(source_file),
    )

    assert result.returncode == 1

    report = json.loads(result.stdout)

    assert report["version"] == "2.1.0"

    driver = report["runs"][0]["tool"]["driver"]
    assert driver["name"] == "AST Auditor"

    rule_ids =  {rule["id"] for rule in driver["rules"]}
    assert {"PY001","PY002"}.issubset(rule_ids)

    finding = report["runs"][0]["results"][0]
    assert finding["ruleId"] == "PY001"
    assert finding["level"] == "error"
    assert "eval()" in finding["message"]["text"]

    location = finding["locations"][0]["physicalLocation"]
    assert location["region"]["startLine"] == 1
    assert location["artifactLocation"]["uri"] == str(source_file)

def test_sarif_report_for_clean_file_has_no_findings(tmp_path):
    source_file = tmp_path / "clean.py"
    source_file.write_text(
        "print('Hello, world!')\n",
        encoding="utf-8",
    )

    result = run_cli(
        "--format",
        "sarif",
        str(source_file),
    )

    assert result.returncode == 0

    report = json.loads(result.stdout)

    assert report["version"] == "2.1.0"
    assert report["runs"][0]["results"] == []
