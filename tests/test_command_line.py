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
    assert report["findings"][0]["cwe"] == "CWE-95"
    assert report["findings"][0]["confidence"] == "MEDIUM"
    assert report["rule_pack_version"] == "2026.1"
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
    assert driver["version"] == "0.3.0"

    rule_ids = {rule["id"] for rule in driver["rules"]}
    assert {"PY001", "PY002"}.issubset(rule_ids)

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


def test_sarif_declares_every_rule_used_by_findings(tmp_path: Path) -> None:
    source_file = tmp_path / "all_rules.py"
    source_file.write_text(
        """
import pickle
import subprocess
import yaml

eval(user_input)
exec(user_input)
pickle.loads(data)
subprocess.run(command, shell=True)
yaml.load(data)
""",
        encoding="utf-8",
    )

    result = run_cli("--format", "sarif", str(source_file))

    assert result.returncode == 1
    report = json.loads(result.stdout)
    driver = report["runs"][0]["tool"]["driver"]

    declared_rule_ids = {rule["id"] for rule in driver["rules"]}
    result_rule_ids = {finding["ruleId"] for finding in report["runs"][0]["results"]}

    assert {"PY001", "PY002", "PY003", "PY004", "PY005"} <= result_rule_ids
    assert result_rule_ids <= declared_rule_ids


def test_sarif_encodes_non_uri_characters_in_target_path(tmp_path: Path) -> None:
    source_file = tmp_path / "source #1 % café.py"
    source_file.write_text("eval(data)\n", encoding="utf-8")

    result = run_cli("--format", "sarif", str(source_file))

    assert result.returncode == 1
    report = json.loads(result.stdout)
    result = report["runs"][0]["results"][0]
    location = result["locations"][0]["physicalLocation"]
    uri = location["artifactLocation"]["uri"]
    assert " " not in uri
    assert "#" not in uri
    assert "%25" in uri
    assert "%C3%A9" in uri


def test_directory_scan_reports_relative_files_and_counts(tmp_path: Path) -> None:
    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    (project / "src" / "bad.py").write_text("eval(user_input)\n", encoding="utf-8")
    (project / "src" / "clean.py").write_text("print('ok')\n", encoding="utf-8")
    (project / ".venv").mkdir()
    (project / ".venv" / "ignored.py").write_text("exec(data)\n", encoding="utf-8")

    result = run_cli("--jobs", "2", "--format", "json", str(project))

    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["files_scanned"] == 2
    assert report["findings_count"] == 1
    assert report["findings"][0]["rule_id"] == "PY001"
    assert report["findings"][0]["file"].endswith("bad.py")


def test_directory_scan_supports_excludes_and_size_limit(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "skip.py").write_text("eval(data)\n", encoding="utf-8")
    (project / "large.py").write_text(
        "# " + ("x" * 200) + "\neval(data)\n", encoding="utf-8"
    )
    (project / "ok.py").write_text("print('ok')\n", encoding="utf-8")

    result = run_cli(
        "--format",
        "json",
        "--jobs",
        "1",
        "--exclude",
        "skip.py",
        "--max-file-bytes",
        "20",
        str(project),
    )

    assert result.returncode == 0
    report = json.loads(result.stdout)
    assert report["files_scanned"] == 1
    assert report["files_skipped_size_limit"] == 1
    assert report["findings_count"] == 0


def test_directory_sarif_uses_each_finding_file(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    source_file = project / "bad #1.py"
    source_file.write_text("eval(data)\n", encoding="utf-8")

    result = run_cli("--format", "sarif", str(project))

    assert result.returncode == 1
    report = json.loads(result.stdout)
    location = report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"].endswith("bad%20%231.py")
