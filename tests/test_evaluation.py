"""Tests for the labelled detection evaluation harness."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.evaluate_detection import evaluate, load_cases, scores

ROOT = Path(__file__).resolve().parents[1]


def test_labelled_corpus_matches_current_scanner() -> None:
    corpus = load_cases(ROOT / "evaluation" / "detection_corpus.jsonl")
    report = evaluate(corpus)

    assert report["corpus_cases"] == 48
    assert report["rules_evaluated"] == 6
    assert report["unsupported_cases"] == 2
    assert report["cases_with_mismatches"] == 0
    assert report["cases_exactly_matched"] == 46


def test_every_rule_has_positive_and_negative_examples() -> None:
    corpus = load_cases(ROOT / "evaluation" / "detection_corpus.jsonl")
    report = evaluate(corpus)

    for rule_id, metrics in report["per_rule"].items():
        assert metrics["tp"] >= 1, f"{rule_id} has no true positives"
        assert metrics["tn"] >= 1, f"{rule_id} has no true negatives"


def test_scores_handle_zero_denominators() -> None:
    result = scores(tp=0, fp=0, fn=0, tn=4)

    assert result["precision"] is None
    assert result["recall"] is None
    assert result["f1"] is None


def test_load_cases_rejects_duplicate_ids(tmp_path: Path) -> None:
    record = {
        "id": "duplicate",
        "source": "pass\n",
        "expected_rules": [],
    }
    path = tmp_path / "duplicate.jsonl"
    path.write_text(
        json.dumps(record) + "\n" + json.dumps(record) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate case id"):
        load_cases(path)


def test_load_cases_rejects_unknown_rule_ids(tmp_path: Path) -> None:
    path = tmp_path / "unknown.jsonl"
    path.write_text(
        json.dumps(
            {
                "id": "unknown-rule",
                "source": "pass\n",
                "expected_rules": ["PY999"],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unknown expected rule IDs"):
        load_cases(path)


def test_load_cases_rejects_non_object_records(tmp_path: Path) -> None:
    path = tmp_path / "not-object.jsonl"
    path.write_text("[]\n", encoding="utf-8")

    with pytest.raises(TypeError, match="each record must be an object"):
        load_cases(path)


def test_evaluation_rejects_invalid_python_source() -> None:
    with pytest.raises(ValueError, match="could not be scanned"):
        evaluate(
            [
                {
                    "id": "invalid-python",
                    "source": "def broken(:\n",
                    "expected_rules": [],
                }
            ]
        )


def test_output_write_failure_returns_error_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from scripts import evaluate_detection

    output = tmp_path / "missing-parent" / "report.json"

    def fail_write(*args: object, **kwargs: object) -> None:
        raise OSError("simulated write failure")

    monkeypatch.setattr(Path, "write_text", fail_write)
    monkeypatch.setattr(
        "sys.argv",
        ["evaluate_detection.py", "--output", str(output)],
    )

    assert evaluate_detection.main() == 2
    assert "simulated write failure" in capsys.readouterr().err
