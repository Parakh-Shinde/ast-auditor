
"""Evaluate AST Auditor against a small, manually labelled JSONL corpus."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from ast_auditor.rules import RULES
from ast_auditor.scanner import scan_source


def ratio(numerator: int, denominator: int) -> float | None:
    """Return a ratio, or None when the metric has no denominator."""
    if denominator == 0:
        return None
    return numerator / denominator


def scores(tp: int, fp: int, fn: int, tn: int) -> dict[str, int | float | None]:
    """Calculate binary classification metrics for one rule."""
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    f1 = (
        None
        if precision is None or recall is None or precision + recall == 0
        else 2 * precision * recall / (precision + recall)
    )
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def load_cases(path: Path) -> list[dict[str, Any]]:
    """Load and validate corpus records, rejecting ambiguous labels."""
    cases: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        if not line.strip():
            continue

        try:
            case = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"line {line_number}: invalid JSON: {exc}"
            ) from exc

        if not isinstance(case, dict):
            raise TypeError(
                f"line {line_number}: each record must be an object"
            )

        case_id = case.get("id")
        source = case.get("source")
        expected = case.get("expected_rules")

        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError(
                f"line {line_number}: id must be a non-empty string"
            )

        if case_id in seen_ids:
            raise ValueError(
                f"line {line_number}: duplicate case id {case_id!r}"
            )

        if not isinstance(source, str) or not source.strip():
            raise ValueError(
                f"line {line_number}: source must be a non-empty string"
            )

        if (
            not isinstance(expected, list)
            or any(not isinstance(rule, str) for rule in expected)
            or len(expected) != len(set(expected))
        ):
            raise ValueError(
                f"line {line_number}: expected_rules must be a unique list "
                "of rule IDs"
            )

        unknown = set(expected) - set(RULES)
        if unknown:
            raise ValueError(
                f"line {line_number}: unknown expected rule IDs: "
                f"{sorted(unknown)}"
            )

        unsupported = case.get("unsupported_rules", [])
        if (
            not isinstance(unsupported, list)
            or any(not isinstance(rule, str) for rule in unsupported)
            or len(unsupported) != len(set(unsupported))
        ):
            raise ValueError(
                f"line {line_number}: unsupported_rules must be a unique list"
            )

        unknown_unsupported = set(unsupported) - set(RULES)
        if unknown_unsupported:
            raise ValueError(
                f"line {line_number}: unknown unsupported rule IDs: "
                f"{sorted(unknown_unsupported)}"
            )

        if set(expected) & set(unsupported):
            raise ValueError(
                f"line {line_number}: a rule cannot be both expected "
                "and unsupported"
            )

        seen_ids.add(case_id)
        cases.append(case)

    if not cases:
        raise ValueError("corpus contains no cases")

    return cases


def evaluate(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Evaluate rule presence per case; multiple findings for one rule count once."""
    per_rule: dict[str, Counter[str]] = {
        rule_id: Counter() for rule_id in sorted(RULES)
    }
    case_results: list[dict[str, Any]] = []
    total_expected = 0
    total_predicted = 0

    for case in cases:
        expected = set(case["expected_rules"])
        unsupported = set(case.get("unsupported_rules", []))

        try:
            findings = scan_source(case["source"])
        except (SyntaxError, ValueError) as exc:
            raise ValueError(
                f"case {case['id']!r} could not be scanned: {exc}"
            ) from exc

        predicted = {finding.rule_id for finding in findings}
        unknown = predicted - set(RULES)
        if unknown:
            raise ValueError(
                f"case {case['id']!r} produced unregistered rules: "
                f"{sorted(unknown)}"
            )

        # Unsupported rule/case combinations are excluded from scoring.
        comparable_predicted = predicted - unsupported
        total_expected += len(expected)
        total_predicted += len(comparable_predicted)

        for rule_id, counts in per_rule.items():
            if rule_id in unsupported:
                continue

            actual_positive = rule_id in comparable_predicted
            expected_positive = rule_id in expected

            if actual_positive and expected_positive:
                counts["tp"] += 1
            elif actual_positive:
                counts["fp"] += 1
            elif expected_positive:
                counts["fn"] += 1
            else:
                counts["tn"] += 1

        matches = expected == comparable_predicted
        case_results.append(
            {
                "id": case["id"],
                "expected_rules": sorted(expected),
                "predicted_rules": sorted(predicted),
                "unsupported_rules": sorted(unsupported),
                "evaluation_status": (
                    "unsupported_pattern" if unsupported else "labelled"
                ),
                "correct": (
                    matches if not unsupported else (None if matches else False)
                ),
                "rationale": case.get("rationale", ""),
            }
        )

    rule_metrics = {
        rule_id: scores(
            counts["tp"],
            counts["fp"],
            counts["fn"],
            counts["tn"],
        )
        for rule_id, counts in per_rule.items()
    }

    totals: Counter[str] = Counter()
    for counts in per_rule.values():
        totals.update(counts)

    overall = scores(
        totals["tp"],
        totals["fp"],
        totals["fn"],
        totals["tn"],
    )

    mismatches = [
        result for result in case_results if result["correct"] is False
    ]
    exactly_matched = sum(
        result["correct"] is True for result in case_results
    )
    unsupported_cases = sum(
        result["evaluation_status"] == "unsupported_pattern"
        for result in case_results
    )

    return {
        "corpus_cases": len(cases),
        "rules_evaluated": len(RULES),
        "expected_rule_labels": total_expected,
        "predicted_rule_labels": total_predicted,
        "cases_exactly_matched": exactly_matched,
        "cases_with_mismatches": len(mismatches),
        "unsupported_cases": unsupported_cases,
        "per_rule": rule_metrics,
        "micro_average": overall,
        "mismatches": mismatches,
        "case_results": case_results,
        "caveat": (
            "Exploratory, manually labelled corpus only; these metrics do not "
            "represent universal scanner accuracy or production performance."
        ),
    }


def main() -> int:
    """Run the evaluator and return a process exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus",
        type=Path,
        default=Path("evaluation/detection_corpus.jsonl"),
        help="Path to the labelled JSONL corpus",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to write the complete JSON report",
    )
    args = parser.parse_args()

    try:
        report = evaluate(load_cases(args.corpus))
    except (OSError, TypeError, ValueError) as exc:
        print(f"evaluation error: {exc}", file=sys.stderr)
        return 2

    rendered = json.dumps(
        report,
        indent=2,
        sort_keys=True,
        allow_nan=False,
    )

    if args.output:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"evaluation error: {exc}", file=sys.stderr)
            return 2

    print(rendered)
    return 0 if report["cases_with_mismatches"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
