"""Repeatable throughput benchmark for a synthetic Python repository."""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path
from typing import Any

from ast_auditor.repository_scanner import scan_project


def scan_signature(results: list[Any]) -> tuple[Any, ...]:
    """Create a stable signature for comparing scan results across runs."""
    return tuple(
        (
            str(result.path),
            repr(result.findings),
            result.error,
            result.skipped,
        )
        for result in results
    )


def result_summary(results: list[Any]) -> dict[str, int]:
    """Summarize successful, failed, skipped files, and findings."""
    return {
        "files_returned": len(results),
        "files_scanned": sum(
            not result.error and not result.skipped for result in results
        ),
        "errors": sum(bool(result.error) for result in results),
        "skipped": sum(bool(result.skipped) for result in results),
        "findings": sum(len(result.findings) for result in results),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=int, default=10_000)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument(
        "--findings-every",
        type=int,
        default=10,
        help="Put one eval finding in every Nth file; 0 disables findings",
    )
    args = parser.parse_args()

    if (
        args.files < 1
        or args.jobs < 1
        or args.repeats < 1
        or args.findings_every < 0
    ):
        parser.error(
            "files/jobs/repeats must be positive and findings-every "
            "cannot be negative"
        )

    with tempfile.TemporaryDirectory(
        prefix="ast-auditor-benchmark-"
    ) as temporary:
        root = Path(temporary)

        for index in range(args.files):
            source = (
                "value = eval(user_input)\n"
                if args.findings_every
                and index % args.findings_every == 0
                else "def calculate(value):\n    return value * 2\n"
            )
            (root / f"module_{index:07d}.py").write_text(
                source, encoding="utf-8"
            )

        # Warm-up is excluded from timing samples.
        warmup = scan_project(root, jobs=args.jobs)
        reference_signature = scan_signature(warmup)
        reference_summary = result_summary(warmup)

        expected_findings = (
            len(range(0, args.files, args.findings_every))
            if args.findings_every
            else 0
        )
        baseline_valid = (
            reference_summary["files_scanned"] == args.files
            and reference_summary["errors"] == 0
            and reference_summary["skipped"] == 0
            and reference_summary["findings"] == expected_findings
        )

        elapsed_samples: list[float] = []
        consistent = baseline_valid

        for _ in range(args.repeats):
            started = time.perf_counter()
            results = scan_project(root, jobs=args.jobs)
            elapsed = time.perf_counter() - started

            elapsed_samples.append(elapsed)
            consistent = (
                consistent
                and scan_signature(results) == reference_signature
                and result_summary(results) == reference_summary
            )

        # Measure traced allocations in a separate run so tracing overhead
        # does not distort the timed throughput samples.
        tracemalloc.start()
        try:
            memory_results = scan_project(root, jobs=args.jobs)
            _, peak_bytes = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        consistent = (
            consistent
            and scan_signature(memory_results) == reference_signature
            and result_summary(memory_results) == reference_summary
        )

        median_seconds = statistics.median(elapsed_samples)
        summary = reference_summary

        report = {
            "benchmark": "synthetic_repository_scan",
            "files_requested": args.files,
            **summary,
            "expected_findings": expected_findings,
            "workers": args.jobs,
            "repeats": args.repeats,
            "elapsed_seconds_samples": [
                round(sample, 6) for sample in elapsed_samples
            ],
            "median_elapsed_seconds": round(median_seconds, 6),
            "min_elapsed_seconds": round(min(elapsed_samples), 6),
            "max_elapsed_seconds": round(max(elapsed_samples), 6),
            "files_per_second_median": (
                round(summary["files_scanned"] / median_seconds, 1)
                if median_seconds
                else None
            ),
            "findings_per_second_median": (
                round(summary["findings"] / median_seconds, 1)
                if median_seconds
                else None
            ),
            "parent_process_traced_peak_bytes": peak_bytes,
            "results_consistent": consistent,
            "python_version": sys.version.split()[0],
            "platform": platform.platform(),
            "notes": [
                "Synthetic local benchmark, not a production-scale guarantee.",
                "Throughput uses the median of repeated timed scans.",
                (
                    "Peak memory is traced in the benchmark process only; "
                    "worker-process and native allocations are not fully captured."
                ),
                "Warm-up and memory measurement are excluded from timed samples.",
            ],
        }

        print(json.dumps(report, indent=2, allow_nan=False))
        return 0 if consistent else 1


if __name__ == "__main__":
    raise SystemExit(main())
