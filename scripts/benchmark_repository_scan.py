"""Generate a synthetic Python corpus and measure AST Auditor throughput."""

from __future__ import annotations

import argparse
import json
import tempfile
import time
from pathlib import Path

from ast_auditor.repository_scanner import scan_project


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=int, default=10_000)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument(
        "--findings-every",
        type=int,
        default=10,
        help="Put one eval finding in every Nth file; 0 disables findings",
    )
    args = parser.parse_args()
    if args.files < 1 or args.jobs < 1 or args.findings_every < 0:
        parser.error(
            "files/jobs must be positive and findings-every cannot be negative"
        )

    with tempfile.TemporaryDirectory(prefix="ast-auditor-benchmark-") as temporary:
        root = Path(temporary)
        for index in range(args.files):
            source = (
                "value = eval(user_input)\n"
                if args.findings_every and index % args.findings_every == 0
                else "def calculate(value):\n    return value * 2\n"
            )
            (root / f"module_{index:07d}.py").write_text(source, encoding="utf-8")

        started = time.perf_counter()
        results = scan_project(root, jobs=args.jobs)
        elapsed = time.perf_counter() - started
        findings = sum(len(result.findings) for result in results)
        print(
            json.dumps(
                {
                    "files_requested": args.files,
                    "files_scanned": len(results)
                    - sum(bool(result.error) for result in results)
                    - sum(result.skipped for result in results),
                    "findings": findings,
                    "workers": args.jobs,
                    "elapsed_seconds": round(elapsed, 3),
                    "files_per_second": round(args.files / elapsed, 1)
                    if elapsed
                    else None,
                    "note": "Synthetic local benchmark; not a production-scale guarantee.",
                },
                indent=2,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
