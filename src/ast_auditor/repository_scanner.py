"""Bounded-memory, parallel project scanning for Python repositories."""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Iterator
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import dataclass, replace
from pathlib import Path

from ast_auditor.security_scanner import Finding, scan_source

DEFAULT_IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "node_modules",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "build",
    "dist",
    "site-packages",
    "vendor",
    ".tox",
    ".nox",
    ".cache",
}


@dataclass(frozen=True)
class FileResult:
    path: str
    findings: tuple[Finding, ...]
    error: str | None = None
    skipped: bool = False


def discover_python_files(root: Path, excludes: tuple[str, ...] = ()) -> Iterator[Path]:
    """Yield Python files without following symlinks or retaining the full tree."""
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        dirs[:] = sorted(
            name
            for name in dirs
            if name not in DEFAULT_IGNORED_DIRS
            and not (Path(current) / name).is_symlink()
        )

        current_path = Path(current)

        for name in sorted(files):
            if not name.endswith(".py"):
                continue

            path = current_path / name
            if path.is_symlink():
                continue

            relative = path.relative_to(root).as_posix()
            if any(fnmatch.fnmatch(relative, pattern) for pattern in excludes):
                continue

            yield path


def _scan_one(
    payload: tuple[str, str, int],
) -> FileResult:
    path_text, display_path, max_file_bytes = payload
    path = Path(path_text)

    try:
        if path.stat().st_size > max_file_bytes:
            return FileResult(display_path, (), skipped=True)

        source = path.read_text(encoding="utf-8")
        findings = tuple(
            replace(finding, file=display_path) for finding in scan_source(source)
        )
        return FileResult(display_path, findings)

    except SyntaxError as exc:
        return FileResult(
            display_path,
            (),
            error=f"syntax error at line {exc.lineno}: {exc.msg}",
        )
    except (OSError, UnicodeError) as exc:
        return FileResult(
            display_path,
            (),
            error=f"cannot read file: {exc}",
        )


def scan_project(
    root: Path,
    *,
    jobs: int | None = None,
    excludes: tuple[str, ...] = (),
    max_file_bytes: int = 2_000_000,
) -> list[FileResult]:
    """Scan a directory with bounded in-flight work and deterministic output.

    In-flight futures are bounded to four per worker. Unexpected worker
    exceptions are reported as per-file errors instead of aborting the scan.
    """
    if not root.is_dir():
        raise NotADirectoryError(f"not a directory: {root}")

    if max_file_bytes < 1:
        raise ValueError("max_file_bytes must be positive")

    root = root.resolve()
    worker_count = max(1, jobs or min(os.cpu_count() or 1, 8))
    pending_limit = worker_count * 4
    results: list[FileResult] = []
    paths = (str(path) for path in discover_python_files(root, excludes))

    with ProcessPoolExecutor(max_workers=worker_count) as executor:
        pending = {}
        exhausted = False

        while pending or not exhausted:
            while len(pending) < pending_limit and not exhausted:
                try:
                    path_text = next(paths)
                except StopIteration:
                    exhausted = True
                    break

                display_path = Path(path_text).relative_to(root).as_posix()
                future = executor.submit(
                    _scan_one,
                    (path_text, display_path, max_file_bytes),
                )
                pending[future] = display_path

            if pending:
                completed, _ = wait(pending, return_when=FIRST_COMPLETED)

                for future in completed:
                    display_path = pending.pop(future)

                    try:
                        results.append(future.result())
                    except Exception as exc:  # noqa: BLE001
                        results.append(
                            FileResult(
                                display_path,
                                (),
                                error=(f"worker failed: {type(exc).__name__}: {exc}"),
                            )
                        )

    return sorted(results, key=lambda result: result.path)
