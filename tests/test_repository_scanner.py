from concurrent.futures import Future
from pathlib import Path

from ast_auditor import repository_scanner


def test_worker_exception_is_reported_per_file(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "bad.py").write_text("print('hello')\n", encoding="utf-8")

    class FakeExecutor:
        def __init__(self, max_workers: int) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:
            return None

        def submit(self, *args) -> Future:
            future = Future()
            future.set_exception(ValueError("simulated worker failure"))
            return future

    monkeypatch.setattr(repository_scanner, "ProcessPoolExecutor", FakeExecutor)

    results = repository_scanner.scan_project(project, jobs=1)

    assert len(results) == 1
    assert results[0].path == "bad.py"
    assert results[0].error is not None
    assert "worker failed" in results[0].error
    assert "ValueError" in results[0].error
