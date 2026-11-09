"""Reproducible import benchmark smoke test (Phase A performance baseline)."""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_import_benchmark_reports_completeness():
    env = dict(os.environ)
    env.update(BREADCRUMB_SKIP_BACKUP="1", PYTHONPATH=str(ROOT))
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "bench_import.py"),
            "--entities",
            "1000",
            "--json",
        ],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["completeness"] == 1.0
    assert payload["skipped_rows"] == 0
    assert payload["parsed_entities"] >= 1000
    assert payload["entities_per_second"] > 0
