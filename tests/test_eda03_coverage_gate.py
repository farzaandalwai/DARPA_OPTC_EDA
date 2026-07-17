"""
Focused tests for EDA 3 coverage reliability gate.
"""

from __future__ import annotations

import pathlib
import sys

import pandas as pd

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src" / "eda"))
from eda_03_time_window_selection import (  # type: ignore
    _apply_window_recommendations,
    assess_coverage_from_df,
    assess_coverage_metrics,
    compute_t5,
    write_n1,
)


def _dense_t5_rows() -> list:
    """Synthetic T5 rows that would qualify under density rules alone."""
    return [
        {
            "window_size": ws,
            "number_of_windows": 100,
            "median_events_per_window": 20.0,
            "mean_events_per_window": 22.0,
            "empty_window_percent": 5.0,
            "median_unique_hosts": 2.0,
            "median_unique_processes": 3.0,
            "median_unique_destinations": 1.0,
            "recommendation_primary_backup_no": "pending",
            "reason": "pending",
        }
        for ws in ("1min", "5min", "15min", "1h", "1d")
    ]


def test_limited_coverage_returns_review_needed(tmp_path):
    # Mimic a 10K single-member / single-host pilot sample.
    coverage = assess_coverage_metrics(
        n_events=10_000,
        n_parseable=10_000,
        unique_archives=1,
        unique_members=1,
        unique_hosts=1,
        unique_dates=1,
        span_hours=2.0,
    )
    assert coverage["status"] == "review_needed"
    assert any("unique_hosts" in c for c in coverage["failed_conditions"])
    assert any("unique_members" in c for c in coverage["failed_conditions"])
    assert any("unique_dates" in c for c in coverage["failed_conditions"])
    assert any("span_hours" in c for c in coverage["failed_conditions"])

    rows = _apply_window_recommendations(_dense_t5_rows(), coverage)
    assert all(r["recommendation_primary_backup_no"] == "review_needed" for r in rows)
    assert not any(r["recommendation_primary_backup_no"] in ("primary", "backup") for r in rows)

    primary, backup = write_n1(
        rows, tmp_path, "[PILOT]", 10_000, 10_000, "test-rule", coverage=coverage
    )
    assert primary == "review_needed"
    assert backup == "review_needed"
    n1 = (tmp_path / "N1_window_recommendation_note.txt").read_text(encoding="utf-8")
    assert "failed_conditions" in n1.lower() or "Failed coverage" in n1
    assert "unique_hosts=1" in n1


def test_coverage_pass_allows_primary_backup():
    coverage = assess_coverage_metrics(
        n_events=50_000,
        n_parseable=49_500,
        unique_archives=2,
        unique_members=5,
        unique_hosts=3,
        unique_dates=3,
        span_hours=48.0,
    )
    assert coverage["status"] == "ok"
    assert coverage["failed_conditions"] == []

    rows = _apply_window_recommendations(_dense_t5_rows(), coverage)
    recs = {r["window_size"]: r["recommendation_primary_backup_no"] for r in rows}
    assert recs["1min"] == "primary"
    assert recs["5min"] == "backup"
    assert "primary" in recs.values()
    assert "backup" in recs.values()
    assert "review_needed" not in recs.values()


def test_assess_coverage_from_df_single_host():
    ts = pd.date_range("2019-09-16", periods=20, freq="min")
    df = pd.DataFrame({
        "archive_name": ["a.tar"] * 20,
        "member_name": ["m1.json.gz"] * 20,
        "host_raw": ["h1"] * 20,
        "ts": ts,
        "timestamp_parsed": ts.astype(str),
    })
    cov = assess_coverage_from_df(df, n_events=20, n_parseable=20)
    assert cov["status"] == "review_needed"
    assert cov["unique_hosts"] == 1
    assert cov["unique_members"] == 1


def test_compute_t5_honors_coverage_gate():
    # Dense enough for density rules, but coverage fails.
    ts = pd.date_range("2019-09-16", periods=200, freq="min")
    df = pd.DataFrame({
        "archive_name": ["a.tar"] * 200,
        "member_name": ["m1.json.gz"] * 200,
        "host_raw": ["h1"] * 200,
        "process_raw": [f"p{i % 5}" for i in range(200)],
        "destination_raw": [""] * 200,
        "user_raw": ["u"] * 200,
        "ts": ts,
    })
    coverage = assess_coverage_from_df(df, 200, 200)
    assert coverage["status"] == "review_needed"
    rows = compute_t5(df, "[test]", coverage=coverage)
    assert rows
    assert all(r["recommendation_primary_backup_no"] == "review_needed" for r in rows)
