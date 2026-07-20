"""
Focused tests for EDA 3 coverage reliability gate.
"""

from __future__ import annotations

import json
import pathlib
import sys

import pandas as pd
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src" / "eda"))
from eda_03_time_window_selection import (  # type: ignore
    _apply_window_recommendations,
    assess_coverage_from_df,
    assess_coverage_metrics,
    compute_t5,
    write_n1,
)
from optc_streaming_parser import SLIM_EVENT_COLUMNS  # type: ignore


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


# ── Cache-mode bounded DuckDB (scale-safe) ────────────────────────────────

def _write_slim_cache(cache_dir: pathlib.Path, events: list[dict]) -> None:
    df = pd.DataFrame(events)
    for c in SLIM_EVENT_COLUMNS:
        if c not in df.columns:
            df[c] = ""
    cache_dir.mkdir(parents=True, exist_ok=True)
    df[list(SLIM_EVENT_COLUMNS)].to_parquet(
        cache_dir / "chunk_00000_date_20190916.parquet", index=False
    )


def _dense_passing_events(n: int = 200) -> list[dict]:
    from optc_streaming_parser import SLIM_EVENT_COLUMNS  # type: ignore

    events = []
    for i in range(n):
        events.append({
            **{c: "" for c in SLIM_EVENT_COLUMNS},
            "source_type": "endpoint",
            "archive_name": f"2019-09-16.tar" if i % 2 == 0 else "2019-09-17.tar",
            "member_name": f"ecar/host{i % 5}.json.gz",
            "host_raw": f"host{i % 4}",
            "process_raw": f"C:\\proc{i % 8}.exe",
            "destination_raw": f"10.0.{i % 6}.1",
            "user_raw": f"user{i % 3}",
            "timestamp_parsed": (
                f"2019-09-{16 + (i // 80):02d}T"
                f"{(10 + (i % 50) // 60) % 24:02d}:{i % 60:02d}:00"
            ),
            "parse_status": "ok",
            "raw_event_id": f"e{i}",
        })
    return events


def _cache_t5(events, tmp_path, cache_meta=None, **duck_kwargs):
    from eda_03_time_window_selection import (  # type: ignore
        _duck_conn,
        compute_t5_from_cache,
        fetch_cache_baseline,
    )
    import shutil

    cache = tmp_path / "cache"
    _write_slim_cache(cache, events)
    if cache_meta is not None:
        (cache / "cache_metadata.json").write_text(
            json.dumps(cache_meta), encoding="utf-8"
        )
    kwargs = {"memory_limit": "128MB", "threads": 1}
    kwargs.update(duck_kwargs)
    con, spill, owned = _duck_conn(cache, **kwargs)
    try:
        meta = cache_meta or {"total_events_written": len(events)}
        baseline = fetch_cache_baseline(con, meta)
        rows, buckets = compute_t5_from_cache(
            con,
            baseline["coverage"],
            n_parseable=baseline["n_parseable"],
            tmin=baseline["tmin"],
            tmax=baseline["tmax"],
        )
        return rows, buckets, baseline, con
    finally:
        con.close()
        if owned:
            shutil.rmtree(spill, ignore_errors=True)


def test_cache_t5_recommendations_match_legacy_on_low_cardinality(tmp_path):
    from optc_streaming_parser import SLIM_EVENT_COLUMNS  # type: ignore

    events = _dense_passing_events(240)
    df = pd.DataFrame(events)
    df["ts"] = pd.to_datetime(df["timestamp_parsed"])
    coverage = assess_coverage_from_df(df, len(events), len(events))
    assert coverage["status"] == "ok"
    legacy = compute_t5(df, "[legacy]", coverage=coverage)
    cache_rows, _, baseline, _ = _cache_t5(
        events, tmp_path, cache_meta={"total_events_written": len(events)}
    )
    assert baseline["n_parseable"] == len(events)
    for leg, cache in zip(legacy, cache_rows):
        assert leg["window_size"] == cache["window_size"]
        assert (
            leg["recommendation_primary_backup_no"]
            == cache["recommendation_primary_backup_no"]
        )
        assert leg["empty_window_percent"] == cache["empty_window_percent"]
        assert leg["median_events_per_window"] == cache["median_events_per_window"]


def test_cache_t5_exact_window_metrics_and_approx_labels(tmp_path):
    events = _dense_passing_events(180)
    cache_rows, buckets, baseline, _ = _cache_t5(
        events, tmp_path, cache_meta={"total_events_written": len(events)}
    )
    ws = "15min"
    row = next(r for r in cache_rows if r["window_size"] == ws)
    b = buckets[ws]
    assert int(b["n_events"].sum()) == baseline["n_parseable"]
    assert row["median_unique_hosts_method"] == "exact_count_distinct"
    assert row["median_unique_processes_method"] == "approx_count_distinct"
    assert row["median_unique_destinations_method"] == "approx_count_distinct"
    assert "u_users" in b.columns


def test_true_parseability_excludes_invalid_nonempty_timestamp(tmp_path):
    from eda_03_time_window_selection import _duck_conn, fetch_cache_baseline, fetch_window_buckets  # type: ignore
    import shutil

    events = _dense_passing_events(8)
    # Non-empty but invalid timestamp; must be excluded from parseable counts.
    events.append({**events[0], "raw_event_id": "bad-ts", "timestamp_parsed": "NOT_A_TIMESTAMP"})
    cache = tmp_path / "cache_ts"
    _write_slim_cache(cache, events)
    con, spill, owned = _duck_conn(cache, memory_limit="64MB", threads=1)
    try:
        baseline = fetch_cache_baseline(con, {"total_events_written": len(events)})
        assert baseline["n_total"] == len(events)
        assert baseline["n_parseable"] == len(events) - 1
        for ws in ("1min", "5min", "15min", "1h", "1d"):
            b = fetch_window_buckets(con, ws)
            assert int(b["n_events"].sum()) == len(events) - 1
    finally:
        con.close()
        if owned:
            shutil.rmtree(spill, ignore_errors=True)


@pytest.mark.parametrize(
    ("window_size", "expected_windows", "expected_empty_pct"),
    [
        ("1min", 63, 96.8),    # 00:59..02:01
        ("5min", 14, 85.7),    # 00:55..02:00
        ("15min", 6, 66.7),    # 00:45..02:00
        ("1h", 3, 33.3),       # 00:00,01:00,02:00
        ("1d", 1, 0.0),
    ],
)
def test_exact_bucket_grid_alignment(tmp_path, window_size, expected_windows, expected_empty_pct):
    from eda_03_time_window_selection import _t5_row_from_buckets, _duck_conn, fetch_window_buckets  # type: ignore
    import shutil

    # Events at 00:59 and 02:01 should align to bucket boundaries before grid math.
    events = _dense_passing_events(2)
    events[0]["timestamp_parsed"] = "2019-09-16T00:59:00"
    events[1]["timestamp_parsed"] = "2019-09-16T02:01:00"
    cache = tmp_path / f"cache_{window_size}"
    _write_slim_cache(cache, events)
    con, spill, owned = _duck_conn(cache, memory_limit="64MB", threads=1)
    try:
        buckets = fetch_window_buckets(con, window_size)
    finally:
        con.close()
        if owned:
            shutil.rmtree(spill, ignore_errors=True)

    row = _t5_row_from_buckets(
        buckets, window_size, tmin=None, tmax=None, n_parseable=2
    )
    assert row["number_of_windows"] == expected_windows
    assert row["empty_window_percent"] == expected_empty_pct


def test_dense_plotting_table_contains_missing_zero_bucket():
    from eda_03_time_window_selection import densify_bucket_table  # type: ignore
    import pandas as pd

    sparse = pd.DataFrame({
        "bucket": pd.to_datetime(["2019-09-16 00:00:00", "2019-09-16 00:02:00"]),
        "n_events": [5, 7],
        "u_hosts": [2, 3],
        "u_procs": [4, 5],
        "u_dests": [1, 1],
        "u_users": [2, 2],
    })
    dense = densify_bucket_table(sparse, "1min")
    assert len(dense) == 3
    mid = dense[dense["bucket"] == pd.Timestamp("2019-09-16 00:01:00")].iloc[0]
    assert int(mid["n_events"]) == 0
    assert int(mid["u_hosts"]) == 0
    assert int(mid["u_users"]) == 0


def test_t5_window_count_arithmetic_without_densify(monkeypatch):
    """T5 uses aligned first/last bucket arithmetic; never densifies."""
    from eda_03_time_window_selection import (  # type: ignore
        _t5_row_from_buckets,
        densify_bucket_table,
    )
    import pandas as pd

    buckets = pd.DataFrame({
        "bucket": pd.to_datetime(["2019-09-16 00:59:00", "2019-09-16 02:01:00"]),
        "n_events": [1, 1],
        "u_hosts": [1, 1],
        "u_procs": [1, 1],
        "u_dests": [0, 0],
        "u_users": [1, 1],
    })

    def _boom(*_a, **_k):
        raise AssertionError("densify_bucket_table must not be called for T5")

    monkeypatch.setattr(
        "eda_03_time_window_selection.densify_bucket_table", _boom
    )
    row = _t5_row_from_buckets(
        buckets, "1min", tmin=None, tmax=None, n_parseable=2
    )
    assert row["number_of_windows"] == 63
    assert row["empty_window_percent"] == 96.8
    # Plotting helper remains available for F3/F4 densification.
    assert callable(densify_bucket_table)


def test_t5_does_not_call_pd_date_range(monkeypatch):
    """Prove _t5_row_from_buckets never allocates via pd.date_range."""
    from eda_03_time_window_selection import _t5_row_from_buckets  # type: ignore
    import pandas as pd

    buckets = pd.DataFrame({
        "bucket": pd.to_datetime(["2019-09-16 00:00:00", "2019-09-16 00:05:00"]),
        "n_events": [3, 4],
        "u_hosts": [1, 1],
        "u_procs": [1, 1],
        "u_dests": [0, 0],
        "u_users": [1, 1],
    })

    def _fail_date_range(*_a, **_k):
        raise AssertionError("pd.date_range must not be called by T5")

    monkeypatch.setattr(pd, "date_range", _fail_date_range)
    row = _t5_row_from_buckets(
        buckets, "1min", tmin=None, tmax=None, n_parseable=7
    )
    assert row["number_of_windows"] == 6
    assert row["empty_window_percent"] == round((6 - 2) / 6 * 100, 1)


def test_densify_rejects_extreme_span_before_date_range(monkeypatch):
    from eda_03_time_window_selection import (  # type: ignore
        CacheAuditError,
        MAX_DENSE_PLOT_BUCKETS,
        densify_bucket_table,
    )
    import pandas as pd

    # ~100 years of 1-minute buckets >> 1_000_000 cap
    sparse = pd.DataFrame({
        "bucket": pd.to_datetime(["1900-01-01 00:00:00", "2000-01-01 00:00:00"]),
        "n_events": [1, 1],
        "u_hosts": [1, 1],
        "u_procs": [1, 1],
        "u_dests": [0, 0],
        "u_users": [1, 1],
    })
    called = {"n": 0}

    def _fail_date_range(*_a, **_k):
        called["n"] += 1
        raise AssertionError("pd.date_range must not run after cap rejection")

    monkeypatch.setattr(pd, "date_range", _fail_date_range)
    with pytest.raises(CacheAuditError, match="MAX_DENSE_PLOT_BUCKETS") as exc:
        densify_bucket_table(sparse, "1min")
    msg = str(exc.value)
    assert "first_bucket=" in msg
    assert "last_bucket=" in msg
    assert "1min" in msg
    assert "outlier" in msg.lower() or "unexpectedly" in msg.lower()
    assert called["n"] == 0
    assert MAX_DENSE_PLOT_BUCKETS == 1_000_000


def test_normal_10day_1min_grid_below_dense_cap():
    from eda_03_time_window_selection import (  # type: ignore
        MAX_DENSE_PLOT_BUCKETS,
        _aligned_bucket_window_count,
        densify_bucket_table,
    )
    import pandas as pd

    first = pd.Timestamp("2019-09-16 00:00:00")
    last = pd.Timestamp("2019-09-25 23:59:00")  # 10 calendar days, 1-min aligned
    n = _aligned_bucket_window_count(first, last, "1min")
    assert n == 14_400
    assert n < MAX_DENSE_PLOT_BUCKETS

    # Small real densify still allocates normally under the cap
    sparse = pd.DataFrame({
        "bucket": [first, last],
        "n_events": [1, 1],
        "u_hosts": [1, 1],
        "u_procs": [1, 1],
        "u_dests": [0, 0],
        "u_users": [1, 1],
    })
    # Cap check uses arithmetic only; avoid allocating 14_400 rows here —
    # instead verify a tiny span densifies and the 10-day count is under cap.
    tiny = sparse.copy()
    tiny.loc[1, "bucket"] = first + pd.Timedelta(minutes=2)
    dense = densify_bucket_table(tiny, "1min")
    assert len(dense) == 3


def test_bucket_sql_uses_approx_for_high_cardinality_only():
    from eda_03_time_window_selection import fetch_window_buckets  # type: ignore
    import inspect

    src = inspect.getsource(fetch_window_buckets)
    lowered = src.lower()
    assert "approx_count_distinct" in lowered
    assert "count(distinct nullif(cast(process_raw" not in lowered.replace(
        "approx_count_distinct", ""
    )
    assert "count(distinct nullif(cast(destination_raw" not in lowered.replace(
        "approx_count_distinct", ""
    )
    assert "count(distinct nullif(cast(user_raw" not in lowered.replace(
        "approx_count_distinct", ""
    )
    assert "count(distinct nullif(cast(host_raw" in lowered


def test_f3_f4_reuse_buckets_without_cache_rescan(tmp_path, monkeypatch):
    from eda_03_time_window_selection import (  # type: ignore
        _duck_conn,
        compute_t5_from_cache,
        fetch_cache_baseline,
        plot_f3_from_buckets,
        plot_f4_from_buckets,
    )
    import duckdb

    execute_calls: list[str] = []
    real_connect = duckdb.connect

    class SpyConn:
        def __init__(self):
            self._real = real_connect()

        def execute(self, query, *a, **k):
            execute_calls.append(str(query))
            return self._real.execute(query, *a, **k)

        def close(self):
            return self._real.close()

        def __getattr__(self, name):
            return getattr(self._real, name)

    monkeypatch.setattr(duckdb, "connect", SpyConn)

    events = _dense_passing_events(100)
    cache = tmp_path / "cache"
    _write_slim_cache(cache, events)
    con, spill, owned = _duck_conn(cache, memory_limit="64MB", threads=1)
    try:
        baseline = fetch_cache_baseline(con, {"total_events_written": len(events)})
        n_before_t5 = len(execute_calls)
        rows, buckets = compute_t5_from_cache(
            con,
            baseline["coverage"],
            n_parseable=baseline["n_parseable"],
            tmin=baseline["tmin"],
            tmax=baseline["tmax"],
        )
        n_after_t5 = len(execute_calls)
        assert n_after_t5 > n_before_t5
        payload_sql = [q.lower() for q in execute_calls if " from events" in q.lower()]
        baseline_payload = [q for q in payload_sql if "count(*)::bigint as n_total" in q]
        bucket_payload = [q for q in payload_sql if "time_bucket(" in q]
        assert len(baseline_payload) == 1
        assert len(bucket_payload) == 5
        primary = next(
            r for r in rows if r["recommendation_primary_backup_no"] == "primary"
        )
        primary_buckets = buckets[primary["window_size"]]
        plot_f3_from_buckets(
            primary_buckets, tmp_path / "out", tmp_path / "fig",
            primary["window_size"], "[test]",
        )
        plot_f4_from_buckets(
            primary_buckets, tmp_path / "out", tmp_path / "fig",
            primary["window_size"], "[test]",
        )
        assert len(execute_calls) == n_after_t5
    finally:
        con.close()
        if owned:
            import shutil
            shutil.rmtree(spill, ignore_errors=True)


def test_bucket_sum_mismatch_raises(tmp_path):
    from eda_03_time_window_selection import (  # type: ignore
        CacheAuditError,
        assert_bucket_sums_match_parseable,
    )
    import pandas as pd

    buckets = pd.DataFrame({"n_events": [10, 10]})
    with pytest.raises(CacheAuditError, match="SUM\\(n_events\\)"):
        assert_bucket_sums_match_parseable(buckets, 25, "15min")


def test_metadata_total_mismatch_raises(tmp_path):
    from eda_03_time_window_selection import (  # type: ignore
        CacheAuditError,
        _duck_conn,
        fetch_cache_baseline,
    )
    import shutil

    events = _dense_passing_events(30)
    cache = tmp_path / "cache"
    _write_slim_cache(cache, events)
    con, spill, owned = _duck_conn(cache, memory_limit="64MB", threads=1)
    try:
        with pytest.raises(CacheAuditError, match="total_events_written"):
            fetch_cache_baseline(con, {"total_events_written": 999_999})
    finally:
        con.close()
        if owned:
            shutil.rmtree(spill, ignore_errors=True)


def test_duckdb_owned_spill_cleaned_explicit_preserved(tmp_path):
    from eda_03_time_window_selection import (  # type: ignore
        _configure_duckdb,
        _duck_conn,
    )
    import duckdb
    import shutil

    events = _dense_passing_events(10)
    cache = tmp_path / "cache"
    _write_slim_cache(cache, events)

    con, spill, owned = _duck_conn(cache, memory_limit="64MB", threads=1)
    assert owned is True
    spill_path = pathlib.Path(spill)
    assert spill_path.is_dir()
    con.close()
    shutil.rmtree(spill_path)
    assert not spill_path.exists()

    explicit = tmp_path / "explicit_spill"
    explicit.mkdir()
    marker = explicit / "keep.txt"
    marker.write_text("stay", encoding="utf-8")
    con2, used, owned2 = _duck_conn(
        cache, memory_limit="64MB", threads=1, temp_dir=str(explicit)
    )
    assert owned2 is False
    assert used == str(explicit)
    con2.close()
    assert marker.read_text(encoding="utf-8") == "stay"

    settings = []
    con3 = duckdb.connect()

    class Spy:
        def execute(self, query, *a, **k):
            settings.append(str(query))
            return con3.execute(query, *a, **k)

    _configure_duckdb(
        Spy(), memory_limit="64MB", temp_dir=str(explicit), threads=1
    )
    joined = "\n".join(settings)
    assert "memory_limit='64MB'" in joined
    assert "threads=1" in joined.replace(" ", "")
    assert "preserve_insertion_order=false" in joined.replace(" ", "")
    con3.close()


def test_duckdb_internal_spill_removed_on_setup_failure(tmp_path, monkeypatch):
    from eda_03_time_window_selection import _duck_conn  # type: ignore
    import duckdb
    import tempfile

    events = _dense_passing_events(4)
    cache = tmp_path / "cache_fail"
    _write_slim_cache(cache, events)

    created = {}
    real_mkdtemp = tempfile.mkdtemp

    def tracking_mkdtemp(*a, **k):
        p = real_mkdtemp(*a, **k)
        created["path"] = p
        return p

    monkeypatch.setattr(tempfile, "mkdtemp", tracking_mkdtemp)

    real_connect = duckdb.connect

    class BoomConn:
        def __init__(self):
            self._real = real_connect()

        def execute(self, query, *a, **k):
            q = str(query)
            if "CREATE VIEW events AS SELECT * FROM read_parquet" in q:
                self._real.close()
                raise RuntimeError("forced create view failure")
            return self._real.execute(query, *a, **k)

        def close(self):
            try:
                self._real.close()
            except Exception:
                pass

    monkeypatch.setattr(duckdb, "connect", BoomConn)
    with pytest.raises(RuntimeError, match="forced create view failure"):
        _duck_conn(cache, memory_limit="64MB", threads=1)
    assert "path" in created
    assert not pathlib.Path(created["path"]).exists()


def test_duckdb_cli_validation():
    from eda_03_time_window_selection import (  # type: ignore
        CacheAuditError,
        _validate_duckdb_memory_limit,
        _validate_duckdb_threads,
    )

    assert _validate_duckdb_threads(2) == 2
    with pytest.raises(CacheAuditError, match="must be >= 1"):
        _validate_duckdb_threads(0)
    with pytest.raises(CacheAuditError, match="Invalid --duckdb-memory-limit"):
        _validate_duckdb_memory_limit("not-a-size")


def test_sampling_strategy_full_does_not_force_review():
    from eda_03_time_window_selection import apply_sampling_strategy_gate  # type: ignore

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
    gated = apply_sampling_strategy_gate(coverage, "full")
    assert gated["status"] == "ok"
    assert gated["sampling_strategy"] == "full"


def test_legacy_mode_compute_t5_unchanged_no_method_columns_required():
    """Legacy path still produces core T5 columns without cache-mode labels."""
    ts = pd.date_range("2019-09-16", periods=50, freq="min")
    df = pd.DataFrame({
        "archive_name": ["a.tar"] * 50,
        "member_name": ["m1.json.gz"] * 50,
        "host_raw": ["h1"] * 50,
        "process_raw": [f"p{i % 3}" for i in range(50)],
        "destination_raw": [""] * 50,
        "user_raw": ["u"] * 50,
        "ts": ts,
    })
    coverage = assess_coverage_from_df(df, 50, 50)
    rows = compute_t5(df, "[legacy]", coverage=coverage)
    assert rows
    assert "median_unique_hosts_method" not in rows[0]
