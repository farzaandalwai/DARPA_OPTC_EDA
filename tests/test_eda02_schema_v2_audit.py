"""
Focused tests for EDA 2 schema-v2 field reliability audit.
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src" / "eda"))
from eda_02_schema_quality_audit import (  # type: ignore
    T3_COLUMNS,
    compute_t3,
    field_role,
)
from optc_streaming_parser import SLIM_EVENT_COLUMNS  # type: ignore


def _base_event(**overrides) -> dict:
    e = {
        "source_type": "endpoint",
        "archive_name": "2019-09-16.tar",
        "member_name": "ecar/host.ecar.json.gz",
        "parse_status": "ok",
        "parse_error": "",
        "raw_event_id": "e1",
        "timestamp_raw": "1568678400",
        "timestamp_parsed": "2019-09-16T00:00:00",
        "host_raw": "SysClient0201",
        "action_raw": "CREATE",
        "object_raw": "PROCESS",
        "user_raw": "u",
        "process_raw": "p",
        "parent_process_raw": "",
        "destination_raw": "",
        "object_value_raw": "oid",
        "file_id": "f1",
        "line_number": "1",
        "command_line_raw": "",
        "image_path_raw": "",
        "file_path_raw": "",
        "service_name_raw": "",
    }
    e.update(overrides)
    # Ensure every slim column exists for audit completeness.
    for col in SLIM_EVENT_COLUMNS:
        e.setdefault(col, "")
    return e


def test_t3_audits_all_slim_event_columns():
    events = [_base_event(raw_event_id=f"e{i}") for i in range(12)]
    rows = compute_t3(events, ["endpoint"])
    fields = {r["field_name"] for r in rows}
    assert fields == set(SLIM_EVENT_COLUMNS)
    assert all(set(T3_COLUMNS).issubset(r.keys()) for r in rows)


def test_object_specific_conditional_missingness():
    # Mostly PROCESS rows; one FILE with file_path present.
    events = [
        _base_event(raw_event_id=f"p{i}", object_raw="PROCESS", file_path_raw="")
        for i in range(20)
    ]
    events.append(
        _base_event(
            raw_event_id="f1",
            object_raw="FILE",
            file_path_raw="C:\\tmp\\a.txt",
            object_value_raw="C:\\tmp\\a.txt",
        )
    )
    rows = compute_t3(events, ["endpoint"])
    by_field = {r["field_name"]: r for r in rows}
    fp = by_field["file_path_raw"]
    assert fp["field_role"] == "object_specific"
    assert fp["applicable_object_types"] == "FILE"
    assert fp["applicable_rows"] == 1
    assert fp["missing_percent_overall"] > 90.0
    assert fp["missing_percent_applicable"] == 0.0
    assert fp["reliability_decision_keep_review_drop"] == "keep"

    # Absent applicable type → review / not assessable (never drop).
    svc = by_field["service_name_raw"]
    assert svc["applicable_rows"] == 0
    assert svc["reliability_decision_keep_review_drop"] == "review"
    assert "not assessable" in svc["reason"]


def test_constant_host_single_host_sample_not_dropped():
    events = [
        _base_event(raw_event_id=f"e{i}", host_raw="SysClient0201")
        for i in range(15)
    ]
    rows = compute_t3(events, ["endpoint"])
    host = next(r for r in rows if r["field_name"] == "host_raw")
    assert host["unique_count"] == 1
    assert host["reliability_decision_keep_review_drop"] == "keep"
    assert "single-host" in host["reason"]


def test_empty_diagnostic_fields_retained():
    events = [
        _base_event(raw_event_id=f"e{i}", parse_error="")
        for i in range(12)
    ]
    rows = compute_t3(events, ["endpoint"])
    pe = next(r for r in rows if r["field_name"] == "parse_error")
    assert pe["field_role"] == "provenance"
    assert pe["missing_percent_overall"] == 100.0
    assert pe["reliability_decision_keep_review_drop"] == "keep"
    assert field_role("parse_status") == "provenance"
    assert field_role("source_type") == "control"


def test_empty_unmapped_discovery_field_kept_as_drift_monitor():
    events = [
        _base_event(
            raw_event_id=f"e{i}",
            unmapped_property_keys_raw="",
            properties_keys_raw="image_path,command_line",
        )
        for i in range(15)
    ]
    rows = compute_t3(events, ["endpoint"])
    by_field = {r["field_name"]: r for r in rows}
    um = by_field["unmapped_property_keys_raw"]
    assert um["field_role"] == "discovery"
    assert um["missing_percent_overall"] == 100.0
    assert um["unique_count"] == 0
    assert um["reliability_decision_keep_review_drop"] == "keep"
    assert "schema-drift monitor" in um["reason"]
    assert "no unmapped property keys observed" in um["reason"]
    # Sparse promoted fields still appear in the audited schema surface.
    assert "property_size_raw" in by_field
    assert "flow_start_time_raw" in by_field


def test_nonempty_unmapped_discovery_field_review_for_schema_drift():
    events = [
        _base_event(
            raw_event_id=f"e{i}",
            unmapped_property_keys_raw="mystery_flag" if i % 2 == 0 else "other_new_key",
        )
        for i in range(12)
    ]
    rows = compute_t3(events, ["endpoint"])
    um = next(r for r in rows if r["field_name"] == "unmapped_property_keys_raw")
    assert um["field_role"] == "discovery"
    assert um["unique_count"] >= 1
    assert um["reliability_decision_keep_review_drop"] == "review"
    assert "schema drift" in um["reason"].lower() or "unmapped keys" in um["reason"]


def test_ordinary_non_discovery_still_uses_missingness_thresholds():
    # A non-discovery entity field that is almost always empty → drop.
    events = [
        _base_event(raw_event_id=f"e{i}", principal_raw="")
        for i in range(20)
    ]
    rows = compute_t3(events, ["endpoint"])
    pr = next(r for r in rows if r["field_name"] == "principal_raw")
    assert pr["field_role"] == "entity"
    assert pr["missing_percent_overall"] == 100.0
    assert pr["reliability_decision_keep_review_drop"] == "drop"
    assert "default modeling feature set" in pr["reason"]
    assert "normalized schema" in pr["reason"]


def test_derived_parent_process_not_dropped_on_non_process_absence():
    """
    Mirror real-cache pattern: parent_process_raw high overall missingness
    because most events are non-PROCESS, but low conditional missing on PROCESS.
    """
    events = []
    # ~90% non-PROCESS (empty parent_process_raw by design)
    for i in range(18):
        events.append(
            _base_event(
                raw_event_id=f"f{i}",
                object_raw="FILE",
                process_raw="",
                parent_process_raw="",
                parent_image_path_raw="",
            )
        )
    # PROCESS rows with parent present (~12.6%-like low applicable missing)
    for i in range(2):
        events.append(
            _base_event(
                raw_event_id=f"p{i}",
                object_raw="PROCESS",
                process_raw=f"C:\\a{i}.exe",
                image_path_raw=f"C:\\a{i}.exe",
                parent_process_raw=f"C:\\parent{i}.exe",
                parent_image_path_raw=f"C:\\parent{i}.exe",
            )
        )
    rows = compute_t3(events, ["endpoint"])
    pp = next(r for r in rows if r["field_name"] == "parent_process_raw")
    assert pp["field_role"] == "object_specific"
    assert pp["applicable_object_types"] == "PROCESS"
    assert pp["applicable_rows"] == 2
    assert pp["missing_percent_overall"] >= 80.0
    assert pp["missing_percent_applicable"] == 0.0
    assert pp["reliability_decision_keep_review_drop"] != "drop"
    assert pp["reliability_decision_keep_review_drop"] == "keep"


def test_derived_destination_not_penalized_on_non_flow_absence():
    """
    destination_raw overall missingness looks reviewable, but FLOW-conditional
    missingness is near-zero — decision must use applicable rows.
    """
    events = []
    for i in range(13):
        events.append(
            _base_event(
                raw_event_id=f"p{i}",
                object_raw="PROCESS",
                destination_raw="",
                dest_ip_raw="",
                process_raw=f"C:\\p{i}.exe",
                image_path_raw=f"C:\\p{i}.exe",
            )
        )
    for i in range(7):
        events.append(
            _base_event(
                raw_event_id=f"fl{i}",
                object_raw="FLOW",
                destination_raw=f"8.8.8.{i}",
                dest_ip_raw=f"8.8.8.{i}",
                process_raw="C:\\svchost.exe",
                image_path_raw="C:\\svchost.exe",
            )
        )
    rows = compute_t3(events, ["endpoint"])
    dest = next(r for r in rows if r["field_name"] == "destination_raw")
    assert dest["field_role"] == "object_specific"
    assert dest["applicable_object_types"] == "FLOW"
    assert dest["applicable_rows"] == 7
    assert dest["missing_percent_overall"] > 60.0
    assert dest["missing_percent_applicable"] == 0.0
    assert dest["reliability_decision_keep_review_drop"] == "keep"
    assert dest["reliability_decision_keep_review_drop"] not in ("review", "drop")


def test_process_raw_shares_image_path_applicability():
    from eda_02_schema_quality_audit import applicable_object_types_for  # type: ignore

    assert field_role("process_raw") == "object_specific"
    assert applicable_object_types_for("process_raw") == [
        "PROCESS", "FLOW", "FILE", "MODULE", "THREAD", "SHELL",
    ]
    assert applicable_object_types_for("process_raw") == applicable_object_types_for(
        "image_path_raw"
    )

    # Mix: PROCESS with process_raw present; REGISTRY (non-applicable) empty.
    events = [
        _base_event(
            raw_event_id=f"p{i}",
            object_raw="PROCESS",
            process_raw=f"C:\\p{i}.exe",
            image_path_raw=f"C:\\p{i}.exe",
        )
        for i in range(10)
    ] + [
        _base_event(
            raw_event_id=f"r{i}",
            object_raw="REGISTRY",
            process_raw="",
            image_path_raw="",
        )
        for i in range(10)
    ]
    rows = compute_t3(events, ["endpoint"])
    pr = next(r for r in rows if r["field_name"] == "process_raw")
    assert pr["field_role"] == "object_specific"
    assert pr["applicable_object_types"] == (
        "PROCESS,FLOW,FILE,MODULE,THREAD,SHELL"
    )
    assert pr["applicable_rows"] == 10
    assert pr["missing_percent_overall"] == 50.0
    assert pr["missing_percent_applicable"] == 0.0
    assert pr["reliability_decision_keep_review_drop"] == "keep"


# ── Cache-mode T3 (memory-bounded DuckDB) ─────────────────────────────────

def _write_slim_cache(cache_dir: pathlib.Path, events: list[dict]) -> None:
    import pandas as pd

    cache_dir.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame(events)
    for c in SLIM_EVENT_COLUMNS:
        if c not in df.columns:
            df[c] = ""
    df[list(SLIM_EVENT_COLUMNS)].to_parquet(
        cache_dir / "chunk_00000_date_20190916.parquet", index=False
    )


def _cache_t3(events, tmp_path, **duck_kwargs):
    from eda_02_schema_quality_audit import (  # type: ignore
        _duck_conn,
        compute_t3_from_cache,
    )
    import shutil

    cache = tmp_path / "cache"
    _write_slim_cache(cache, events)
    kwargs = {"memory_limit": "256MB", "threads": 1}
    kwargs.update(duck_kwargs)
    con, spill, owned = _duck_conn(cache, **kwargs)
    try:
        return compute_t3_from_cache(con), spill
    finally:
        con.close()
        if owned:
            shutil.rmtree(spill, ignore_errors=True)


def test_cache_t3_matches_legacy_missingness_and_decisions(tmp_path):
    events = []
    for i in range(18):
        events.append(
            _base_event(
                raw_event_id=f"p{i}",
                object_raw="PROCESS",
                process_raw=f"C:\\p{i}.exe",
                image_path_raw=f"C:\\p{i}.exe",
                parent_process_raw=f"C:\\parent{i}.exe",
                parent_image_path_raw=f"C:\\parent{i}.exe",
                unmapped_property_keys_raw="",
                host_raw="SysClient0201",
            )
        )
    for i in range(7):
        events.append(
            _base_event(
                raw_event_id=f"f{i}",
                object_raw="FILE",
                file_path_raw=f"C:\\tmp\\{i}.txt",
                process_raw="",
                image_path_raw="",
                parent_process_raw="",
                parent_image_path_raw="",
                unmapped_property_keys_raw="",
                host_raw="SysClient0201",
            )
        )
    legacy = {r["field_name"]: r for r in compute_t3(events, ["endpoint"])}
    cache_rows, _ = _cache_t3(events, tmp_path)
    cache = {r["field_name"]: r for r in cache_rows}

    assert set(cache) == set(SLIM_EVENT_COLUMNS)
    assert len(cache) == 77
    for field in SLIM_EVENT_COLUMNS:
        assert cache[field]["total_rows"] == legacy[field]["total_rows"]
        assert cache[field]["applicable_rows"] == legacy[field]["applicable_rows"]
        assert (
            cache[field]["missing_percent_overall"]
            == legacy[field]["missing_percent_overall"]
        )
        assert (
            cache[field]["missing_percent_applicable"]
            == legacy[field]["missing_percent_applicable"]
        )
        assert (
            cache[field]["reliability_decision_keep_review_drop"]
            == legacy[field]["reliability_decision_keep_review_drop"]
        )


def test_cache_t3_exact_empty_and_constant_detection(tmp_path):
    events = [
        _base_event(
            raw_event_id=f"e{i}",
            host_raw="ONLYHOST",
            parse_error="",
            principal_raw="",
            unmapped_property_keys_raw="",
        )
        for i in range(15)
    ]
    rows, _ = _cache_t3(events, tmp_path)
    by_field = {r["field_name"]: r for r in rows}

    pe = by_field["parse_error"]
    assert pe["unique_count"] == 0
    assert pe["unique_count_method"] == "exact_empty"
    assert pe["reliability_decision_keep_review_drop"] == "keep"

    host = by_field["host_raw"]
    assert host["unique_count"] == 1
    assert host["unique_count_method"] == "exact_constant"
    assert host["reliability_decision_keep_review_drop"] == "keep"

    um = by_field["unmapped_property_keys_raw"]
    assert um["unique_count"] == 0
    assert um["unique_count_method"] == "exact_empty"
    assert um["reliability_decision_keep_review_drop"] == "keep"


def test_cache_t3_nonempty_unmapped_remains_review(tmp_path):
    events = [
        _base_event(
            raw_event_id=f"e{i}",
            unmapped_property_keys_raw="mystery_flag" if i % 2 == 0 else "other_key",
        )
        for i in range(12)
    ]
    legacy = next(
        r for r in compute_t3(events, ["endpoint"])
        if r["field_name"] == "unmapped_property_keys_raw"
    )
    cache_rows, _ = _cache_t3(events, tmp_path)
    um = next(r for r in cache_rows if r["field_name"] == "unmapped_property_keys_raw")
    assert um["unique_count"] >= 1
    assert um["unique_count_method"] in ("exact_constant", "approx_count_distinct")
    assert um["reliability_decision_keep_review_drop"] == "review"
    assert legacy["reliability_decision_keep_review_drop"] == "review"


def test_cache_t3_high_cardinality_skips_exact_distinct_and_full_groupby(tmp_path):
    from eda_02_schema_quality_audit import (  # type: ignore
        _build_t3_primary_aggregate_sql,
        _duck_conn,
        compute_t3_from_cache,
    )

    events = [
        _base_event(raw_event_id=f"id-{i}-{i*i}", host_raw="h1")
        for i in range(40)
    ]
    cache = tmp_path / "hc_cache"
    _write_slim_cache(cache, events)

    sql = _build_t3_primary_aggregate_sql(set(SLIM_EVENT_COLUMNS))
    sql_l = sql.lower()
    # No exact COUNT(DISTINCT ...) — only approx_count_distinct.
    assert "approx_count_distinct" in sql_l
    assert "count(distinct" not in sql_l.replace("approx_count_distinct", "")
    # No full-domain GROUP BY on raw_event_id.
    assert 'group by cast("raw_event_id"' not in sql_l
    assert "group by raw_event_id" not in sql_l
    assert 'group by cast("source_type"' in sql_l
    # High-card field must not request approx_top_k.
    assert 'approx_top_k(case when ("raw_event_id"' not in sql_l

    spill = tmp_path / "spill"
    con, used_spill, owned = _duck_conn(
        cache, memory_limit="128MB", threads=1, temp_dir=str(spill)
    )
    try:
        rows = compute_t3_from_cache(con)
    finally:
        con.close()
        assert owned is False

    reid = next(r for r in rows if r["field_name"] == "raw_event_id")
    assert reid["unique_count_method"] == "approx_count_distinct"
    assert reid["top_3_values_method"] == "skipped_high_cardinality"
    assert reid["top_3_values"] == ""
    assert reid["example_value"] != ""
    assert pathlib.Path(used_spill).exists()
    assert used_spill == str(spill)

def test_cache_t3_approx_and_categorical_labels(tmp_path):
    events = [
        _base_event(
            raw_event_id=f"e{i}",
            action_raw="CREATE" if i % 2 == 0 else "DELETE",
            object_raw="PROCESS" if i % 3 else "FILE",
            host_raw="h1" if i < 10 else "h2",
        )
        for i in range(20)
    ]
    rows, _ = _cache_t3(events, tmp_path)
    by_field = {r["field_name"]: r for r in rows}
    assert by_field["action_raw"]["unique_count_method"] == "approx_count_distinct"
    assert by_field["action_raw"]["top_3_values_method"] == "approx_top_k"
    assert by_field["action_raw"]["top_3_values"]
    assert by_field["raw_event_id"]["top_3_values_method"] == "skipped_high_cardinality"


def test_cache_duckdb_memory_thread_temp_applied(tmp_path, monkeypatch):
    from eda_02_schema_quality_audit import _configure_duckdb  # type: ignore
    import duckdb

    settings = []
    con = duckdb.connect()

    class Spy:
        def execute(self, query, *a, **k):
            settings.append(str(query))
            return con.execute(query, *a, **k)

    spill = tmp_path / "duck_spill"
    spill.mkdir()
    _configure_duckdb(
        Spy(),
        memory_limit="64MB",
        temp_dir=str(spill),
        threads=1,
    )
    joined = "\n".join(settings)
    assert "memory_limit='64MB'" in joined
    assert "temp_directory='" + str(spill) + "'" in joined or str(spill) in joined
    assert "threads=1" in joined.replace(" ", "")
    assert "preserve_insertion_order=false" in joined.replace(" ", "")
    con.close()

    # End-to-end: _duck_conn creates spill dir and opens the view.
    from eda_02_schema_quality_audit import _duck_conn  # type: ignore
    import shutil

    events = [_base_event(raw_event_id="e1")]
    cache = tmp_path / "cfg_cache"
    _write_slim_cache(cache, events)
    spill2 = tmp_path / "duck_spill2"
    dcon, used, owned = _duck_conn(
        cache, memory_limit="64MB", temp_dir=str(spill2), threads=1
    )
    n = dcon.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    dcon.close()
    assert n == 1
    assert used == str(spill2)
    assert spill2.is_dir()
    assert owned is False
    # explicit dir must remain
    assert spill2.exists()
    shutil.rmtree(spill2, ignore_errors=True)

def test_cache_t3_low_memory_high_cardinality_synthetic(tmp_path):
    """Moderately large high-card cache under a tight DuckDB memory limit."""
    n = 2500
    events = [
        _base_event(
            raw_event_id=f"evt-{i:05d}-{i * 17}",
            file_id=str(i + 1),
            line_number=str(i + 1),
            host_raw="hA" if i % 2 == 0 else "hB",
            action_raw="CREATE" if i % 5 else "TERMINATE",
            object_raw="PROCESS" if i % 3 else "FLOW",
            unmapped_property_keys_raw="" if i % 11 else f"drift_{i % 7}",
        )
        for i in range(n)
    ]
    # Split across two chunks to resemble multi-file caches.
    import pandas as pd

    cache = tmp_path / "big_cache"
    cache.mkdir()
    mid = n // 2
    for idx, part in enumerate((events[:mid], events[mid:])):
        df = pd.DataFrame(part)
        for c in SLIM_EVENT_COLUMNS:
            if c not in df.columns:
                df[c] = ""
        df[list(SLIM_EVENT_COLUMNS)].to_parquet(
            cache / f"chunk_{idx:05d}_date_20190916.parquet", index=False
        )

    from eda_02_schema_quality_audit import (  # type: ignore
        _duck_conn,
        compute_t3_from_cache,
    )

    con, _, owned = _duck_conn(
        cache,
        memory_limit="64MB",
        temp_dir=str(tmp_path / "spill_big"),
        threads=1,
    )
    try:
        rows = compute_t3_from_cache(con)
    finally:
        con.close()
        assert owned is False

    by_field = {r["field_name"]: r for r in rows}
    assert len(by_field) == 77
    assert by_field["raw_event_id"]["total_rows"] == n
    assert by_field["raw_event_id"]["unique_count_method"] == "approx_count_distinct"
    assert by_field["raw_event_id"]["top_3_values_method"] == "skipped_high_cardinality"
    assert by_field["unmapped_property_keys_raw"]["reliability_decision_keep_review_drop"] == "review"
    assert set(T3_COLUMNS).issubset(by_field["raw_event_id"].keys())


def test_legacy_mode_still_uses_in_memory_compute_t3_only():
    """Legacy sampled path remains the in-memory compute_t3 implementation."""
    events = [_base_event(raw_event_id=f"e{i}") for i in range(12)]
    rows = compute_t3(events, ["endpoint"])
    assert {r["field_name"] for r in rows} == set(SLIM_EVENT_COLUMNS)
    assert all(r["top_3_values_method"] == "exact_bounded_candidates" for r in rows)
    assert all(
        r["unique_count_method"] in (
            "exact_empty", "exact_constant", "exact_count_distinct"
        )
        for r in rows
    )


def test_approx_reason_wording_honest_for_keep_discovery_unmapped():
    from eda_02_schema_quality_audit import _decide_reliability  # type: ignore

    # Ordinary keep reason with approx uniqueness.
    _, keep_reason = _decide_reliability(
        "action_raw",
        role="core",
        total_rows=100,
        applicable_rows=100,
        missing_pct_overall=5.0,
        missing_pct_applicable=5.0,
        unique_count=12,
        n_hosts=3,
        unique_count_method="approx_count_distinct",
    )
    assert "approximately 12 unique values" in keep_reason
    assert "12 unique values" not in keep_reason.replace("approximately 12 unique values", "")

    # Legacy/exact keep wording preserved.
    _, exact_keep = _decide_reliability(
        "action_raw",
        role="core",
        total_rows=100,
        applicable_rows=100,
        missing_pct_overall=5.0,
        missing_pct_applicable=5.0,
        unique_count=12,
        n_hosts=3,
        unique_count_method="exact_count_distinct",
    )
    assert "12 unique values" in exact_keep
    assert "approximately" not in exact_keep

    # Discovery field (properties_keys_raw).
    _, disc_approx = _decide_reliability(
        "properties_keys_raw",
        role="discovery",
        total_rows=50,
        applicable_rows=50,
        missing_pct_overall=10.0,
        missing_pct_applicable=10.0,
        unique_count=7,
        n_hosts=2,
        unique_count_method="approx_count_distinct",
    )
    assert "approximately 7 unique non-empty value(s)" in disc_approx

    _, disc_exact = _decide_reliability(
        "properties_keys_raw",
        role="discovery",
        total_rows=50,
        applicable_rows=50,
        missing_pct_overall=10.0,
        missing_pct_applicable=10.0,
        unique_count=7,
        n_hosts=2,
        unique_count_method="exact_count_distinct",
    )
    assert "(7 unique non-empty value(s)" in disc_exact
    assert "approximately" not in disc_exact

    # Nonempty unmapped_property_keys_raw review reason.
    _, um_approx = _decide_reliability(
        "unmapped_property_keys_raw",
        role="discovery",
        total_rows=50,
        applicable_rows=50,
        missing_pct_overall=40.0,
        missing_pct_applicable=40.0,
        unique_count=4,
        n_hosts=2,
        unique_count_method="approx_count_distinct",
    )
    assert "approximately 4 distinct non-empty unmapped_property_keys_raw" in um_approx

    _, um_exact = _decide_reliability(
        "unmapped_property_keys_raw",
        role="discovery",
        total_rows=50,
        applicable_rows=50,
        missing_pct_overall=40.0,
        missing_pct_applicable=40.0,
        unique_count=4,
        n_hosts=2,
        unique_count_method="exact_count_distinct",
    )
    assert "(4 distinct non-empty unmapped_property_keys_raw" in um_exact
    assert "approximately" not in um_exact

    # exact_empty / exact_constant wording unchanged (no approx language).
    _, empty_r = _decide_reliability(
        "unmapped_property_keys_raw",
        role="discovery",
        total_rows=50,
        applicable_rows=50,
        missing_pct_overall=100.0,
        missing_pct_applicable=100.0,
        unique_count=0,
        n_hosts=2,
        unique_count_method="exact_empty",
    )
    assert "no unmapped property keys observed" in empty_r
    assert "approximately" not in empty_r


def test_cache_approx_reasons_in_end_to_end_rows(tmp_path):
    events = [
        _base_event(
            raw_event_id=f"e{i}",
            action_raw="CREATE" if i % 2 == 0 else "DELETE",
            properties_keys_raw=f"k{i % 3}",
            unmapped_property_keys_raw=f"drift_{i % 2}",
            host_raw="h1" if i < 8 else "h2",
        )
        for i in range(16)
    ]
    rows, _ = _cache_t3(events, tmp_path)
    by_field = {r["field_name"]: r for r in rows}
    assert by_field["action_raw"]["unique_count_method"] == "approx_count_distinct"
    assert "approximately" in by_field["action_raw"]["reason"]
    assert by_field["properties_keys_raw"]["unique_count_method"] == "approx_count_distinct"
    assert "approximately" in by_field["properties_keys_raw"]["reason"]
    assert by_field["unmapped_property_keys_raw"]["reliability_decision_keep_review_drop"] == "review"
    assert "approximately" in by_field["unmapped_property_keys_raw"]["reason"]


def test_duckdb_threads_and_memory_validation():
    from eda_02_schema_quality_audit import (  # type: ignore
        CacheAuditError,
        _validate_duckdb_memory_limit,
        _validate_duckdb_threads,
        _validate_duckdb_temp_dir,
    )

    assert _validate_duckdb_threads(2) == 2
    with pytest.raises(CacheAuditError, match="must be >= 1"):
        _validate_duckdb_threads(0)
    with pytest.raises(CacheAuditError, match="must be >= 1"):
        _validate_duckdb_threads(-3)

    assert _validate_duckdb_memory_limit("4GB") == "4GB"
    assert _validate_duckdb_memory_limit("512MB") == "512MB"
    with pytest.raises(CacheAuditError, match="Invalid --duckdb-memory-limit"):
        _validate_duckdb_memory_limit("lots")
    with pytest.raises(CacheAuditError, match="Invalid --duckdb-memory-limit"):
        _validate_duckdb_memory_limit("4GB; DROP TABLE")
    with pytest.raises(CacheAuditError, match="disallowed"):
        _validate_duckdb_temp_dir("/tmp/foo;bar")


def test_duckdb_internal_spill_cleaned_on_success_and_setup_failure(tmp_path, monkeypatch):
    from eda_02_schema_quality_audit import _duck_conn  # type: ignore
    import duckdb

    events = [_base_event(raw_event_id="e1")]
    cache = tmp_path / "ok_cache"
    _write_slim_cache(cache, events)

    con, spill, owned = _duck_conn(cache, memory_limit="64MB", threads=1)
    assert owned is True
    spill_path = pathlib.Path(spill)
    assert spill_path.is_dir()
    con.close()
    # Caller owns cleanup of owned spill (as run_eda02_cache_mode finally does).
    import shutil
    shutil.rmtree(spill_path)
    assert not spill_path.exists()

    # Setup failure after mkdtemp must not leak the internal directory.
    bad_cache = tmp_path / "missing_cache"
    bad_cache.mkdir()
    # No parquet files → read_parquet may still succeed on empty glob depending on
    # DuckDB; force failure by monkeypatching execute after connect.
    created = {}
    real_mkdtemp = __import__("tempfile").mkdtemp

    def tracking_mkdtemp(*a, **k):
        path = real_mkdtemp(*a, **k)
        created["path"] = path
        return path

    monkeypatch.setattr("tempfile.mkdtemp", tracking_mkdtemp)
    real_connect = duckdb.connect

    class BoomConn:
        def __init__(self):
            self._real = real_connect()
            self._n = 0

        def execute(self, query, *a, **k):
            q = str(query)
            if "CREATE VIEW" in q or "read_parquet" in q:
                self._real.close()
                raise RuntimeError("forced view failure")
            return self._real.execute(query, *a, **k)

        def close(self):
            try:
                self._real.close()
            except Exception:
                pass

    monkeypatch.setattr(duckdb, "connect", BoomConn)
    with pytest.raises(RuntimeError, match="forced view failure"):
        _duck_conn(cache, memory_limit="64MB", threads=1)
    assert "path" in created
    assert not pathlib.Path(created["path"]).exists()


def test_duckdb_explicit_temp_dir_preserved_after_close(tmp_path):
    from eda_02_schema_quality_audit import _duck_conn  # type: ignore

    events = [_base_event(raw_event_id="e1")]
    cache = tmp_path / "cache_explicit"
    _write_slim_cache(cache, events)
    explicit = tmp_path / "explicit_spill"
    # Pre-create a marker file so we can prove the directory is not wiped.
    explicit.mkdir()
    marker = explicit / "keep_me.txt"
    marker.write_text("preserve", encoding="utf-8")

    con, spill, owned = _duck_conn(
        cache, memory_limit="64MB", threads=1, temp_dir=str(explicit)
    )
    assert owned is False
    assert spill == str(explicit)
    con.close()
    assert explicit.is_dir()
    assert marker.read_text(encoding="utf-8") == "preserve"


def test_t3_metadata_integrity_match_and_mismatch(tmp_path):
    from eda_02_schema_quality_audit import (  # type: ignore
        CacheAuditError,
        assert_t3_matches_cache_metadata,
        _t3_represented_total_rows,
    )

    events = [_base_event(raw_event_id=f"e{i}") for i in range(10)]
    rows, _ = _cache_t3(events, tmp_path / "m1")
    represented = _t3_represented_total_rows(rows)
    assert represented == 10
    assert assert_t3_matches_cache_metadata(
        rows, {"total_events_written": 10}
    ) == 10
    # Metadata absent → no failure.
    assert assert_t3_matches_cache_metadata(rows, {}) == 10
    with pytest.raises(CacheAuditError, match="integrity check failed"):
        assert_t3_matches_cache_metadata(
            rows, {"total_events_written": 180_648_918}
        )


def test_cache_mode_readme_uses_schema_version(tmp_path, monkeypatch):
    """Cache-mode README must label optc_normalized_v3, not schema v2."""
    from eda_02_schema_quality_audit import (  # type: ignore
        SCHEMA_VERSION,
        run_eda02_cache_mode,
    )
    import argparse

    events = [_base_event(raw_event_id=f"e{i}") for i in range(8)]
    cache = tmp_path / "readme_cache"
    _write_slim_cache(cache, events)
    (cache / "cache_metadata.json").write_text(
        json.dumps({
            "total_events_written": 8,
            "chunks_written": 1,
            "schema_version": SCHEMA_VERSION,
        }),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    tables = tmp_path / "tables"
    figs = tmp_path / "figs"
    out.mkdir()
    tables.mkdir()
    figs.mkdir()
    args = argparse.Namespace(
        normalized_cache_dir=str(cache),
        manifest_csv=None,
        archives=None,
        member_name_contains=None,
        duckdb_memory_limit="64MB",
        duckdb_temp_dir=str(tmp_path / "spill_readme"),
        duckdb_threads=1,
    )
    run_eda02_cache_mode(args, tmp_path, out, tables, figs)
    readme = (out / "README_eda02_schema_quality.txt").read_text(encoding="utf-8")
    assert SCHEMA_VERSION == "optc_normalized_v3"
    assert SCHEMA_VERSION in readme
    assert "schema v2" not in readme.lower()
    assert "buffer-manager" in readme
    assert "not an absolute process-RAM ceiling" in readme
