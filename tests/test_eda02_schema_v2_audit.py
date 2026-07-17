"""
Focused tests for EDA 2 schema-v2 field reliability audit.
"""

from __future__ import annotations

import pathlib
import sys

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
