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
