"""
Focused tests for OpTC normalized schema v3 property promotions.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src" / "eda"))
from eda_02_schema_quality_audit import (  # type: ignore
    applicable_object_types_for,
    field_role,
)
from optc_streaming_parser import (  # type: ignore
    SCHEMA_VERSION,
    SLIM_EVENT_COLUMNS,
    normalize_event,
)

# Exact property key → column promotions for v3
_V3_PROMOTIONS = {
    "size": "property_size_raw",
    "base_address": "base_address_raw",
    "stack_base": "stack_base_raw",
    "subprocess_tag": "subprocess_tag_raw",
    "stack_limit": "stack_limit_raw",
    "start_address": "start_address_raw",
    "user_stack_base": "user_stack_base_raw",
    "user_stack_limit": "user_stack_limit_raw",
    "end_time": "flow_end_time_raw",
    "start_time": "flow_start_time_raw",
    "new_path": "new_path_raw",
    "sid": "process_sid_raw",
    "tgt_pid_uuid": "thread_tgt_pid_uuid_raw",
    "requesting_logon_id": "requesting_logon_id_raw",
    "requesting_domain": "requesting_domain_raw",
    "requesting_user": "requesting_user_raw",
    "user_name": "task_user_name_raw",
}

_V3_APPLICABILITY = {
    "property_size_raw": ["FILE", "FLOW"],
    "base_address_raw": ["MODULE"],
    "stack_base_raw": ["THREAD"],
    "subprocess_tag_raw": ["THREAD"],
    "stack_limit_raw": ["THREAD"],
    "start_address_raw": ["THREAD"],
    "user_stack_base_raw": ["THREAD"],
    "user_stack_limit_raw": ["THREAD"],
    "flow_start_time_raw": ["FLOW"],
    "flow_end_time_raw": ["FLOW"],
    "new_path_raw": ["FILE"],
    "process_sid_raw": ["PROCESS"],
    "thread_tgt_pid_uuid_raw": ["THREAD"],
    "requesting_logon_id_raw": ["USER_SESSION"],
    "requesting_domain_raw": ["USER_SESSION"],
    "requesting_user_raw": ["USER_SESSION"],
    "task_user_name_raw": ["TASK"],
}


def _norm(raw: dict) -> dict:
    return normalize_event(
        raw,
        archive_name="2019-09-16.tar",
        member_name="ecar/host.ecar.json.gz",
        line_num=1,
        event_counter=1,
        source_type="endpoint",
        include_raw_json=False,
    )


def test_schema_version_is_v3():
    assert SCHEMA_VERSION == "optc_normalized_v3"


def test_slim_columns_exactly_77_unique():
    assert len(SLIM_EVENT_COLUMNS) == 77
    assert len(SLIM_EVENT_COLUMNS) == len(set(SLIM_EVENT_COLUMNS))
    for col in _V3_PROMOTIONS.values():
        assert col in SLIM_EVENT_COLUMNS


def test_all_17_properties_map_and_preserve_exact_strings():
    # Distinct sentinel values (including leading/trailing spaces after strip
    # behavior of the existing _as_str path — values themselves are exact).
    props = {
        "size": "4096",
        "base_address": "0x7FFE0000",
        "stack_base": "0x00000000AABB0000",
        "subprocess_tag": "tag-42",
        "stack_limit": "0x00000000AAAF0000",
        "start_address": "0x140001000",
        "user_stack_base": "0x000000F1USERBASE",
        "user_stack_limit": "0x000000F1USERLIM",
        "end_time": "1568678500.5",
        "start_time": "1568678400",
        "new_path": "C:\\Windows\\Temp\\renamed.bin",
        "sid": "S-1-5-18",
        "tgt_pid_uuid": "uuid-tgt-pid-9",
        "requesting_logon_id": "0x3E7",
        "requesting_domain": "NT AUTHORITY",
        "requesting_user": "SYSTEM",
        "user_name": "DOMAIN\\taskuser",
        "mystery_unknown_flag": "keep-me-unmapped",
    }
    raw = {
        "action": "CREATE",
        "hostname": "SysClient0201",
        "id": "evt-v3-1",
        "object": "THREAD",
        "objectID": "oid-1",
        "pid": 10,
        "ppid": 4,
        "principal": "NT AUTHORITY\\SYSTEM",
        "tid": 20,
        "timestamp": "2019-09-16T00:00:00Z",
        "properties": props,
    }
    e = _norm(raw)

    assert len(_V3_PROMOTIONS) == 17
    for prop_key, col in _V3_PROMOTIONS.items():
        assert e[col] == props[prop_key], f"{col} mismatch"

    # Promoted keys must not appear in unmapped list
    unmapped = set(filter(None, e["unmapped_property_keys_raw"].split(",")))
    for prop_key in _V3_PROMOTIONS:
        assert prop_key not in unmapped

    # Genuinely unknown keys remain unmapped; keys list still preserved
    assert "mystery_unknown_flag" in unmapped
    assert "mystery_unknown_flag" in e["properties_keys_raw"].split(",")
    for prop_key in _V3_PROMOTIONS:
        assert prop_key in e["properties_keys_raw"].split(",")

    # Evidence locators + no raw_json in slim path
    assert e["archive_name"] == "2019-09-16.tar"
    assert e["member_name"] == "ecar/host.ecar.json.gz"
    assert e["line_number"] == 1
    assert e["raw_event_id"] == "evt-v3-1"
    assert e.get("raw_json", "") == ""


def test_eda2_applicability_for_v3_columns():
    assert len(_V3_APPLICABILITY) == 17
    for col, types in _V3_APPLICABILITY.items():
        assert field_role(col) == "object_specific"
        assert applicable_object_types_for(col) == types
