"""
Focused tests for OpTC normalized cache schema v2 (optc_normalized_v2).

Run:
    python3 tests/test_schema_v2_normalize.py
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src" / "eda"))
from optc_streaming_parser import (  # type: ignore
    SCHEMA_VERSION,
    SLIM_EVENT_COLUMNS,
    normalize_event,
)


def _norm(raw: dict, include_raw_json: bool = False) -> dict:
    return normalize_event(
        raw,
        archive_name="2019-09-16.tar",
        member_name="ecar/host.ecar.json.gz",
        line_num=1,
        event_counter=1,
        source_type="endpoint",
        include_raw_json=include_raw_json,
    )


def test_schema_version_constant():
    assert SCHEMA_VERSION == "optc_normalized_v2"


def test_slim_columns_include_v2_fields():
    required = [
        "actor_id_raw", "object_id_raw", "pid_raw", "ppid_raw", "tid_raw",
        "principal_raw", "image_path_raw", "parent_image_path_raw",
        "command_line_raw", "dest_ip_raw", "object_value_raw",
        "property_name_raw", "service_name_raw",
        "properties_keys_raw", "unmapped_property_keys_raw",
        "file_id", "archive_name", "member_name", "line_number", "raw_event_id",
    ]
    for col in required:
        assert col in SLIM_EVENT_COLUMNS, f"missing {col}"


def test_slim_columns_no_duplicates():
    assert len(SLIM_EVENT_COLUMNS) == len(set(SLIM_EVENT_COLUMNS))


def test_successful_event_has_all_slim_keys():
    raw = {
        "action": "CREATE", "hostname": "h1", "id": "e1", "object": "PROCESS",
        "objectID": "oid", "pid": 1, "ppid": 0, "principal": "p", "tid": 1,
        "timestamp": "2019-09-16T00:00:00Z",
        "properties": {"image_path": "C:\\a.exe"},
    }
    e = _norm(raw)
    for col in SLIM_EVENT_COLUMNS:
        assert col in e, f"missing key {col}"


def test_flow_event():
    raw = {
        "action": "CREATE",
        "actorID": "actor-1",
        "hostname": "SysClient0201",
        "id": "evt-flow-1",
        "object": "FLOW",
        "objectID": "obj-flow-1",
        "pid": 1001,
        "ppid": 4,
        "principal": "NT AUTHORITY\\SYSTEM",
        "tid": 2002,
        "timestamp": "2019-09-16T23:40:12.43Z",
        "properties": {
            "image_path": "C:\\Windows\\System32\\svchost.exe",
            "src_ip": "10.0.0.1",
            "src_port": 49152,
            "dest_ip": "8.8.8.8",
            "dest_port": 443,
            "l4protocol": 6,
            "direction": "OUTBOUND",
            "mystery_flow_flag": "yes",
        },
    }
    e = _norm(raw)
    assert e["raw_event_id"] == "evt-flow-1"
    assert e["actor_id_raw"] == "actor-1"
    assert e["object_id_raw"] == "obj-flow-1"
    assert e["pid_raw"] == "1001"
    assert e["ppid_raw"] == "4"
    assert e["tid_raw"] == "2002"
    assert e["image_path_raw"] == "C:\\Windows\\System32\\svchost.exe"
    assert e["process_raw"] == "C:\\Windows\\System32\\svchost.exe"
    assert e["src_ip_raw"] == "10.0.0.1"
    assert e["dest_ip_raw"] == "8.8.8.8"
    assert e["dest_port_raw"] == "443"
    assert e["destination_raw"] == "8.8.8.8"
    assert e["protocol_raw"] == "6"
    assert e["object_value_raw"] == "8.8.8.8:443"
    assert "mystery_flow_flag" in e["unmapped_property_keys_raw"].split(",")
    assert "dest_ip" in e["properties_keys_raw"].split(",")
    assert e["raw_json"] == ""
    assert e["archive_name"] == "2019-09-16.tar"
    assert e["member_name"] == "ecar/host.ecar.json.gz"
    assert e["line_number"] == 1


def test_process_event():
    raw = {
        "action": "CREATE",
        "actorID": "A",
        "hostname": "h1",
        "id": "p1",
        "object": "PROCESS",
        "objectID": "OID",
        "pid": 55,
        "ppid": 1,
        "principal": "DOMAIN\\user",
        "tid": 9,
        "timestamp": 1568592000000,
        "properties": {
            "image_path": "C:\\Windows\\notepad.exe",
            "parent_image_path": "C:\\Windows\\explorer.exe",
            "command_line": "notepad.exe file.txt",
        },
    }
    e = _norm(raw)
    assert e["command_line_raw"] == "notepad.exe file.txt"
    assert e["image_path_raw"] == "C:\\Windows\\notepad.exe"
    assert e["parent_image_path_raw"] == "C:\\Windows\\explorer.exe"
    assert e["process_raw"] == "C:\\Windows\\notepad.exe"
    assert e["parent_process_raw"] == "C:\\Windows\\explorer.exe"
    assert e["object_value_raw"] == "notepad.exe file.txt"
    assert e["actor_id_raw"] == "A"
    assert e["object_id_raw"] == "OID"


def test_file_event():
    raw = {
        "action": "WRITE", "hostname": "h1", "id": "f1", "object": "FILE",
        "objectID": "fid", "pid": 1, "ppid": 0, "principal": "", "tid": 1,
        "timestamp": "2019-09-16T00:00:00Z",
        "properties": {
            "file_path": "C:\\tmp\\a.txt",
            "image_path": "C:\\Windows\\cmd.exe",
        },
    }
    e = _norm(raw)
    assert e["file_path_raw"] == "C:\\tmp\\a.txt"
    assert e["image_path_raw"] == "C:\\Windows\\cmd.exe"
    assert e["process_raw"] == "C:\\Windows\\cmd.exe"
    assert e["object_value_raw"] == "C:\\tmp\\a.txt"


def test_module_event():
    raw = {
        "action": "LOAD", "hostname": "h1", "id": "m1", "object": "MODULE",
        "objectID": "mid", "pid": 1, "ppid": 0, "principal": "p", "tid": 1,
        "timestamp": "2019-09-16T00:00:00Z",
        "properties": {
            "module_path": "C:\\Windows\\System32\\ntdll.dll",
            "image_path": "C:\\Windows\\System32\\svchost.exe",
        },
    }
    e = _norm(raw)
    assert e["module_path_raw"] == "C:\\Windows\\System32\\ntdll.dll"
    assert e["object_value_raw"] == "C:\\Windows\\System32\\ntdll.dll"
    assert e["process_raw"] == "C:\\Windows\\System32\\svchost.exe"


def test_registry_event():
    raw = {
        "action": "SET", "hostname": "h1", "id": "r1", "object": "REGISTRY",
        "objectID": "rid", "pid": 1, "ppid": 0, "principal": "p", "tid": 1,
        "timestamp": "2019-09-16T00:00:00Z",
        "properties": {
            "key": "HKLM\\Software\\Foo",
            "value": "Bar",
            "data": "1",
            "type": "REG_SZ",
            "image_path": "C:\\Windows\\regedit.exe",
        },
    }
    e = _norm(raw)
    assert e["registry_key_raw"] == "HKLM\\Software\\Foo"
    assert e["registry_value_raw"] == "Bar"
    assert e["registry_data_raw"] == "1"
    assert e["registry_type_raw"] == "REG_SZ"
    assert e["object_value_raw"] == "HKLM\\Software\\Foo"
    assert e["image_path_raw"] == "C:\\Windows\\regedit.exe"


def test_user_session_fallback():
    raw = {
        "action": "LOGIN", "hostname": "h1", "id": "u1", "object": "USER_SESSION",
        "objectID": "uid", "pid": 1, "ppid": 0, "principal": "", "tid": 1,
        "timestamp": "2019-09-16T00:00:00Z",
        "properties": {
            "user": "DOMAIN\\alice",
            "logon_id": "0x3e7",
        },
    }
    e = _norm(raw)
    assert e["principal_raw"] == ""
    assert e["property_user_raw"] == "DOMAIN\\alice"
    assert e["user_raw"] == "DOMAIN\\alice"  # not actorID
    assert e["actor_id_raw"] == ""
    assert e["object_value_raw"] == "DOMAIN\\alice"
    assert e["logon_id_raw"] == "0x3e7"

    # When principal present, prefer it over properties.user
    raw2 = dict(raw)
    raw2["principal"] = "PRINCIPAL\\bob"
    e2 = _norm(raw2)
    assert e2["user_raw"] == "PRINCIPAL\\bob"


def test_shell_event():
    raw = {
        "action": "EXECUTE", "hostname": "h1", "id": "s1", "object": "SHELL",
        "objectID": "sid", "pid": 1, "ppid": 0, "principal": "p", "tid": 1,
        "timestamp": "2019-09-16T00:00:00Z",
        "properties": {
            "payload": "whoami",
            "context_info": "powershell",
        },
    }
    e = _norm(raw)
    assert e["shell_payload_raw"] == "whoami"
    assert e["shell_context_raw"] == "powershell"
    assert e["object_value_raw"] == "whoami"


def test_missing_properties_dict():
    raw = {
        "action": "CREATE", "hostname": "h1", "id": "x1", "object": "PROCESS",
        "objectID": "oid", "pid": 1, "ppid": 0, "principal": "p", "tid": 1,
        "timestamp": "2019-09-16T00:00:00Z",
    }
    e = _norm(raw)
    assert e["image_path_raw"] == ""
    assert e["process_raw"] == ""
    assert e["properties_keys_raw"] == ""
    assert e["unmapped_property_keys_raw"] == ""
    # PROCESS: command_line -> image_path -> objectID
    assert e["object_value_raw"] == "oid"


def test_non_service_name_does_not_fill_service_name_raw():
    raw = {
        "action": "CREATE", "hostname": "h1", "id": "n1", "object": "PROCESS",
        "objectID": "oid", "pid": 1, "ppid": 0, "principal": "p", "tid": 1,
        "timestamp": "2019-09-16T00:00:00Z",
        "properties": {
            "name": "NotAService",
            "image_path": "C:\\Windows\\notepad.exe",
        },
    }
    e = _norm(raw)
    assert e["property_name_raw"] == "NotAService"
    assert e["service_name_raw"] == ""
    assert "name" not in (
        e["unmapped_property_keys_raw"].split(",") if e["unmapped_property_keys_raw"] else []
    )


def test_service_event_fills_service_name_raw():
    raw = {
        "action": "START", "hostname": "h1", "id": "svc1", "object": "SERVICE",
        "objectID": "sid", "pid": 1, "ppid": 0, "principal": "p", "tid": 1,
        "timestamp": "2019-09-16T00:00:00Z",
        "properties": {
            "name": "Wuauserv",
            "service_type": "WIN32_OWN_PROCESS",
            "start_type": "AUTO",
        },
    }
    e = _norm(raw)
    assert e["property_name_raw"] == "Wuauserv"
    assert e["service_name_raw"] == "Wuauserv"
    assert e["object_value_raw"] == "Wuauserv"


def test_unknown_property_in_unmapped():
    raw = {
        "action": "X", "hostname": "h1", "id": "u", "object": "OTHER",
        "objectID": "o", "pid": 1, "ppid": 0, "principal": "p", "tid": 1,
        "timestamp": "2019-09-16T00:00:00Z",
        "properties": {"brand_new_field": 123, "image_path": "C:\\a.exe"},
    }
    e = _norm(raw)
    unmapped = e["unmapped_property_keys_raw"].split(",")
    assert "brand_new_field" in unmapped
    assert "image_path" not in unmapped
    assert e["object_value_raw"] == "o"


def test_raw_json_excluded_when_disabled():
    raw = {
        "action": "X", "hostname": "h1", "id": "u", "object": "FILE",
        "objectID": "o", "pid": 1, "ppid": 0, "principal": "p", "tid": 1,
        "timestamp": "2019-09-16T00:00:00Z",
        "properties": {"file_path": "C:\\a"},
    }
    e = _norm(raw, include_raw_json=False)
    assert e["raw_json"] == ""
    e2 = _norm(raw, include_raw_json=True)
    assert "file_path" in e2["raw_json"]


def test_evidence_locators_unchanged():
    raw = {
        "action": "X", "hostname": "h1", "id": "my-id", "object": "FILE",
        "objectID": "o", "pid": 1, "ppid": 0, "principal": "p", "tid": 1,
        "timestamp": "2019-09-16T00:00:00Z",
        "properties": {},
    }
    e = normalize_event(
        raw, "arch.tar", "path/member.json.gz", 42, 7, "endpoint", False,
    )
    assert e["file_id"] == 7
    assert e["archive_name"] == "arch.tar"
    assert e["member_name"] == "path/member.json.gz"
    assert e["line_number"] == 42
    assert e["raw_event_id"] == "my-id"


def test_user_raw_never_uses_actor_id():
    raw = {
        "action": "X", "hostname": "h1", "id": "u", "object": "FLOW",
        "actorID": "should-not-be-user",
        "objectID": "o", "pid": 1, "ppid": 0, "principal": "", "tid": 1,
        "timestamp": "2019-09-16T00:00:00Z",
        "properties": {},
    }
    e = _norm(raw)
    assert e["user_raw"] == ""
    assert e["actor_id_raw"] == "should-not-be-user"


if __name__ == "__main__":
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in tests:
        fn()
        print(f"  PASS {fn.__name__}")
    print(f"All {len(tests)} schema-v2 tests passed.")
