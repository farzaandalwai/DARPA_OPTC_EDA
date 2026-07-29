"""Synthetic, repository-local tests for scale-safe EDA 8."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import pathlib
import re
import shutil
import sys
import warnings

import pandas as pd
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src" / "eda"))

import eda_04_event_taxonomy as eda4  # type: ignore
import eda_05_entity_dictionary as eda5  # type: ignore
import eda_08_endpoint_network_pivot as eda8  # type: ignore
from optc_streaming_parser import SCHEMA_VERSION, SLIM_EVENT_COLUMNS  # type: ignore


def _base_row(index: int, *, timestamp: str, archive_date: str, host: str = "h1") -> dict:
    row = {column: "" for column in SLIM_EVENT_COLUMNS}
    row.update(
        {
            "timestamp_parsed": timestamp,
            "timestamp_raw": timestamp,
            "parse_status": "ok",
            "host_raw": host,
            "user_raw": "alice",
            "principal_raw": "alice",
            "archive_name": f"{archive_date}.tar",
            "member_name": f"{host}.json.gz",
            "line_number": index + 1,
            "raw_event_id": f"e{index:03d}",
        }
    )
    return row


def _process_event(
    index: int,
    *,
    timestamp: str,
    archive_date: str,
    host: str = "h1",
    image: str = "C:\\Windows\\System32\\svc.exe",
    pid: str = "1000",
) -> dict:
    row = _base_row(index, timestamp=timestamp, archive_date=archive_date, host=host)
    row.update(
        {
            "object_raw": "PROCESS",
            "action_raw": "CREATE",
            "image_path_raw": image,
            "process_raw": image,
            "pid_raw": pid,
            "actor_id_raw": f"actor-{index}",
            "object_id_raw": f"object-{index}",
        }
    )
    return row


def _flow_event(
    index: int,
    *,
    timestamp: str,
    archive_date: str,
    host: str = "h1",
    dest: str = "10.0.0.5",
    port: str = "443",
    protocol: str = "TCP",
    process: str = "",
    pid: str = "",
) -> dict:
    row = _base_row(index, timestamp=timestamp, archive_date=archive_date, host=host)
    row.update(
        {
            "object_raw": "FLOW",
            "action_raw": "OPEN",
            "dest_ip_raw": dest,
            "destination_raw": dest,
            "dest_port_raw": port,
            "protocol_raw": protocol,
            "image_path_raw": process,
            "process_raw": process,
            "pid_raw": pid,
            "actor_id_raw": f"actor-{index}",
            "object_id_raw": f"object-{index}",
        }
    )
    return row


def _base_events() -> list[dict]:
    return [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            image="C:\\Windows\\System32\\browser.exe",
            pid="2000",
        ),
        _flow_event(
            1,
            timestamp="2020-01-01T00:00:05",
            archive_date="2020-01-01",
            dest="10.0.0.10",
            port="443",
            process="C:\\Windows\\System32\\browser.exe",
        ),
        _process_event(
            2,
            timestamp="2020-01-02T00:00:00",
            archive_date="2020-01-02",
            image="C:\\Windows\\System32\\browser.exe",
            pid="2000",
        ),
        _flow_event(
            3,
            timestamp="2020-01-02T00:00:05",
            archive_date="2020-01-02",
            dest="10.0.0.10",
            port="443",
            process="C:\\Windows\\System32\\browser.exe",
        ),
        _process_event(
            4,
            timestamp="2020-01-03T00:00:00",
            archive_date="2020-01-03",
            image="C:\\Users\\alice\\new.exe",
            pid="3000",
        ),
        _flow_event(
            5,
            timestamp="2020-01-03T00:00:10",
            archive_date="2020-01-03",
            dest="203.0.113.50",
            port="8080",
            pid="3000",
        ),
        _flow_event(
            6,
            timestamp="2020-01-03T00:00:20",
            archive_date="2020-01-03",
            dest="127.0.0.1",
            port="53",
            process="C:\\Users\\alice\\new.exe",
        ),
    ]


def _write_period_map(root: pathlib.Path) -> pathlib.Path:
    path = root / "periods.csv"
    pd.DataFrame(
        [
            {
                "period": "baseline",
                "start_time": "2020-01-01T00:00:00Z",
                "end_time": "2020-01-03T00:00:00Z",
                "period_role": "verified_benign",
            },
            {
                "period": "evaluation",
                "start_time": "2020-01-03T00:00:00Z",
                "end_time": "2020-01-04T00:00:00Z",
                "period_role": "evaluation",
            },
        ],
        columns=eda4.PERIOD_MAP_COLUMNS,
    ).to_csv(path, index=False)
    return path


def _write_cache(root: pathlib.Path, rows: list[dict]) -> pathlib.Path:
    cache = root / "cache"
    cache.mkdir(parents=True)
    pd.DataFrame(rows, columns=SLIM_EVENT_COLUMNS).to_parquet(
        cache / "chunk_00000.parquet", index=False
    )
    (cache / "cache_metadata.json").write_text(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "total_events_written": len(rows),
                "sampling_strategy": "full",
            }
        ),
        encoding="utf-8",
    )
    return cache


def _write_manifest(root: pathlib.Path) -> pathlib.Path:
    path = root / "manifest.csv"
    pd.DataFrame({"manifest_version": ["synthetic_eda08_v1"]}).to_csv(
        path, index=False
    )
    return path


def _t9_row(entity_type: str, raw_value: str, host_scope: str, index: int) -> dict:
    source = {
        "host": "host_raw",
        "user_principal": "user_raw",
        "process": "image_path_raw/process_raw_alias",
        "file_path": "file_path_raw",
        "destination": "dest_ip_raw/destination_raw_alias",
    }[entity_type]
    entity = eda5.normalize_entity(
        entity_type=entity_type,
        raw_value=raw_value,
        host_scope=host_scope,
        source_field=source,
    )
    entity.update(
        {
            "first_seen_time": pd.Timestamp("2020-01-01"),
            "last_seen_time": pd.Timestamp("2020-01-04"),
            "source_count": 1,
            "observation_count": 1,
            "raw_event_example_id": f"t9-{index}",
            "archive_name": "2020-01-01.tar",
            "member_name": "synthetic.json.gz",
            "line_number": index + 1,
        }
    )
    return {column: entity[column] for column in eda5.T9_COLUMNS}


def _write_t9(root: pathlib.Path, rows: list[dict]) -> pathlib.Path:
    import pyarrow as pa
    import pyarrow.parquet as pq

    t9 = root / "T9_canonical_entity_dictionary"
    by_type: dict[str, list[dict]] = {name: [] for name in eda5.ENTITY_TYPES}
    index = 0
    seen: set[tuple] = set()

    def add(entity_type: str, raw: str, host: str = "") -> None:
        nonlocal index
        if not str(raw).strip():
            return
        key = (
            entity_type,
            host if entity_type in ("user_principal", "process", "file_path") else "",
            raw,
        )
        if key in seen:
            return
        seen.add(key)
        by_type[entity_type].append(_t9_row(entity_type, raw, key[1], index))
        index += 1

    for event in rows:
        add("host", event["host_raw"])
        add("user_principal", event["user_raw"], event["host_raw"])
        if event["object_raw"] == "PROCESS":
            add("process", event["image_path_raw"], event["host_raw"])
        if event["object_raw"] == "FLOW":
            add("destination", event["dest_ip_raw"])

    for entity_type, values in by_type.items():
        partition = t9 / f"entity_type={entity_type}"
        partition.mkdir(parents=True)
        pq.write_table(
            pa.Table.from_pylist(values, schema=eda5._arrow_schema()),
            partition / "part-00000.parquet",
        )
    return t9


def _fixture(root: pathlib.Path, rows: list[dict] | None = None) -> dict:
    events = list(_base_events() if rows is None else rows)
    return {
        "rows": events,
        "cache": _write_cache(root, events),
        "manifest": _write_manifest(root),
        "period_map": _write_period_map(root),
        "t9": _write_t9(root, events),
    }


def _args(root: pathlib.Path, fixture: dict, **overrides) -> argparse.Namespace:
    values = {
        "project_root": str(pathlib.Path(__file__).resolve().parents[1]),
        "normalized_cache_dir": str(fixture["cache"]),
        "manifest_csv": str(fixture["manifest"]),
        "period_map_csv": str(fixture["period_map"]),
        "entity_dictionary_path": str(fixture["t9"]),
        "output_dir": str(root / "eda08_out"),
        "window_size": "1min",
        "evidence_cap": 20,
        "duckdb_memory_limit": "1GB",
        "duckdb_temp_dir": None,
        "duckdb_threads": 2,
        "cascade_probe_only": False,
        "t17_probe_only": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


@pytest.fixture
def completed_run(tmp_path):
    fixture = _fixture(tmp_path)
    args = _args(tmp_path, fixture)
    cache_file = next(fixture["cache"].glob("*.parquet"))
    before = hashlib.sha256(cache_file.read_bytes()).hexdigest()
    metadata = eda8.run_eda08(args)
    after = hashlib.sha256(cache_file.read_bytes()).hexdigest()
    assert before == after
    return fixture, args, metadata, pathlib.Path(args.output_dir)


def test_exact_t16_t17_schemas_and_nine_deliverables(completed_run):
    _, _, _, output = completed_run
    expected = {
        "T16_endpoint_network_pivot_success.csv",
        "T17_process_to_destination_behavior.csv",
        "F9_destination_novelty_over_time.png",
        "F9_destination_novelty_over_time.pdf",
        "F10_process_to_network_lag.png",
        "F10_process_to_network_lag.pdf",
        "README.md",
        "eda08_run_metadata.json",
        "eda08_execution.log",
    }
    assert {path.name for path in output.iterdir()} == expected
    assert list(
        pd.read_csv(output / "T16_endpoint_network_pivot_success.csv").columns
    ) == eda8.T16_COLUMNS
    assert list(
        pd.read_csv(output / "T17_process_to_destination_behavior.csv").columns
    ) == eda8.T17_COLUMNS


def test_half_open_period_assignment(tmp_path):
    rows = [
        _flow_event(
            0,
            timestamp="2020-01-03T00:00:00",
            archive_date="2020-01-03",
            dest="198.51.100.1",
            process="C:\\Eval\\p.exe",
        ),
        _flow_event(
            1,
            timestamp="2020-01-01T23:59:59",
            archive_date="2020-01-01",
            dest="10.0.0.20",
            process="C:\\Benign\\p.exe",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    eda8.run_eda08(args)
    t17 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T17_process_to_destination_behavior.csv"
    )
    assert set(t17["period"]) == {"verified_benign", "evaluation"}
    assert t17.loc[t17["destination_value"] == "10.0.0.20", "period"].iloc[0] == (
        "verified_benign"
    )
    assert t17.loc[t17["destination_value"] == "198.51.100.1", "period"].iloc[0] == (
        "evaluation"
    )


def test_benign_only_vocabulary_fitting_and_evaluation_not_updating_baseline(
    completed_run,
):
    _, _, _, output = completed_run
    t17 = pd.read_csv(output / "T17_process_to_destination_behavior.csv")
    benign = t17.loc[t17["period"] == "verified_benign"]
    evaluation = t17.loc[t17["period"] == "evaluation"]
    assert not benign.empty
    assert not evaluation.empty
    assert (benign["benign_seen_before_yes_no"] == "yes").all()
    assert (evaluation["benign_seen_before_yes_no"] == "no").any()
    novel_eval = evaluation.loc[
        evaluation["destination_value"].isin(["203.0.113.50", "127.0.0.1"])
    ]
    assert not novel_eval.empty
    assert (novel_eval["benign_seen_before_yes_no"] == "no").all()


def test_direct_pivot_success(tmp_path):
    rows = [
        _flow_event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            dest="10.0.0.1",
            process="C:\\Windows\\System32\\direct.exe",
        )
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    eda8.run_eda08(args)
    t16 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T16_endpoint_network_pivot_success.csv"
    )
    direct = t16.loc[
        (t16["pivot_rule"] == "direct_same_event")
        & (t16["date_label"] == "2020-01-01")
    ].iloc[0]
    assert int(direct["matched_network_events"]) == 1
    t17 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T17_process_to_destination_behavior.csv"
    )
    assert "direct.exe" in t17.iloc[0]["process_name"]


def test_unique_temporal_pivot_success(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            image="C:\\Windows\\temporal.exe",
            pid="4000",
        ),
        _flow_event(
            1,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            dest="10.0.0.2",
            pid="",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    eda8.run_eda08(args)
    t16 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T16_endpoint_network_pivot_success.csv"
    )
    strict = t16.loc[
        (t16["pivot_rule"] == "host_temporal_strict")
        & (t16["date_label"] == "2020-01-01")
    ].iloc[0]
    assert int(strict["matched_network_events"]) == 1
    t17 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T17_process_to_destination_behavior.csv"
    )
    assert "temporal.exe" in t17.iloc[0]["process_name"]


def test_ambiguous_temporal_pivot_rejection(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            image="C:\\Windows\\a.exe",
            pid="5001",
        ),
        _process_event(
            1,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            image="C:\\Windows\\b.exe",
            pid="5002",
        ),
        _flow_event(
            2,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            dest="10.0.0.3",
            pid="",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    eda8.run_eda08(args)
    t16 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T16_endpoint_network_pivot_success.csv"
    )
    strict = t16.loc[
        (t16["pivot_rule"] == "host_temporal_strict")
        & (t16["date_label"] == "2020-01-01")
    ].iloc[0]
    assert int(strict["ambiguous_match_count"]) == 1
    assert int(strict["matched_network_events"]) == 0
    t17 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T17_process_to_destination_behavior.csv"
    )
    assert t17.empty


def test_unmatched_row_accounting(tmp_path):
    rows = [
        _flow_event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            dest="10.0.0.9",
            pid="",
        )
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    eda8.run_eda08(args)
    t16 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T16_endpoint_network_pivot_success.csv"
    )
    for rule_id in (
        "direct_same_event",
        "host_process_pid",
        "host_temporal_strict",
        "host_temporal_relaxed",
    ):
        row = t16.loc[
            (t16["pivot_rule"] == rule_id) & (t16["date_label"] == "2020-01-01")
        ].iloc[0]
        assert int(row["endpoint_flow_events"]) == 1
        assert int(row["matched_network_events"]) == 0
        assert int(row["unmatched_count"]) == 1
    unmatched = t16.loc[
        (t16["pivot_rule"] == "unmatched") & (t16["date_label"] == "2020-01-01")
    ].iloc[0]
    assert int(unmatched["endpoint_flow_events"]) == 1
    assert int(unmatched["matched_network_events"]) == 0
    assert int(unmatched["ambiguous_match_count"]) == 0
    assert int(unmatched["unmatched_count"]) == 1
    t17 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T17_process_to_destination_behavior.csv"
    )
    assert t17.empty


@pytest.mark.parametrize(
    ("dest", "expected"),
    [
        ("127.0.0.1", "loopback"),
        ("10.0.0.5", "internal-looking"),
        ("203.0.113.50", "external-looking"),
        ("224.0.0.5", "multicast_or_broadcast"),
        ("", "missing"),
        ("not-an-ip", "invalid_or_unresolved"),
    ],
)
def test_destination_structural_categorization(dest, expected):
    assert eda8.destination_structural_category(dest) == expected


def test_t16_grouped_by_date_label_and_host_id(completed_run):
    _, _, _, output = completed_run
    t16 = pd.read_csv(output / "T16_endpoint_network_pivot_success.csv")
    assert {"date_label", "host_id", "pivot_rule"}.issubset(t16.columns)
    assert t16["date_label"].notna().all()
    assert t16["host_id"].notna().all()
    assert len(t16) >= len(eda8.PIVOT_RULE_IDS)


def test_missing_host_flow_rows_remain_in_t16_denominator(tmp_path):
    row = _flow_event(
        0,
        timestamp="2020-01-01T00:00:00",
        archive_date="2020-01-01",
        dest="10.0.0.1",
        process="C:\\Windows\\orphan.exe",
    )
    row["host_raw"] = ""
    fixture = _fixture(tmp_path, [row])
    args = _args(tmp_path, fixture)
    eda8.run_eda08(args)
    t16 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T16_endpoint_network_pivot_success.csv"
    )
    host_rows = t16.loc[t16["host_id"] == eda8.MISSING_HOST_SENTINEL]
    assert not host_rows.empty
    assert int(host_rows.iloc[0]["endpoint_flow_events"]) >= 1


def test_missing_destination_flow_rows_remain_in_t16_denominator(tmp_path):
    row = _flow_event(
        0,
        timestamp="2020-01-01T00:00:00",
        archive_date="2020-01-01",
        dest="",
        process="C:\\Windows\\nodest.exe",
    )
    fixture = _fixture(tmp_path, [row])
    args = _args(tmp_path, fixture)
    eda8.run_eda08(args)
    t16 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T16_endpoint_network_pivot_success.csv"
    )
    assert int(t16.iloc[0]["endpoint_flow_events"]) == 1
    unmatched = t16.loc[t16["pivot_rule"] == "unmatched"].iloc[0]
    assert int(unmatched["matched_network_events"]) == 0
    assert int(unmatched["unmatched_count"]) == 1
    assert int(unmatched["endpoint_flow_events"]) == 1


def test_direct_cascade_priority_over_pid(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            image="C:\\Windows\\pid.exe",
            pid="7000",
        ),
        _flow_event(
            1,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            dest="10.0.0.7",
            process="C:\\Windows\\direct.exe",
            pid="7000",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    eda8.run_eda08(args)
    t17 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T17_process_to_destination_behavior.csv"
    )
    assert "direct.exe" in t17.iloc[0]["process_name"]


def test_pid_mapping_accepts_unique_process_identity(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            image="C:\\Windows\\pidmatch.exe",
            pid="8000",
        ),
        _flow_event(
            1,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            dest="10.0.0.8",
            pid="8000",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    eda8.run_eda08(args)
    t16 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T16_endpoint_network_pivot_success.csv"
    )
    pid_row = t16.loc[t16["pivot_rule"] == "host_process_pid"].iloc[0]
    assert int(pid_row["matched_network_events"]) == 1


def test_pid_reuse_ambiguity_rejection(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            image="C:\\Windows\\a.exe",
            pid="9000",
        ),
        _process_event(
            1,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            image="C:\\Windows\\b.exe",
            pid="9000",
        ),
        _flow_event(
            2,
            timestamp="2020-01-01T00:00:02",
            archive_date="2020-01-01",
            dest="10.0.0.9",
            pid="9000",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    eda8.run_eda08(args)
    t16 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T16_endpoint_network_pivot_success.csv"
    )
    pid_row = t16.loc[t16["pivot_rule"] == "host_process_pid"].iloc[0]
    assert int(pid_row["ambiguous_match_count"]) == 1
    assert int(pid_row["matched_network_events"]) == 0


def test_relaxed_temporal_unique_match(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            image="C:\\Windows\\relaxed.exe",
            pid="4100",
        ),
        _flow_event(
            1,
            timestamp="2020-01-01T00:00:12",
            archive_date="2020-01-01",
            dest="10.0.0.12",
            pid="",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    eda8.run_eda08(args)
    t16 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T16_endpoint_network_pivot_success.csv"
    )
    relaxed = t16.loc[t16["pivot_rule"] == "host_temporal_relaxed"].iloc[0]
    assert int(relaxed["matched_network_events"]) == 1


def test_duplicate_raw_event_id_values_do_not_collapse(tmp_path):
    rows = [
        _flow_event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            dest="10.0.0.21",
            process="C:\\Windows\\dup.exe",
        ),
        _flow_event(
            1,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            dest="10.0.0.22",
            process="C:\\Windows\\dup.exe",
        ),
    ]
    rows[1]["raw_event_id"] = "dup-id"
    rows[0]["raw_event_id"] = "dup-id"
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    eda8.run_eda08(args)
    t16 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T16_endpoint_network_pivot_success.csv"
    )
    direct = t16.loc[t16["pivot_rule"] == "direct_same_event"].iloc[0]
    assert int(direct["matched_network_events"]) == 2


def test_missing_raw_event_id_values_receive_distinct_locators(tmp_path):
    rows = [
        _flow_event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            dest="10.0.0.31",
            process="C:\\Windows\\noid.exe",
        ),
        _flow_event(
            1,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            dest="10.0.0.32",
            process="C:\\Windows\\noid.exe",
        ),
    ]
    rows[0]["raw_event_id"] = ""
    rows[1]["raw_event_id"] = ""
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    eda8.run_eda08(args)
    t17 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T17_process_to_destination_behavior.csv"
    )
    assert int(t17["connection_count"].sum()) == 2
    assert len(t17) == 2


def test_f9_includes_zero_novelty_evaluation_host_minutes(tmp_path):
    rows = [
        _flow_event(
            0,
            timestamp="2020-01-03T00:00:00",
            archive_date="2020-01-03",
            dest="10.0.0.10",
            process="C:\\Eval\\known.exe",
        ),
        _flow_event(
            1,
            timestamp="2020-01-03T00:01:00",
            archive_date="2020-01-03",
            dest="10.0.0.10",
            process="C:\\Eval\\known.exe",
        ),
        _flow_event(
            2,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            dest="10.0.0.10",
            process="C:\\Benign\\known.exe",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    metadata = eda8.run_eda08(args)
    assert metadata["f9_host_minute_count"] == 2


def test_f10_counts_process_novelty_windows_not_destination_pairs(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-03T00:00:00",
            archive_date="2020-01-03",
            image="C:\\Eval\\novel.exe",
            pid="3300",
        ),
        _flow_event(
            1,
            timestamp="2020-01-03T00:00:05",
            archive_date="2020-01-03",
            dest="203.0.113.10",
            pid="3300",
        ),
        _flow_event(
            2,
            timestamp="2020-01-03T00:00:10",
            archive_date="2020-01-03",
            dest="203.0.113.11",
            pid="3300",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    metadata = eda8.run_eda08(args)
    counts = metadata["f10_cumulative_counts"]
    assert int(counts["5"]) <= int(counts["15"]) <= int(counts["60"])
    assert int(counts["60"]) == 1


def test_user_supplied_spill_directory_is_not_deleted(tmp_path, monkeypatch):
    fixture = _fixture(tmp_path)
    spill = tmp_path / "user_spill"
    spill.mkdir()
    marker = spill / "keep.txt"
    marker.write_text("keep", encoding="utf-8")
    monkeypatch.setattr(eda8, "_looks_like_drive", lambda _path: False)
    args = _args(
        tmp_path,
        fixture,
        duckdb_temp_dir=str(spill),
        output_dir=str(tmp_path / "spill_out"),
    )
    eda8.run_eda08(args)
    assert marker.exists()


def test_f9_and_f10_data_preparation(completed_run):
    _, _, _, output = completed_run
    metadata = json.loads((output / "eda08_run_metadata.json").read_text())
    assert metadata["linked_flow_count"] >= 1
    assert (output / "F9_destination_novelty_over_time.png").stat().st_size > 0
    assert (output / "F10_process_to_network_lag.png").stat().st_size > 0


def test_deterministic_evidence_ordering(tmp_path):
    rows = [
        _flow_event(
            0,
            timestamp="2020-01-01T00:00:10",
            archive_date="2020-01-01",
            dest="10.0.0.10",
            process="C:\\Windows\\ordered.exe",
        ),
        _flow_event(
            1,
            timestamp="2020-01-01T00:00:05",
            archive_date="2020-01-01",
            dest="10.0.0.10",
            process="C:\\Windows\\ordered.exe",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    eda8.run_eda08(args)
    t17 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T17_process_to_destination_behavior.csv"
    )
    assert json.loads(t17.iloc[0]["raw_event_ids"]) == ["e000", "e001"]


def test_atomic_cleanup_on_failure(tmp_path, monkeypatch):
    fixture = _fixture(tmp_path)
    args = _args(tmp_path, fixture)
    original = eda8.create_f9

    def boom(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(eda8, "create_f9", boom)
    with pytest.raises(RuntimeError):
        eda8.run_eda08(args)
    assert not pathlib.Path(args.output_dir).exists()
    monkeypatch.setattr(eda8, "create_f9", original)


def test_output_safety_and_drive_refusal(tmp_path):
    fixture = _fixture(tmp_path)
    existing = tmp_path / "exists"
    existing.mkdir()
    args = _args(tmp_path, fixture, output_dir=str(existing))
    with pytest.raises(eda8.CacheAuditError, match="pre-exist"):
        eda8.validate_run_config(args)

    inside = fixture["cache"] / "nested_out"
    args2 = _args(tmp_path, fixture, output_dir=str(inside))
    with pytest.raises(eda8.CacheAuditError, match="inside"):
        eda8.validate_run_config(args2)

    args3 = _args(
        tmp_path,
        fixture,
        duckdb_temp_dir="/content/drive/MyDrive/spill",
        output_dir=str(tmp_path / "ok_out"),
    )
    with pytest.raises(eda8.CacheAuditError, match="Drive|drive"):
        eda8.validate_run_config(args3)


def _query_frame_sql_literals(source: str) -> list[str]:
    tree = ast.parse(source)

    def _func_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ""

    def _literal_string(node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            parts: list[str] = []
            for value in node.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    parts.append(value.value)
                else:
                    parts.append(" ")
            return "".join(parts)
        return None

    literals: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _func_name(node.func) != "_query_frame":
            continue
        if len(node.args) < 2:
            continue
        text = _literal_string(node.args[1])
        if text is not None:
            literals.append(text)
    return literals


def _sql_fetches_row_level_forbidden_table(sql: str) -> bool:
    normalized = " ".join(str(sql).split()).lower()
    forbidden_tables = (
        "events",
        "network_scan",
        "flow_events",
        "flow_inventory",
        "process_events",
        "process_inventory",
        "linked_flows",
        "cascade_result",
        "pivot_assignments",
        "pivot_stage_flows",
    )
    if not any(f" from {table}" in normalized for table in forbidden_tables):
        return False
    if re.search(r"\bgroup\s+by\b", normalized):
        return False
    if re.search(r"\bselect\s+distinct\b", normalized):
        return False
    if "create temp table" in normalized or "create or replace temp table" in normalized:
        return False
    if " count(*) " in f" {normalized} ":
        return False
    return True


def test_no_row_level_forbidden_table_pandas_fetch():
    source = pathlib.Path(eda8.__file__).read_text(encoding="utf-8")
    literals = _query_frame_sql_literals(source)
    offenders = [
        sql for sql in literals if _sql_fetches_row_level_forbidden_table(sql)
    ]
    assert offenders == []

    forbidden = '''
_query_frame(
    connection,
    """SELECT * FROM cascade_result""",
)
'''
    forbidden_literals = _query_frame_sql_literals(forbidden)
    assert forbidden_literals == ["SELECT * FROM cascade_result"]
    assert _sql_fetches_row_level_forbidden_table(forbidden_literals[0])


def test_t17_aggregation_occurs_in_duckdb():
    source = pathlib.Path(eda8.__file__).read_text(encoding="utf-8")
    assert "CREATE TEMP TABLE t17_behavior_aggregate" in source
    assert "arg_min(" in source
    assert "bounded_evidence_candidates" in source
    assert "CREATE TEMP TABLE t17_bounded_evidence" in source
    assert "CREATE TEMP TABLE t17_final" in source
    assert "CREATE TEMP TABLE t17_unique_evidence" not in source
    assert "CREATE TEMP TABLE t17_ranked_evidence" not in source
    assert "list_slice(list(all evidence" not in source.lower()


def test_no_wholesale_events_pandas_fetch():
    source = pathlib.Path(eda8.__file__).read_text(encoding="utf-8")
    literals = _query_frame_sql_literals(source)
    offenders = [sql for sql in literals if _sql_fetches_row_level_forbidden_table(sql)]
    assert offenders == []


def test_no_deprecation_warnings_in_module(tmp_path):
    fixture = _fixture(tmp_path)
    args = _args(tmp_path, fixture)
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        eda8.run_eda08(args)


def test_readme_mentions_non_maliciousness(completed_run):
    _, _, metadata, output = completed_run
    readme = (output / "README.md").read_text(encoding="utf-8")
    assert "not maliciousness" in readme.lower() or "not attack" in readme.lower()
    assert "EDA 10" in readme
    assert metadata.get("code_commit")
    assert metadata.get("duckdb_temp_dir_policy") == "owned_local_tempfile"
    assert metadata.get("count_semantics")
    assert metadata.get("cache_reconciliation_scan_count") == 1
    assert metadata.get("payload_flow_scan_count") == 1
    assert metadata.get("payload_process_scan_count") == 1


def test_f9_figure_presentation_wording():
    source = pathlib.Path(eda8.__file__).read_text(encoding="utf-8")
    start = source.index("def create_f9(")
    end = source.index("\ndef create_f10(")
    body = source[start:end].lower()
    assert "1-minute windows" in body
    assert "ground-truth intervals not overlaid" in body
    assert "eda 10" in body


def test_f10_figure_presentation_wording():
    source = pathlib.Path(eda8.__file__).read_text(encoding="utf-8")
    start = source.index("def create_f10(")
    end = source.index("\ndef validate_outputs(")
    body = source[start:end].lower()
    assert "1-minute process-novelty windows" in body
    assert "5/15/60-minute lags" in body
    assert "ground-truth intervals not overlaid" in body
    assert "eda 10" in body


def test_execution_log_contains_all_seven_stages(completed_run):
    _, _, _, output = completed_run
    log = (output / "eda08_execution.log").read_text(encoding="utf-8")
    for stage in range(1, 8):
        assert f"[STAGE {stage}/7]" in log
    for substage in ("4A", "4B", "4C", "4D", "4E", "4F"):
        assert f"[STAGE {substage}/7]" in log
    assert "published deliverables" not in log.lower()
    assert "staging validated and ready for atomic publication" in log


def test_pid_ambiguity_cannot_fall_through_to_temporal(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            image="C:\\Windows\\a.exe",
            pid="9100",
        ),
        _process_event(
            1,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            image="C:\\Windows\\b.exe",
            pid="9100",
        ),
        _process_event(
            2,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            image="C:\\Windows\\temporal.exe",
            pid="9101",
        ),
        _flow_event(
            3,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            dest="10.0.0.40",
            pid="9100",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    eda8.run_eda08(args)
    t16 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T16_endpoint_network_pivot_success.csv"
    )
    strict = t16.loc[t16["pivot_rule"] == "host_temporal_strict"].iloc[0]
    relaxed = t16.loc[t16["pivot_rule"] == "host_temporal_relaxed"].iloc[0]
    assert int(strict["matched_network_events"]) == 0
    assert int(relaxed["matched_network_events"]) == 0


def test_strict_ambiguity_cannot_fall_through_to_relaxed(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            image="C:\\Windows\\a.exe",
            pid="9201",
        ),
        _process_event(
            1,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            image="C:\\Windows\\b.exe",
            pid="9202",
        ),
        _flow_event(
            2,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            dest="10.0.0.41",
            pid="",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    eda8.run_eda08(args)
    t16 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T16_endpoint_network_pivot_success.csv"
    )
    strict = t16.loc[t16["pivot_rule"] == "host_temporal_strict"].iloc[0]
    relaxed = t16.loc[t16["pivot_rule"] == "host_temporal_relaxed"].iloc[0]
    assert int(strict["ambiguous_match_count"]) == 1
    assert int(relaxed["matched_network_events"]) == 0


def test_no_temporal_candidate_row_expansion_in_source():
    source = pathlib.Path(eda8.__file__).read_text(encoding="utf-8")
    assert "CREATE TEMP TABLE process_time_bounds" in source
    assert "CREATE TEMP TABLE temporal_window_candidates" not in source
    assert "proc_ord BETWEEN" not in source
    assert "ASOF LEFT JOIN process_time_bounds" in source
    assert not re.search(
        r"flow_inventory[\s\S]{0,400}process_inventory[\s\S]{0,200}ABS\s*\(\s*date_diff",
        source,
        flags=re.IGNORECASE,
    )


def test_temporal_candidate_logic_computed_once():
    source = pathlib.Path(eda8.__file__).read_text(encoding="utf-8")
    assert source.count("CREATE TEMP TABLE cascade_temporal AS") == 1
    assert "ASOF LEFT JOIN process_time_bounds" in source
    assert "strict_upper_ord - sl.strict_lower_ord + 1" in source
    assert "CREATE TEMP TABLE temporal_strict_lo" not in source
    assert "CREATE TEMP TABLE temporal_strict_hi" not in source
    assert "CREATE TEMP TABLE temporal_relaxed_lo" not in source
    assert "CREATE TEMP TABLE temporal_relaxed_hi" not in source


def test_no_network_scan_or_linked_flows_table():
    source = pathlib.Path(eda8.__file__).read_text(encoding="utf-8")
    assert "CREATE TEMP TABLE network_scan" not in source
    assert "CREATE TEMP TABLE linked_flows" not in source
    assert "CREATE TEMP VIEW linked_flows" in source
    assert "CREATE TEMP TABLE cascade_direct" not in source
    assert "NOT IN (SELECT" not in source
    assert "SELECT f.*" not in source


def test_cascade_uses_numeric_flow_id():
    source = pathlib.Path(eda8.__file__).read_text(encoding="utf-8")
    assert "ROW_NUMBER() OVER ()::BIGINT AS flow_id" in source
    assert "CREATE TEMP TABLE cascade_result AS" in source
    assert "c.flow_id = f.flow_id" in source or "pm.flow_id = f.flow_id" in source
    # Cascade intermediates must not join on event_locator.
    assert "JOIN cascade_pid_match" in source
    assert "ON pm.event_locator" not in source
    assert "ON pa.event_locator" not in source
    assert "ON ts.event_locator" not in source


def test_cascade_result_is_narrow():
    source = pathlib.Path(eda8.__file__).read_text(encoding="utf-8")
    start = source.index("CREATE TEMP TABLE cascade_result AS")
    end = source.index("Drop intermediate PID/temporal tables")
    body = source[start:end]
    assert "status_code" in body
    assert "chosen_process_locator" in body
    assert "archive_name" not in body
    assert "member_name" not in body
    assert "raw_event_id" not in body
    assert "destination_value" not in body


def test_cascade_probe_only_creates_no_output_directory(tmp_path):
    fixture = _fixture(tmp_path)
    out = tmp_path / "probe_out"
    args = _args(tmp_path, fixture, output_dir=str(out), cascade_probe_only=True)
    # Bypass Namespace default: _args may not know the flag.
    args.cascade_probe_only = True
    metadata = eda8.run_eda08(args)
    assert metadata["cascade_probe_only"] is True
    assert not out.exists()
    assert (
        metadata["direct_count"]
        + metadata["pid_matched"]
        + metadata["pid_ambiguous"]
        + metadata["strict_matched"]
        + metadata["strict_ambiguous"]
        + metadata["relaxed_matched"]
        + metadata["relaxed_ambiguous"]
        + metadata["unmatched_plain"]
        == metadata["flow_total"]
    )


def test_cascade_row_reconciliation(completed_run):
    _, _, metadata, _ = completed_run
    assert metadata["payload_flow_scan_count"] == 1
    assert metadata["payload_process_scan_count"] == 1
    assert metadata["cache_reconciliation_scan_count"] == 1
    # Full-run metadata still exposes linked/unmatched totals.
    assert metadata["unmatched_count"] >= 0
    assert metadata["linked_flow_count"] >= 0


def _run_temporal_fixture(tmp_path, rows: list[dict]) -> pd.DataFrame:
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    eda8.run_eda08(args)
    return pd.read_csv(
        pathlib.Path(args.output_dir) / "T16_endpoint_network_pivot_success.csv"
    )


def _temporal_row(t16: pd.DataFrame, rule: str) -> pd.Series:
    return t16.loc[
        (t16["pivot_rule"] == rule) & (t16["date_label"] == "2020-01-01")
    ].iloc[0]


def test_temporal_zero_candidates(tmp_path):
    rows = [
        _flow_event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            dest="10.0.0.81",
            pid="",
        )
    ]
    t16 = _run_temporal_fixture(tmp_path, rows)
    assert int(_temporal_row(t16, "host_temporal_strict")["matched_network_events"]) == 0
    assert int(_temporal_row(t16, "host_temporal_relaxed")["matched_network_events"]) == 0


def test_temporal_one_strict_candidate(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            image="C:\\Windows\\only.exe",
            pid="9301",
        ),
        _flow_event(
            1,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            dest="10.0.0.82",
            pid="",
        ),
    ]
    t16 = _run_temporal_fixture(tmp_path, rows)
    assert int(_temporal_row(t16, "host_temporal_strict")["matched_network_events"]) == 1


def test_temporal_multiple_strict_candidates(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            image="C:\\Windows\\a.exe",
            pid="9401",
        ),
        _process_event(
            1,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            image="C:\\Windows\\b.exe",
            pid="9402",
        ),
        _flow_event(
            2,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            dest="10.0.0.83",
            pid="",
        ),
    ]
    t16 = _run_temporal_fixture(tmp_path, rows)
    assert int(_temporal_row(t16, "host_temporal_strict")["ambiguous_match_count"]) == 1
    assert int(_temporal_row(t16, "host_temporal_strict")["matched_network_events"]) == 0


def test_temporal_one_relaxed_candidate(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            image="C:\\Windows\\relaxed-only.exe",
            pid="9501",
        ),
        _flow_event(
            1,
            timestamp="2020-01-01T00:00:12",
            archive_date="2020-01-01",
            dest="10.0.0.84",
            pid="",
        ),
    ]
    t16 = _run_temporal_fixture(tmp_path, rows)
    assert int(_temporal_row(t16, "host_temporal_strict")["matched_network_events"]) == 0
    assert int(_temporal_row(t16, "host_temporal_relaxed")["matched_network_events"]) == 1


def test_temporal_multiple_relaxed_candidates(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            image="C:\\Windows\\r1.exe",
            pid="9601",
        ),
        _process_event(
            1,
            timestamp="2020-01-01T00:00:10",
            archive_date="2020-01-01",
            image="C:\\Windows\\r2.exe",
            pid="9602",
        ),
        _flow_event(
            2,
            timestamp="2020-01-01T00:00:12",
            archive_date="2020-01-01",
            dest="10.0.0.85",
            pid="",
        ),
    ]
    t16 = _run_temporal_fixture(tmp_path, rows)
    assert int(_temporal_row(t16, "host_temporal_strict")["matched_network_events"]) == 0
    assert int(_temporal_row(t16, "host_temporal_relaxed")["ambiguous_match_count"]) == 1
    assert int(_temporal_row(t16, "host_temporal_relaxed")["matched_network_events"]) == 0


def test_temporal_duplicate_timestamp_at_lower_boundary_is_ambiguous(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            image="C:\\Windows\\low1.exe",
            pid="9701",
        ),
        _process_event(
            1,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            image="C:\\Windows\\low2.exe",
            pid="9702",
        ),
        _flow_event(
            2,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            dest="10.0.0.86",
            pid="",
        ),
    ]
    t16 = _run_temporal_fixture(tmp_path, rows)
    assert int(_temporal_row(t16, "host_temporal_strict")["ambiguous_match_count"]) == 1


def test_temporal_duplicate_timestamp_at_upper_boundary_is_ambiguous(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            image="C:\\Windows\\high1.exe",
            pid="9801",
        ),
        _process_event(
            1,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            image="C:\\Windows\\high2.exe",
            pid="9802",
        ),
        _flow_event(
            2,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            dest="10.0.0.87",
            pid="",
        ),
    ]
    t16 = _run_temporal_fixture(tmp_path, rows)
    assert int(_temporal_row(t16, "host_temporal_strict")["ambiguous_match_count"]) == 1


def test_pid_same_host_date_maps_successfully(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            image="C:\\Windows\\dated.exe",
            pid="9901",
        ),
        _flow_event(
            1,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            dest="10.0.0.88",
            pid="9901",
        ),
    ]
    t16 = _run_temporal_fixture(tmp_path, rows)
    assert int(_temporal_row(t16, "host_process_pid")["matched_network_events"]) == 1


def test_pid_on_other_archive_date_does_not_map(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-02T00:00:00",
            archive_date="2020-01-02",
            image="C:\\Windows\\otherday.exe",
            pid="9902",
        ),
        _flow_event(
            1,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            dest="10.0.0.89",
            pid="9902",
        ),
    ]
    t16 = _run_temporal_fixture(tmp_path, rows)
    assert int(_temporal_row(t16, "host_process_pid")["matched_network_events"]) == 0


def test_f10_counts_one_host_window_for_two_novel_process_names(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-03T00:00:05",
            archive_date="2020-01-03",
            image="C:\\Eval\\novel-a.exe",
            pid="3401",
        ),
        _process_event(
            1,
            timestamp="2020-01-03T00:00:20",
            archive_date="2020-01-03",
            image="C:\\Eval\\novel-b.exe",
            pid="3402",
        ),
        _flow_event(
            2,
            timestamp="2020-01-03T00:00:25",
            archive_date="2020-01-03",
            dest="203.0.113.30",
            pid="3401",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    metadata = eda8.run_eda08(args)
    assert int(metadata["f10_cumulative_counts"]["60"]) == 1


def test_t17_evidence_ordering_uses_earliest_event_locator(tmp_path):
    rows = [
        _flow_event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            dest="10.0.0.90",
            process="C:\\Windows\\loc.exe",
        ),
        _flow_event(
            1,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            dest="10.0.0.90",
            process="C:\\Windows\\loc.exe",
        ),
        _flow_event(
            2,
            timestamp="2020-01-01T00:00:02",
            archive_date="2020-01-01",
            dest="10.0.0.90",
            process="C:\\Windows\\loc.exe",
        ),
    ]
    rows[0]["raw_event_id"] = "shared"
    rows[0]["member_name"] = "z.json.gz"
    rows[0]["line_number"] = 99
    rows[1]["raw_event_id"] = "shared"
    rows[1]["member_name"] = "a.json.gz"
    rows[1]["line_number"] = 1
    rows[2]["raw_event_id"] = "later"
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture, evidence_cap=5)
    eda8.run_eda08(args)
    t17 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T17_process_to_destination_behavior.csv"
    )
    assert json.loads(t17.iloc[0]["raw_event_ids"]) == ["shared", "later"]


def test_no_many_to_many_temporal_range_join_in_source():
    test_no_temporal_candidate_row_expansion_in_source()


def test_t16_row_arithmetic_reconciliation(completed_run):
    _, _, _, output = completed_run
    t16 = pd.read_csv(output / "T16_endpoint_network_pivot_success.csv")
    totals = (
        t16["matched_network_events"]
        + t16["ambiguous_match_count"]
        + t16["unmatched_count"]
    )
    assert (totals == t16["endpoint_flow_events"]).all()


def test_event_locator_collision_failure(tmp_path):
    rows = [
        _flow_event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            dest="10.0.0.50",
            process="C:\\Windows\\collision.exe",
        ),
        _flow_event(
            1,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            dest="10.0.0.51",
            process="C:\\Windows\\collision.exe",
        ),
    ]
    rows[1]["archive_name"] = rows[0]["archive_name"]
    rows[1]["member_name"] = rows[0]["member_name"]
    rows[1]["line_number"] = rows[0]["line_number"]
    rows[1]["raw_event_id"] = rows[0]["raw_event_id"]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    with pytest.raises(eda8.CacheAuditError, match="event_locator collision"):
        eda8.run_eda08(args)


def test_t17_raw_event_ids_unique_and_bounded(tmp_path):
    rows = []
    for index in range(25):
        rows.append(
            _flow_event(
                index,
                timestamp=f"2020-01-01T00:00:{index:02d}",
                archive_date="2020-01-01",
                dest="10.0.0.60",
                process="C:\\Windows\\many.exe",
            )
        )
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture, evidence_cap=5)
    eda8.run_eda08(args)
    t17 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T17_process_to_destination_behavior.csv"
    )
    evidence = json.loads(t17.iloc[0]["raw_event_ids"])
    assert len(evidence) == 5
    assert len(evidence) == len(set(evidence))


def test_f9_includes_eligible_unmatched_flow_rows(tmp_path):
    rows = [
        _flow_event(
            0,
            timestamp="2020-01-03T00:00:00",
            archive_date="2020-01-03",
            dest="10.0.0.70",
            pid="",
        ),
        _flow_event(
            1,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            dest="10.0.0.70",
            process="C:\\Benign\\known.exe",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    metadata = eda8.run_eda08(args)
    assert metadata["f9_host_minute_count"] == 1


def test_f10_exact_five_minute_boundary(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-03T00:00:00",
            archive_date="2020-01-03",
            image="C:\\Eval\\novel.exe",
            pid="4400",
        ),
        _flow_event(
            1,
            timestamp="2020-01-03T00:05:00",
            archive_date="2020-01-03",
            dest="203.0.113.20",
            pid="4400",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    metadata = eda8.run_eda08(args)
    assert int(metadata["f10_cumulative_counts"]["5"]) == 1


def test_f10_five_minutes_plus_one_microsecond_rejected(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-03T00:00:00",
            archive_date="2020-01-03",
            image="C:\\Eval\\novel.exe",
            pid="4500",
        ),
        _flow_event(
            1,
            timestamp="2020-01-03T00:05:00.000001",
            archive_date="2020-01-03",
            dest="203.0.113.21",
            pid="4500",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    metadata = eda8.run_eda08(args)
    assert int(metadata["f10_cumulative_counts"]["5"]) == 0
    assert int(metadata["f10_cumulative_counts"]["15"]) == 1


def test_f10_destination_lag_join_bounded_to_sixty_minutes():
    source = pathlib.Path(eda8.__file__).read_text(encoding="utf-8")
    assert "INTERVAL '60 minutes'" in source
    assert "dest_novelty_events" in source
    assert "process_inventory" in source
    assert "flow_inventory" in source


def test_t17_rejects_unbounded_evidence_tables():
    source = pathlib.Path(eda8.__file__).read_text(encoding="utf-8")
    assert "CREATE TEMP TABLE t17_unique_evidence" not in source
    assert "CREATE TEMP TABLE t17_ranked_evidence" not in source
    assert "FROM t17_unique_evidence" not in source
    assert "FROM t17_ranked_evidence" not in source


def test_t17_rejects_row_number_over_linked_flows_evidence():
    source = pathlib.Path(eda8.__file__).read_text(encoding="utf-8")
    start = source.index("def build_t17(")
    end = source.index("\ndef validate_t17_in_duckdb(")
    body = source[start:end]
    assert "ROW_NUMBER() OVER" in body
    assert "FROM linked_flows" not in body.split("ROW_NUMBER() OVER", 1)[1]


def test_t17_not_fetched_into_pandas():
    source = pathlib.Path(eda8.__file__).read_text(encoding="utf-8")
    start = source.index("def build_t17(")
    end = source.index("\ndef validate_t17_in_duckdb(")
    body = source[start:end]
    assert "_query_frame(" not in body
    assert "fetchdf(" not in body
    assert ".df(" not in body
    assert "fetchall(" not in body


def test_t17_exported_with_duckdb_copy():
    source = pathlib.Path(eda8.__file__).read_text(encoding="utf-8")
    assert "def _export_t17_csv(" in source
    assert "COPY (" in source
    assert "FROM t17_final" in source
    assert "_export_t17_csv(connection" in source


def test_t17_validation_runs_inside_duckdb():
    source = pathlib.Path(eda8.__file__).read_text(encoding="utf-8")
    assert "def validate_t17_in_duckdb(" in source
    assert "DESCRIBE t17_final" in source
    assert "json_valid(raw_event_ids)" in source
    start = source.index("def validate_t17_in_duckdb(")
    end = source.index("\ndef _export_t17_csv(")
    body = source[start:end]
    assert "fetchdf(" not in body


def test_t17_bounded_aggregate_during_behavior_aggregation():
    source = pathlib.Path(eda8.__file__).read_text(encoding="utf-8")
    assert "CREATE TEMP TABLE t17_behavior_aggregate" in source
    assert "arg_min(" in source
    assert "bounded_evidence_candidates" in source
    assert "FROM linked_flows" in source.split("t17_behavior_aggregate", 1)[1]


def test_t17_benign_keys_derived_from_behavior_aggregate():
    source = pathlib.Path(eda8.__file__).read_text(encoding="utf-8")
    assert "FROM t17_behavior_aggregate" in source
    assert (
        "FROM linked_flows\n        WHERE period_role = 'verified_benign'"
        not in source
    )


def test_f9_uses_count_star_not_distinct_event_locator():
    source = pathlib.Path(eda8.__file__).read_text(encoding="utf-8")
    start = source.index("def build_f9_data(")
    end = source.index("\ndef build_f10_data(")
    body = source[start:end]
    assert "COUNT(*)::BIGINT AS flow_count" in body
    assert "COUNT(DISTINCT ef.event_locator)" not in body


def test_t17_probe_only_creates_no_output_directory(tmp_path):
    fixture = _fixture(tmp_path)
    out = tmp_path / "t17_probe_out"
    args = _args(tmp_path, fixture, output_dir=str(out), t17_probe_only=True)
    args.t17_probe_only = True
    metadata = eda8.run_eda08(args)
    assert metadata["t17_probe_only"] is True
    assert not out.exists()
    assert metadata["t16_row_count"] >= 0
    assert metadata["t17_row_count"] >= 0
    assert metadata["linked_flow_count"] >= 0


def test_t17_evidence_candidates_bounded_by_cap(tmp_path):
    rows = []
    for index in range(25):
        rows.append(
            _flow_event(
                index,
                timestamp=f"2020-01-01T00:00:{index:02d}",
                archive_date="2020-01-01",
                dest="10.0.0.60",
                process="C:\\Windows\\many.exe",
            )
        )
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture, evidence_cap=5)
    metadata = eda8.run_eda08(args)
    assert metadata["t17_evidence_max_count"] <= 5
    t17 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T17_process_to_destination_behavior.csv"
    )
    evidence = json.loads(t17.iloc[0]["raw_event_ids"])
    assert len(evidence) == 5
    assert len(evidence) == len(set(evidence))


def test_t17_rejects_unbounded_list_aggregation_before_cap():
    source = pathlib.Path(eda8.__file__).read_text(encoding="utf-8")
    start = source.index("def build_t17(")
    end = source.index("\ndef validate_t17_in_duckdb(")
    body = source[start:end]
    assert "list(" not in body.split("bounded_evidence_candidates", 1)[0]
    assert "list_slice(" not in body
