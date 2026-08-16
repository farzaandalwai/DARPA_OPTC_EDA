"""Synthetic, repository-local tests for EDA 9 provenance graph."""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import pathlib
import shutil
import sys

import pandas as pd
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src" / "eda"))

import eda_04_event_taxonomy as eda4  # type: ignore
import eda_05_entity_dictionary as eda5  # type: ignore
import eda_09_provenance_graph as eda9  # type: ignore
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
            "task_process_uuid_raw": "",
            "thread_tgt_pid_uuid_raw": "",
        }
    )
    return row


def _process_event(
    index: int,
    *,
    timestamp: str,
    archive_date: str,
    host: str = "h1",
    action: str = "CREATE",
    image: str = "C:\\Windows\\child.exe",
    parent: str = "C:\\Windows\\parent.exe",
    command: str = "child.exe -x",
    pid: str = "2000",
    ppid: str = "1000",
    actor_uuid: str = "actor-a",
    object_uuid: str = "object-b",
) -> dict:
    row = _base_row(index, timestamp=timestamp, archive_date=archive_date, host=host)
    row.update(
        {
            "object_raw": "PROCESS",
            "action_raw": action,
            "image_path_raw": image,
            "process_raw": image,
            "parent_image_path_raw": parent,
            "parent_process_raw": parent,
            "command_line_raw": command,
            "pid_raw": pid,
            "ppid_raw": ppid,
            "actor_id_raw": actor_uuid,
            "object_id_raw": object_uuid,
        }
    )
    return row


def _file_event(
    index: int,
    *,
    timestamp: str,
    archive_date: str,
    host: str = "h1",
    action: str = "WRITE",
    image: str = "C:\\Windows\\child.exe",
    file_path: str = "C:\\Temp\\x.txt",
    pid: str = "2000",
    ppid: str = "1000",
    actor_uuid: str = "object-b",
) -> dict:
    row = _base_row(index, timestamp=timestamp, archive_date=archive_date, host=host)
    row.update(
        {
            "object_raw": "FILE",
            "action_raw": action,
            "image_path_raw": image,
            "process_raw": image,
            "file_path_raw": file_path,
            "pid_raw": pid,
            "ppid_raw": ppid,
            "actor_id_raw": actor_uuid,
            "object_id_raw": f"obj-file-{index}",
        }
    )
    return row


def _flow_event(
    index: int,
    *,
    timestamp: str,
    archive_date: str,
    host: str = "h1",
    action: str = "OPEN",
    image: str = "C:\\Windows\\child.exe",
    dest: str = "203.0.113.9",
    port: str = "443",
    protocol: str = "TCP",
    pid: str = "2000",
    ppid: str = "1000",
    actor_uuid: str = "object-b",
) -> dict:
    row = _base_row(index, timestamp=timestamp, archive_date=archive_date, host=host)
    row.update(
        {
            "object_raw": "FLOW",
            "action_raw": action,
            "image_path_raw": image,
            "process_raw": image,
            "dest_ip_raw": dest,
            "destination_raw": dest,
            "dest_port_raw": port,
            "protocol_raw": protocol,
            "pid_raw": pid,
            "ppid_raw": ppid,
            "actor_id_raw": actor_uuid,
            "object_id_raw": f"obj-flow-{index}",
        }
    )
    return row


def _base_events() -> list[dict]:
    return [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            image="C:\\Windows\\child.exe",
            parent="C:\\Windows\\parent.exe",
            actor_uuid="uuid-parent",
            object_uuid="uuid-child",
        ),
        _file_event(
            1,
            timestamp="2020-01-01T00:00:20",
            archive_date="2020-01-01",
            image="C:\\Windows\\child.exe",
            actor_uuid="uuid-child",
        ),
        _flow_event(
            2,
            timestamp="2020-01-01T00:00:40",
            archive_date="2020-01-01",
            image="C:\\Windows\\child.exe",
            actor_uuid="uuid-child",
        ),
    ]


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


def _write_period_map(root: pathlib.Path) -> pathlib.Path:
    path = root / "periods.csv"
    pd.DataFrame(
        [
            {
                "period": "baseline",
                "start_time": "2020-01-01T00:00:00Z",
                "end_time": "2020-01-02T00:00:00Z",
                "period_role": "verified_benign",
            }
        ],
        columns=eda4.PERIOD_MAP_COLUMNS,
    ).to_csv(path, index=False)
    return path


def _write_t7(root: pathlib.Path, rows: list[dict]) -> pathlib.Path:
    observed = sorted(
        {
            (event["object_raw"] or eda4.MISSING_MARKER, event["action_raw"] or eda4.MISSING_MARKER)
            for event in rows
        }
    )
    mappings = [eda4.semantic_mapping(raw_object, raw_action) for raw_object, raw_action in observed]
    path = root / "T7_semantic_event_mapping.csv"
    pd.DataFrame(mappings, columns=eda4.T7_COLUMNS).to_csv(path, index=False)
    return path


def _fixture(root: pathlib.Path, rows: list[dict] | None = None) -> dict:
    events = list(_base_events() if rows is None else rows)
    return {
        "rows": events,
        "cache": _write_cache(root, events),
        "period_map": _write_period_map(root),
        "t7": _write_t7(root, events),
    }


def _args(root: pathlib.Path, fixture: dict, **overrides) -> argparse.Namespace:
    values = {
        "normalized_cache_dir": str(fixture["cache"]),
        "period_map_csv": str(fixture["period_map"]),
        "semantic_mapping_csv": str(fixture["t7"]),
        "output_dir": str(root / "eda09_out"),
        "host": "h1",
        "start_time": "2020-01-01T00:00:00",
        "end_time": "2020-01-01T00:01:00",
        "project_root": str(pathlib.Path(__file__).resolve().parents[1]),
        "manifest_csv": None,
        "process_instance_key": "uuid",
        "probe_process_semantics": False,
        "process_create_actions": "",
        "batch_size": 2,
        "duckdb_memory_limit": "1GB",
        "duckdb_temp_dir": None,
        "duckdb_threads": 2,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


@pytest.fixture
def completed_run(tmp_path):
    fixture = _fixture(tmp_path)
    args = _args(tmp_path, fixture)
    cache_file = next(fixture["cache"].glob("*.parquet"))
    before = hashlib.sha256(cache_file.read_bytes()).hexdigest()
    metadata = eda9.run_eda09(args)
    after = hashlib.sha256(cache_file.read_bytes()).hexdigest()
    assert before == after
    return fixture, args, metadata, pathlib.Path(args.output_dir)


def _load_edges(output_dir: pathlib.Path) -> pd.DataFrame:
    return pd.read_csv(output_dir / "edges.csv", keep_default_na=False)


def _load_nodes(output_dir: pathlib.Path) -> pd.DataFrame:
    return pd.read_csv(output_dir / "nodes.csv", keep_default_na=False)


def _load_summary(output_dir: pathlib.Path) -> dict:
    return json.loads((output_dir / "graph_summary.json").read_text(encoding="utf-8"))


def _run_probe(tmp_path: pathlib.Path, rows: list[dict]) -> dict:
    fixture = _fixture(tmp_path, rows=rows)
    args = _args(tmp_path, fixture, probe_process_semantics=True)
    return eda9.run_eda09(args)


def test_process_creation_edge(completed_run):
    _fixture, _args_ns, _meta, output_dir = completed_run
    edges = _load_edges(output_dir)
    creation = edges.loc[edges["relation"] == "process_created_process"]
    assert len(creation) == 1
    row = creation.iloc[0]
    assert row["source_type"] == "PROCESS"
    assert row["destination_type"] == "PROCESS"
    assert row["source_instance_source"] in {"uuid", "provisional_fallback"}
    assert row["destination_instance_source"] in {"uuid", "provisional_fallback"}


def test_file_access_edge(completed_run):
    _fixture, _args_ns, _meta, output_dir = completed_run
    edges = _load_edges(output_dir)
    rows = edges.loc[edges["relation"] == "process_accessed_file"]
    assert len(rows) == 1
    row = rows.iloc[0]
    assert row["object_type"] == "FILE"
    assert row["action"] == "WRITE"
    assert row["destination_type"] == "FILE"


def test_network_connection_edge(completed_run):
    _fixture, _args_ns, _meta, output_dir = completed_run
    edges = _load_edges(output_dir)
    rows = edges.loc[edges["relation"] == "process_connected_destination"]
    assert len(rows) == 1
    row = rows.iloc[0]
    assert row["dest_ip_raw"] == "203.0.113.9"
    assert row["dest_port_raw"] == "443"
    assert row["protocol_raw"] == "TCP"
    assert row["destination_port_key"] == "203.0.113.9:443"


def test_user_process_relationship(completed_run):
    _fixture, _args_ns, _meta, output_dir = completed_run
    edges = _load_edges(output_dir)
    rows = edges.loc[edges["relation"] == "user_ran_process_instance"]
    assert len(rows) >= 1
    assert (rows["source_type"] == "USER").all()
    assert (rows["destination_type"] == "PROCESS").all()


def test_raw_event_id_preserved(completed_run):
    fixture, _args_ns, _meta, output_dir = completed_run
    edges = _load_edges(output_dir)
    input_ids = {row["raw_event_id"] for row in fixture["rows"]}
    assert input_ids.issubset(set(edges["raw_event_id"]))


def test_deterministic_node_ids(tmp_path):
    fixture = _fixture(tmp_path)
    args_a = _args(tmp_path, fixture, output_dir=str(tmp_path / "out_a"))
    args_b = _args(tmp_path, fixture, output_dir=str(tmp_path / "out_b"))
    eda9.run_eda09(args_a)
    eda9.run_eda09(args_b)
    nodes_a = (pathlib.Path(args_a.output_dir) / "nodes.csv").read_text(encoding="utf-8")
    nodes_b = (pathlib.Path(args_b.output_dir) / "nodes.csv").read_text(encoding="utf-8")
    assert nodes_a == nodes_b

    nodes = _load_nodes(pathlib.Path(args_a.output_dir))
    host_row = nodes.loc[nodes["node_type"] == "HOST"].iloc[0]
    expected_host = eda5.normalize_entity(
        entity_type="host",
        raw_value="h1",
        host_scope="",
        source_field="host_raw",
    )["canonical_id"]
    assert host_row["node_id"] == expected_host


def test_process_instances_remain_distinct_but_share_identity_attribute(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            image="C:\\Windows\\same.exe",
            actor_uuid="a1",
            object_uuid="o1",
            pid="100",
        ),
        _process_event(
            1,
            timestamp="2020-01-01T00:00:02",
            archive_date="2020-01-01",
            image="C:\\Windows\\same.exe",
            actor_uuid="a2",
            object_uuid="o2",
            pid="101",
        ),
    ]
    fixture = _fixture(tmp_path, rows=rows)
    args = _args(tmp_path, fixture)
    eda9.run_eda09(args)
    nodes = _load_nodes(pathlib.Path(args.output_dir))
    process_nodes = nodes.loc[nodes["node_type"] == "PROCESS"].copy()
    assert len(process_nodes["node_id"].unique()) >= 2
    assert len(process_nodes["process_identity_id"].unique()) == 1


def test_pid_reuse_does_not_merge_instances(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            actor_uuid="a1",
            object_uuid="o1",
            pid="777",
        ),
        _process_event(
            1,
            timestamp="2020-01-01T00:00:02",
            archive_date="2020-01-01",
            actor_uuid="a2",
            object_uuid="o2",
            pid="777",
        ),
    ]
    fixture = _fixture(tmp_path, rows=rows)
    args = _args(tmp_path, fixture)
    eda9.run_eda09(args)
    nodes = _load_nodes(pathlib.Path(args.output_dir))
    process_nodes = nodes.loc[nodes["node_type"] == "PROCESS"]
    assert len(process_nodes["node_id"].unique()) >= 2


@pytest.mark.parametrize("mode", ["uuid", "path_pid"])
def test_full_provenance_chain_parent_child_file_destination(tmp_path, mode):
    fixture = _fixture(tmp_path)
    args = _args(tmp_path, fixture, process_instance_key=mode)
    eda9.run_eda09(args)
    edges = _load_edges(pathlib.Path(args.output_dir))
    creation = edges.loc[edges["relation"] == "process_created_process"].iloc[0]
    child = creation["destination_id"]
    file_edges = edges.loc[(edges["relation"] == "process_accessed_file") & (edges["source_id"] == child)]
    flow_edges = edges.loc[
        (edges["relation"] == "process_connected_destination") & (edges["source_id"] == child)
    ]
    assert len(file_edges) == 1
    assert len(flow_edges) == 1


def test_provisional_fallback_links_parent_reference(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            image="C:\\Windows\\child.exe",
            parent="C:\\Windows\\parent.exe",
            actor_uuid="",
            object_uuid="",
            pid="2000",
            ppid="1000",
        ),
        _file_event(
            1,
            timestamp="2020-01-01T00:00:05",
            archive_date="2020-01-01",
            image="C:\\Windows\\parent.exe",
            actor_uuid="",
            pid="1000",
            ppid="4",
        ),
    ]
    fixture = _fixture(tmp_path, rows=rows)
    args = _args(tmp_path, fixture, process_instance_key="path_pid")
    eda9.run_eda09(args)
    edges = _load_edges(pathlib.Path(args.output_dir))
    creation = edges.loc[edges["relation"] == "process_created_process"].iloc[0]
    parent_id = creation["source_id"]
    parent_file = edges.loc[
        (edges["relation"] == "process_accessed_file") & (edges["source_id"] == parent_id)
    ]
    assert len(parent_file) == 1


def test_process_instance_id_excludes_pid_alone():
    a = eda9._process_instance_id(
        mode="path_pid",
        host_node_id="host-1",
        uuid_text="",
        comparison_form="a",
        pid_text="123",
        date_label="2020-01-01",
    )
    b = eda9._process_instance_id(
        mode="path_pid",
        host_node_id="host-2",
        uuid_text="",
        comparison_form="a",
        pid_text="123",
        date_label="2020-01-01",
    )
    assert a["node_id"] != b["node_id"]
    source = inspect.getsource(eda9._process_instance_id)
    assert "date_label" in source
    assert "comparison_form" in source


def test_no_action_filter_on_process_edges(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            action="WEIRD_ACTION",
            actor_uuid="a1",
            object_uuid="o1",
        )
    ]
    fixture = _fixture(tmp_path, rows=rows)
    args_default = _args(tmp_path, fixture, output_dir=str(tmp_path / "out_default"))
    eda9.run_eda09(args_default)
    edges_default = _load_edges(pathlib.Path(args_default.output_dir))
    assert (edges_default["relation"] == "process_created_process").any()

    args_filtered = _args(
        tmp_path,
        fixture,
        output_dir=str(tmp_path / "out_filtered"),
        process_create_actions="CREATE",
    )
    eda9.run_eda09(args_filtered)
    edges_filtered = _load_edges(pathlib.Path(args_filtered.output_dir))
    assert not (edges_filtered["relation"] == "process_created_process").any()


def test_process_semantics_assumption_is_declared(completed_run):
    _fixture, _args_ns, _meta, output_dir = completed_run
    summary = _load_summary(output_dir)
    block = summary["process_event_semantics_v1"]
    assert "q1_actor_id_raw_on_process_events" in block
    assert block["fallback_pid_semantics_assumed"] is True
    assert "eda07_preflight_warning" in block


def test_uuid_backed_instances_are_medium_reliability(completed_run):
    _fixture, _args_ns, _meta, output_dir = completed_run
    nodes = _load_nodes(output_dir)
    process_rows = nodes.loc[nodes["node_type"] == "PROCESS"]
    assert (process_rows["process_instance_reliability"] == "medium").any()
    assert (process_rows["instance_identity_status"] == "assumed_uuid_unverified").any()


def test_probe_process_semantics_publishes_nothing(tmp_path):
    fixture = _fixture(tmp_path)
    args = _args(tmp_path, fixture, probe_process_semantics=True)
    summary = eda9.run_eda09(args)
    assert "process_action_vocabulary" in summary
    assert "missing_uuid_rates" in summary
    assert not pathlib.Path(args.output_dir).exists()


def test_probe_later_actor_does_not_match_earlier_file_object_id(tmp_path):
    rows = [
        _file_event(
            0,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            actor_uuid="file-actor-0",
        ),
        _flow_event(
            1,
            timestamp="2020-01-01T00:00:02",
            archive_date="2020-01-01",
            actor_uuid="file-object-x",
        ),
    ]
    rows[0]["object_id_raw"] = "file-object-x"
    summary = _run_probe(tmp_path, rows)
    rate = summary["later_actor_equals_earlier_object_rate"]
    assert rate["denominator"] == 2
    assert rate["numerator"] == 0
    assert rate["rate"] == 0.0


def test_probe_later_actor_matches_earlier_process_object_id(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            actor_uuid="proc-actor",
            object_uuid="proc-child-1",
        ),
        _file_event(
            1,
            timestamp="2020-01-01T00:00:02",
            archive_date="2020-01-01",
            actor_uuid="proc-child-1",
        ),
    ]
    summary = _run_probe(tmp_path, rows)
    rate = summary["later_actor_equals_earlier_object_rate"]
    assert rate["denominator"] == 1
    assert rate["numerator"] == 1
    assert rate["rate"] == 1.0


def test_probe_process_object_after_file_does_not_count_as_earlier(tmp_path):
    rows = [
        _file_event(
            0,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            actor_uuid="future-proc-object",
        ),
        _process_event(
            1,
            timestamp="2020-01-01T00:00:02",
            archive_date="2020-01-01",
            actor_uuid="proc-actor",
            object_uuid="future-proc-object",
        ),
    ]
    summary = _run_probe(tmp_path, rows)
    rate = summary["later_actor_equals_earlier_object_rate"]
    assert rate["denominator"] == 1
    assert rate["numerator"] == 0
    assert rate["rate"] == 0.0


def test_probe_denominator_only_file_flow_with_nonempty_actor(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            actor_uuid="proc-actor",
            object_uuid="proc-child",
        ),
        _file_event(
            1,
            timestamp="2020-01-01T00:00:02",
            archive_date="2020-01-01",
            actor_uuid="",
        ),
        _flow_event(
            2,
            timestamp="2020-01-01T00:00:03",
            archive_date="2020-01-01",
            actor_uuid="proc-child",
        ),
        _process_event(
            3,
            timestamp="2020-01-01T00:00:04",
            archive_date="2020-01-01",
            actor_uuid="another-proc-actor",
            object_uuid="another-proc-object",
        ),
    ]
    summary = _run_probe(tmp_path, rows)
    rate = summary["later_actor_equals_earlier_object_rate"]
    assert rate["denominator"] == 1
    assert rate["numerator"] == 1
    assert rate["rate"] == 1.0


def test_probe_equal_timestamp_process_not_earlier(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            actor_uuid="proc-actor",
            object_uuid="same-ts-object",
        ),
        _file_event(
            1,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            actor_uuid="same-ts-object",
        ),
    ]
    summary = _run_probe(tmp_path, rows)
    rate = summary["later_actor_equals_earlier_object_rate"]
    assert rate["denominator"] == 1
    assert rate["numerator"] == 0
    assert rate["rate"] == 0.0


def test_probe_ppid_match_from_earlier_non_process_event(tmp_path):
    rows = [
        _flow_event(
            0,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            actor_uuid="actor-x",
            pid="100",
            ppid="1",
        ),
        _process_event(
            1,
            timestamp="2020-01-01T00:00:02",
            archive_date="2020-01-01",
            actor_uuid="actor-x",
            object_uuid="proc-child",
            pid="200",
            ppid="100",
        ),
    ]
    summary = _run_probe(tmp_path, rows)
    ppid_diag = summary["ppid_equals_prior_actor_pid_rate"]
    assert ppid_diag["denominator"] == 1
    assert ppid_diag["numerator"] == 1
    assert ppid_diag["rate"] == 1.0


def test_probe_source_does_not_accumulate_all_rows_list():
    source = inspect.getsource(eda9._probe_process_semantics)
    assert "rows.extend(batch.to_pylist())" not in source
    assert "rows: list[dict[str, Any]]" not in source
    assert "for batch in _projection_reader(connection, config):" in source


def test_host_and_window_bounds(tmp_path):
    rows = _base_events() + [
        _process_event(
            30,
            timestamp="2020-01-01T00:00:30",
            archive_date="2020-01-01",
            host="h2",
            actor_uuid="other",
            object_uuid="other2",
        ),
        _process_event(
            31,
            timestamp="2020-01-01T00:02:00",
            archive_date="2020-01-01",
            actor_uuid="late",
            object_uuid="late2",
        ),
    ]
    fixture = _fixture(tmp_path, rows=rows)
    args = _args(tmp_path, fixture)
    eda9.run_eda09(args)
    edges = _load_edges(pathlib.Path(args.output_dir))
    assert (edges["host"] == "h1").all()
    assert not edges["raw_event_id"].str.contains("e031").any()


def test_summary_reconciliation(completed_run):
    _fixture, _args_ns, _meta, output_dir = completed_run
    summary = _load_summary(output_dir)
    edges = _load_edges(output_dir)
    nodes = _load_nodes(output_dir)
    assert summary["reconciliation"]["edge_rows"] == len(edges)
    assert summary["reconciliation"]["node_rows"] == len(nodes)
    assert summary["process_instance_count"] >= summary["process_identity_count"]


def test_outputs_exactly_three_files_and_refuses_existing_output_dir(tmp_path):
    fixture = _fixture(tmp_path)
    args = _args(tmp_path, fixture)
    eda9.run_eda09(args)
    output_dir = pathlib.Path(args.output_dir)
    assert sorted(path.name for path in output_dir.iterdir()) == [
        "edges.csv",
        "graph_summary.json",
        "nodes.csv",
    ]

    with pytest.raises(eda9.CacheAuditError):
        eda9.run_eda09(args)


def test_bounded_batch_reader_used():
    source = pathlib.Path(eda9.__file__).read_text(encoding="utf-8")
    assert "to_arrow_reader" in source
    assert "fetch_record_batch" in source
    assert "fetchdf(" not in source


def test_one_minute_window_runs(tmp_path):
    fixture = _fixture(tmp_path)
    args = _args(tmp_path, fixture)
    meta = eda9.run_eda09(args)
    assert pathlib.Path(args.output_dir).is_dir()
    assert meta["events_scanned"] >= 1

