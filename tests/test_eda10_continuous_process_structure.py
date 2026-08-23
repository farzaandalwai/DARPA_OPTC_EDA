"""Synthetic tests for EDA 10 continuous process-structure analysis."""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import pathlib
import sys

import pandas as pd
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src" / "eda"))

import eda_04_event_taxonomy as eda4  # type: ignore
import eda_09_provenance_graph as eda9  # type: ignore
import eda_10_continuous_process_structure as eda10  # type: ignore
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
            "raw_event_id": f"e{index:04d}",
        }
    )
    return row


def _process_event(
    index: int,
    *,
    timestamp: str,
    archive_date: str,
    action: str = "CREATE",
    image: str = "C:\\Windows\\child.exe",
    parent: str = "C:\\Windows\\parent.exe",
    command: str = "child.exe -x",
    pid: str = "2000",
    ppid: str = "1000",
    actor_uuid: str = "actor-a",
    object_uuid: str = "object-b",
    host: str = "h1",
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
    action: str = "WRITE",
    image: str = "C:\\Windows\\child.exe",
    file_path: str = "C:\\Temp\\x.txt",
    pid: str = "2000",
    ppid: str = "1000",
    actor_uuid: str = "object-b",
    host: str = "h1",
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
            "object_id_raw": f"f-{index}",
        }
    )
    return row


def _flow_event(
    index: int,
    *,
    timestamp: str,
    archive_date: str,
    image: str = "C:\\Windows\\child.exe",
    dest: str = "203.0.113.9",
    port: str = "443",
    protocol: str = "TCP",
    pid: str = "2000",
    ppid: str = "1000",
    actor_uuid: str = "object-b",
    host: str = "h1",
) -> dict:
    row = _base_row(index, timestamp=timestamp, archive_date=archive_date, host=host)
    row.update(
        {
            "object_raw": "FLOW",
            "action_raw": "OPEN",
            "image_path_raw": image,
            "process_raw": image,
            "dest_ip_raw": dest,
            "destination_raw": dest,
            "dest_port_raw": port,
            "protocol_raw": protocol,
            "pid_raw": pid,
            "ppid_raw": ppid,
            "actor_id_raw": actor_uuid,
            "object_id_raw": f"flow-{index}",
        }
    )
    return row


def _module_event(
    index: int,
    *,
    timestamp: str,
    archive_date: str,
    image: str = "C:\\Windows\\child.exe",
    module_path: str = "C:\\Windows\\m.dll",
    pid: str = "2000",
    ppid: str = "1000",
    actor_uuid: str = "object-b",
    host: str = "h1",
) -> dict:
    row = _base_row(index, timestamp=timestamp, archive_date=archive_date, host=host)
    row.update(
        {
            "object_raw": "MODULE",
            "action_raw": "LOAD",
            "image_path_raw": image,
            "process_raw": image,
            "module_path_raw": module_path,
            "pid_raw": pid,
            "ppid_raw": ppid,
            "actor_id_raw": actor_uuid,
            "object_id_raw": f"m-{index}",
        }
    )
    return row


def _write_cache(root: pathlib.Path, rows: list[dict]) -> pathlib.Path:
    cache = root / "cache"
    cache.mkdir(parents=True)
    pd.DataFrame(rows, columns=SLIM_EVENT_COLUMNS).to_parquet(cache / "chunk_00000.parquet", index=False)
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


def _fixture(root: pathlib.Path, rows: list[dict]) -> dict:
    return {
        "rows": rows,
        "cache": _write_cache(root, rows),
        "period_map": _write_period_map(root),
        "t7": _write_t7(root, rows),
    }


def _args(root: pathlib.Path, fixture: dict, **overrides) -> argparse.Namespace:
    values = {
        "normalized_cache_dir": str(fixture["cache"]),
        "period_map_csv": str(fixture["period_map"]),
        "semantic_mapping_csv": str(fixture["t7"]),
        "output_dir": str(root / "eda10_out"),
        "host": "h1",
        "start_time": None,
        "end_time": None,
        "project_root": str(pathlib.Path(__file__).resolve().parents[1]),
        "manifest_csv": None,
        "process_instance_key": "uuid",
        "batch_size": 2,
        "duckdb_memory_limit": "1GB",
        "duckdb_temp_dir": None,
        "duckdb_threads": 2,
        "export_csv": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def _load_parquet(path: pathlib.Path, name: str) -> pd.DataFrame:
    return pd.read_parquet(path / name)


def _load_json(path: pathlib.Path, name: str) -> dict:
    return json.loads((path / name).read_text(encoding="utf-8"))


def test_optional_time_bounds_default_full_host_range(tmp_path):
    rows = [
        _process_event(0, timestamp="2020-01-01T00:00:01", archive_date="2020-01-01"),
        _process_event(1, timestamp="2020-01-01T00:00:10", archive_date="2020-01-01"),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture, start_time=None, end_time=None)
    summary = eda10.run_eda10(args)
    assert summary["events_scanned"] == 2
    assert summary["run_config"]["analysis_start_time"].startswith("2020-01-01T00:00:01")
    assert summary["run_config"]["requested_start_time"] is None
    assert summary["run_config"]["requested_end_time"] is None


def test_optional_time_bounds_subset_window(tmp_path):
    rows = [
        _process_event(0, timestamp="2020-01-01T00:00:01", archive_date="2020-01-01"),
        _process_event(1, timestamp="2020-01-01T00:00:30", archive_date="2020-01-01"),
        _process_event(2, timestamp="2020-01-01T00:01:30", archive_date="2020-01-01"),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(
        tmp_path,
        fixture,
        start_time="2020-01-01T00:00:00",
        end_time="2020-01-01T00:01:00",
    )
    summary = eda10.run_eda10(args)
    assert summary["events_scanned"] == 2


def test_self_uuid_create_suppresses_parent_child_edge(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            actor_uuid="same",
            object_uuid="same",
            image="C:\\Windows\\child-self.exe",
        )
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    out = pathlib.Path(args.output_dir)
    summary = eda10.run_eda10(args)
    edges = _load_parquet(out, "process_create_edges_compact.parquet")
    instances = _load_parquet(out, "process_instances.parquet")
    assert edges.empty
    assert len(instances) == 1
    assert summary["process_instance_count"] == 1
    assert summary["singleton_structure_count"] == 1
    assert summary["process_create_self_uuid_events"] == 1
    assert summary["process_create_self_uuid_edges_suppressed"] == 1


def test_dag_path_distributions_and_singleton_controls(tmp_path):
    # Backbone:
    # A->B->C->D gives 3 hops
    # A->B->E gives 2 hops
    # plus singleton S from FILE actor only gives 0 hops
    rows = [
        _process_event(0, timestamp="2020-01-01T00:00:01", archive_date="2020-01-01", actor_uuid="A", object_uuid="B"),
        _process_event(1, timestamp="2020-01-01T00:00:02", archive_date="2020-01-01", actor_uuid="B", object_uuid="C"),
        _process_event(2, timestamp="2020-01-01T00:00:03", archive_date="2020-01-01", actor_uuid="C", object_uuid="D"),
        _process_event(3, timestamp="2020-01-01T00:00:04", archive_date="2020-01-01", actor_uuid="B", object_uuid="E"),
        _file_event(
            4,
            timestamp="2020-01-01T00:00:05",
            archive_date="2020-01-01",
            actor_uuid="S",
            image="C:\\Windows\\singleton.exe",
            file_path="C:\\Temp\\solo.txt",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    summary = eda10.run_eda10(args)
    metrics = summary["chain_metrics"]
    inc = metrics["root_to_leaf_distribution_including_singletons"]
    exc = metrics["root_to_leaf_distribution_excluding_singletons"]
    assert inc["frequency_by_hops"] == {"0": 1, "2": 1, "3": 1}
    assert inc["path_count"] == 3
    assert exc["frequency_by_hops"] == {"2": 1, "3": 1}
    assert exc["path_count"] == 2
    assert metrics["root_to_leaf_node_distribution_including_singletons"]["frequency_by_nodes"] == {
        "1": 1,
        "3": 1,
        "4": 1,
    }
    assert summary["singleton_structure_count"] == 1


def test_cycle_scc_diagnostics_disable_dag_metrics(tmp_path):
    rows = [
        _process_event(0, timestamp="2020-01-01T00:00:01", archive_date="2020-01-01", actor_uuid="A", object_uuid="B"),
        _process_event(1, timestamp="2020-01-01T00:00:02", archive_date="2020-01-01", actor_uuid="B", object_uuid="A"),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    summary = eda10.run_eda10(args)
    assert summary["graph_is_acyclic"] is False
    assert summary["cyclic_strongly_connected_component_count"] >= 1
    assert summary["number_of_processes_in_cyclic_sccs"] >= 2
    assert summary["cyclic_structure_count"] >= 1
    assert summary["acyclic_structure_count"] == 0
    assert "acyclic structures" in summary["chain_metrics"]["chain_metrics_scope"]
    assert summary["chain_metrics"]["global_longest_process_chain_hops"] is None


def test_global_longest_chain_uses_acyclic_subset_when_cycles_exist(tmp_path):
    rows = [
        _process_event(0, timestamp="2020-01-01T00:00:01", archive_date="2020-01-01", actor_uuid="A", object_uuid="B"),
        _process_event(1, timestamp="2020-01-01T00:00:02", archive_date="2020-01-01", actor_uuid="X", object_uuid="Y"),
        _process_event(2, timestamp="2020-01-01T00:00:03", archive_date="2020-01-01", actor_uuid="Y", object_uuid="X"),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    summary = eda10.run_eda10(args)
    assert summary["graph_is_acyclic"] is False
    assert summary["acyclic_structure_count"] >= 1
    assert summary["cyclic_structure_count"] >= 1
    assert summary["chain_metrics"]["global_longest_process_chain_hops"] == 1


def test_structure_summary_required_fields_and_dual_spans(tmp_path):
    rows = [
        _process_event(0, timestamp="2020-01-01T00:00:01", archive_date="2020-01-01", actor_uuid="P", object_uuid="C"),
        _file_event(
            1,
            timestamp="2020-01-01T00:00:30",
            archive_date="2020-01-01",
            actor_uuid="C",
            image="C:\\Windows\\child.exe",
            file_path="C:\\Temp\\later.txt",
        ),
        _module_event(
            2,
            timestamp="2020-01-01T00:00:40",
            archive_date="2020-01-01",
            actor_uuid="C",
        ),
        _flow_event(
            3,
            timestamp="2020-01-01T00:00:50",
            archive_date="2020-01-01",
            actor_uuid="C",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    out = pathlib.Path(args.output_dir)
    eda10.run_eda10(args)
    structures = _load_parquet(out, "structure_summary.parquet")
    required = {
        "structure_id",
        "observed_root_ids",
        "observed_root_count",
        "process_count",
        "create_edge_count",
        "root_to_leaf_path_count",
        "longest_process_chain_hops",
        "longest_process_chain_nodes",
        "max_children",
        "leaf_count",
        "create_backbone_start",
        "create_backbone_end",
        "create_backbone_duration",
        "full_activity_start",
        "full_activity_end",
        "full_activity_duration",
        "file_count",
        "module_count",
        "destination_count",
    }
    assert required.issubset(set(structures.columns))
    row = structures.iloc[0]
    assert float(row["full_activity_duration"]) >= float(row["create_backbone_duration"])
    assert int(row["file_count"]) >= 1
    assert int(row["module_count"]) >= 1
    assert int(row["destination_count"]) >= 1


def test_chunk_boundary_invariance(tmp_path):
    rows = [
        _process_event(0, timestamp="2020-01-01T00:00:01", archive_date="2020-01-01", actor_uuid="A", object_uuid="B"),
        _process_event(1, timestamp="2020-01-01T00:00:02", archive_date="2020-01-01", actor_uuid="B", object_uuid="C"),
        _file_event(2, timestamp="2020-01-01T00:00:03", archive_date="2020-01-01", actor_uuid="C"),
        _flow_event(3, timestamp="2020-01-01T00:00:04", archive_date="2020-01-01", actor_uuid="C"),
    ]
    fixture = _fixture(tmp_path, rows)
    args_small = _args(tmp_path, fixture, output_dir=str(tmp_path / "out_small"), batch_size=1)
    args_large = _args(tmp_path, fixture, output_dir=str(tmp_path / "out_large"), batch_size=1000)
    s_small = eda10.run_eda10(args_small)
    s_large = eda10.run_eda10(args_large)
    assert s_small["process_instance_count"] == s_large["process_instance_count"]
    assert s_small["process_create_edge_count"] == s_large["process_create_edge_count"]
    assert s_small["chain_metrics"]["root_to_leaf_distribution_including_singletons"] == s_large[
        "chain_metrics"
    ]["root_to_leaf_distribution_including_singletons"]


def test_no_path_materialization_and_dp_style_counts():
    source = pathlib.Path(eda10.__file__).read_text(encoding="utf-8")
    assert "global_longest_process_chain_sequence" in source
    assert "Counter()" in source
    assert "root_to_leaf_hops_including" in source
    assert "all_paths" not in source
    assert "process_event_rows" not in source
    assert "observed_timestamps" not in source
    assert "LIMIT {int(batch_size)} OFFSET {int(offset)}" not in source


def test_outputs_and_summary_files_exist(tmp_path):
    rows = [_process_event(0, timestamp="2020-01-01T00:00:01", archive_date="2020-01-01")]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    out = pathlib.Path(args.output_dir)
    cache_file = next((pathlib.Path(fixture["cache"]).glob("*.parquet")))
    before = hashlib.sha256(cache_file.read_bytes()).hexdigest()
    summary = eda10.run_eda10(args)
    after = hashlib.sha256(cache_file.read_bytes()).hexdigest()
    assert before == after
    assert out.is_dir()
    expected = {
        "process_instances.parquet",
        "process_create_edges_compact.parquet",
        "process_behavior_compact.parquet",
        "structure_summary.parquet",
        "chain_metrics.json",
        "graph_summary.json",
    }
    assert expected.issubset({p.name for p in out.iterdir()})
    assert "left_boundary_caveat" in summary
    assert "right_boundary_caveat" in summary
    assert summary["event_stream_reconciliation_matches"] is True
    assert summary["expected_events_in_analysis_range"] == summary["events_scanned"]
    chain_metrics = _load_json(out, "chain_metrics.json")
    assert "analysis_rule_version" in chain_metrics


def test_duckdb_temp_dir_isolation_and_cleanup(tmp_path):
    rows = [
        _process_event(0, timestamp="2020-01-01T00:00:01", archive_date="2020-01-01", actor_uuid="A", object_uuid="B"),
        _file_event(1, timestamp="2020-01-01T00:00:02", archive_date="2020-01-01", actor_uuid="B"),
    ]
    fixture = _fixture(tmp_path, rows)
    spill_root = tmp_path / "spill_root"
    spill_root.mkdir(parents=True, exist_ok=True)
    sentinel = spill_root / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    args = _args(tmp_path, fixture, duckdb_temp_dir=str(spill_root))
    summary = eda10.run_eda10(args)
    stream_dir = pathlib.Path(summary["stream_duckdb_temp_dir"])
    agg_dir = pathlib.Path(summary["aggregation_duckdb_temp_dir"])
    assert summary["duckdb_temp_dirs_are_distinct"] is True
    assert stream_dir != agg_dir
    assert stream_dir.parent == spill_root
    assert agg_dir.parent == spill_root
    assert not stream_dir.exists()
    assert not agg_dir.exists()
    assert spill_root.exists()
    assert sentinel.exists()


def test_duckdb_temp_root_does_not_change_chain_results(tmp_path):
    rows = [
        _process_event(0, timestamp="2020-01-01T00:00:01", archive_date="2020-01-01", actor_uuid="A", object_uuid="B"),
        _process_event(1, timestamp="2020-01-01T00:00:02", archive_date="2020-01-01", actor_uuid="B", object_uuid="C"),
        _file_event(2, timestamp="2020-01-01T00:00:03", archive_date="2020-01-01", actor_uuid="C"),
    ]
    fixture = _fixture(tmp_path, rows)
    root = tmp_path / "local_spill"
    args_default = _args(tmp_path, fixture, output_dir=str(tmp_path / "out_default"))
    args_root = _args(
        tmp_path,
        fixture,
        output_dir=str(tmp_path / "out_root"),
        duckdb_temp_dir=str(root),
    )
    summary_default = eda10.run_eda10(args_default)
    summary_root = eda10.run_eda10(args_root)
    assert summary_default["process_instance_count"] == summary_root["process_instance_count"]
    assert summary_default["process_create_edge_count"] == summary_root["process_create_edge_count"]
    assert (
        summary_default["chain_metrics"]["root_to_leaf_distribution_including_singletons"]
        == summary_root["chain_metrics"]["root_to_leaf_distribution_including_singletons"]
    )


def test_unequal_length_path_merge_exact_histogram(tmp_path):
    # A->B->D is 2 hops; A->C->E->D is 3 hops.
    rows = [
        _process_event(0, timestamp="2020-01-01T00:00:01", archive_date="2020-01-01", actor_uuid="A", object_uuid="B"),
        _process_event(1, timestamp="2020-01-01T00:00:02", archive_date="2020-01-01", actor_uuid="A", object_uuid="C"),
        _process_event(2, timestamp="2020-01-01T00:00:03", archive_date="2020-01-01", actor_uuid="B", object_uuid="D"),
        _process_event(3, timestamp="2020-01-01T00:00:04", archive_date="2020-01-01", actor_uuid="C", object_uuid="E"),
        _process_event(4, timestamp="2020-01-01T00:00:05", archive_date="2020-01-01", actor_uuid="E", object_uuid="D"),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    summary = eda10.run_eda10(args)
    freq = summary["chain_metrics"]["root_to_leaf_distribution_excluding_singletons"][
        "frequency_by_hops"
    ]
    assert freq == {"2": 1, "3": 1}


def test_multiple_root_component_count(tmp_path):
    rows = [
        _process_event(0, timestamp="2020-01-01T00:00:01", archive_date="2020-01-01", actor_uuid="A", object_uuid="D"),
        _process_event(1, timestamp="2020-01-01T00:00:02", archive_date="2020-01-01", actor_uuid="C", object_uuid="D"),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    summary = eda10.run_eda10(args)
    assert summary["multi_root_component_count"] == 1
    assert summary["single_root_component_count"] == 0


def test_multiple_parent_topology_count(tmp_path):
    rows = [
        _process_event(0, timestamp="2020-01-01T00:00:01", archive_date="2020-01-01", actor_uuid="P1", object_uuid="C"),
        _process_event(1, timestamp="2020-01-01T00:00:02", archive_date="2020-01-01", actor_uuid="P2", object_uuid="C"),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    summary = eda10.run_eda10(args)
    assert summary["multi_parent_process_count"] == 1


def test_action_preserving_behavior_compaction(tmp_path):
    rows = [
        _process_event(0, timestamp="2020-01-01T00:00:01", archive_date="2020-01-01", actor_uuid="A", object_uuid="B"),
        _file_event(
            1,
            timestamp="2020-01-01T00:00:02",
            archive_date="2020-01-01",
            actor_uuid="B",
            action="READ",
            file_path="C:\\Temp\\same.txt",
        ),
        _file_event(
            2,
            timestamp="2020-01-01T00:00:03",
            archive_date="2020-01-01",
            actor_uuid="B",
            action="WRITE",
            file_path="C:\\Temp\\same.txt",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    out = pathlib.Path(args.output_dir)
    eda10.run_eda10(args)
    behaviors = _load_parquet(out, "process_behavior_compact.parquet")
    same = behaviors.loc[behaviors["behavior_key"] == "C:\\Temp\\same.txt"]
    assert sorted(same["action_raw"].tolist()) == ["READ", "WRITE"]
    assert len(same) == 2


def test_eda9_eda10_process_id_equality(tmp_path):
    host_id = "host_test"
    cmp_form = "c:/windows/cmd.exe"
    uuid_value = "uuid-equal-1"
    date_label = "2020-01-01"
    from_eda9 = eda9._resolve_process_instance(
        mode="uuid",
        host_node_id=host_id,
        uuid_text=uuid_value,
        comparison_form=cmp_form,
        pid_text="123",
        date_label=date_label,
    )
    from_eda10 = eda10._resolve_process_instance(
        mode="uuid",
        host_node_id=host_id,
        uuid_text=uuid_value,
        comparison_form=cmp_form,
        pid_text="123",
        date_label=date_label,
    )
    assert from_eda9 is not None and from_eda10 is not None
    assert from_eda9["node_id"] == from_eda10["process_id"]


def test_eda9_eda10_process_id_equality_provisional_fallback(tmp_path):
    host_id = "host_fallback"
    cmp_form = "c:/program files/tool.exe"
    pid_text = "4242"
    date_label = "2020-01-01"
    from_eda9 = eda9._resolve_process_instance(
        mode="uuid",
        host_node_id=host_id,
        uuid_text="",
        comparison_form=cmp_form,
        pid_text=pid_text,
        date_label=date_label,
    )
    from_eda10 = eda10._resolve_process_instance(
        mode="uuid",
        host_node_id=host_id,
        uuid_text="",
        comparison_form=cmp_form,
        pid_text=pid_text,
        date_label=date_label,
    )
    assert from_eda9 is not None and from_eda10 is not None
    assert from_eda9["node_id"] == from_eda10["process_id"]


def test_open_only_ambiguous_uuid_excluded_from_singleton_metrics(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            action="OPEN",
            actor_uuid="open-only-uuid",
            object_uuid="object-open",
        )
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    summary = eda10.run_eda10(args)
    assert summary["process_instances_observed_total"] >= 1
    assert summary["process_instance_count"] == 0
    assert summary["singleton_structure_count"] == 0
    assert summary["process_open_terminate_only_observations_excluded_from_chain_universe"] >= 1


def test_create_with_unresolved_parent_resolvable_child_included(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            action="CREATE",
            parent="",
            ppid="",
            actor_uuid="",
            object_uuid="child-only",
            image="C:\\Windows\\child.exe",
        )
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    summary = eda10.run_eda10(args)
    assert summary["process_instance_count"] == 1
    assert summary["singleton_structure_count"] == 1


def test_create_with_resolvable_parent_unresolved_child_included(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            action="CREATE",
            actor_uuid="parent-only",
            object_uuid="",
            image="",
            pid="",
            parent="C:\\Windows\\parent.exe",
            ppid="888",
        )
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    summary = eda10.run_eda10(args)
    assert summary["process_instance_count"] == 1
    assert summary["singleton_structure_count"] == 1


def test_late_open_does_not_extend_full_activity_end(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            action="CREATE",
            actor_uuid="P",
            object_uuid="C",
        ),
        _process_event(
            1,
            timestamp="2020-01-01T00:20:00",
            archive_date="2020-01-01",
            action="OPEN",
            actor_uuid="C",
            object_uuid="open-object",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    out = pathlib.Path(args.output_dir)
    eda10.run_eda10(args)
    structures = _load_parquet(out, "structure_summary.parquet")
    row = structures.iloc[0]
    assert row["full_activity_end"] == row["create_backbone_end"]


def test_weighted_statistical_definitions():
    stats = eda10._weighted_stats_from_counts({2: 1, 3: 1})
    assert stats["median"] == 2.5
    assert stats["p90"] == 3.0
    assert stats["p95"] == 3.0
    weighted = eda10._weighted_stats_from_counts({1: 8, 5: 2})
    assert weighted["median"] == 1.0
    assert weighted["p90"] == 5.0
    assert weighted["p95"] == 5.0


def test_identity_conflict_same_normalized_identity_no_conflict(tmp_path):
    rows = [
        _file_event(
            0,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            actor_uuid="same-u",
            image="C:\\Windows\\System32\\CMD.EXE",
        ),
        _file_event(
            1,
            timestamp="2020-01-01T00:00:02",
            archive_date="2020-01-01",
            actor_uuid="same-u",
            image="c:/windows/system32/cmd.exe",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    out = pathlib.Path(args.output_dir)
    summary = eda10.run_eda10(args)
    proc = _load_parquet(out, "process_instances.parquet")
    assert int(summary["identity_attribute_conflict_count"]) == 0
    assert summary["chain_metrics_interpretation_status"] == "clean"
    assert bool(proc["identity_attribute_conflict"].any()) is False


def test_identity_conflict_blank_then_real_no_conflict(tmp_path):
    rows = [
        _process_event(
            0,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            action="OPEN",
            actor_uuid="same-u",
            object_uuid="open-o",
            image="",
        ),
        _file_event(
            1,
            timestamp="2020-01-01T00:00:02",
            archive_date="2020-01-01",
            actor_uuid="same-u",
            image="C:\\Windows\\real.exe",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    out = pathlib.Path(args.output_dir)
    summary = eda10.run_eda10(args)
    proc = _load_parquet(out, "process_instances.parquet")
    assert int(summary["identity_attribute_conflict_count"]) == 0
    assert summary["chain_metrics_interpretation_status"] == "clean"
    assert bool(proc["identity_attribute_conflict"].any()) is False


def test_identity_conflict_genuine_mismatch_is_flagged(tmp_path):
    rows = [
        _file_event(
            0,
            timestamp="2020-01-01T00:00:01",
            archive_date="2020-01-01",
            actor_uuid="same-u",
            image="C:\\Windows\\a.exe",
        ),
        _file_event(
            1,
            timestamp="2020-01-01T00:00:02",
            archive_date="2020-01-01",
            actor_uuid="same-u",
            image="C:\\Windows\\b.exe",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    out = pathlib.Path(args.output_dir)
    summary = eda10.run_eda10(args)
    proc = _load_parquet(out, "process_instances.parquet")
    assert int(summary["identity_attribute_conflict_count"]) == 1
    assert summary["chain_metrics_interpretation_status"] == "requires_identity_conflict_review"
    assert len(summary["identity_attribute_conflict_process_ids_sample"]) >= 1
    assert bool(proc["identity_attribute_conflict"].any()) is True


def test_structure_id_membership_on_process_and_behavior(tmp_path):
    rows = [
        _process_event(0, timestamp="2020-01-01T00:00:01", archive_date="2020-01-01", actor_uuid="A", object_uuid="B"),
        _file_event(1, timestamp="2020-01-01T00:00:02", archive_date="2020-01-01", actor_uuid="B"),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    out = pathlib.Path(args.output_dir)
    eda10.run_eda10(args)
    proc = _load_parquet(out, "process_instances.parquet")
    beh = _load_parquet(out, "process_behavior_compact.parquet")
    included = proc.loc[proc["included_in_chain_universe"] == True]
    assert not included.empty
    assert (included["structure_id"].astype(str).str.strip() != "").all()
    assert (beh["structure_id"].astype(str).str.strip() != "").all()


def test_first_last_count_aggregation_batch_invariance(tmp_path):
    rows = [
        _process_event(0, timestamp="2020-01-01T00:00:01", archive_date="2020-01-01", actor_uuid="A", object_uuid="B"),
        _file_event(1, timestamp="2020-01-01T00:00:02", archive_date="2020-01-01", actor_uuid="B", file_path="C:\\Temp\\agg.txt"),
        _file_event(2, timestamp="2020-01-01T00:00:03", archive_date="2020-01-01", actor_uuid="B", file_path="C:\\Temp\\agg.txt"),
        _file_event(3, timestamp="2020-01-01T00:00:04", archive_date="2020-01-01", actor_uuid="B", file_path="C:\\Temp\\agg.txt"),
    ]
    fixture = _fixture(tmp_path, rows)
    args_small = _args(tmp_path, fixture, output_dir=str(tmp_path / "out_bs1"), batch_size=1)
    args_large = _args(tmp_path, fixture, output_dir=str(tmp_path / "out_bs999"), batch_size=999)
    eda10.run_eda10(args_small)
    eda10.run_eda10(args_large)
    b_small = _load_parquet(pathlib.Path(args_small.output_dir), "process_behavior_compact.parquet")
    b_large = _load_parquet(pathlib.Path(args_large.output_dir), "process_behavior_compact.parquet")
    cols = [
        "process_id",
        "behavior_type",
        "action_raw",
        "behavior_key",
        "attach_event_count",
        "first_seen_time",
        "last_seen_time",
        "first_raw_event_id",
        "last_raw_event_id",
    ]
    pd.testing.assert_frame_equal(
        b_small[cols].sort_values(cols[:4]).reset_index(drop=True),
        b_large[cols].sort_values(cols[:4]).reset_index(drop=True),
    )


def test_no_blank_structural_ids(tmp_path):
    rows = [
        _process_event(0, timestamp="2020-01-01T00:00:01", archive_date="2020-01-01", actor_uuid="A", object_uuid="B"),
        _process_event(1, timestamp="2020-01-01T00:00:02", archive_date="2020-01-01", actor_uuid="B", object_uuid="C"),
        _file_event(2, timestamp="2020-01-01T00:00:03", archive_date="2020-01-01", actor_uuid="C"),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    out = pathlib.Path(args.output_dir)
    eda10.run_eda10(args)
    proc = _load_parquet(out, "process_instances.parquet")
    edges = _load_parquet(out, "process_create_edges_compact.parquet")
    included = proc.loc[proc["included_in_chain_universe"] == True]
    assert (included["process_id"].astype(str).str.strip() != "").all()
    if not edges.empty:
        assert (edges["parent_process_id"].astype(str).str.strip() != "").all()
        assert (edges["child_process_id"].astype(str).str.strip() != "").all()

