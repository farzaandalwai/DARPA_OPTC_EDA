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
    direct = t16.loc[t16["pivot_rule_id"] == "direct_same_event"].iloc[0]
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
    strict = t16.loc[t16["pivot_rule_id"] == "host_temporal_strict"].iloc[0]
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
    strict = t16.loc[t16["pivot_rule_id"] == "host_temporal_strict"].iloc[0]
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
        row = t16.loc[t16["pivot_rule_id"] == rule_id].iloc[0]
        assert int(row["endpoint_flow_events"]) == 1
        assert int(row["matched_network_events"]) == 0
        assert int(row["unmatched_count"]) == 1
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
    assert json.loads(t17.iloc[0]["raw_event_ids"]) == ["e001", "e000"]


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


def _sql_fetches_wholesale_events(sql: str) -> bool:
    normalized = " ".join(str(sql).split()).lower()
    if " from events" not in normalized and " from events\n" not in normalized:
        return False
    if re.search(r"\bgroup\s+by\b", normalized):
        return False
    if re.search(r"\bselect\s+distinct\b", normalized):
        return False
    if "create temp table" in normalized or "create or replace temp table" in normalized:
        return False
    return True


def test_no_wholesale_events_pandas_fetch():
    source = pathlib.Path(eda8.__file__).read_text(encoding="utf-8")
    literals = _query_frame_sql_literals(source)
    offenders = [sql for sql in literals if _sql_fetches_wholesale_events(sql)]
    assert offenders == []

    forbidden = '''
_query_frame(
    connection,
    """SELECT * FROM events""",
)
'''
    forbidden_literals = _query_frame_sql_literals(forbidden)
    assert forbidden_literals == ["SELECT * FROM events"]
    assert _sql_fetches_wholesale_events(forbidden_literals[0])


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
