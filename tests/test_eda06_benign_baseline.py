"""Synthetic, repository-local tests for scale-safe EDA 6."""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import os
import pathlib
import shutil
import sys

import pandas as pd
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src" / "eda"))

import eda_04_event_taxonomy as eda4  # type: ignore
import eda_05_entity_dictionary as eda5  # type: ignore
import eda_06_benign_baseline as eda6  # type: ignore
from optc_streaming_parser import SCHEMA_VERSION, SLIM_EVENT_COLUMNS  # type: ignore


def _event(
    index: int,
    *,
    timestamp: str,
    archive_date: str,
    host: str = "h1",
    user: str = "alice",
    object_type: str = "PROCESS",
    action: str = "START",
    image: str = "",
    parent: str = "",
    file_path: str = "",
    destination: str = "",
) -> dict:
    row = {column: "" for column in SLIM_EVENT_COLUMNS}
    row.update(
        {
            "timestamp_parsed": timestamp,
            "timestamp_raw": timestamp,
            "parse_status": "ok",
            "host_raw": host,
            "user_raw": user,
            "principal_raw": user,
            "object_raw": object_type,
            "action_raw": action,
            "image_path_raw": image,
            "process_raw": image,
            "parent_image_path_raw": parent,
            "parent_process_raw": parent,
            "file_path_raw": file_path,
            "dest_ip_raw": destination,
            "destination_raw": destination,
            "archive_name": f"{archive_date}.tar",
            "member_name": f"{host}.json.gz",
            "line_number": index + 1,
            "raw_event_id": f"e{index:03d}",
            "pid_raw": str(1000 + index),
            "ppid_raw": str(900 + index),
        }
    )
    return row


def _base_events() -> list[dict]:
    return [
        _event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            image="C:\\Program Files\\Base\\base.exe",
            parent="C:\\Windows\\System32\\parent.exe",
        ),
        _event(
            1,
            timestamp="2020-01-02T00:00:00",
            archive_date="2020-01-02",
            image="C:\\Program Files\\Base\\base.exe",
            parent="C:\\Windows\\System32\\parent.exe",
        ),
        _event(
            2,
            timestamp="2020-01-01T01:00:00",
            archive_date="2020-01-01",
            object_type="FILE",
            action="READ",
            file_path="C:\\Temp\\base.txt",
        ),
        _event(
            3,
            timestamp="2020-01-02T01:00:00",
            archive_date="2020-01-02",
            object_type="FLOW",
            action="CONNECT",
            destination="10.0.0.1",
        ),
        _event(
            4,
            timestamp="2020-01-01T03:00:00",
            archive_date="2020-01-01",
            host="h2",
            user="bob",
            image="relative/path/unresolved.exe",
            parent="",
        ),
        # Exactly the shared half-open boundary: evaluation.
        _event(
            5,
            timestamp="2020-01-03T00:00:00",
            archive_date="2020-01-03",
            image="C:\\Users\\alice\\new.exe",
            parent="C:\\Users\\alice\\launcher.exe",
        ),
        _event(
            6,
            timestamp="2020-01-03T00:00:10",
            archive_date="2020-01-03",
            object_type="FILE",
            action="WRITE",
            file_path="C:\\Users\\alice\\new.txt",
        ),
        _event(
            7,
            timestamp="2020-01-03T00:00:20",
            archive_date="2020-01-03",
            object_type="FLOW",
            action="CONNECT",
            destination="8.8.8.8",
        ),
    ]


def _write_period_map(
    root: pathlib.Path,
    *,
    include_benign: bool = True,
    include_evaluation: bool = True,
    benign_start: str = "2020-01-01T00:00:00Z",
    benign_end: str = "2020-01-03T00:00:00Z",
    evaluation_start: str = "2020-01-03T00:00:00Z",
    evaluation_end: str = "2020-01-04T00:00:00Z",
) -> pathlib.Path:
    rows = []
    if include_benign:
        rows.append(
            {
                "period": "baseline",
                "start_time": benign_start,
                "end_time": benign_end,
                "period_role": "verified_benign",
            }
        )
    if include_evaluation:
        rows.append(
            {
                "period": "evaluation",
                "start_time": evaluation_start,
                "end_time": evaluation_end,
                "period_role": "evaluation",
            }
        )
    path = root / "periods.csv"
    pd.DataFrame(rows, columns=eda4.PERIOD_MAP_COLUMNS).to_csv(path, index=False)
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
    pd.DataFrame({"manifest_version": ["synthetic_eda06_v1"]}).to_csv(
        path, index=False
    )
    return path


def _t9_row(
    entity_type: str,
    raw_value: str,
    host_scope: str,
    index: int,
) -> dict:
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

    def add(entity_type: str, raw: str, host: str = ""):
        nonlocal index
        if not raw.strip():
            return
        key = (
            entity_type,
            host if entity_type in ("user_principal", "process", "file_path") else "",
            raw,
        )
        existing = {
            (
                row["entity_type"],
                row["host_if_applicable"]
                if row["entity_type"] in ("user_principal", "process", "file_path")
                else "",
                row["raw_value"],
            )
            for values in by_type.values()
            for row in values
        }
        normalized_host = host if key[1] else ""
        if key in existing:
            return
        by_type[entity_type].append(_t9_row(entity_type, raw, normalized_host, index))
        index += 1

    for event in rows:
        add("host", event["host_raw"])
        add("user_principal", event["user_raw"], event["host_raw"])
        if event["object_raw"] in {
            "PROCESS",
            "FLOW",
            "FILE",
            "MODULE",
            "THREAD",
            "SHELL",
        }:
            add("process", event["image_path_raw"], event["host_raw"])
        if event["object_raw"] == "FILE":
            add("file_path", event["file_path_raw"], event["host_raw"])
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


def _write_t7(root: pathlib.Path, rows: list[dict]) -> pathlib.Path:
    observed = sorted(
        {
            (
                event["object_raw"] or eda4.MISSING_MARKER,
                event["action_raw"] or eda4.MISSING_MARKER,
            )
            for event in rows
        }
    )
    mappings = [
        eda4.semantic_mapping(raw_object, raw_action)
        for raw_object, raw_action in observed
    ]
    path = root / "T7_semantic_event_mapping.csv"
    pd.DataFrame(mappings, columns=eda4.T7_COLUMNS).to_csv(path, index=False)
    return path


def _fixture(root: pathlib.Path, rows: list[dict] | None = None) -> dict:
    events = list(_base_events() if rows is None else rows)
    return {
        "rows": events,
        "cache": _write_cache(root, events),
        "manifest": _write_manifest(root),
        "period_map": _write_period_map(root),
        "t9": _write_t9(root, events),
        "t7": _write_t7(root, events),
    }


def _args(root: pathlib.Path, fixture: dict, **overrides) -> argparse.Namespace:
    values = {
        "project_root": str(pathlib.Path(__file__).resolve().parents[1]),
        "normalized_cache_dir": str(fixture["cache"]),
        "manifest_csv": str(fixture["manifest"]),
        "period_map_csv": str(fixture["period_map"]),
        "entity_dictionary_path": str(fixture["t9"]),
        "semantic_mapping_csv": str(fixture["t7"]),
        "output_dir": str(root / "eda06_out"),
        "window_size": "1min",
        "duckdb_memory_limit": "64MB",
        "duckdb_temp_dir": None,
        "duckdb_threads": 1,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


@pytest.fixture
def completed_run(tmp_path):
    fixture = _fixture(tmp_path)
    cache_file = next(fixture["cache"].glob("*.parquet"))
    fixture["cache_hash_before"] = hashlib.sha256(cache_file.read_bytes()).hexdigest()
    args = _args(tmp_path, fixture)
    metadata = eda6.run_eda06(args)
    return fixture, args, metadata, pathlib.Path(args.output_dir)


def test_exact_output_schemas_and_deliverables(completed_run):
    _, _, _, output = completed_run
    expected = {
        "T11_host_baseline_profile.csv",
        "T12_user_principal_baseline_profile.csv",
        "T13_deviation_feature_table.csv",
        "F7_host_deviation_score_over_time.png",
        "F7_host_deviation_score_over_time.pdf",
        "README.md",
        "eda06_run_metadata.json",
        "eda06_execution.log",
    }
    assert {path.name for path in output.iterdir()} == expected
    assert list(pd.read_csv(output / "T11_host_baseline_profile.csv").columns) == (
        eda6.T11_COLUMNS
    )
    assert list(
        pd.read_csv(output / "T12_user_principal_baseline_profile.csv").columns
    ) == eda6.T12_COLUMNS
    assert list(pd.read_csv(output / "T13_deviation_feature_table.csv").columns) == (
        eda6.T13_COLUMNS
    )


def test_half_open_boundary_and_new_feature_counts(completed_run):
    _, _, _, output = completed_run
    t13 = pd.read_csv(output / "T13_deviation_feature_table.csv")
    boundary = t13.loc[t13["window_start"].str.startswith("2020-01-03T00:00:00")]
    assert len(boundary) == 1
    row = boundary.iloc[0]
    assert row["new_process_count"] == 1
    assert row["new_chain_count"] == 1
    assert row["new_destination_count"] == 1
    assert row["new_path_category_count"] == 1
    assert 0 <= row["semantic_distribution_distance"] <= 1
    assert 0 <= row["deviation_score"] <= 1
    assert json.loads(row["evidence_event_ids"]) == ["e005", "e006", "e007"]


def test_evaluation_events_cannot_alter_baseline_profiles(tmp_path):
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    base = _base_events()
    extra = _event(
        99,
        timestamp="2020-01-03T12:34:00",
        archive_date="2020-01-03",
        image="C:\\Users\\alice\\evaluation-only.exe",
        parent="C:\\Users\\alice\\evaluation-parent.exe",
    )
    outputs = []
    for root, rows in ((first_root, base), (second_root, base + [extra])):
        fixture = _fixture(root, rows)
        args = _args(root, fixture)
        eda6.run_eda06(args)
        output = pathlib.Path(args.output_dir)
        outputs.append(
            (
                pd.read_csv(output / "T11_host_baseline_profile.csv"),
                pd.read_csv(output / "T12_user_principal_baseline_profile.csv"),
            )
        )
    pd.testing.assert_frame_equal(outputs[0][0], outputs[1][0])
    baseline_columns = [
        column
        for column in eda6.T12_COLUMNS
        if column != "unusual_behavior_flags_after_baseline"
    ]
    pd.testing.assert_frame_equal(
        outputs[0][1][baseline_columns], outputs[1][1][baseline_columns]
    )
    assert (
        outputs[0][1]["unusual_behavior_flags_after_baseline"]
        != outputs[1][1]["unusual_behavior_flags_after_baseline"]
    ).any()


def test_missing_verified_benign_interval_fails(tmp_path):
    path = _write_period_map(tmp_path, include_benign=False)
    with pytest.raises(eda6.CacheAuditError, match="verified_benign"):
        eda6.load_eda6_period_policy(path)


def test_missing_evaluation_interval_fails(tmp_path):
    path = _write_period_map(tmp_path, include_evaluation=False)
    with pytest.raises(eda6.CacheAuditError, match="evaluation"):
        eda6.load_eda6_period_policy(path)


def test_benign_coverage_below_24_hours_fails(tmp_path):
    path = _write_period_map(
        tmp_path,
        benign_start="2020-01-01T12:00:00Z",
        benign_end="2020-01-02T11:59:59Z",
        evaluation_start="2020-01-02T11:59:59Z",
    )
    with pytest.raises(eda6.CacheAuditError, match="24 hours"):
        eda6.load_eda6_period_policy(path)


def test_benign_requires_two_dates(tmp_path):
    path = _write_period_map(
        tmp_path,
        benign_start="2020-01-01T00:00:00Z",
        benign_end="2020-01-02T00:00:00Z",
        evaluation_start="2020-01-02T00:00:00Z",
    )
    # Half-open 24 hours touches only January 1.
    with pytest.raises(eda6.CacheAuditError, match="at least two dates"):
        eda6.load_eda6_period_policy(path)


def test_overlap_rejected_by_existing_eda4_validator(tmp_path):
    path = _write_period_map(
        tmp_path,
        benign_end="2020-01-03T12:00:00Z",
        evaluation_start="2020-01-03T00:00:00Z",
    )
    with pytest.raises(eda6.CacheAuditError, match="must not overlap"):
        eda6.load_eda6_period_policy(path)


def test_unassigned_events_fail_reconciliation(tmp_path):
    rows = _base_events()
    rows.append(
        _event(
            100,
            timestamp="2020-01-05T00:00:00",
            archive_date="2020-01-05",
            image="C:\\Program Files\\outside.exe",
        )
    )
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    with pytest.raises(eda6.CacheAuditError, match="unassigned"):
        eda6.run_eda06(args)
    assert not pathlib.Path(args.output_dir).exists()
    assert not any(
        path.name.startswith(".eda06_staging_") for path in tmp_path.iterdir()
    )


def test_canonical_ids_are_from_t9_and_unresolved_process_visible(completed_run):
    fixture, _, _, output = completed_run
    t11 = pd.read_csv(output / "T11_host_baseline_profile.csv")
    t9_parts = sorted(fixture["t9"].glob("*/*.parquet"))
    t9 = pd.concat([pd.read_parquet(path) for path in t9_parts], ignore_index=True)
    known_ids = set(t9["canonical_id"])
    assert set(t11["host_id"]).issubset(known_ids)
    top_entries = [
        entry
        for value in t11["top_10_processes"]
        for entry in json.loads(value)
    ]
    assert all(entry["stable_key"] in known_ids for entry in top_entries)
    unresolved = [entry for entry in top_entries if entry["status"] == "unresolved"]
    assert unresolved
    assert unresolved[0]["reliability"] == "low"


def test_parent_child_pairs_same_event_only_and_no_multihop(completed_run):
    _, _, _, output = completed_run
    t11 = pd.read_csv(output / "T11_host_baseline_profile.csv")
    associations = [
        entry
        for value in t11["top_10_parent_child_chains"]
        for entry in json.loads(value)
    ]
    assert associations
    assert all(entry["stable_key"].startswith("chain_") for entry in associations)
    assert all(entry["parent_raw"] for entry in associations)
    assert all(entry["child_raw"] for entry in associations)
    assert all("child_process_id" in entry for entry in associations)
    assert all(entry["evidence_event_id"] for entry in associations)
    assert all(entry["evidence_archive_name"] for entry in associations)
    assert all(entry["evidence_member_name"] for entry in associations)
    assert all(entry["evidence_line_number"] >= 1 for entry in associations)
    source = inspect.getsource(eda6._create_process_aggregate)
    assert "ppid_raw" not in source
    assert "pid_raw" not in source
    assert "parent_process_id AS child" not in source


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("C:\\Temp\\x", "temporary"),
        ("\\\\server\\share\\x", "network"),
        ("C:\\Windows\\System32\\x", "system"),
        ("C:\\Program Files\\App\\x", "program"),
        ("C:\\Users\\alice\\x", "user"),
        ("\\\\?\\C:\\Windows\\System32\\x", "system"),
        ("\\\\?\\C:\\Program Files\\App\\x", "program"),
        ("\\\\?\\UNC\\server\\share\\x", "network"),
        ("C:\\Other\\x", "other"),
        ("tool.exe", "unknown"),
        ("", "unknown"),
    ],
)
def test_path_category_precedence_and_unknown(raw, expected):
    assert eda6.path_category(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("127.0.0.1", "loopback"),
        ("10.0.0.1", "private"),
        ("169.254.1.1", "link_local"),
        ("224.0.0.1", "multicast"),
        ("0.0.0.0", "unspecified"),
        ("192.0.2.1", "reserved"),
        ("8.8.8.8", "global_syntax"),
        ("fictional.example", "hostname_or_other"),
        ("", "unknown"),
    ],
)
def test_destination_structural_categories(raw, expected):
    assert eda6.destination_category(raw) == expected


def test_normal_hour_half_support_ceiling_rule():
    # Three active dates require ceil(1.5)=2 supporting dates.
    result = eda6.normal_active_hours({0: 3, 1: 2, 2: 1}, 3)
    assert [row["hour"] for row in result] == [0, 1]
    assert result[1]["active_date_share"] == pytest.approx(2 / 3)
    assert eda6.normal_active_hours({}, 0) == []


@pytest.mark.parametrize(
    ("dates", "windows", "possible", "expected"),
    [
        (5, 50, 100, "high"),
        (5, 49, 100, "medium"),
        (3, 20, 100, "medium"),
        (2, 90, 100, "low"),
    ],
)
def test_baseline_confidence_boundaries(dates, windows, possible, expected):
    confidence = eda6.baseline_confidence(dates, windows, possible)
    assert confidence["label"] == expected
    assert confidence["rule_version"] == eda6.CONFIDENCE_RULE_VERSION


def test_jensen_shannon_distance_properties():
    assert eda6.jensen_shannon_divergence({"a": 2}, {"a": 9}) == 0
    orthogonal = eda6.jensen_shannon_divergence({"a": 1}, {"b": 1})
    with_zero = eda6.jensen_shannon_divergence({"a": 1, "b": 0}, {"b": 1})
    assert orthogonal == pytest.approx(1.0)
    assert 0 <= with_zero <= 1
    assert math_is_finite(with_zero)


def math_is_finite(value: float) -> bool:
    import math

    return math.isfinite(value)


def test_deviation_score_exact_formula_and_bounds():
    score = eda6.deviation_score(
        new_process_count=2,
        new_chain_count=0,
        new_destination_count=1,
        new_path_category_count=0,
        unusual_hour_flag=1,
        semantic_distribution_distance=0.5,
    )
    assert score == pytest.approx(3.5 / 6)
    assert 0 <= score <= 1
    assert (
        eda6.deviation_score(
            new_process_count=1,
            new_chain_count=1,
            new_destination_count=1,
            new_path_category_count=1,
            unusual_hour_flag=1,
            semantic_distribution_distance=1,
        )
        == 1
    )


def test_evidence_ordering_uniqueness_and_cap():
    values = [
        [
            {
                "timestamp": pd.Timestamp("2020-01-01T00:00:00"),
                "archive_name": "b.tar",
                "member_name": "m",
                "line_number": index,
                "raw_event_id": f"e{index:02d}",
            }
            for index in range(25, 0, -1)
        ],
        [
            {
                "timestamp": pd.Timestamp("2020-01-01T00:00:00"),
                "archive_name": "a.tar",
                "member_name": "m",
                "line_number": 1,
                "raw_event_id": "first",
            },
            {
                "timestamp": pd.Timestamp("2020-01-01T00:00:00"),
                "archive_name": "a.tar",
                "member_name": "m",
                "line_number": 1,
                "raw_event_id": "first",
            },
        ],
    ]
    result = eda6._ordered_evidence(values)
    assert result[0] == "first"
    assert len(result) == eda6.EVIDENCE_CAP
    assert len(result) == len(set(result))


def test_evidence_flattening_handles_numpy_arrays_without_deprecation():
    import warnings

    import numpy as np

    inner = np.array(
        [
            {
                "event_time": "2020-01-01T00:00:01",
                "archive_name": "a.tar",
                "member_name": "m",
                "line_number": 2,
                "raw_event_id": "second",
            }
        ],
        dtype=object,
    )
    outer = np.empty(2, dtype=object)
    outer[0] = inner
    outer[1] = {
        "event_time": "2020-01-01T00:00:00",
        "archive_name": "a.tar",
        "member_name": "m",
        "line_number": 1,
        "raw_event_id": "first",
    }
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        assert eda6._is_missing(outer) is False
        assert eda6._is_missing(np.array([1.0])) is False
        assert eda6._is_missing(np.float64("nan")) is True
        assert eda6._is_missing(float("nan")) is True
        assert eda6._is_missing(None) is True
        assert eda6._is_missing({"raw_event_id": "x"}) is False
        result = eda6._ordered_evidence([outer, None, float("nan")])
    assert result == ["first", "second"]


def test_core_evidence_aggregate_is_bounded_before_materialization():
    source = inspect.getsource(eda6._create_core_aggregate)
    assert "arg_min(" in source
    assert "list_slice(" not in source


def test_parent_separator_aliases_share_observed_chain_key():
    first = eda6.observed_chain_key(
        "host-id", "C:/Windows/System32/parent.exe", "child-id"
    )
    second = eda6.observed_chain_key(
        "host-id", "C:\\Windows\\System32\\parent.exe", "child-id"
    )
    assert first == second
    assert first != eda6.observed_chain_key(
        "other-host", "C:\\Windows\\System32\\parent.exe", "child-id"
    )


def test_parent_separator_alias_does_not_create_new_evaluation_chain(tmp_path):
    rows = [
        _event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            image="C:\\Program Files\\Base\\base.exe",
            parent="C:\\Windows\\System32\\parent.exe",
        ),
        _event(
            1,
            timestamp="2020-01-02T00:00:00",
            archive_date="2020-01-02",
            image="C:\\Program Files\\Base\\base.exe",
            parent="C:/Windows/System32/parent.exe",
        ),
        _event(
            2,
            timestamp="2020-01-02T01:00:00",
            archive_date="2020-01-02",
            image="C:\\Windows\\System32\\parent.exe",
            parent="",
        ),
        _event(
            3,
            timestamp="2020-01-03T00:00:00",
            archive_date="2020-01-03",
            image="C:\\Program Files\\Base\\base.exe",
            parent="C:/Windows/System32/parent.exe",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    eda6.run_eda06(args)
    t13 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T13_deviation_feature_table.csv"
    )
    assert len(t13) == 1
    assert t13.iloc[0]["new_process_count"] == 0
    assert t13.iloc[0]["new_chain_count"] == 0
    t11 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T11_host_baseline_profile.csv"
    )
    associations = json.loads(t11.iloc[0]["top_10_parent_child_chains"])
    assert len(associations) == 1
    entry = associations[0]
    assert entry["event_count"] == 2
    # The representative is the deterministic earliest benign observation
    # (event 0), and every row-level field comes from that same observation.
    assert entry["evidence_event_id"] == "e000"
    assert entry["evidence_archive_name"] == "2020-01-01.tar"
    assert entry["evidence_member_name"] == "h1.json.gz"
    assert entry["evidence_line_number"] == 1
    assert entry["parent_raw"] == "C:\\Windows\\System32\\parent.exe"
    parent_entity = eda5.normalize_entity(
        entity_type="process",
        raw_value="C:\\Windows\\System32\\parent.exe",
        host_scope="h1",
        source_field="image_path_raw/process_raw_alias",
    )
    assert parent_entity["entity_status"] == "resolved"
    assert entry["parent_process_id"] == parent_entity["canonical_id"]
    assert entry["parent_status"] == parent_entity["entity_status"]
    assert entry["parent_normalized"] == parent_entity["normalized_value"]
    child_entity = eda5.normalize_entity(
        entity_type="process",
        raw_value="C:\\Program Files\\Base\\base.exe",
        host_scope="h1",
        source_field="image_path_raw/process_raw_alias",
    )
    assert entry["child_raw"] == "C:\\Program Files\\Base\\base.exe"
    assert entry["child_process_id"] == child_entity["canonical_id"]
    assert entry["child_label"] == child_entity["normalized_value"]
    assert entry["status"] == child_entity["entity_status"]


def test_nonapplicable_image_path_does_not_enter_process_baseline(tmp_path):
    rows = _base_events()
    rows.append(
        _event(
            100,
            timestamp="2020-01-02T02:00:00",
            archive_date="2020-01-02",
            object_type="REGISTRY",
            action="SET",
            image="C:\\ShouldNot\\be-a-process.exe",
        )
    )
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    eda6.run_eda06(args)
    t11 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T11_host_baseline_profile.csv"
    )
    serialized = "".join(t11["top_10_processes"])
    assert "ShouldNot" not in serialized


def test_t12_post_baseline_flags_and_json_encoding(completed_run):
    _, _, _, output = completed_run
    t12 = pd.read_csv(output / "T12_user_principal_baseline_profile.csv")
    parsed_flags = [
        json.loads(value)
        for value in t12["unusual_behavior_flags_after_baseline"]
    ]
    for flags in parsed_flags:
        assert set(flags) == {
            "new_host_after_baseline",
            "new_user_process_pair_after_baseline",
            "unusual_hour_after_baseline",
        }
    assert max(
        flags["new_user_process_pair_after_baseline"] for flags in parsed_flags
    ) >= 1
    for row in t12.itertuples(index=False):
        for column in (
            "active_hosts",
            "top_processes",
            "top_semantic_groups",
            "common_active_hours",
        ):
            json.loads(getattr(row, column))


def test_f7_created_without_zero_fill(completed_run):
    _, _, _, output = completed_run
    assert (output / "F7_host_deviation_score_over_time.png").stat().st_size > 0
    assert (output / "F7_host_deviation_score_over_time.pdf").stat().st_size > 0
    source = inspect.getsource(eda6.create_f7)
    assert "date_range" not in source
    assert "reindex" not in source
    assert "fillna" not in source
    assert "groupby(segment_ids" in source


def test_deterministic_rerun_tables(tmp_path):
    results = []
    for name in ("first", "second"):
        root = tmp_path / name
        root.mkdir()
        fixture = _fixture(root)
        args = _args(root, fixture)
        eda6.run_eda06(args)
        output = pathlib.Path(args.output_dir)
        results.append(
            [
                (output / filename).read_bytes()
                for filename in (
                    "T11_host_baseline_profile.csv",
                    "T12_user_principal_baseline_profile.csv",
                    "T13_deviation_feature_table.csv",
                )
            ]
        )
    assert results[0] == results[1]


@pytest.mark.parametrize("kind", ["directory", "file", "broken_symlink"])
def test_existing_output_refused_and_preserved(tmp_path, kind):
    fixture = _fixture(tmp_path)
    output = tmp_path / "eda06_out"
    if kind == "directory":
        output.mkdir()
    elif kind == "file":
        output.write_bytes(b"keep")
    else:
        output.symlink_to(tmp_path / "missing")
    args = _args(tmp_path, fixture)
    with pytest.raises(eda6.CacheAuditError, match="must not pre-exist"):
        eda6.run_eda06(args)
    if kind == "directory":
        assert output.is_dir() and not any(output.iterdir())
    elif kind == "file":
        assert output.read_bytes() == b"keep"
    else:
        assert output.is_symlink()


def test_atomic_cleanup_after_injected_publication_failure(tmp_path, monkeypatch):
    fixture = _fixture(tmp_path)
    args = _args(tmp_path, fixture)

    def fail(staging, output):
        raise eda6.CacheAuditError("forced publication failure")

    monkeypatch.setattr(eda6, "_publish_staging", fail)
    with pytest.raises(eda6.CacheAuditError, match="forced publication"):
        eda6.run_eda06(args)
    assert not pathlib.Path(args.output_dir).exists()
    assert not any(
        path.name.startswith(".eda06_staging_") for path in tmp_path.iterdir()
    )


def test_cache_bytes_unchanged_no_drive_and_metadata_reconciles(completed_run):
    fixture, args, metadata, output = completed_run
    cache_file = next(fixture["cache"].glob("*.parquet"))
    stored = json.loads((output / "eda06_run_metadata.json").read_text())
    after = hashlib.sha256(cache_file.read_bytes()).hexdigest()
    assert fixture["cache_hash_before"] == after
    assert metadata["cache_event_count"] == len(fixture["rows"])
    assert metadata["verified_benign_event_count"] == 5
    assert metadata["evaluation_event_count"] == 3
    assert metadata["unassigned_count"] == 0
    assert metadata["payload_scan_count"] == 4
    assert stored["period_map_sha256"] == hashlib.sha256(
        fixture["period_map"].read_bytes()
    ).hexdigest()
    assert "/content/drive" not in json.dumps(stored).lower()
    assert not any(
        path.name.startswith(".") or path.suffix == ".tmp"
        for path in output.rglob("*")
    )
    assert args.window_size == "1min"


def test_cli_and_configuration_validation(tmp_path):
    parser = eda6.build_parser()
    required = {
        action.dest
        for action in parser._actions
        if getattr(action, "required", False)
    }
    assert required == {
        "project_root",
        "normalized_cache_dir",
        "manifest_csv",
        "period_map_csv",
        "entity_dictionary_path",
        "semantic_mapping_csv",
        "output_dir",
    }
    fixture = _fixture(tmp_path)
    with pytest.raises(eda6.CacheAuditError, match="only '1min'"):
        eda6.validate_run_config(_args(tmp_path, fixture, window_size="5min"))
    with pytest.raises(eda6.CacheAuditError, match="Google Drive"):
        eda6.validate_run_config(
            _args(
                tmp_path,
                fixture,
                duckdb_temp_dir="/content/drive/MyDrive/spill",
            )
        )


def test_no_rarity_threshold_or_full_event_materialization():
    source = pathlib.Path(eda6.__file__).read_text(encoding="utf-8")
    assert "rare_benign_max_count=0" not in source
    assert "--rare-benign" not in source
    assert "fetchall()" not in inspect.getsource(eda6.build_outputs)
    assert "FROM events" not in inspect.getsource(eda6.build_outputs)
    assert eda6.PAYLOAD_SCAN_COUNT == 4
    assert "length-2" in eda6._readme(
        {"generated_utc": "2020-01-01T00:00:00Z"}
    )
