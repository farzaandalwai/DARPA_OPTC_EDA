"""Synthetic, cache-only tests for scale-safe EDA 4."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import random
import sys

import pandas as pd
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src" / "eda"))

import eda_04_event_taxonomy as eda4  # type: ignore
from optc_streaming_parser import SCHEMA_VERSION, SLIM_EVENT_COLUMNS  # type: ignore


def _events() -> list[dict]:
    rows = [
        # Earliest tie is resolved by archive/member/line/id, not input order.
        ("2019-09-16T00:00:00", "h1", "PROCESS", "START", "a.tar", "m.json.gz", 2, "e2"),
        ("2019-09-16T00:00:00", "h1", "process", "start", "a.tar", "m.json.gz", 1, "e1"),
        ("2019-09-16T00:01:00", "h1", "FILE", "READ", "a.tar", "m.json.gz", 3, "e3"),
        ("2019-09-16T00:02:00", "h2", "FLOW", "CONNECT", "a.tar", "n.json.gz", 4, "e4"),
        ("2019-09-16T00:03:00", "h2", "", "", "b.tar", "n.json.gz", 5, "e5"),
        ("2019-09-16T00:04:00", "h1", "FILE", "READ", "b.tar", "m.json.gz", 6, "e6"),
    ]
    events = []
    for timestamp, host, obj, action, archive, member, line, event_id in rows:
        event = {column: "" for column in SLIM_EVENT_COLUMNS}
        event.update(
            {
                "timestamp_parsed": timestamp,
                "host_raw": host,
                "object_raw": obj,
                "action_raw": action,
                "parse_status": "ok",
                "archive_name": archive,
                "member_name": member,
                "line_number": line,
                "raw_event_id": event_id,
            }
        )
        events.append(event)
    return events


def _write_cache(
    root: pathlib.Path,
    events: list[dict] | None = None,
    *,
    columns: list[str] | None = None,
    metadata_total: int | None = None,
) -> pathlib.Path:
    cache = root / "cache"
    cache.mkdir(parents=True)
    rows = _events() if events is None else events
    frame = pd.DataFrame(rows)
    selected = columns or list(SLIM_EVENT_COLUMNS)
    frame[selected].to_parquet(cache / "chunk_00000.parquet", index=False)
    metadata = {
        "schema_version": SCHEMA_VERSION,
        "total_events_written": (
            len(rows) if metadata_total is None else metadata_total
        ),
        "sampling_strategy": "full",
    }
    (cache / "cache_metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
    return cache


def _write_manifest(root: pathlib.Path) -> pathlib.Path:
    manifest = root / "manifest.csv"
    pd.DataFrame(
        {
            "manifest_version": ["pilot_manifest_10gb_v1"],
            "archive_filename": ["a.tar"],
            "member_name": ["m.json.gz"],
            "archive_date": ["2019-09-16"],
            "inferred_host_or_client": ["h1"],
            "member_size_gib": [1.0],
        }
    ).to_csv(manifest, index=False)
    return manifest


def _args(
    tmp_path: pathlib.Path,
    cache: pathlib.Path,
    manifest: pathlib.Path,
    **overrides,
) -> argparse.Namespace:
    values = {
        "project_root": str(pathlib.Path(__file__).resolve().parents[1]),
        "normalized_cache_dir": str(cache),
        "manifest_csv": str(manifest),
        "output_dir": str(tmp_path / "eda04_out"),
        "duckdb_memory_limit": "64MB",
        "duckdb_temp_dir": None,
        "duckdb_threads": 1,
        "period_map_csv": None,
        "rare_benign_max_count": None,
        "max_pattern_rows": 100_000,
        "heatmap_top_objects": 30,
        "heatmap_top_actions": 30,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def _policy_none() -> eda4.PeriodPolicy:
    return eda4.load_period_policy(None, None)


def _compact(tmp_path: pathlib.Path, events: list[dict] | None = None):
    cache = _write_cache(tmp_path, events)
    con, spill, owned = eda4._duck_conn(cache, memory_limit="64MB", threads=1)
    try:
        eda4.validate_required_cache_columns(con)
        eda4._register_periods(con, _policy_none())
        return eda4.fetch_primary_aggregate(con)
    finally:
        con.close()
        if owned:
            import shutil

            shutil.rmtree(spill, ignore_errors=True)


@pytest.mark.parametrize(
    ("object_type", "expected"),
    [
        ("PROCESS", "process_activity"),
        ("THREAD", "process_activity"),
        ("FILE", "file_activity"),
        ("MODULE", "module_activity"),
        ("FLOW", "network_activity"),
        ("REGISTRY", "configuration_activity"),
        ("SERVICE", "configuration_activity"),
        ("TASK", "configuration_activity"),
        ("USER_SESSION", "identity_session_activity"),
    ],
)
def test_deterministic_closed_semantic_mapping(object_type, expected):
    first = eda4.semantic_mapping(object_type, "SomeAction")
    second = eda4.semantic_mapping(object_type.lower(), "SomeAction")
    assert first["semantic_group"] == expected
    assert second["semantic_group"] == expected
    assert first["keep_raw_fields_yes_no"] == "yes"


@pytest.mark.parametrize("object_type", [None, "", "UNKNOWN_FUTURE_TYPE"])
def test_unknown_and_missing_map_to_other(object_type):
    assert eda4.semantic_mapping(object_type, "x")["semantic_group"] == "other_activity"


def test_t7_preserves_raw_object_and_action_labels(tmp_path):
    compact = _compact(tmp_path)
    t7 = eda4.build_t7(compact)
    assert {"PROCESS", "process"}.issubset(set(t7["raw_object_type"]))
    assert {"START", "start"}.issubset(set(t7["raw_action_type"]))
    assert (t7["keep_raw_fields_yes_no"] == "yes").all()


def test_t6_aggregation_times_and_period_percentages(tmp_path):
    compact = _compact(tmp_path)
    t6 = eda4.build_t6(compact)
    process = t6[
        (t6["host"] == "h1")
        & (t6["object_type"] == "PROCESS")
        & (t6["action_type"] == "START")
    ].iloc[0]
    assert int(process["event_count"]) == 2
    assert process["first_seen_time"] == "2019-09-16T00:00:00"
    assert process["last_seen_time"] == "2019-09-16T00:00:00"
    assert int(t6["event_count"].sum()) == 6
    assert t6.groupby("period")["percent_of_period_events"].sum().iloc[0] == pytest.approx(
        100.0
    )


def test_metadata_and_t6_total_reconciliation(tmp_path):
    compact = _compact(tmp_path)
    t6, t7 = eda4.build_t6(compact), eda4.build_t7(compact)
    t8 = eda4.build_t8(compact, _policy_none(), None, 100)
    assert eda4.validate_integrity(
        compact,
        t6,
        t7,
        t8,
        {"total_events_written": 6},
    ) == 6
    with pytest.raises(eda4.CacheAuditError, match="total_events_written"):
        eda4.validate_integrity(
            compact, t6, t7, t8, {"total_events_written": 7}
        )


def test_pattern_ids_and_evidence_are_order_independent(tmp_path):
    compact = _compact(tmp_path)
    normal = eda4.build_t8(compact, _policy_none(), None, 100)
    reversed_rows = eda4.build_t8(
        compact.iloc[::-1].reset_index(drop=True), _policy_none(), None, 100
    )
    pd.testing.assert_frame_equal(normal, reversed_rows)
    process = normal[
        normal["object_action_pair"]
        == eda4.object_action_pair("PROCESS", "START")
    ].iloc[0]
    assert process["raw_event_example_id"] == "e1"
    assert process["line_number"] == 1
    assert process["pattern_id"] == eda4.deterministic_pattern_id(
        "h1", eda4.object_action_pair("PROCESS", "START")
    )


def test_default_unassigned_t8_is_deferred_and_null(tmp_path):
    compact = _compact(tmp_path)
    t8 = eda4.build_t8(compact, _policy_none(), None, 100)
    assert set(t8["period"]) == {eda4.DEFAULT_PERIOD}
    assert set(t8["rarity_status"]) == {eda4.DEFERRED_RARITY_STATUS}
    assert t8["benign_frequency"].isna().all()
    assert t8["evaluation_frequency"].isna().all()
    wording = " ".join(t8["rare_reason"]).lower()
    assert "deferred" in wording
    assert "malicious" not in wording
    assert "attack" not in wording


def _write_period_map(root: pathlib.Path, rows: list[dict]) -> pathlib.Path:
    path = root / "periods.csv"
    pd.DataFrame(rows).to_csv(path, index=False)
    return path


def test_valid_period_assignment_and_benign_only_threshold(tmp_path):
    period_map = _write_period_map(
        tmp_path,
        [
            {
                "period": "known_baseline",
                "start_time": "2019-09-16T00:00:00Z",
                "end_time": "2019-09-16T00:02:00Z",
                "period_role": "verified_benign",
            },
            {
                "period": "held_out",
                "start_time": "2019-09-16T00:02:00Z",
                "end_time": "2019-09-16T00:04:00Z",
                "period_role": "evaluation",
            },
        ],
    )
    policy = eda4.load_period_policy(str(period_map), 1)
    cache = _write_cache(tmp_path / "data")
    con, spill, owned = eda4._duck_conn(cache, memory_limit="64MB", threads=1)
    try:
        eda4._register_periods(con, policy)
        compact = eda4.fetch_primary_aggregate(con)
    finally:
        con.close()
        if owned:
            import shutil

            shutil.rmtree(spill, ignore_errors=True)
    assert set(compact["period"]) == {
        "known_baseline",
        "held_out",
        eda4.DEFAULT_PERIOD,
    }
    t8 = eda4.build_t8(compact, policy, 1, 100)
    flow = t8[
        t8["object_action_pair"] == eda4.object_action_pair("FLOW", "CONNECT")
    ].iloc[0]
    assert flow["benign_frequency"] == 0
    assert flow["evaluation_frequency"] == 1
    assert flow["rarity_status"] == "first_seen_in_evaluation"
    process = t8[
        t8["object_action_pair"] == eda4.object_action_pair("PROCESS", "START")
    ].iloc[0]
    # Two evaluation events added elsewhere would not change this benign count/status.
    assert process["benign_frequency"] == 2
    assert process["rarity_status"] == "common_in_verified_benign"


@pytest.mark.parametrize(
    "rows,match",
    [
        (
            [
                {
                    "period": "x",
                    "start_time": "bad",
                    "end_time": "2019-01-02",
                    "period_role": "other",
                }
            ],
            "invalid start_time",
        ),
        (
            [
                {
                    "period": "x",
                    "start_time": "2019-01-02",
                    "end_time": "2019-01-01",
                    "period_role": "other",
                }
            ],
            "end_time > start_time",
        ),
        (
            [
                {
                    "period": "x",
                    "start_time": "2019-01-01",
                    "end_time": "2019-01-03",
                    "period_role": "other",
                },
                {
                    "period": "y",
                    "start_time": "2019-01-02",
                    "end_time": "2019-01-04",
                    "period_role": "evaluation",
                },
            ],
            "must not overlap",
        ),
    ],
)
def test_invalid_period_maps_rejected(tmp_path, rows, match):
    path = _write_period_map(tmp_path, rows)
    with pytest.raises(eda4.CacheAuditError, match=match):
        eda4.load_period_policy(str(path), None)


def test_verified_benign_requires_threshold(tmp_path):
    path = _write_period_map(
        tmp_path,
        [
            {
                "period": "baseline",
                "start_time": "2019-01-01",
                "end_time": "2019-01-02",
                "period_role": "verified_benign",
            }
        ],
    )
    with pytest.raises(eda4.CacheAuditError, match="rare-benign-max-count"):
        eda4.load_period_policy(str(path), None)


def test_t8_max_row_guard_precedes_final_writes(tmp_path):
    cache = _write_cache(tmp_path)
    manifest = _write_manifest(tmp_path)
    args = _args(tmp_path, cache, manifest, max_pattern_rows=1)
    with pytest.raises(eda4.CacheAuditError, match="T8 requires"):
        eda4.run_eda04(args)
    assert not pathlib.Path(args.output_dir).exists()


def test_required_column_failure(tmp_path):
    columns = [column for column in SLIM_EVENT_COLUMNS if column != "action_raw"]
    cache = _write_cache(tmp_path, columns=columns)
    con, spill, owned = eda4._duck_conn(cache, memory_limit="64MB", threads=1)
    try:
        with pytest.raises(eda4.CacheAuditError, match="action_raw"):
            eda4.validate_required_cache_columns(con)
    finally:
        con.close()
        if owned:
            import shutil

            shutil.rmtree(spill, ignore_errors=True)


def test_duckdb_memory_thread_and_temp_validation(tmp_path):
    assert eda4._validate_duckdb_memory_limit("1.5GiB") == "1.5GiB"
    assert eda4._validate_duckdb_threads(2) == 2
    with pytest.raises(eda4.CacheAuditError):
        eda4._validate_duckdb_memory_limit("4GB; DROP TABLE x")
    with pytest.raises(eda4.CacheAuditError):
        eda4._validate_duckdb_threads(0)
    with pytest.raises(eda4.CacheAuditError, match="Google Drive"):
        eda4._validate_duckdb_temp_dir("/content/drive/MyDrive/spill")


def test_owned_spill_removed_and_explicit_spill_preserved(tmp_path):
    cache = _write_cache(tmp_path)
    con, spill, owned = eda4._duck_conn(cache, memory_limit="64MB", threads=1)
    assert owned and pathlib.Path(spill).is_dir()
    con.close()
    import shutil

    shutil.rmtree(spill, ignore_errors=True)
    assert not pathlib.Path(spill).exists()

    explicit = tmp_path / "explicit_spill"
    con, spill, owned = eda4._duck_conn(
        cache, memory_limit="64MB", threads=1, temp_dir=str(explicit)
    )
    con.close()
    assert not owned
    assert pathlib.Path(spill).is_dir()


def test_complete_run_outputs_cleanup_figures_and_cache_unchanged(tmp_path):
    cache = _write_cache(tmp_path)
    manifest = _write_manifest(tmp_path)
    parquet = next(cache.glob("*.parquet"))
    before = hashlib.sha256(parquet.read_bytes()).hexdigest()
    args = _args(
        tmp_path,
        cache,
        manifest,
        heatmap_top_objects=2,
        heatmap_top_actions=2,
    )
    metadata = eda4.run_eda04(args)
    output = pathlib.Path(args.output_dir)
    expected = {
        "T6_object_action_frequency.csv",
        "T7_semantic_event_mapping.csv",
        "T8_rare_first_seen_patterns.csv",
        "F5_object_action_heatmap.png",
        "F5_object_action_heatmap.pdf",
        "README_eda04_event_taxonomy.txt",
        "eda04_run_metadata.json",
    }
    assert {path.name for path in output.iterdir()} == expected
    assert all((output / name).stat().st_size > 0 for name in expected)
    assert not any(path.name.startswith(".") for path in output.iterdir())
    assert hashlib.sha256(parquet.read_bytes()).hexdigest() == before
    assert metadata["number_of_payload_scans"] == 1
    assert metadata["aggregated_event_count"] == 6
    t6 = pd.read_csv(output / "T6_object_action_frequency.csv")
    assert len(t6) > metadata["heatmap_limits"]["displayed_objects"]
    assert int(t6["event_count"].sum()) == 6
    readme = (output / "README_eda04_event_taxonomy.txt").read_text()
    assert "full_pilot_unassigned" in readme
    assert "1 minute as primary and 5 minutes as backup" in readme
    assert "transition analysis is deferred" in readme


def test_existing_nonempty_output_directory_rejected_byte_identical(tmp_path):
    cache = _write_cache(tmp_path)
    manifest = _write_manifest(tmp_path)
    output = tmp_path / "eda04_out"
    output.mkdir()
    marker = output / "keep.txt"
    marker.write_bytes(b"user data")
    before = hashlib.sha256(marker.read_bytes()).hexdigest()
    with pytest.raises(eda4.CacheAuditError, match="must not pre-exist"):
        eda4.run_eda04(_args(tmp_path, cache, manifest))
    assert hashlib.sha256(marker.read_bytes()).hexdigest() == before
    assert {path.name for path in output.iterdir()} == {"keep.txt"}


def test_existing_empty_output_directory_rejected_and_untouched(tmp_path):
    cache = _write_cache(tmp_path)
    manifest = _write_manifest(tmp_path)
    output = tmp_path / "eda04_out"
    output.mkdir()
    with pytest.raises(eda4.CacheAuditError, match="must not pre-exist"):
        eda4.run_eda04(_args(tmp_path, cache, manifest))
    assert output.is_dir()
    assert not any(output.iterdir())


def test_missing_output_dir_published_via_single_directory_rename(
    tmp_path, monkeypatch
):
    import os as os_module

    cache = _write_cache(tmp_path)
    manifest = _write_manifest(tmp_path)
    args = _args(tmp_path, cache, manifest)
    output = pathlib.Path(args.output_dir)
    calls: list[tuple[str, str]] = []
    original_replace = os_module.replace

    def recording_replace(src, dst, *extra, **kwargs):
        calls.append((str(src), str(dst)))
        return original_replace(src, dst, *extra, **kwargs)

    monkeypatch.setattr(eda4.os, "replace", recording_replace)
    eda4.run_eda04(args)
    publication_calls = [
        (src, dst) for src, dst in calls if pathlib.Path(dst) == output
    ]
    assert len(publication_calls) == 1
    staging_src = pathlib.Path(publication_calls[0][0])
    assert staging_src.name.startswith(".eda04_staging_")
    assert output.is_dir()
    # No per-file moves into the final directory ever occurred.
    assert not any(pathlib.Path(dst).parent == output for _, dst in calls)


def test_broken_symlink_output_dir_rejected_and_preserved(tmp_path):
    import os as os_module

    cache = _write_cache(tmp_path)
    manifest = _write_manifest(tmp_path)
    output = tmp_path / "eda04_out"
    dangling_target = tmp_path / "does_not_exist"
    output.symlink_to(dangling_target)
    assert not output.exists()  # Path.exists() follows the dangling link
    assert os_module.path.lexists(output)
    with pytest.raises(eda4.CacheAuditError, match="must not pre-exist"):
        eda4.run_eda04(_args(tmp_path, cache, manifest))
    assert output.is_symlink()
    assert os_module.readlink(output) == str(dangling_target)


def test_publish_race_broken_symlink_refused_and_staging_untouched(tmp_path):
    import os as os_module

    staging = tmp_path / ".eda04_staging_test"
    staging.mkdir()
    marker = staging / "marker.txt"
    marker.write_text("staged content")
    output = tmp_path / "final_out"
    dangling_target = tmp_path / "missing_target"
    output.symlink_to(dangling_target)
    with pytest.raises(eda4.CacheAuditError, match="appeared before publication"):
        eda4._publish_staging(staging, output)
    # The pre-existing symlink was not replaced or retargeted.
    assert output.is_symlink()
    assert os_module.readlink(output) == str(dangling_target)
    # The staging directory and its contents remain unchanged.
    assert staging.is_dir()
    assert marker.read_text() == "staged content"
    assert {path.name for path in staging.iterdir()} == {"marker.txt"}


def test_publication_failure_leaves_no_partial_output_or_staging(
    tmp_path, monkeypatch
):
    cache = _write_cache(tmp_path)
    manifest = _write_manifest(tmp_path)
    args = _args(tmp_path, cache, manifest)
    output = pathlib.Path(args.output_dir)

    def failing_publish(staging, output_dir):
        raise eda4.CacheAuditError("forced publication failure")

    monkeypatch.setattr(eda4, "_publish_staging", failing_publish)
    with pytest.raises(eda4.CacheAuditError, match="forced publication failure"):
        eda4.run_eda04(args)
    assert not output.exists()
    leftovers = [
        path.name
        for path in output.parent.iterdir()
        if path.name.startswith(".eda04_staging_")
    ]
    assert leftovers == []


def test_payload_query_budget_is_exactly_one(tmp_path, monkeypatch):
    cache = _write_cache(tmp_path)
    manifest = _write_manifest(tmp_path)
    original = eda4._duck_conn
    observed = {"payload": 0, "closed": False}

    class CountingConnection:
        def __init__(self, connection):
            self.connection = connection

        def execute(self, sql, *args, **kwargs):
            if "FROM events" in str(sql):
                observed["payload"] += 1
            return self.connection.execute(sql, *args, **kwargs)

        def register(self, *args, **kwargs):
            return self.connection.register(*args, **kwargs)

        def unregister(self, *args, **kwargs):
            return self.connection.unregister(*args, **kwargs)

        def close(self):
            observed["closed"] = True
            return self.connection.close()

    def wrapped(*args, **kwargs):
        connection, spill, owned = original(*args, **kwargs)
        return CountingConnection(connection), spill, owned

    monkeypatch.setattr(eda4, "_duck_conn", wrapped)
    eda4.run_eda04(_args(tmp_path, cache, manifest))
    assert observed == {"payload": 1, "closed": True}


def test_connection_and_owned_spill_cleanup_on_failure(tmp_path, monkeypatch):
    cache = _write_cache(tmp_path)
    manifest = _write_manifest(tmp_path)
    original = eda4._duck_conn
    state = {}

    class ClosingConnection:
        def __init__(self, connection):
            self.connection = connection

        def execute(self, *args, **kwargs):
            return self.connection.execute(*args, **kwargs)

        def register(self, *args, **kwargs):
            return self.connection.register(*args, **kwargs)

        def unregister(self, *args, **kwargs):
            return self.connection.unregister(*args, **kwargs)

        def close(self):
            state["closed"] = True
            return self.connection.close()

    def wrapped(*args, **kwargs):
        connection, spill, owned = original(*args, **kwargs)
        state["spill"] = pathlib.Path(spill)
        return ClosingConnection(connection), spill, owned

    monkeypatch.setattr(eda4, "_duck_conn", wrapped)
    monkeypatch.setattr(
        eda4,
        "fetch_primary_aggregate",
        lambda _connection: (_ for _ in ()).throw(eda4.CacheAuditError("forced")),
    )
    with pytest.raises(eda4.CacheAuditError, match="forced"):
        eda4.run_eda04(_args(tmp_path, cache, manifest))
    assert state["closed"]
    assert not state["spill"].exists()


def test_cli_conflicts_and_full_pilot_requires_no_archives(tmp_path):
    parser = eda4.build_parser()
    args = parser.parse_args(
        [
            "--project-root",
            str(tmp_path),
            "--normalized-cache-dir",
            str(tmp_path / "cache"),
            "--manifest-csv",
            str(tmp_path / "manifest.csv"),
            "--output-dir",
            str(tmp_path / "out"),
        ]
    )
    assert not hasattr(args, "corrected_dir")
    assert not hasattr(args, "archives")
    assert args.duckdb_memory_limit == "4GB"
    assert args.duckdb_threads == 2
    assert args.max_pattern_rows == 100_000
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "--project-root",
                str(tmp_path),
                "--normalized-cache-dir",
                str(tmp_path / "cache"),
                "--manifest-csv",
                str(tmp_path / "manifest.csv"),
            ]
        )


def test_rarity_threshold_without_period_map_rejected(tmp_path):
    cache = _write_cache(tmp_path)
    manifest = _write_manifest(tmp_path)
    args = _args(tmp_path, cache, manifest, rare_benign_max_count=1)
    with pytest.raises(eda4.CacheAuditError, match="only with --period-map-csv"):
        eda4.validate_run_config(args)


def test_t7_preserves_exact_whitespace_and_case_raw_labels(tmp_path):
    rows = [
        ("2019-09-16T00:00:00", "h1", " PROCESS ", " START ", "a.tar", "m.json.gz", 1, "w1"),
        ("2019-09-16T00:01:00", "h1", "process", "start", "a.tar", "m.json.gz", 2, "w2"),
        ("2019-09-16T00:02:00", "h1", "PROCESS", "START", "a.tar", "m.json.gz", 3, "w3"),
    ]
    events = []
    for timestamp, host, obj, action, archive, member, line, event_id in rows:
        event = {column: "" for column in SLIM_EVENT_COLUMNS}
        event.update(
            {
                "timestamp_parsed": timestamp,
                "host_raw": host,
                "object_raw": obj,
                "action_raw": action,
                "parse_status": "ok",
                "archive_name": archive,
                "member_name": member,
                "line_number": line,
                "raw_event_id": event_id,
            }
        )
        events.append(event)
    compact = _compact(tmp_path, events)

    t6 = eda4.build_t6(compact)
    assert len(t6) == 1
    merged = t6.iloc[0]
    assert merged["object_type"] == "PROCESS"
    assert merged["action_type"] == "START"
    assert int(merged["event_count"]) == 3

    t7 = eda4.build_t7(compact)
    assert set(t7["raw_object_type"]) == {" PROCESS ", "process", "PROCESS"}
    assert set(t7["raw_action_type"]) == {" START ", "start", "START"}
    assert set(t7["semantic_group"]) == {"process_activity"}

    mapping = eda4.semantic_mapping(" PROCESS ", " START ")
    assert mapping["raw_object_type"] == " PROCESS "
    assert mapping["raw_action_type"] == " START "
    assert mapping["semantic_group"] == "process_activity"
    assert mapping == eda4.semantic_mapping(" PROCESS ", " START ")


def _compact_row(
    period: str,
    pair: tuple[str, str],
    count: int,
    first_seen: str,
    event_id: str,
    line: int,
) -> dict:
    obj, action = pair
    return {
        "period": period,
        "host": "h1",
        "raw_object_type": obj,
        "raw_action_type": action,
        "object_type": obj,
        "action_type": action,
        "event_count": count,
        "first_seen_time": pd.Timestamp(first_seen),
        "last_seen_time": pd.Timestamp(first_seen),
        "raw_event_example_id": event_id,
        "archive_name": "a.tar",
        "member_name": "m.json.gz",
        "line_number": line,
    }


def _three_role_policy(tmp_path: pathlib.Path) -> eda4.PeriodPolicy:
    path = _write_period_map(
        tmp_path,
        [
            {
                "period": "baseline",
                "start_time": "2019-09-16T00:00:00Z",
                "end_time": "2019-09-16T06:00:00Z",
                "period_role": "verified_benign",
            },
            {
                "period": "misc",
                "start_time": "2019-09-16T06:00:00Z",
                "end_time": "2019-09-16T12:00:00Z",
                "period_role": "other",
            },
            {
                "period": "held_out",
                "start_time": "2019-09-16T12:00:00Z",
                "end_time": "2019-09-16T18:00:00Z",
                "period_role": "evaluation",
            },
        ],
    )
    return eda4.load_period_policy(str(path), 1)


def test_pattern_only_in_other_role_is_unresolved(tmp_path):
    policy = _three_role_policy(tmp_path)
    compact = pd.DataFrame(
        [_compact_row("misc", ("SVC", "ACT"), 3, "2019-09-16T06:30:00", "e1", 1)]
    )
    t8 = eda4.build_t8(compact, policy, 1, 100)
    row = t8.iloc[0]
    assert row["rarity_status"] == "unresolved_unassigned"
    assert row["benign_frequency"] == 0
    lowered = row["rare_reason"].lower()
    assert "unresolved" in lowered
    assert "malicious" not in lowered and "attack" not in lowered


def test_first_in_unassigned_then_evaluation_is_unresolved(tmp_path):
    policy = _three_role_policy(tmp_path)
    compact = pd.DataFrame(
        [
            _compact_row(
                eda4.DEFAULT_PERIOD, ("NEW", "ACT"), 1, "2019-09-15T23:00:00", "e1", 1
            ),
            _compact_row("held_out", ("NEW", "ACT"), 2, "2019-09-16T12:30:00", "e2", 2),
        ]
    )
    t8 = eda4.build_t8(compact, policy, 1, 100)
    row = t8.iloc[0]
    assert row["rarity_status"] == "unresolved_unassigned"
    assert row["evaluation_frequency"] == 2
    assert row["period"] == eda4.DEFAULT_PERIOD
    assert row["first_seen_time"] == "2019-09-15T23:00:00"


def test_first_in_evaluation_zero_benign_is_first_seen(tmp_path):
    policy = _three_role_policy(tmp_path)
    compact = pd.DataFrame(
        [_compact_row("held_out", ("NEW", "ACT"), 1, "2019-09-16T12:10:00", "e1", 1)]
    )
    row = eda4.build_t8(compact, policy, 1, 100).iloc[0]
    assert row["rarity_status"] == "first_seen_in_evaluation"
    assert row["benign_frequency"] == 0
    assert row["evaluation_frequency"] == 1


def test_genuine_verified_benign_rare_and_common_unchanged(tmp_path):
    policy = _three_role_policy(tmp_path)
    compact = pd.DataFrame(
        [
            _compact_row("baseline", ("RARE", "ACT"), 1, "2019-09-16T01:00:00", "e1", 1),
            _compact_row("baseline", ("COMMON", "ACT"), 5, "2019-09-16T02:00:00", "e2", 2),
        ]
    )
    t8 = eda4.build_t8(compact, policy, 1, 100)
    by_pair = {row["object_action_pair"]: row for _, row in t8.iterrows()}
    rare = by_pair[eda4.object_action_pair("RARE", "ACT")]
    common = by_pair[eda4.object_action_pair("COMMON", "ACT")]
    assert rare["rarity_status"] == "rare_in_verified_benign"
    assert rare["benign_frequency"] == 1
    assert common["rarity_status"] == "common_in_verified_benign"
    assert common["benign_frequency"] == 5


def test_benign_before_evaluation_ordering_enforced(tmp_path):
    valid_dir = tmp_path / "valid"
    valid_dir.mkdir()
    reversed_dir = tmp_path / "reversed"
    reversed_dir.mkdir()
    valid = _write_period_map(
        valid_dir,
        [
            {
                "period": "baseline",
                "start_time": "2019-09-16T00:00:00Z",
                "end_time": "2019-09-16T06:00:00Z",
                "period_role": "verified_benign",
            },
            {
                "period": "held_out",
                "start_time": "2019-09-16T08:00:00Z",
                "end_time": "2019-09-16T12:00:00Z",
                "period_role": "evaluation",
            },
        ],
    )
    policy = eda4.load_period_policy(str(valid), 1)
    assert policy.has_verified_benign and policy.has_evaluation

    reversed_map = _write_period_map(
        reversed_dir,
        [
            {
                "period": "held_out",
                "start_time": "2019-09-16T00:00:00Z",
                "end_time": "2019-09-16T06:00:00Z",
                "period_role": "evaluation",
            },
            {
                "period": "late_baseline",
                "start_time": "2019-09-16T08:00:00Z",
                "end_time": "2019-09-16T12:00:00Z",
                "period_role": "verified_benign",
            },
        ],
    )
    with pytest.raises(
        eda4.CacheAuditError, match="end at or before the earliest evaluation"
    ):
        eda4.load_period_policy(str(reversed_map), 1)


def test_benign_evaluation_boundary_equality_valid(tmp_path):
    boundary = _write_period_map(
        tmp_path,
        [
            {
                "period": "baseline",
                "start_time": "2019-09-16T00:00:00Z",
                "end_time": "2019-09-16T06:00:00Z",
                "period_role": "verified_benign",
            },
            {
                "period": "held_out",
                "start_time": "2019-09-16T06:00:00Z",
                "end_time": "2019-09-16T12:00:00Z",
                "period_role": "evaluation",
            },
        ],
    )
    policy = eda4.load_period_policy(str(boundary), 0)
    assert policy.has_verified_benign and policy.has_evaluation


def test_pattern_id_independent_of_arbitrary_input_order():
    values = [
        eda4.deterministic_pattern_id("h1", eda4.object_action_pair("FILE", "READ"))
        for _ in range(5)
    ]
    random.shuffle(values)
    assert len(set(values)) == 1
