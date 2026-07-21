"""Synthetic tests for scale-safe EDA 5."""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import os
import pathlib
import random
import shutil
import sys

import pandas as pd
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src" / "eda"))

import eda_05_entity_dictionary as eda5  # type: ignore
from optc_streaming_parser import SCHEMA_VERSION, SLIM_EVENT_COLUMNS  # type: ignore


def _event(
    index: int,
    *,
    timestamp: str,
    host: str = "h1",
    object_type: str = "PROCESS",
    user: str = "DOMAIN\\alice",
    principal: str = "DOMAIN\\alice",
    image: str = "",
    process: str | None = None,
    file_path: str = "",
    destination: str = "",
    destination_alias: str | None = None,
    archive: str = "a.tar",
    member: str = "m1.json.gz",
) -> dict:
    row = {column: "" for column in SLIM_EVENT_COLUMNS}
    row.update(
        {
            "timestamp_parsed": timestamp,
            "parse_status": "ok",
            "host_raw": host,
            "object_raw": object_type,
            "user_raw": user,
            "principal_raw": principal,
            "image_path_raw": image,
            "process_raw": image if process is None else process,
            "file_path_raw": file_path,
            "dest_ip_raw": destination,
            "destination_raw": (
                destination if destination_alias is None else destination_alias
            ),
            "archive_name": archive,
            "member_name": member,
            "line_number": index + 1,
            "raw_event_id": f"e{index}",
            # Deliberately populated excluded process fields.
            "command_line_raw": f"{image} --arg {index}" if image else "",
            "parent_image_path_raw": "C:\\Parent\\p.exe",
            "parent_process_raw": "C:\\Parent\\p.exe",
            "pid_raw": str(100 + index),
            "ppid_raw": "1",
            "tid_raw": str(200 + index),
            "actor_id_raw": f"actor-{index}",
        }
    )
    return row


def _events() -> list[dict]:
    return [
        _event(
            0,
            timestamp="2019-09-16T00:00:00",
            image="C:/Apps/tool.exe",
            member="m1.json.gz",
        ),
        _event(
            1,
            timestamp="2019-09-16T00:01:00",
            image="C:\\Apps\\tool.exe",
            principal="",
            member="m2.json.gz",
        ),
        _event(
            2,
            timestamp="2019-09-16T00:02:00",
            object_type="FILE",
            file_path="C:/Temp/a.txt",
            user="",
            principal="",
        ),
        _event(
            3,
            timestamp="2019-09-16T00:03:00",
            host="h2",
            object_type="FILE",
            file_path="C:\\Temp\\a.txt",
        ),
        _event(
            4,
            timestamp="2019-09-16T00:04:00",
            object_type="FLOW",
            destination="2001:0db8::1",
        ),
        _event(
            5,
            timestamp="2019-09-16T00:05:00",
            host="h2",
            object_type="FLOW",
            destination="2001:db8::1",
        ),
        _event(
            6,
            timestamp="2019-09-16T00:06:00",
            host="h2",
            object_type="FLOW",
            destination="not-an-ip",
        ),
        _event(
            7,
            timestamp="2019-09-16T00:07:00",
            host="h2",
            object_type="FLOW",
            destination="",
        ),
        _event(
            8,
            timestamp="2019-09-16T00:08:00",
            object_type="FILE",
            file_path="",
        ),
        _event(
            9,
            timestamp="2019-09-16T00:09:00",
            image="cmd.exe",
        ),
        # Missing host remains an unresolved host scope for a present user/path.
        _event(
            10,
            timestamp="2019-09-16T00:10:00",
            host="",
            image="C:\\Apps\\orphan.exe",
            user="orphan",
            principal="orphan",
        ),
        # Applicability adversaries: these values must not enter file/destination.
        _event(
            11,
            timestamp="2019-09-16T00:11:00",
            object_type="PROCESS",
            image="C:\\Apps\\other.exe",
            file_path="C:\\ShouldNot\\file.txt",
            destination="8.8.8.8",
        ),
    ]


def _write_cache(
    root: pathlib.Path,
    rows: list[dict] | None = None,
    *,
    columns: list[str] | None = None,
    metadata_total: int | None = None,
    reverse: bool = False,
) -> pathlib.Path:
    cache = root / "cache"
    cache.mkdir(parents=True)
    events = list(_events() if rows is None else rows)
    if reverse:
        events.reverse()
    frame = pd.DataFrame(events)
    selected = columns or list(SLIM_EVENT_COLUMNS)
    frame[selected].to_parquet(cache / "chunk_00000.parquet", index=False)
    metadata = {
        "schema_version": SCHEMA_VERSION,
        "total_events_written": (
            len(events) if metadata_total is None else metadata_total
        ),
        "sampling_strategy": "full",
    }
    (cache / "cache_metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
    return cache


def _write_manifest(root: pathlib.Path) -> pathlib.Path:
    path = root / "manifest.csv"
    pd.DataFrame({"manifest_version": ["pilot_manifest_10gb_v1"]}).to_csv(
        path, index=False
    )
    return path


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
        "output_dir": str(tmp_path / "eda05_out"),
        "duckdb_memory_limit": "64MB",
        "duckdb_temp_dir": None,
        "duckdb_threads": 1,
        "window_size": "1min",
        "max_t9_rows": 10_000,
        "batch_size": 2,
        "max_unresolved_example_rows": 100,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def _read_t9(output: pathlib.Path) -> pd.DataFrame:
    parts = sorted((output / "T9_canonical_entity_dictionary").glob("*/*.parquet"))
    assert parts
    return pd.concat([pd.read_parquet(path) for path in parts], ignore_index=True)


def test_host_and_user_normalization_exact():
    host = eda5.normalize_entity(
        entity_type="host",
        raw_value="HostA.EXAMPLE",
        host_scope="",
        source_field="host_raw",
    )
    assert host["normalized_value"] == "HostA.EXAMPLE"
    assert host["normalization_rule_id"] == "host_exact_v1"
    user = eda5.normalize_entity(
        entity_type="user_principal",
        raw_value="DOMAIN\\Alice",
        host_scope="HostA",
        source_field="user_raw:principal_preferred",
    )
    assert user["normalized_value"] == "DOMAIN\\Alice"
    assert user["host_if_applicable"] == "HostA"
    assert user["normalization_rule_id"] == "user_host_scoped_exact_v1"


@pytest.mark.parametrize(
    ("raw", "expected", "resolved"),
    [
        ("C:/A/B.exe", "C:\\A\\B.exe", True),
        ("C:\\A\\B.exe", "C:\\A\\B.exe", True),
        ("\\\\server/share/a.exe", "\\\\server\\share\\a.exe", True),
        ("//server/share/a.exe", "\\\\server\\share\\a.exe", True),
        ("C:\\A\\..\\B.exe", "C:\\A\\..\\B.exe", True),
        ("relative\\path\\tool.exe", "relative\\path\\tool.exe", True),
        ("Tool.EXE", "Tool.EXE", False),
        ("/usr/bin/tool", "/usr/bin/tool", False),
        ("relative/path/tool.exe", "relative/path/tool.exe", False),
    ],
)
def test_path_normalization_separator_only_idempotent(raw, expected, resolved):
    entity = eda5.normalize_entity(
        entity_type="process",
        raw_value=raw,
        host_scope="h1",
        source_field="image_path_raw/process_raw_alias",
    )
    assert entity["normalized_value"] == expected
    assert (entity["entity_status"] == "resolved") is resolved
    normalized_again = eda5.normalize_entity(
        entity_type="process",
        raw_value=entity["normalized_value"],
        host_scope="h1",
        source_field="image_path_raw/process_raw_alias",
    )
    assert normalized_again["normalized_value"] == expected
    assert normalized_again["canonical_id"] == entity["canonical_id"]


@pytest.mark.parametrize("entity_type", ["process", "file_path"])
@pytest.mark.parametrize(
    "raw", ["/usr/bin/tool", "relative/path/tool.exe", "tool.exe"]
)
def test_ambiguous_posix_literals_preserved_unresolved(entity_type, raw):
    entity = eda5.normalize_entity(
        entity_type=entity_type,
        raw_value=raw,
        host_scope="h1",
        source_field="x",
    )
    assert entity["normalized_value"] == raw
    assert entity["entity_status"] == "unresolved"
    assert entity["reliability_high_medium_low"] == "low"
    assert entity["normalization_rule_id"] == (
        "process_path_literal_unresolved_v1"
        if entity_type == "process"
        else "file_path_literal_unresolved_v1"
    )
    again = eda5.normalize_entity(
        entity_type=entity_type,
        raw_value=entity["normalized_value"],
        host_scope="h1",
        source_field="x",
    )
    assert again["canonical_id"] == entity["canonical_id"]


def test_windows_looking_paths_use_separator_rule():
    for entity_type, expected_rule in (
        ("process", "process_path_separator_v1"),
        ("file_path", "file_path_separator_v1"),
    ):
        entity = eda5.normalize_entity(
            entity_type=entity_type,
            raw_value="C:/Tools/tool.exe",
            host_scope="h1",
            source_field="x",
        )
        assert entity["normalization_rule_id"] == expected_rule
        assert entity["normalized_value"] == "C:\\Tools\\tool.exe"
        assert entity["entity_status"] == "resolved"


def test_missing_scope_distinct_from_literal_sentinel_hostname():
    kwargs = {
        "entity_type": "user_principal",
        "raw_value": "alice",
        "source_field": "user_raw",
    }
    missing = eda5.normalize_entity(host_scope="", **kwargs)
    sentinel_host = eda5.normalize_entity(
        host_scope=eda5.MISSING_HOST_SCOPE, **kwargs
    )
    other_host = eda5.normalize_entity(host_scope="h1", **kwargs)
    # Stored sentinel may match, but hash tokens must never collide.
    assert missing["host_if_applicable"] == eda5.MISSING_HOST_SCOPE
    assert sentinel_host["host_if_applicable"] == eda5.MISSING_HOST_SCOPE
    assert missing["canonical_id"] != sentinel_host["canonical_id"]
    assert missing["canonical_id"] != other_host["canonical_id"]
    assert sentinel_host["canonical_id"] != other_host["canonical_id"]
    assert (
        eda5.normalize_entity(host_scope="", **kwargs)["canonical_id"]
        == missing["canonical_id"]
    )
    assert (
        eda5.normalize_entity(host_scope="h1", **kwargs)["canonical_id"]
        == other_host["canonical_id"]
    )


def test_process_basename_and_full_path_do_not_merge():
    basename = eda5.normalize_entity(
        entity_type="process",
        raw_value="tool.exe",
        host_scope="h1",
        source_field="x",
    )
    full = eda5.normalize_entity(
        entity_type="process",
        raw_value="C:\\Apps\\tool.exe",
        host_scope="h1",
        source_field="x",
    )
    assert basename["canonical_id"] != full["canonical_id"]
    assert basename["entity_status"] == "unresolved"


def test_approved_path_aliases_share_id_but_case_does_not():
    def norm(raw):
        return eda5.normalize_entity(
            entity_type="file_path",
            raw_value=raw,
            host_scope="h1",
            source_field="file_path_raw",
        )

    assert norm("C:/Temp/a.txt")["canonical_id"] == norm(
        "C:\\Temp\\a.txt"
    )["canonical_id"]
    assert norm("C:\\Temp\\a.txt")["canonical_id"] != norm(
        "c:\\Temp\\a.txt"
    )["canonical_id"]


def test_host_scope_changes_process_file_and_user_ids():
    for entity_type, raw, source in (
        ("process", "C:\\A\\x.exe", "process"),
        ("file_path", "C:\\A\\x.txt", "file"),
        ("user_principal", "alice", "user"),
    ):
        first = eda5.normalize_entity(
            entity_type=entity_type,
            raw_value=raw,
            host_scope="h1",
            source_field=source,
        )
        second = eda5.normalize_entity(
            entity_type=entity_type,
            raw_value=raw,
            host_scope="h2",
            source_field=source,
        )
        assert first["canonical_id"] != second["canonical_id"]


@pytest.mark.parametrize(
    ("raw", "normalized", "category", "status"),
    [
        ("127.0.0.1", "127.0.0.1", "loopback", "resolved"),
        ("::1", "::1", "loopback", "resolved"),
        ("224.0.0.1", "224.0.0.1", "multicast", "resolved"),
        ("ff02::1", "ff02::1", "multicast", "resolved"),
        ("255.255.255.255", "255.255.255.255", "limited_broadcast", "resolved"),
        ("10.1.2.3", "10.1.2.3", "internal-looking", "resolved"),
        ("172.16.0.1", "172.16.0.1", "internal-looking", "resolved"),
        ("192.168.1.2", "192.168.1.2", "internal-looking", "resolved"),
        ("fc00::1", "fc00::1", "internal-looking", "resolved"),
        ("8.8.8.8", "8.8.8.8", "external-looking", "resolved"),
        ("169.254.1.1", "169.254.1.1", "other_non_global", "resolved"),
        ("0.0.0.0", "0.0.0.0", "other_non_global", "resolved"),
        ("192.0.2.1", "192.0.2.1", "other_non_global", "resolved"),
        ("2001:0db8::1", "2001:db8::1", "other_non_global", "resolved"),
        (
            "not-an-ip",
            "not-an-ip",
            "other_non_global/unresolved",
            "unresolved",
        ),
    ],
)
def test_destination_normalization_and_structural_categories(
    raw, normalized, category, status
):
    entity = eda5.normalize_entity(
        entity_type="destination",
        raw_value=raw,
        host_scope="",
        source_field="dest_ip_raw/destination_raw_alias",
    )
    assert entity["normalized_value"] == normalized
    assert entity["structural_category"] == category
    assert entity["entity_status"] == status


def test_no_directed_broadcast_inference_without_subnet():
    entity = eda5.normalize_entity(
        entity_type="destination",
        raw_value="192.168.1.255",
        host_scope="",
        source_field="destination",
    )
    assert entity["structural_category"] == "internal-looking"
    assert entity["structural_category"] != "limited_broadcast"


def test_ipv6_aliases_share_canonical_id():
    kwargs = {
        "entity_type": "destination",
        "host_scope": "",
        "source_field": "destination",
    }
    first = eda5.normalize_entity(raw_value="2001:0db8::1", **kwargs)
    second = eda5.normalize_entity(raw_value="2001:db8::1", **kwargs)
    assert first["canonical_id"] == second["canonical_id"]


def test_canonical_id_deterministic_and_order_independent():
    values = [
        eda5.canonical_id("host", "", "host_exact_v1", value)
        for value in ("h3", "h1", "h2")
    ]
    shuffled = list(values)
    random.shuffle(shuffled)
    assert sorted(values) == sorted(shuffled)
    assert all(value.startswith("ent_") and len(value) == 36 for value in values)


def test_scan_sql_is_projected_and_true_parseability():
    for spec in eda5.SCAN_SPECS:
        sql = eda5._scan_sql(spec)
        assert "FROM events" in sql
        assert "TRY_CAST(timestamp_parsed AS TIMESTAMP) IS NOT NULL" in sql
        assert "SELECT *" not in sql
    assert len(eda5.SCAN_SPECS) == 5


def test_complete_run_deliverables_counts_and_cache_unchanged(tmp_path):
    cache = _write_cache(tmp_path)
    manifest = _write_manifest(tmp_path)
    parquet = next(cache.glob("*.parquet"))
    cache_hash = hashlib.sha256(parquet.read_bytes()).hexdigest()
    args = _args(tmp_path, cache, manifest)
    metadata = eda5.run_eda05(args)
    output = pathlib.Path(args.output_dir)
    expected = {
        "T9_canonical_entity_dictionary",
        "T10_entity_count_summary.csv",
        "F6_new_entity_rate_over_time.png",
        "F6_new_entity_rate_over_time.pdf",
        "D1_entity_normalization_rulebook.csv",
        "D1_entity_normalization_rulebook.txt",
        "README_eda05_entity_dictionary.txt",
        "eda05_run_metadata.json",
        "T9_unresolved_examples.csv",
    }
    assert {path.name for path in output.iterdir()} == expected
    assert metadata["payload_scan_count"] == 5
    assert metadata["baseline_status"] == eda5.BASELINE_STATUS
    assert metadata["first_seen_after_baseline_count"] is None
    assert hashlib.sha256(parquet.read_bytes()).hexdigest() == cache_hash
    assert not any(
        path.name.startswith(".") or path.suffix == ".tmp"
        for path in output.rglob("*")
    )

    t9 = _read_t9(output)
    assert list(t9.columns) == eda5.T9_COLUMNS
    assert not (t9["raw_value"] == "").any()
    assert set(t9["entity_type"]) == set(eda5.ENTITY_TYPES)
    assert not t9.duplicated(
        ["entity_type", "host_if_applicable", "raw_value"]
    ).any()
    # Slash and IPv6 aliases repeat approved canonical IDs.
    process_alias = t9[
        (t9["entity_type"] == "process")
        & (t9["raw_value"].isin(["C:/Apps/tool.exe", "C:\\Apps\\tool.exe"]))
    ]
    assert process_alias["canonical_id"].nunique() == 1
    ip_alias = t9[
        (t9["entity_type"] == "destination")
        & (t9["raw_value"].isin(["2001:0db8::1", "2001:db8::1"]))
    ]
    assert ip_alias["canonical_id"].nunique() == 1
    # Same file raw aliases on different hosts remain separate canonical IDs.
    files = t9[t9["entity_type"] == "file_path"]
    assert files["canonical_id"].nunique() == 2
    # Excluded fields/applicability do not leak into T9.
    assert "C:\\ShouldNot\\file.txt" not in set(t9["raw_value"])
    assert "8.8.8.8" not in set(t9["raw_value"])
    assert not set(t9["raw_value"]).intersection(
        {"C:\\Parent\\p.exe", "actor-0", "100"}
    )

    t10 = pd.read_csv(output / "T10_entity_count_summary.csv")
    assert list(t10.columns) == eda5.T10_COLUMNS
    assert len(t10) == 5
    assert t10["first_seen_after_baseline_count"].isna().all()
    assert set(t10["baseline_status"]) == {eda5.BASELINE_STATUS}
    assert (
        t10["merged_count"]
        == t10["total_unique_raw_values"] - t10["total_unique_canonical_ids"]
    ).all()
    assert (t10["merged_count"] >= 0).all()
    by_type = t10.set_index("entity_type")
    assert by_type.loc["host", "missing_observation_count"] == 1
    assert by_type.loc["user_principal", "missing_observation_count"] == 1
    assert by_type.loc["file_path", "missing_observation_count"] == 1
    assert by_type.loc["destination", "missing_observation_count"] == 1
    assert by_type.loc["process", "merged_count"] == 1
    assert by_type.loc["destination", "merged_count"] == 1

    # source_count and observation_count are separate exact definitions.
    first_process = t9[
        (t9["entity_type"] == "process")
        & (t9["raw_value"] == "C:/Apps/tool.exe")
    ].iloc[0]
    assert first_process["source_count"] == 1
    assert first_process["observation_count"] == 1
    readme = (output / "README_eda05_entity_dictionary.txt").read_text()
    assert "full_pilot_unassigned" in readme
    assert "first_seen_after_baseline_count is null/deferred" in readme
    assert "EDA 6 onward" in readme
    assert "timestamp[us]" in readme
    assert "includes every nonmissing canonical entity, both resolved and" in readme
    run_metadata = json.loads(
        (output / "eda05_run_metadata.json").read_text()
    )
    assert "timestamp[us]" in run_metadata["t9_timestamp_type"]
    assert "unresolved" in run_metadata["f6_eligibility"]


def test_exact_source_count_distinct_member_and_observation_count(tmp_path):
    rows = [
        _event(
            0,
            timestamp="2019-09-16T00:00:00",
            host="same",
            archive="a.tar",
            member="m1",
        ),
        _event(
            1,
            timestamp="2019-09-16T00:01:00",
            host="same",
            archive="a.tar",
            member="m1",
        ),
        _event(
            2,
            timestamp="2019-09-16T00:02:00",
            host="same",
            archive="a.tar",
            member="m2",
        ),
    ]
    cache = _write_cache(tmp_path, rows)
    con, spill, owned = eda5._duck_conn(cache, memory_limit="64MB", threads=1)
    try:
        reader = eda5._record_batches(con, eda5.SCAN_SPECS[0], 100)
        result = [row for batch in reader for row in batch.to_pylist()]
    finally:
        con.close()
        if owned:
            shutil.rmtree(spill, ignore_errors=True)
    assert result[0]["observation_count"] == 3
    assert result[0]["source_count"] == 2


class _FakeStreamingConnection:
    """Returns a prebuilt fake relation for any executed SQL."""

    def __init__(self, relation):
        self.relation = relation

    def execute(self, sql, *args, **kwargs):
        return self.relation


def test_record_batches_prefers_modern_to_arrow_reader():
    calls = {}

    class ModernRelation:
        def to_arrow_reader(self, *, batch_size):
            calls["modern"] = batch_size
            return "modern-reader"

        def fetch_record_batch(self, *, rows_per_batch):
            raise AssertionError("legacy API must not be used when modern exists")

    reader = eda5._record_batches(
        _FakeStreamingConnection(ModernRelation()), eda5.SCAN_SPECS[0], 7
    )
    assert reader == "modern-reader"
    assert calls == {"modern": 7}


def test_record_batches_falls_back_to_legacy_fetch_record_batch():
    calls = {}

    class LegacyRelation:
        def fetch_record_batch(self, *, rows_per_batch):
            calls["legacy"] = rows_per_batch
            return "legacy-reader"

    reader = eda5._record_batches(
        _FakeStreamingConnection(LegacyRelation()), eda5.SCAN_SPECS[0], 9
    )
    assert reader == "legacy-reader"
    assert calls == {"legacy": 9}


def test_record_batches_fails_when_no_streaming_api_exists():
    class BareRelation:
        pass

    with pytest.raises(
        eda5.CacheAuditError, match="no supported streaming Arrow reader"
    ):
        eda5._record_batches(
            _FakeStreamingConnection(BareRelation()), eda5.SCAN_SPECS[0], 3
        )


def test_record_batches_real_duckdb_streams_arrow_reader(tmp_path):
    import pyarrow as pa

    rows = [
        _event(index, timestamp=f"2019-09-16T00:0{index}:00", host=f"h{index}")
        for index in range(5)
    ]
    cache = _write_cache(tmp_path, rows)
    con, spill, owned = eda5._duck_conn(cache, memory_limit="64MB", threads=1)
    try:
        reader = eda5._record_batches(con, eda5.SCAN_SPECS[0], 2)
        # Streaming contract: an Arrow RecordBatchReader, not a materialized
        # table/DataFrame, honoring the requested batch size.
        assert isinstance(reader, pa.RecordBatchReader)
        batches = list(reader)
        assert batches
        assert all(isinstance(batch, pa.RecordBatch) for batch in batches)
        assert all(batch.num_rows <= 2 for batch in batches)
        assert sum(batch.num_rows for batch in batches) == 5
    finally:
        con.close()
        if owned:
            shutil.rmtree(spill, ignore_errors=True)
    # Capability detection, never version detection or full materialization.
    source = inspect.getsource(eda5._record_batches)
    assert "to_arrow_reader" in source
    assert "fetch_record_batch" in source
    assert "duckdb.__version__" not in source
    assert "fetchdf" not in inspect.getsource(eda5.extract_t9)
    assert "fetchall" not in inspect.getsource(eda5.extract_t9)


def test_actor_parent_pid_and_command_line_do_not_affect_process_id():
    first = eda5.normalize_entity(
        entity_type="process",
        raw_value="C:\\A\\x.exe",
        host_scope="h1",
        source_field="image_path_raw/process_raw_alias",
    )
    second = eda5.normalize_entity(
        entity_type="process",
        raw_value="C:\\A\\x.exe",
        host_scope="h1",
        source_field="image_path_raw/process_raw_alias",
    )
    assert first["canonical_id"] == second["canonical_id"]
    source = inspect.getsource(eda5.normalize_entity)
    assert "command_line_raw" not in source
    assert "parent_process_raw" not in source
    assert "pid_raw" not in source


def test_raw_value_preserved_exactly():
    raw = "C:/Mixed Case/../Tool.EXE"
    entity = eda5.normalize_entity(
        entity_type="process",
        raw_value=raw,
        host_scope="HostA",
        source_field="process",
    )
    assert entity["raw_value"] == raw
    assert entity["normalized_value"] == "C:\\Mixed Case\\..\\Tool.EXE"


def test_input_order_independence_full_run(tmp_path):
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    cache1 = _write_cache(first_root)
    cache2 = _write_cache(second_root, reverse=True)
    manifest1 = _write_manifest(first_root)
    manifest2 = _write_manifest(second_root)
    args1 = _args(first_root, cache1, manifest1)
    args2 = _args(second_root, cache2, manifest2)
    eda5.run_eda05(args1)
    eda5.run_eda05(args2)
    keys = ["entity_type", "host_if_applicable", "raw_value", "canonical_id"]
    first = _read_t9(pathlib.Path(args1.output_dir))[keys].sort_values(keys)
    second = _read_t9(pathlib.Path(args2.output_dir))[keys].sort_values(keys)
    pd.testing.assert_frame_equal(
        first.reset_index(drop=True), second.reset_index(drop=True)
    )


def test_chunk_order_independence(tmp_path):
    roots = [tmp_path / "forward", tmp_path / "reversed"]
    outputs = []
    events = _events()
    for index, root in enumerate(roots):
        cache = root / "cache"
        cache.mkdir(parents=True)
        halves = [events[:6], events[6:]]
        if index:
            halves.reverse()
        for part_index, rows in enumerate(halves):
            frame = pd.DataFrame(rows)
            frame[list(SLIM_EVENT_COLUMNS)].to_parquet(
                cache / f"chunk_{part_index:05d}.parquet", index=False
            )
        (cache / "cache_metadata.json").write_text(
            json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
                    "total_events_written": len(events),
                    "sampling_strategy": "full",
                }
            ),
            encoding="utf-8",
        )
        manifest = _write_manifest(root)
        args = _args(root, cache, manifest)
        eda5.run_eda05(args)
        output = _read_t9(pathlib.Path(args.output_dir))
        outputs.append(
            output[
                ["entity_type", "host_if_applicable", "raw_value", "canonical_id"]
            ]
            .sort_values(["entity_type", "host_if_applicable", "raw_value"])
            .reset_index(drop=True)
        )
    pd.testing.assert_frame_equal(outputs[0], outputs[1])


def test_f6_deduplicates_canonical_aliases_and_zero_fills():
    sparse = pd.DataFrame(
        {
            "entity_type": ["process", "process", "file_path"],
            "bucket": pd.to_datetime(
                [
                    "2019-09-16 00:00:00",
                    "2019-09-16 00:02:00",
                    "2019-09-16 00:02:00",
                ]
            ),
            "new_entity_count": [1, 1, 1],
        }
    )
    dense = eda5.build_dense_f6(sparse)
    assert len(dense) == 3
    assert list(dense["process"]) == [1, 0, 1]
    assert list(dense["file_path"]) == [0, 0, 1]
    assert dense["destination"].sum() == 0
    assert dense["user_principal"].sum() == 0


def test_f6_cap_precedes_date_range(monkeypatch):
    sparse = pd.DataFrame(
        {
            "entity_type": ["process", "process"],
            "bucket": pd.to_datetime(["1900-01-01", "2100-01-01"]),
            "new_entity_count": [1, 1],
        }
    )
    calls = {"count": 0}

    def fail(*args, **kwargs):
        calls["count"] += 1
        raise AssertionError("date_range must not be called")

    monkeypatch.setattr(pd, "date_range", fail)
    with pytest.raises(eda5.CacheAuditError, match="before pd.date_range"):
        eda5.build_dense_f6(sparse)
    assert calls["count"] == 0


def test_fetch_f6_sparse_has_zero_cache_queries_by_construction():
    source = inspect.getsource(eda5.fetch_f6_sparse)
    assert "read_parquet" in source
    assert "FROM events" not in source
    assert "normalized_cache" not in source


def test_exact_five_payload_scan_budget(tmp_path, monkeypatch):
    cache = _write_cache(tmp_path)
    manifest = _write_manifest(tmp_path)
    original = eda5._duck_conn
    observed = {"payload": 0}

    class CountingConnection:
        def __init__(self, connection):
            self.connection = connection

        def execute(self, sql, *args, **kwargs):
            if "FROM events" in str(sql):
                observed["payload"] += 1
            return self.connection.execute(sql, *args, **kwargs)

        def close(self):
            return self.connection.close()

    def wrapped(*args, **kwargs):
        connection, spill, owned = original(*args, **kwargs)
        return CountingConnection(connection), spill, owned

    monkeypatch.setattr(eda5, "_duck_conn", wrapped)
    metadata = eda5.run_eda05(_args(tmp_path, cache, manifest))
    assert observed["payload"] == 5
    assert metadata["payload_scan_count"] == 5


def test_scan_progress_printed_once_per_scan(tmp_path, capsys):
    cache = _write_cache(tmp_path)
    manifest = _write_manifest(tmp_path)
    eda5.run_eda05(_args(tmp_path, cache, manifest))
    out = capsys.readouterr().out
    for index, entity_type in enumerate(eda5.ENTITY_TYPES, start=1):
        assert f"[SCAN {index}/5] {entity_type} ..." in out
        assert f"[SCAN {index}/5] {entity_type} complete:" in out
    # One start and one completion line per scan; no per-row/batch noise.
    assert out.count("[SCAN") == 10


def test_required_column_failure(tmp_path):
    columns = [column for column in SLIM_EVENT_COLUMNS if column != "dest_ip_raw"]
    cache = _write_cache(tmp_path, columns=columns)
    con, spill, owned = eda5._duck_conn(cache, memory_limit="64MB", threads=1)
    try:
        with pytest.raises(eda5.CacheAuditError, match="dest_ip_raw"):
            eda5.validate_required_cache_columns(con)
    finally:
        con.close()
        if owned:
            shutil.rmtree(spill, ignore_errors=True)


def test_alias_mismatch_fails_without_output(tmp_path):
    rows = _events()
    rows[0]["process_raw"] = "C:\\Different.exe"
    cache = _write_cache(tmp_path, rows)
    manifest = _write_manifest(tmp_path)
    args = _args(tmp_path, cache, manifest)
    with pytest.raises(eda5.CacheAuditError, match="alias integrity"):
        eda5.run_eda05(args)
    assert not pathlib.Path(args.output_dir).exists()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        # Two-sided process mismatch.
        ("process_raw", "C:\\Different.exe"),
        # One-sided process mismatches.
        ("process_raw", ""),
        ("image_path_raw", ""),
    ],
)
def test_process_alias_one_and_two_sided_mismatch_fails(tmp_path, field, value):
    rows = _events()
    assert rows[0]["image_path_raw"] == "C:/Apps/tool.exe"
    rows[0][field] = value
    cache = _write_cache(tmp_path, rows)
    manifest = _write_manifest(tmp_path)
    args = _args(tmp_path, cache, manifest)
    with pytest.raises(eda5.CacheAuditError, match="process alias integrity"):
        eda5.run_eda05(args)
    assert not pathlib.Path(args.output_dir).exists()
    assert not any(
        path.name.startswith(".eda05_staging_") for path in tmp_path.iterdir()
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        # Two-sided destination mismatch.
        ("destination_raw", "9.9.9.9"),
        # One-sided destination mismatches.
        ("destination_raw", ""),
        ("dest_ip_raw", ""),
    ],
)
def test_destination_alias_one_and_two_sided_mismatch_fails(
    tmp_path, field, value
):
    rows = _events()
    assert rows[4]["dest_ip_raw"] == "2001:0db8::1"
    rows[4][field] = value
    cache = _write_cache(tmp_path, rows)
    manifest = _write_manifest(tmp_path)
    args = _args(tmp_path, cache, manifest)
    with pytest.raises(eda5.CacheAuditError, match="destination alias integrity"):
        eda5.run_eda05(args)
    assert not pathlib.Path(args.output_dir).exists()
    assert not any(
        path.name.startswith(".eda05_staging_") for path in tmp_path.iterdir()
    )


@pytest.mark.parametrize("user_value", ["", "DOMAIN\\other"])
def test_nonempty_principal_must_equal_user_raw(tmp_path, user_value):
    rows = _events()
    rows[0]["principal_raw"] = "DOMAIN\\alice"
    rows[0]["user_raw"] = user_value
    cache = _write_cache(tmp_path, rows)
    manifest = _write_manifest(tmp_path)
    args = _args(tmp_path, cache, manifest)
    with pytest.raises(
        eda5.CacheAuditError, match="user_principal alias integrity"
    ):
        eda5.run_eda05(args)
    assert not pathlib.Path(args.output_dir).exists()
    assert not any(
        path.name.startswith(".eda05_staging_") for path in tmp_path.iterdir()
    )


def test_t9_evidence_locator_earliest_and_tiebreak(tmp_path):
    rows = [
        # Same host observed three times; earliest timestamp wins, then
        # archive/member/line/raw_event_id break ties deterministically.
        _event(
            5,
            timestamp="2019-09-16T00:00:00",
            host="same",
            archive="b.tar",
            member="m9",
        ),
        _event(
            3,
            timestamp="2019-09-16T00:00:00",
            host="same",
            archive="a.tar",
            member="m2",
        ),
        _event(
            1,
            timestamp="2019-09-16T00:00:00",
            host="same",
            archive="a.tar",
            member="m1",
        ),
        _event(
            0,
            timestamp="2019-09-16T00:05:00",
            host="same",
            archive="a.tar",
            member="m0",
        ),
    ]
    cache = _write_cache(tmp_path, rows)
    manifest = _write_manifest(tmp_path)
    args = _args(tmp_path, cache, manifest)
    eda5.run_eda05(args)
    t9 = _read_t9(pathlib.Path(args.output_dir))
    host_row = t9[(t9["entity_type"] == "host") & (t9["raw_value"] == "same")]
    assert len(host_row) == 1
    row = host_row.iloc[0]
    assert row["raw_event_example_id"] == "e1"
    assert row["archive_name"] == "a.tar"
    assert row["member_name"] == "m1"
    assert row["line_number"] == 2


def test_t9_evidence_locator_stable_under_reordering(tmp_path):
    keys = [
        "entity_type",
        "host_if_applicable",
        "raw_value",
        "raw_event_example_id",
        "archive_name",
        "member_name",
        "line_number",
    ]
    frames = []
    for name, reverse in (("forward", False), ("reversed", True)):
        root = tmp_path / name
        root.mkdir()
        cache = _write_cache(root, reverse=reverse)
        manifest = _write_manifest(root)
        args = _args(root, cache, manifest)
        eda5.run_eda05(args)
        frames.append(
            _read_t9(pathlib.Path(args.output_dir))[keys]
            .sort_values(keys)
            .reset_index(drop=True)
        )
    pd.testing.assert_frame_equal(frames[0], frames[1])


def test_missing_evidence_locator_fails_without_publication(tmp_path):
    rows = _events()
    for row in rows:
        if row["host_raw"] == "h2":
            row["raw_event_id"] = ""
    cache = _write_cache(tmp_path, rows)
    manifest = _write_manifest(tmp_path)
    args = _args(tmp_path, cache, manifest)
    with pytest.raises(eda5.CacheAuditError, match="incomplete evidence locator"):
        eda5.run_eda05(args)
    assert not pathlib.Path(args.output_dir).exists()
    assert not any(
        path.name.startswith(".eda05_staging_") for path in tmp_path.iterdir()
    )


def test_t9_native_timestamp_parquet_schema_and_values(tmp_path):
    import pyarrow as pa
    import pyarrow.parquet as pq

    cache = _write_cache(tmp_path)
    manifest = _write_manifest(tmp_path)
    args = _args(tmp_path, cache, manifest)
    eda5.run_eda05(args)
    output = pathlib.Path(args.output_dir)
    parts = sorted(
        (output / "T9_canonical_entity_dictionary").glob("*/*.parquet")
    )
    assert parts
    for part in parts:
        schema = pq.read_schema(part)
        assert schema.field("first_seen_time").type == pa.timestamp("us")
        assert schema.field("last_seen_time").type == pa.timestamp("us")
    t9 = _read_t9(output)
    host_row = t9[(t9["entity_type"] == "host") & (t9["raw_value"] == "h1")]
    assert host_row.iloc[0]["first_seen_time"] == pd.Timestamp(
        "2019-09-16T00:00:00"
    )
    assert host_row.iloc[0]["last_seen_time"] == pd.Timestamp(
        "2019-09-16T00:11:00"
    )
    # Naive UTC: no timezone attached anywhere in T9.
    assert t9["first_seen_time"].dt.tz is None
    assert t9["last_seen_time"].dt.tz is None


def test_whitespace_only_values_are_missing_observations(tmp_path):
    rows = _events()
    rows.append(
        _event(
            12,
            timestamp="2019-09-16T00:12:00",
            host="   ",
            user=" \t ",
            principal=" \t ",
            image="  ",
        )
    )
    rows.append(
        _event(
            13,
            timestamp="2019-09-16T00:13:00",
            object_type="FILE",
            file_path="  ",
        )
    )
    rows.append(
        _event(
            14,
            timestamp="2019-09-16T00:14:00",
            object_type="FLOW",
            destination=" ",
        )
    )
    cache = _write_cache(tmp_path, rows)
    manifest = _write_manifest(tmp_path)
    args = _args(tmp_path, cache, manifest)
    eda5.run_eda05(args)
    output = pathlib.Path(args.output_dir)
    t9 = _read_t9(output)
    assert not t9["raw_value"].str.strip().eq("").any()
    t10 = pd.read_csv(output / "T10_entity_count_summary.csv").set_index(
        "entity_type"
    )
    # The base fixture already contributes exactly one missing observation
    # for host, user_principal, file_path, and destination; each whitespace
    # value above adds exactly one more.
    assert t10.loc["host", "missing_observation_count"] == 2
    assert t10.loc["user_principal", "missing_observation_count"] == 2
    assert t10.loc["file_path", "missing_observation_count"] == 2
    assert t10.loc["destination", "missing_observation_count"] == 2


def test_all_missing_cache_produces_safe_empty_outputs(tmp_path):
    rows = [
        _event(
            index,
            timestamp=f"2019-09-16T00:0{index}:00",
            host="",
            user="",
            principal="",
            image="",
            file_path="",
            destination="",
            object_type=object_type,
        )
        for index, object_type in enumerate(("PROCESS", "FILE", "FLOW"))
    ]
    for row in rows:
        row["user_raw"] = "   "
    cache = _write_cache(tmp_path, rows)
    manifest = _write_manifest(tmp_path)
    args = _args(tmp_path, cache, manifest)
    metadata = eda5.run_eda05(args)
    output = pathlib.Path(args.output_dir)
    # Every partition still holds a schema-valid (empty) Parquet part.
    for entity_type in eda5.ENTITY_TYPES:
        parts = sorted(
            (output / "T9_canonical_entity_dictionary").glob(
                f"entity_type={entity_type}/*.parquet"
            )
        )
        assert parts
        assert all(len(pd.read_parquet(path)) == 0 for path in parts)
    t10 = pd.read_csv(output / "T10_entity_count_summary.csv")
    assert len(t10) == 5
    assert (t10["total_unique_raw_values"] == 0).all()
    assert (t10["total_unique_canonical_ids"] == 0).all()
    assert (t10["unresolved_count"] == 0).all()
    png = output / "F6_new_entity_rate_over_time.png"
    pdf = output / "F6_new_entity_rate_over_time.pdf"
    assert png.stat().st_size > 0 and pdf.stat().st_size > 0
    assert metadata["t9_row_count"] == 0


def test_metadata_count_mismatch_fails(tmp_path):
    cache = _write_cache(tmp_path, metadata_total=999)
    manifest = _write_manifest(tmp_path)
    args = _args(tmp_path, cache, manifest)
    with pytest.raises(eda5.CacheAuditError, match="cache metadata"):
        eda5.run_eda05(args)
    assert not pathlib.Path(args.output_dir).exists()


def test_t9_cap_failure_no_output_or_staging(tmp_path):
    cache = _write_cache(tmp_path)
    manifest = _write_manifest(tmp_path)
    args = _args(tmp_path, cache, manifest, max_t9_rows=1)
    with pytest.raises(eda5.CacheAuditError, match="max-t9-rows"):
        eda5.run_eda05(args)
    assert not pathlib.Path(args.output_dir).exists()
    assert not any(
        path.name.startswith(".eda05_staging_") for path in tmp_path.iterdir()
    )


def test_owned_spill_cleanup_on_setup_failure(tmp_path, monkeypatch):
    import duckdb

    cache = _write_cache(tmp_path)
    owned = tmp_path / "owned_spill"

    def make_temp(*args, **kwargs):
        owned.mkdir()
        return str(owned)

    monkeypatch.setattr(eda5.tempfile, "mkdtemp", make_temp)
    monkeypatch.setattr(
        duckdb,
        "connect",
        lambda: (_ for _ in ()).throw(RuntimeError("forced setup failure")),
    )
    with pytest.raises(RuntimeError, match="forced"):
        eda5._duck_conn(cache, memory_limit="64MB", threads=1)
    assert not owned.exists()


def test_explicit_spill_preserved(tmp_path):
    cache = _write_cache(tmp_path)
    spill_dir = tmp_path / "explicit_spill"
    con, spill, owned = eda5._duck_conn(
        cache,
        memory_limit="64MB",
        threads=1,
        temp_dir=str(spill_dir),
    )
    marker = spill_dir / "keep.txt"
    marker.write_text("keep")
    con.close()
    assert not owned
    assert pathlib.Path(spill) == spill_dir
    assert marker.read_text() == "keep"


@pytest.mark.parametrize("kind", ["empty_dir", "nonempty_dir", "file", "symlink", "broken"])
def test_output_preexistence_refused_and_unchanged(tmp_path, kind):
    cache = _write_cache(tmp_path)
    manifest = _write_manifest(tmp_path)
    output = tmp_path / "eda05_out"
    expected = None
    if kind == "empty_dir":
        output.mkdir()
    elif kind == "nonempty_dir":
        output.mkdir()
        (output / "keep").write_bytes(b"unchanged")
        expected = b"unchanged"
    elif kind == "file":
        output.write_bytes(b"unchanged")
        expected = b"unchanged"
    elif kind == "symlink":
        target = tmp_path / "target"
        target.mkdir()
        output.symlink_to(target)
        expected = os.readlink(output)
    else:
        target = tmp_path / "missing"
        output.symlink_to(target)
        expected = os.readlink(output)
        assert not output.exists() and os.path.lexists(output)
    with pytest.raises(eda5.CacheAuditError, match="must not pre-exist"):
        eda5.run_eda05(_args(tmp_path, cache, manifest))
    if kind in ("nonempty_dir",):
        assert (output / "keep").read_bytes() == expected
    elif kind == "file":
        assert output.read_bytes() == expected
    elif kind in ("symlink", "broken"):
        assert output.is_symlink() and os.readlink(output) == expected
    else:
        assert output.is_dir() and not any(output.iterdir())


def test_publication_single_directory_rename(tmp_path, monkeypatch):
    cache = _write_cache(tmp_path)
    manifest = _write_manifest(tmp_path)
    args = _args(tmp_path, cache, manifest)
    output = pathlib.Path(args.output_dir)
    original = os.replace
    calls = []

    def recording(src, dst):
        calls.append((pathlib.Path(src), pathlib.Path(dst)))
        return original(src, dst)

    monkeypatch.setattr(eda5.os, "replace", recording)
    eda5.run_eda05(args)
    publishes = [(src, dst) for src, dst in calls if dst == output]
    assert len(publishes) == 1
    assert publishes[0][0].name.startswith(".eda05_staging_")
    assert not any(dst.parent == output for _, dst in calls)


def test_publication_race_refuses_broken_symlink_staging_unchanged(tmp_path):
    staging = tmp_path / ".eda05_staging_test"
    staging.mkdir()
    marker = staging / "marker"
    marker.write_bytes(b"staged")
    output = tmp_path / "out"
    target = tmp_path / "missing"
    output.symlink_to(target)
    with pytest.raises(eda5.CacheAuditError, match="appeared before publication"):
        eda5._publish_staging(staging, output)
    assert output.is_symlink() and os.readlink(output) == str(target)
    assert staging.is_dir() and marker.read_bytes() == b"staged"


def test_publication_failure_no_partial_output_and_staging_cleaned(
    tmp_path, monkeypatch
):
    cache = _write_cache(tmp_path)
    manifest = _write_manifest(tmp_path)
    args = _args(tmp_path, cache, manifest)
    output = pathlib.Path(args.output_dir)

    def fail(staging, output_dir):
        raise eda5.CacheAuditError("forced publication failure")

    monkeypatch.setattr(eda5, "_publish_staging", fail)
    with pytest.raises(eda5.CacheAuditError, match="forced"):
        eda5.run_eda05(args)
    assert not output.exists()
    assert not any(
        path.name.startswith(".eda05_staging_") for path in tmp_path.iterdir()
    )


def test_cli_validation_and_no_archive_mode(tmp_path):
    parser = eda5.build_parser()
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
    assert args.window_size == "1min"
    assert args.max_t9_rows == eda5.DEFAULT_MAX_T9_ROWS
    assert args.batch_size == eda5.DEFAULT_BATCH_SIZE
    assert not hasattr(args, "archives")
    assert not hasattr(args, "corrected_dir")


def test_invalid_window_and_drive_spill_rejected(tmp_path):
    cache = _write_cache(tmp_path)
    manifest = _write_manifest(tmp_path)
    with pytest.raises(eda5.CacheAuditError, match="only '1min'"):
        eda5.validate_run_config(
            _args(tmp_path, cache, manifest, window_size="5min")
        )
    with pytest.raises(eda5.CacheAuditError, match="Google Drive"):
        eda5._validate_duckdb_temp_dir("/content/drive/MyDrive/spill")


def test_d1_contains_every_used_rule_and_prohibitions():
    rows = eda5.d1_rows()
    rules = {row["rule_id"] for row in rows}
    assert rules == {
        "host_exact_v1",
        "user_host_scoped_exact_v1",
        "process_path_separator_v1",
        "process_path_literal_unresolved_v1",
        "file_path_separator_v1",
        "file_path_literal_unresolved_v1",
        "destination_ip_v1",
        "destination_literal_unresolved_v1",
    }
    text = eda5.d1_text(rows).lower()
    assert "fuzzy" in text
    assert "reputation" in text
    assert "deferred" in text
    assert "process_path_literal_unresolved_v1" in text
    assert "file_path_literal_unresolved_v1" in text
    assert "windows-looking" in text
