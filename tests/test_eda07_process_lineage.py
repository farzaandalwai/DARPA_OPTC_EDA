"""Synthetic, repository-local tests for scale-safe EDA 7."""

from __future__ import annotations

import argparse
import hashlib
import inspect
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
import eda_07_process_lineage as eda7  # type: ignore
from optc_streaming_parser import SCHEMA_VERSION, SLIM_EVENT_COLUMNS  # type: ignore


def _event(
    index: int,
    *,
    timestamp: str,
    archive_date: str,
    host: str = "h1",
    object_type: str = "PROCESS",
    action: str = "CREATE",
    image: str = "",
    parent: str = "",
    command: str = "",
    actor_id: str = "",
    object_id: str = "",
    pid: str = "",
    ppid: str = "",
) -> dict:
    row = {column: "" for column in SLIM_EVENT_COLUMNS}
    row.update(
        {
            "timestamp_parsed": timestamp,
            "timestamp_raw": timestamp,
            "parse_status": "ok",
            "host_raw": host,
            "user_raw": "alice",
            "principal_raw": "alice",
            "object_raw": object_type,
            "action_raw": action,
            "image_path_raw": image,
            "process_raw": image,
            "parent_image_path_raw": parent,
            "parent_process_raw": parent,
            "command_line_raw": command,
            "actor_id_raw": actor_id or f"actor-{index}",
            "object_id_raw": object_id or f"object-{index}",
            "pid_raw": pid or str(1000 + index),
            "ppid_raw": ppid or str(900 + index),
            "archive_name": f"{archive_date}.tar",
            "member_name": f"{host}.json.gz",
            "line_number": index + 1,
            "raw_event_id": f"e{index:03d}",
        }
    )
    return row


def _base_events() -> list[dict]:
    # Benign day 1 / day 2 plus evaluation day 3.
    return [
        _event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            image="C:\\Windows\\System32\\child.exe",
            parent="C:\\Windows\\System32\\parent.exe",
            command="C:\\Windows\\System32\\child.exe /flag 1",
        ),
        _event(
            1,
            timestamp="2020-01-01T00:00:10",
            archive_date="2020-01-01",
            image="C:\\Windows\\System32\\grandchild.exe",
            parent="C:\\Windows\\System32\\child.exe",
            command="C:\\Windows\\System32\\grandchild.exe",
        ),
        _event(
            2,
            timestamp="2020-01-01T00:00:20",
            archive_date="2020-01-01",
            image="C:\\Windows\\System32\\great.exe",
            parent="C:\\Windows\\System32\\grandchild.exe",
            command="C:\\Windows\\System32\\great.exe",
        ),
        _event(
            3,
            timestamp="2020-01-01T00:00:30",
            archive_date="2020-01-01",
            image="C:\\Windows\\System32\\leaf.exe",
            parent="C:\\Windows\\System32\\great.exe",
            command="C:\\Windows\\System32\\leaf.exe",
        ),
        _event(
            4,
            timestamp="2020-01-02T00:00:00",
            archive_date="2020-01-02",
            image="C:\\Windows\\System32\\child.exe",
            parent="C:\\Windows\\System32\\parent.exe",
            command="C:\\Windows\\System32\\child.exe /flag 1",
        ),
        _event(
            5,
            timestamp="2020-01-02T00:00:10",
            archive_date="2020-01-02",
            image="C:\\Windows\\System32\\grandchild.exe",
            parent="C:\\Windows\\System32\\child.exe",
            command="C:\\Windows\\System32\\grandchild.exe",
        ),
        # Evaluation unusual command / chain
        _event(
            6,
            timestamp="2020-01-03T00:00:00",
            archive_date="2020-01-03",
            image="C:\\Users\\alice\\new.exe",
            parent="C:\\Users\\alice\\launcher.exe",
            command=(
                "C:\\Users\\alice\\new.exe /id "
                "123e4567-e89b-12d3-a456-426614174000"
            ),
        ),
        _event(
            7,
            timestamp="2020-01-03T00:00:10",
            archive_date="2020-01-03",
            image="C:\\Users\\alice\\payload.exe",
            parent="C:\\Users\\alice\\new.exe",
            command="C:\\Users\\alice\\payload.exe /pid 12345678",
        ),
        # FILE event should not create process edges
        _event(
            8,
            timestamp="2020-01-01T01:00:00",
            archive_date="2020-01-01",
            object_type="FILE",
            action="WRITE",
            image="C:\\Temp\\ignored.exe",
            parent="C:\\Temp\\ignored-parent.exe",
        ),
        # Missing parent: no observed edge
        _event(
            9,
            timestamp="2020-01-01T02:00:00",
            archive_date="2020-01-01",
            image="C:\\Windows\\System32\\orphan.exe",
            parent="",
            command="C:\\Windows\\System32\\orphan.exe",
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
    pd.DataFrame({"manifest_version": ["synthetic_eda07_v1"]}).to_csv(
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
        by_type[entity_type].append(
            _t9_row(entity_type, raw, key[1], index)
        )
        index += 1

    for event in rows:
        add("host", event["host_raw"])
        add("user_principal", event["user_raw"], event["host_raw"])
        if event["object_raw"] == "PROCESS":
            add("process", event["image_path_raw"], event["host_raw"])
            add("process", event["parent_image_path_raw"], event["host_raw"])

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
        "output_dir": str(root / "eda07_out"),
        "window_size": "1min",
        "rare_benign_max_count": 5,
        "evidence_cap": 20,
        "max_unusual_examples": 1000,
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
    metadata = eda7.run_eda07(args)
    after = hashlib.sha256(cache_file.read_bytes()).hexdigest()
    assert before == after
    return fixture, args, metadata, pathlib.Path(args.output_dir)


def test_exact_t14_t15_d2_schemas_and_eight_deliverables(completed_run):
    _, _, _, output = completed_run
    expected = {
        "T14_process_chain_frequency.csv",
        "T15_unusual_command_process_examples.csv",
        "F8_process_command_novelty_over_time.png",
        "F8_process_command_novelty_over_time.pdf",
        "D2_command_normalization_rulebook.csv",
        "README.md",
        "eda07_run_metadata.json",
        "eda07_execution.log",
    }
    assert {path.name for path in output.iterdir()} == expected
    assert list(pd.read_csv(output / "T14_process_chain_frequency.csv").columns) == (
        eda7.T14_COLUMNS
    )
    assert list(
        pd.read_csv(output / "T15_unusual_command_process_examples.csv").columns
    ) == eda7.T15_COLUMNS
    assert list(
        pd.read_csv(output / "D2_command_normalization_rulebook.csv").columns
    ) == eda7.D2_COLUMNS


def test_same_event_edges_and_missing_parent(completed_run):
    _, _, _, output = completed_run
    t14 = pd.read_csv(output / "T14_process_chain_frequency.csv")
    length2 = t14.loc[t14["chain_length"] == 2]
    assert not length2.empty
    assert (length2["construction_type"] == "observed_same_event").all()
    assert (length2["link_status"] == "observed").all()
    serialized = " ".join(t14["full_chain"].astype(str))
    assert "orphan.exe" not in serialized


def test_inferred_lengths_and_constraints(completed_run):
    _, _, _, output = completed_run
    t14 = pd.read_csv(output / "T14_process_chain_frequency.csv")
    longer = t14.loc[t14["chain_length"] > 2]
    assert not longer.empty
    assert (longer["construction_type"] == "inferred_path_composition").all()
    assert (longer["link_status"] == "inferred_not_causal").all()
    assert set(t14["chain_length"]).issubset({2, 3, 4, 5})
    assert t14["chain_length"].max() <= 5
    for value in longer["normalized_chain"]:
        nodes = str(value).split(" -> ")
        assert len(nodes) == len(set(nodes))


def test_full_path_not_basename_matching(tmp_path):
    rows = [
        _event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            image="C:\\DirA\\shared.exe",
            parent="C:\\Root\\a.exe",
            command="a",
        ),
        _event(
            1,
            timestamp="2020-01-01T00:00:10",
            archive_date="2020-01-01",
            image="C:\\Leaf\\x.exe",
            parent="C:\\DirB\\shared.exe",
            command="b",
        ),
        _event(
            2,
            timestamp="2020-01-02T00:00:00",
            archive_date="2020-01-02",
            image="C:\\DirA\\shared.exe",
            parent="C:\\Root\\a.exe",
            command="a",
        ),
        _event(
            3,
            timestamp="2020-01-03T00:00:00",
            archive_date="2020-01-03",
            image="C:\\Eval\\e.exe",
            parent="C:\\Eval\\p.exe",
            command="e",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    eda7.run_eda07(args)
    t14 = pd.read_csv(pathlib.Path(args.output_dir) / "T14_process_chain_frequency.csv")
    # Basename shared.exe differs by directory; no length-3 composition.
    assert t14.loc[t14["chain_length"] >= 3].empty


def test_same_host_window_period_restrictions(tmp_path):
    rows = [
        _event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            host="h1",
            image="C:\\Windows\\B.exe",
            parent="C:\\Windows\\A.exe",
        ),
        _event(
            1,
            timestamp="2020-01-01T00:00:10",
            archive_date="2020-01-01",
            host="h2",
            image="C:\\Windows\\C.exe",
            parent="C:\\Windows\\B.exe",
        ),
        _event(
            2,
            timestamp="2020-01-01T00:02:00",
            archive_date="2020-01-01",
            host="h1",
            image="C:\\Windows\\C.exe",
            parent="C:\\Windows\\B.exe",
        ),
        _event(
            3,
            timestamp="2020-01-02T00:00:00",
            archive_date="2020-01-02",
            host="h1",
            image="C:\\Windows\\B.exe",
            parent="C:\\Windows\\A.exe",
        ),
        _event(
            4,
            timestamp="2020-01-03T00:00:00",
            archive_date="2020-01-03",
            host="h1",
            image="C:\\Windows\\E.exe",
            parent="C:\\Windows\\D.exe",
            command="eval",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    eda7.run_eda07(args)
    t14 = pd.read_csv(pathlib.Path(args.output_dir) / "T14_process_chain_frequency.csv")
    # Cross-host and cross-minute should not create A->B->C
    long_chains = t14.loc[t14["chain_length"] >= 3, "full_chain"].astype(str)
    assert not any("A.exe" in value and "C.exe" in value for value in long_chains)


def test_cycle_and_repeated_node_rejection(tmp_path):
    rows = [
        _event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            image="C:\\Windows\\B.exe",
            parent="C:\\Windows\\A.exe",
        ),
        _event(
            1,
            timestamp="2020-01-01T00:00:10",
            archive_date="2020-01-01",
            image="C:\\Windows\\A.exe",
            parent="C:\\Windows\\B.exe",
        ),
        _event(
            2,
            timestamp="2020-01-02T00:00:00",
            archive_date="2020-01-02",
            image="C:\\Windows\\B.exe",
            parent="C:\\Windows\\A.exe",
        ),
        _event(
            3,
            timestamp="2020-01-03T00:00:00",
            archive_date="2020-01-03",
            image="C:\\Windows\\Z.exe",
            parent="C:\\Windows\\Y.exe",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    eda7.run_eda07(args)
    t14 = pd.read_csv(pathlib.Path(args.output_dir) / "T14_process_chain_frequency.csv")
    for value in t14["normalized_chain"]:
        nodes = str(value).split(" -> ")
        assert len(nodes) == len(set(nodes))


def test_deterministic_chain_ids_and_evidence(completed_run, tmp_path):
    fixture, args, _, output = completed_run
    first = pd.read_csv(output / "T14_process_chain_frequency.csv")
    second_root = tmp_path / "second"
    second_root.mkdir()
    fixture2 = _fixture(second_root, list(reversed(fixture["rows"])))
    args2 = _args(second_root, fixture2)
    eda7.run_eda07(args2)
    second = pd.read_csv(
        pathlib.Path(args2.output_dir) / "T14_process_chain_frequency.csv"
    )
    left = first.sort_values("chain_id").reset_index(drop=True)
    right = second.sort_values("chain_id").reset_index(drop=True)
    assert list(left["chain_id"]) == list(right["chain_id"])
    assert list(left["evidence_ids"]) == list(right["evidence_ids"])
    for value in first["evidence_ids"]:
        ids = json.loads(value)
        assert len(ids) == len(set(ids))
        assert len(ids) <= eda7.DEFAULT_EVIDENCE_CAP


def test_pid_and_actor_not_used_as_identity():
    source = pathlib.Path(eda7.__file__).read_text(encoding="utf-8")
    assert "pid_raw = ppid_raw" not in source
    assert "JOIN" in source.upper() or "join" in source
    # No global PID identity join pattern
    assert not re.search(
        r"ON\s+[^\n]*pid_raw\s*=\s*[^\n]*ppid_raw", source, flags=re.IGNORECASE
    )
    assert "guaranteed causal" not in source.lower() or "never" in source.lower()


def test_command_normalization_rules():
    raw = "  tool.exe /id 123e4567-e89b-12d3-a456-426614174000 /x  "
    result = eda7.normalize_command_line(raw)
    assert result["command_line_normalized"] == "tool.exe /id <UUID> /x"
    assert eda7.normalize_command_line(
        "tool.exe /h 0xdeadbeefcafebabe /v 0x1"
    )["command_line_normalized"] == "tool.exe /h <HEX> /v 0x1"
    assert eda7.normalize_command_line(
        "tool.exe /pid 12345678 /port 445"
    )["command_line_normalized"] == "tool.exe /pid <NUMBER> /port 445"
    quoted = eda7.normalize_command_line(
        'tool.exe --guid "123e4567-e89b-12d3-a456-426614174000"'
    )
    assert quoted["command_line_normalized"] == 'tool.exe --guid "<UUID>"'
    fallback = eda7.normalize_command_line('tool.exe "unterminated')
    assert fallback["normalization_status"] == "fallback_preserved"
    assert fallback["command_line_normalized"] == 'tool.exe "unterminated'


def test_raw_command_preserved_exactly(completed_run):
    _, _, _, output = completed_run
    t15 = pd.read_csv(
        output / "T15_unusual_command_process_examples.csv", keep_default_na=False
    )
    assert "command_line_raw" in t15.columns
    assert t15["command_line_raw"].isna().sum() == 0
    # Original UUID still present in at least one raw field
    assert t15["command_line_raw"].astype(str).str.contains(
        "123e4567-e89b-12d3-a456-426614174000"
    ).any()


def test_baseline_fitting_no_evaluation_leakage(tmp_path):
    base = _base_events()
    fixture = _fixture(tmp_path / "a", base)
    args = _args(tmp_path / "a", fixture)
    eda7.run_eda07(args)
    t14_a = pd.read_csv(pathlib.Path(args.output_dir) / "T14_process_chain_frequency.csv")

    extra = list(base) + [
        _event(
            100,
            timestamp="2020-01-03T01:00:00",
            archive_date="2020-01-03",
            image="C:\\EvalOnly\\x.exe",
            parent="C:\\EvalOnly\\p.exe",
            command="eval-only-command",
        )
    ]
    fixture_b = _fixture(tmp_path / "b", extra)
    args_b = _args(tmp_path / "b", fixture_b)
    eda7.run_eda07(args_b)
    t14_b = pd.read_csv(
        pathlib.Path(args_b.output_dir) / "T14_process_chain_frequency.csv"
    )

    benign_a = t14_a.loc[t14_a["period"] == "verified_benign"].copy()
    benign_b = t14_b.loc[t14_b["period"] == "verified_benign"].copy()
    cols = ["chain_id", "benign_count", "benign_rank", "normalized_chain"]
    left = benign_a[cols].sort_values("chain_id").reset_index(drop=True)
    right = benign_b[cols].sort_values("chain_id").reset_index(drop=True)
    pd.testing.assert_frame_equal(left, right)


def test_novelty_unseen_rare_common_and_ranking(completed_run):
    _, _, metadata, output = completed_run
    t14 = pd.read_csv(output / "T14_process_chain_frequency.csv")
    eval_rows = t14.loc[t14["period"] == "evaluation"]
    assert (
        eval_rows["novelty_status"]
        .isin(
            [
                "unseen_in_verified_benign",
                "rare_in_verified_benign",
                "common_in_verified_benign",
                "unresolved_mapping",
                "inferred_chain_only",
            ]
        )
        .all()
    )
    assert (eval_rows["novelty_status"] == "unseen_in_verified_benign").any()
    benign = t14.loc[t14["period"] == "verified_benign"]
    assert benign["benign_rank"].notna().any()
    assert metadata["rare_benign_max_count"] == 5


def test_next_process_support(completed_run):
    _, _, _, output = completed_run
    t14 = pd.read_csv(output / "T14_process_chain_frequency.csv")
    length2 = t14.loc[
        (t14["period"] == "verified_benign") & (t14["chain_length"] == 2)
    ]
    assert (length2["next_process_support"] >= 0).all()
    with_next = length2.loc[length2["next_process"].astype(str).str.len() > 0]
    if not with_next.empty:
        assert with_next["next_process_conditional_frequency"].between(0, 1).all()


def test_t15_evidence_and_ground_truth(completed_run):
    _, _, _, output = completed_run
    t15 = pd.read_csv(
        output / "T15_unusual_command_process_examples.csv", keep_default_na=False
    )
    assert not t15.empty
    assert (t15["ground_truth_overlap_yes_no"] == eda7.GROUND_TRUTH_OVERLAP).all()
    assert t15["timestamp"].astype(str).str.len().gt(0).all()
    for value in t15["raw_event_ids"]:
        assert json.loads(value)
    banned = re.compile(
        r"\b(malicious|attack|compromised|exploit|threat|adversarial)\b",
        re.I,
    )
    blob = " ".join(t15["novelty_reason"].astype(str))
    assert not banned.search(blob)


def test_f8_gaps_titles_and_fixed_colors(tmp_path, monkeypatch):
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    host_id = "ent_host_demo"
    chain_novelty = pd.DataFrame(
        [
            {
                "host_id": host_id,
                "window_start": "2020-01-03T00:00:00",
                "chain_novelty_count": 1,
            },
            {
                "host_id": host_id,
                "window_start": "2020-01-03T00:01:00",
                "chain_novelty_count": 1,
            },
            {
                "host_id": host_id,
                "window_start": "2020-01-03T00:05:00",
                "chain_novelty_count": 1,
            },
        ]
    )
    command_novelty = pd.DataFrame(
        [
            {
                "host_id": host_id,
                "window_start": "2020-01-03T00:00:00",
                "command_novelty_count": 1,
            },
            {
                "host_id": host_id,
                "window_start": "2020-01-03T00:05:00",
                "command_novelty_count": 1,
            },
        ]
    )
    plot_colors: list[str] = []
    titles: list[str] = []
    original_plot = plt.Axes.plot
    original_title = plt.Axes.set_title

    def capturing_plot(self, *args, **kwargs):
        plot_colors.append(kwargs.get("color"))
        return original_plot(self, *args, **kwargs)

    def capturing_title(self, label, *args, **kwargs):
        titles.append(str(label))
        return original_title(self, label, *args, **kwargs)

    monkeypatch.setattr(plt.Axes, "plot", capturing_plot)
    monkeypatch.setattr(plt.Axes, "set_title", capturing_title)
    eda7.create_f8(
        chain_novelty,
        command_novelty,
        png_path=tmp_path / "f8.png",
        pdf_path=tmp_path / "f8.pdf",
        host_labels={host_id: "SysClient0101"},
    )
    assert eda7.F8_CHAIN_COLOR in plot_colors
    assert eda7.F8_COMMAND_COLOR in plot_colors
    assert titles == ["SysClient0101"]
    source = inspect.getsource(eda7.create_f8)
    assert "date_range" not in source
    assert "reindex" not in source
    assert "fillna" not in source


def test_output_safety_and_drive_refusal(tmp_path):
    fixture = _fixture(tmp_path)
    existing = tmp_path / "exists"
    existing.mkdir()
    args = _args(tmp_path, fixture, output_dir=str(existing))
    with pytest.raises(eda7.CacheAuditError, match="pre-exist"):
        eda7.validate_run_config(args)

    inside = fixture["cache"] / "nested_out"
    args2 = _args(tmp_path, fixture, output_dir=str(inside))
    with pytest.raises(eda7.CacheAuditError, match="inside"):
        eda7.validate_run_config(args2)

    args3 = _args(
        tmp_path,
        fixture,
        duckdb_temp_dir="/content/drive/MyDrive/spill",
        output_dir=str(tmp_path / "ok_out"),
    )
    with pytest.raises(eda7.CacheAuditError, match="Drive|drive"):
        eda7.validate_run_config(args3)


def test_atomic_cleanup_on_failure(tmp_path, monkeypatch):
    fixture = _fixture(tmp_path)
    args = _args(tmp_path, fixture)
    original = eda7.create_f8

    def boom(*_a, **_k):
        raise RuntimeError("forced failure")

    monkeypatch.setattr(eda7, "create_f8", boom)
    with pytest.raises(RuntimeError, match="forced failure"):
        eda7.run_eda07(args)
    assert not pathlib.Path(args.output_dir).exists()
    parent = pathlib.Path(args.output_dir).parent
    leftovers = list(parent.glob(".eda07_staging_*"))
    assert leftovers == []
    monkeypatch.setattr(eda7, "create_f8", original)


def test_process_reconciliation_and_metadata(completed_run):
    fixture, _, metadata, output = completed_run
    process_events = sum(
        1 for row in fixture["rows"] if row["object_raw"] == "PROCESS"
    )
    assert metadata["process_total"] == process_events
    assert (
        metadata["process_verified_benign"]
        + metadata["process_evaluation"]
        + metadata["process_other"]
        + metadata["process_unassigned"]
        == metadata["process_total"]
    )
    assert metadata["unassigned_count"] == 0
    assert metadata["payload_scan_count"] == 1
    assert metadata["missing_parent_process_count"] >= 1
    assert metadata["missing_link_count_total"] == (
        metadata["missing_parent_process_count"]
        + metadata["missing_child_process_count"]
    )
    assert metadata["metadata_self_hash_policy"] == "excluded_self_reference"
    assert "eda07_run_metadata.json" not in metadata["deliverable_sha256"]
    meta = json.loads((output / "eda07_run_metadata.json").read_text(encoding="utf-8"))
    assert "deliverable_sha256" in meta
    assert "count_semantics" in meta
    assert meta["t14_row_count"] >= 1
    for name, digest in meta["deliverable_sha256"].items():
        assert digest == hashlib.sha256((output / name).read_bytes()).hexdigest()
    readme = (output / "README.md").read_text(encoding="utf-8")
    assert "observed" in readme.lower()
    assert "inferred" in readme.lower()
    assert "supporting windows" in readme.lower()
    assert "EDA 10" in readme
    assert "missing_parent" in readme or "missing parent" in readme.lower()
    assert "pid" in readme.lower()


def test_rare_threshold_never_zero(tmp_path):
    fixture = _fixture(tmp_path)
    args = _args(tmp_path, fixture, rare_benign_max_count=0)
    with pytest.raises(eda7.CacheAuditError, match=">= 1"):
        eda7.validate_run_config(args)


def test_separator_alias_comparison_form():
    left = eda7.process_comparison_form("C:/Windows/System32/parent.exe")
    right = eda7.process_comparison_form("C:\\Windows\\System32\\PARENT.exe")
    assert left == right
    assert left != eda7.process_comparison_form(
        "C:\\Windows\\System32\\other.exe"
    )


def test_d2_matches_implemented_behavior(completed_run):
    _, _, _, output = completed_run
    d2 = pd.read_csv(output / "D2_command_normalization_rulebook.csv")
    assert set(d2["rule_id"]) == {row["rule_id"] for row in eda7.D2_RULEBOOK}
    for row in d2.itertuples(index=False):
        before = row.example_before
        after = eda7.normalize_command_line(before)["command_line_normalized"]
        assert after == row.example_after


def test_no_deprecation_warnings_in_module(tmp_path):
    fixture = _fixture(tmp_path)
    args = _args(tmp_path, fixture)
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        eda7.run_eda07(args)


def test_max_chain_length_five(tmp_path):
    # A->B->C->D->E->F in one minute should cap at length 5.
    chain = [
        ("C:\\W\\A.exe", ""),
        ("C:\\W\\B.exe", "C:\\W\\A.exe"),
        ("C:\\W\\C.exe", "C:\\W\\B.exe"),
        ("C:\\W\\D.exe", "C:\\W\\C.exe"),
        ("C:\\W\\E.exe", "C:\\W\\D.exe"),
        ("C:\\W\\F.exe", "C:\\W\\E.exe"),
    ]
    rows = []
    for index, (image, parent) in enumerate(chain):
        if not parent:
            continue
        rows.append(
            _event(
                index,
                timestamp=f"2020-01-01T00:00:{index:02d}",
                archive_date="2020-01-01",
                image=image,
                parent=parent,
                command=image,
            )
        )
    rows.append(
        _event(
            20,
            timestamp="2020-01-02T00:00:00",
            archive_date="2020-01-02",
            image="C:\\W\\B.exe",
            parent="C:\\W\\A.exe",
            command="repeat",
        )
    )
    rows.append(
        _event(
            21,
            timestamp="2020-01-03T00:00:00",
            archive_date="2020-01-03",
            image="C:\\W\\Z.exe",
            parent="C:\\W\\Y.exe",
            command="eval",
        )
    )
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    eda7.run_eda07(args)
    t14 = pd.read_csv(pathlib.Path(args.output_dir) / "T14_process_chain_frequency.csv")
    assert t14["chain_length"].max() == 5
    assert not (t14["chain_length"] > 5).any()


def test_evidence_cap_respected(tmp_path):
    rows = []
    for index in range(30):
        rows.append(
            _event(
                index,
                timestamp="2020-01-01T00:00:00",
                archive_date="2020-01-01",
                image="C:\\Windows\\child.exe",
                parent="C:\\Windows\\parent.exe",
                command=f"cmd-{index}",
            )
        )
    rows.append(
        _event(
            40,
            timestamp="2020-01-02T00:00:00",
            archive_date="2020-01-02",
            image="C:\\Windows\\child.exe",
            parent="C:\\Windows\\parent.exe",
            command="repeat",
        )
    )
    rows.append(
        _event(
            41,
            timestamp="2020-01-03T00:00:00",
            archive_date="2020-01-03",
            image="C:\\Windows\\eval.exe",
            parent="C:\\Windows\\parent.exe",
            command="eval",
        )
    )
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture, evidence_cap=5)
    eda7.run_eda07(args)
    t14 = pd.read_csv(pathlib.Path(args.output_dir) / "T14_process_chain_frequency.csv")
    assert (t14["evidence_count"] <= 5).all()
    for value in t14["evidence_ids"]:
        assert len(json.loads(value)) <= 5


def test_first_seen_timestamps(completed_run):
    _, _, _, output = completed_run
    t14 = pd.read_csv(output / "T14_process_chain_frequency.csv")
    assert t14["first_seen_time"].notna().all()
    assert t14["last_seen_time"].notna().all()
    assert (
        pd.to_datetime(t14["first_seen_time"]) <= pd.to_datetime(t14["last_seen_time"])
    ).all()


def test_manifest_schema_validation(tmp_path):
    fixture = _fixture(tmp_path)
    bad_meta = fixture["cache"] / "cache_metadata.json"
    bad_meta.write_text(
        json.dumps(
            {
                "schema_version": "wrong",
                "total_events_written": len(fixture["rows"]),
            }
        ),
        encoding="utf-8",
    )
    args = _args(tmp_path, fixture, output_dir=str(tmp_path / "bad_schema_out"))
    with pytest.raises(eda7.CacheAuditError):
        eda7.validate_run_config(args)


def test_comparison_form_not_basename_only():
    assert eda7.process_comparison_form(
        "C:\\DirA\\tool.exe"
    ) != eda7.process_comparison_form("C:\\DirB\\tool.exe")


def test_make_chain_id_deterministic():
    first = eda7.make_chain_id(
        host_id="h",
        construction_type="observed_same_event",
        normalized_nodes=["a", "b"],
    )
    second = eda7.make_chain_id(
        host_id="h",
        construction_type="observed_same_event",
        normalized_nodes=["a", "b"],
    )
    assert first == second
    assert first.startswith("pch_")


def test_short_flags_preserved():
    result = eda7.normalize_command_line("tool.exe /v 0x1 /n 12 /port 445")
    assert result["command_line_normalized"] == "tool.exe /v 0x1 /n 12 /port 445"


def test_f8_created_in_pipeline(completed_run):
    _, _, _, output = completed_run
    assert (output / "F8_process_command_novelty_over_time.png").stat().st_size > 0
    assert (output / "F8_process_command_novelty_over_time.pdf").stat().st_size > 0


def test_period_role_restriction_no_cross_period_composition(tmp_path):
    rows = [
        _event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            image="C:\\Windows\\B.exe",
            parent="C:\\Windows\\A.exe",
        ),
        _event(
            1,
            timestamp="2020-01-02T00:00:00",
            archive_date="2020-01-02",
            image="C:\\Windows\\B.exe",
            parent="C:\\Windows\\A.exe",
        ),
        # Evaluation continues the path but must not compose with benign edge
        _event(
            2,
            timestamp="2020-01-03T00:00:00",
            archive_date="2020-01-03",
            image="C:\\Windows\\C.exe",
            parent="C:\\Windows\\B.exe",
            command="eval-continue",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    eda7.run_eda07(args)
    t14 = pd.read_csv(pathlib.Path(args.output_dir) / "T14_process_chain_frequency.csv")
    eval_long = t14.loc[
        (t14["period"] == "evaluation") & (t14["chain_length"] >= 3)
    ]
    assert eval_long.empty


def test_insufficient_command_novelty_status():
    assert (
        eda7.novelty_status_for_command(
            0, rare_benign_max_count=5, command_raw=""
        )
        == "insufficient_or_missing_command"
    )
    assert (
        eda7.novelty_status_for_command(
            3, rare_benign_max_count=5, command_raw="x"
        )
        == "rare_in_verified_benign"
    )
    assert (
        eda7.novelty_status_for_command(
            9, rare_benign_max_count=5, command_raw="x"
        )
        == "common_in_verified_benign"
    )


def test_execution_log_stages(completed_run):
    _, _, _, output = completed_run
    log = (output / "eda07_execution.log").read_text(encoding="utf-8")
    assert "[STAGE 1/8]" in log
    assert "[STAGE 8/8]" in log


def _query_frame_sql_literals(source: str) -> list[str]:
    """Return literal SQL strings passed as the second arg to _query_frame()."""
    import ast

    tree = ast.parse(source)
    literals: list[str] = []

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
            # f-strings: concatenate constant parts for SQL keyword checks.
            parts: list[str] = []
            for value in node.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    parts.append(value.value)
                else:
                    parts.append(" ")
            return "".join(parts)
        return None

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


def _sql_fetches_unaggregated_command_observations(sql: str) -> bool:
    """True when SQL loads unaggregated/non-DISTINCT command_observations."""
    normalized = " ".join(str(sql).split()).lower()
    if "command_observations" not in normalized:
        return False
    # Joins that only reference the table through enriched/derived names are OK
    # when the FROM target is not the raw observation table itself.
    from_match = re.search(
        r"\bfrom\s+([a-z0-9_\.]+)",
        normalized,
    )
    if from_match is None:
        return False
    from_table = from_match.group(1)
    if from_table != "command_observations":
        return False
    # Allow DISTINCT vocabulary extraction.
    if re.search(r"\bselect\s+distinct\b", normalized):
        return False
    # Allow aggregated summaries.
    if re.search(r"\bgroup\s+by\b", normalized):
        return False
    return True


def test_no_wholesale_command_observation_pandas_fetch():
    source = pathlib.Path(eda7.__file__).read_text(encoding="utf-8")
    assert "def _build_command_tables" not in source
    assert "def _build_bounded_command_aggregates" in source

    literals = _query_frame_sql_literals(source)
    assert literals, "expected at least one _query_frame SQL literal"
    offenders = [
        sql
        for sql in literals
        if _sql_fetches_unaggregated_command_observations(sql)
    ]
    assert offenders == []

    # Mutation-style guard: trailing-comma _query_frame form must be rejected.
    forbidden = '''
_query_frame(
    connection,
    """SELECT * FROM command_observations""",
)
'''
    forbidden_literals = _query_frame_sql_literals(forbidden)
    assert forbidden_literals == ["SELECT * FROM command_observations"]
    assert _sql_fetches_unaggregated_command_observations(forbidden_literals[0])

    allowed = '''
_query_frame(
    connection,
    """
    SELECT DISTINCT CAST(command_line_raw AS VARCHAR) AS command_line_raw
    FROM command_observations
    ORDER BY command_line_raw
    """,
)
'''
    allowed_literals = _query_frame_sql_literals(allowed)
    assert allowed_literals
    assert not _sql_fetches_unaggregated_command_observations(allowed_literals[0])


def test_f8_two_window_chain_novelty_timing(tmp_path):
    rows = [
        _event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            image="C:\\Windows\\B.exe",
            parent="C:\\Windows\\A.exe",
            command="common-benign",
        ),
        _event(
            1,
            timestamp="2020-01-02T00:00:00",
            archive_date="2020-01-02",
            image="C:\\Windows\\B.exe",
            parent="C:\\Windows\\A.exe",
            command="common-benign",
        ),
        _event(
            2,
            timestamp="2020-01-03T00:00:00",
            archive_date="2020-01-03",
            image="C:\\Users\\alice\\novel.exe",
            parent="C:\\Users\\alice\\launch.exe",
            command="novel-eval",
        ),
        _event(
            3,
            timestamp="2020-01-03T00:05:00",
            archive_date="2020-01-03",
            image="C:\\Users\\alice\\novel.exe",
            parent="C:\\Users\\alice\\launch.exe",
            command="novel-eval",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    # Build window chains through a full run, then inspect F8 helper input
    # by reconstructing from outputs is hard; call the helper via internals.
    config = eda7.validate_run_config(args)
    connection, spill, owned = eda7._duck_conn(
        config["cache_dir"],
        memory_limit=config["memory_limit"],
        temp_dir=None,
        threads=config["threads"],
    )
    try:
        eda7.validate_required_cache_columns(connection)
        eda7._register_inputs(connection, config)
        eda7._create_process_edge_aggregate(connection, config["evidence_cap"])
        window_chains = eda7._build_window_chains(
            connection, config["evidence_cap"]
        )
        f8_chain = eda7._build_f8_chain_novelty(
            window_chains, rare_benign_max_count=5
        )
    finally:
        connection.close()
        if owned:
            shutil.rmtree(spill, ignore_errors=True)
    windows = sorted(pd.to_datetime(f8_chain["window_start"]).unique())
    assert len(windows) == 2
    assert windows[0] == pd.Timestamp("2020-01-03T00:00:00")
    assert windows[1] == pd.Timestamp("2020-01-03T00:05:00")
    assert list(f8_chain["chain_novelty_count"]) == [1, 1]


def test_inferred_support_window_count_not_min_edge(tmp_path):
    rows = []
    for index in range(10):
        rows.append(
            _event(
                index,
                timestamp="2020-01-01T00:00:00",
                archive_date="2020-01-01",
                image="C:\\Windows\\B.exe",
                parent="C:\\Windows\\A.exe",
                command=f"ab-{index}",
            )
        )
    for index in range(5):
        rows.append(
            _event(
                20 + index,
                timestamp="2020-01-01T00:00:10",
                archive_date="2020-01-01",
                image="C:\\Windows\\C.exe",
                parent="C:\\Windows\\B.exe",
                command=f"bc-{index}",
            )
        )
    rows.append(
        _event(
            40,
            timestamp="2020-01-02T00:00:00",
            archive_date="2020-01-02",
            image="C:\\Windows\\B.exe",
            parent="C:\\Windows\\A.exe",
            command="repeat",
        )
    )
    rows.append(
        _event(
            41,
            timestamp="2020-01-03T00:00:00",
            archive_date="2020-01-03",
            image="C:\\Windows\\Z.exe",
            parent="C:\\Windows\\Y.exe",
            command="eval",
        )
    )
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    eda7.run_eda07(args)
    t14 = pd.read_csv(pathlib.Path(args.output_dir) / "T14_process_chain_frequency.csv")
    inferred = t14.loc[
        (t14["period"] == "verified_benign")
        & (t14["chain_length"] == 3)
        & t14["normalized_chain"].astype(str).str.contains("a.exe", case=False)
    ]
    assert not inferred.empty
    # One supporting window only in benign for A->B->C => count 1, not min(10,5)=5
    assert int(inferred.iloc[0]["count"]) == 1


def test_orphan_missing_parent_link_count(tmp_path):
    rows = [
        _event(
            0,
            timestamp="2020-01-01T00:00:00",
            archive_date="2020-01-01",
            image="C:\\Windows\\child.exe",
            parent="C:\\Windows\\parent.exe",
            command="ok",
        ),
        _event(
            1,
            timestamp="2020-01-02T00:00:00",
            archive_date="2020-01-02",
            image="C:\\Windows\\child.exe",
            parent="C:\\Windows\\parent.exe",
            command="ok",
        ),
        _event(
            2,
            timestamp="2020-01-01T01:00:00",
            archive_date="2020-01-01",
            image="C:\\Windows\\orphan.exe",
            parent="",
            command="orphan",
        ),
        _event(
            3,
            timestamp="2020-01-03T00:00:00",
            archive_date="2020-01-03",
            image="C:\\Windows\\eval.exe",
            parent="C:\\Windows\\parent.exe",
            command="eval",
        ),
    ]
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    metadata = eda7.run_eda07(args)
    assert metadata["missing_parent_process_count"] == 1
    assert metadata["missing_link_count_total"] >= 1


def test_separate_common_and_unusual_limits(tmp_path):
    rows = []
    # Many benign repeats to create common chains/commands
    for day, date in enumerate(("2020-01-01", "2020-01-02")):
        for index in range(6):
            rows.append(
                _event(
                    day * 10 + index,
                    timestamp=f"{date}T00:00:{index:02d}",
                    archive_date=date,
                    image="C:\\Windows\\common-child.exe",
                    parent="C:\\Windows\\common-parent.exe",
                    command="common-command",
                )
            )
    # Two distinct unusual evaluation examples
    rows.append(
        _event(
            30,
            timestamp="2020-01-03T00:00:00",
            archive_date="2020-01-03",
            image="C:\\Users\\alice\\u1.exe",
            parent="C:\\Users\\alice\\p1.exe",
            command="unusual-one",
        )
    )
    rows.append(
        _event(
            31,
            timestamp="2020-01-03T00:01:00",
            archive_date="2020-01-03",
            image="C:\\Users\\alice\\u2.exe",
            parent="C:\\Users\\alice\\p2.exe",
            command="unusual-two",
        )
    )
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture, max_unusual_examples=1)
    eda7.run_eda07(args)
    t15 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T15_unusual_command_process_examples.csv",
        keep_default_na=False,
    )
    common = t15.loc[
        t15["evidence_selection_reason"] == "common_verified_benign_example"
    ]
    unusual = t15.loc[
        t15["evidence_selection_reason"] == "unusual_evaluation_example"
    ]
    assert len(common) >= 1
    assert len(unusual) == 1
    assert len(t15) == len(common) + len(unusual)


def test_chain_only_novelty_in_t15(tmp_path):
    rows = []
    for day, date in enumerate(("2020-01-01", "2020-01-02")):
        for index in range(6):
            rows.append(
                _event(
                    day * 10 + index,
                    timestamp=f"{date}T00:00:{index:02d}",
                    archive_date=date,
                    image="C:\\Windows\\shared-child.exe",
                    parent="C:\\Windows\\shared-parent.exe",
                    command="shared-common-command",
                )
            )
    # Evaluation uses a new chain but the same common command text.
    rows.append(
        _event(
            40,
            timestamp="2020-01-03T00:00:00",
            archive_date="2020-01-03",
            image="C:\\Users\\alice\\new-child.exe",
            parent="C:\\Users\\alice\\new-parent.exe",
            command="shared-common-command",
        )
    )
    fixture = _fixture(tmp_path, rows)
    args = _args(tmp_path, fixture)
    eda7.run_eda07(args)
    t15 = pd.read_csv(
        pathlib.Path(args.output_dir) / "T15_unusual_command_process_examples.csv",
        keep_default_na=False,
    )
    unusual = t15.loc[
        t15["evidence_selection_reason"] == "unusual_evaluation_example"
    ]
    assert not unusual.empty
    assert (
        unusual["novelty_reason"] == "unusual_chain_common_command"
    ).any()
    assert (
        unusual["ground_truth_overlap_yes_no"] == eda7.GROUND_TRUTH_OVERLAP
    ).all()


def test_t15_chain_candidate_construction_is_bounded(monkeypatch):
    """Many unusual eval chains with max_unusual_examples=1 must not unpack all."""
    n_eval = 200
    rows: list[dict] = []
    # Enough benign support for a common example set.
    for day, date in enumerate(("2020-01-01", "2020-01-02")):
        for index in range(6):
            rows.append(
                {
                    "period": "verified_benign",
                    "window_start": pd.Timestamp(f"{date}T00:00:00"),
                    "host_id": "host-a",
                    "chain_length": 2,
                    "parent_process": "C:\\Windows\\common-parent.exe",
                    "child_process": "C:\\Windows\\common-child.exe",
                    "full_chain": (
                        "C:\\Windows\\common-parent.exe -> "
                        "C:\\Windows\\common-child.exe"
                    ),
                    "normalized_chain": (
                        "c:\\windows\\common-parent.exe -> "
                        "c:\\windows\\common-child.exe"
                    ),
                    "count": 1,
                    "first_seen_time": pd.Timestamp(f"{date}T00:00:{index:02d}"),
                    "last_seen_time": pd.Timestamp(f"{date}T00:00:{index:02d}"),
                    "construction_type": "observed_same_event",
                    "link_status": "observed",
                    "ambiguity_count": 0,
                    "missing_link_count": 0,
                    "supporting_observed_edge_count": 1,
                    "parent_process_raw": "C:\\Windows\\common-parent.exe",
                    "child_process_raw": "C:\\Windows\\common-child.exe",
                    "parent_process_id": "parent-common",
                    "child_process_id": "child-common",
                    "mapping_status": "resolved",
                    "evidence_ids": [f"benign-{day}-{index}"],
                    "evidence_records": {
                        "event_time": f"{date}T00:00:{index:02d}",
                        "archive_name": f"{date}.tar",
                        "member_name": "h1.json.gz",
                        "line_number": index + 1,
                        "raw_event_id": f"benign-{day}-{index}",
                        "command_line_raw": "shared-common-command",
                        "actor_id_raw": "",
                        "object_id_raw": "",
                        "pid_raw": "",
                        "ppid_raw": "",
                    },
                    "normalized_nodes": [
                        "c:\\windows\\common-parent.exe",
                        "c:\\windows\\common-child.exe",
                    ],
                    "chain_id": "pch_common",
                    "first_evidence_event_time": f"{date}T00:00:{index:02d}",
                    "first_evidence_archive_name": f"{date}.tar",
                    "first_evidence_member_name": "h1.json.gz",
                    "first_evidence_line_number": index + 1,
                    "first_evidence_raw_event_id": f"benign-{day}-{index}",
                }
            )

    for index in range(n_eval):
        minute = index // 60
        second = index % 60
        stamp = f"2020-01-03T00:{minute:02d}:{second:02d}"
        parent = f"C:\\Users\\alice\\p{index:04d}.exe"
        child = f"C:\\Users\\alice\\c{index:04d}.exe"
        chain_id = f"pch_eval_{index:04d}"
        rows.append(
            {
                "period": "evaluation",
                "window_start": pd.Timestamp(stamp),
                "host_id": "host-a",
                "chain_length": 2,
                "parent_process": parent,
                "child_process": child,
                "full_chain": f"{parent} -> {child}",
                "normalized_chain": (
                    f"{parent.casefold()} -> {child.casefold()}"
                ),
                "count": 1,
                "first_seen_time": pd.Timestamp(stamp),
                "last_seen_time": pd.Timestamp(stamp),
                "construction_type": "observed_same_event",
                "link_status": "observed",
                "ambiguity_count": 0,
                "missing_link_count": 0,
                "supporting_observed_edge_count": 1,
                "parent_process_raw": parent,
                "child_process_raw": child,
                "parent_process_id": f"parent-{index}",
                "child_process_id": f"child-{index}",
                "mapping_status": "resolved",
                "evidence_ids": [f"e{index:04d}"],
                "evidence_records": {
                    "event_time": stamp,
                    "archive_name": "2020-01-03.tar",
                    "member_name": "h1.json.gz",
                    "line_number": index + 1,
                    "raw_event_id": f"e{index:04d}",
                    "command_line_raw": "shared-common-command",
                    "actor_id_raw": "",
                    "object_id_raw": "",
                    "pid_raw": "",
                    "ppid_raw": "",
                },
                "normalized_nodes": [parent.casefold(), child.casefold()],
                "chain_id": chain_id,
                "first_evidence_event_time": stamp,
                "first_evidence_archive_name": "2020-01-03.tar",
                "first_evidence_member_name": "h1.json.gz",
                "first_evidence_line_number": index + 1,
                "first_evidence_raw_event_id": f"e{index:04d}",
            }
        )

    window_chains = pd.DataFrame(rows)
    t14_rows = []
    for chain_id in sorted(set(window_chains["chain_id"])):
        subset = window_chains.loc[window_chains["chain_id"] == chain_id]
        period = "verified_benign" if chain_id == "pch_common" else "evaluation"
        benign_count = int((subset["period"] == "verified_benign").sum())
        eval_count = int((subset["period"] == "evaluation").sum())
        sample = subset.iloc[0]
        t14_rows.append(
            {
                "period": period,
                "host_id": sample.host_id,
                "chain_length": 2,
                "parent_process": sample.parent_process,
                "child_process": sample.child_process,
                "full_chain": sample.full_chain,
                "count": int(subset["count"].sum()),
                "first_seen_time": sample.first_seen_time,
                "last_seen_time": sample.last_seen_time,
                "benign_rank": 1 if chain_id == "pch_common" else None,
                "chain_id": chain_id,
                "window_size": "1min",
                "construction_type": "observed_same_event",
                "link_status": "observed",
                "ambiguity_count": 0,
                "missing_link_count": 0,
                "supporting_observed_edge_count": 1,
                "parent_process_raw": sample.parent_process_raw,
                "child_process_raw": sample.child_process_raw,
                "parent_process_id": sample.parent_process_id,
                "child_process_id": sample.child_process_id,
                "normalized_chain": sample.normalized_chain,
                "benign_count": 12 if chain_id == "pch_common" else 0,
                "evaluation_count": eval_count,
                "first_seen_period": (
                    "verified_benign"
                    if chain_id == "pch_common"
                    else "evaluation"
                ),
                "novelty_status": (
                    "common_in_verified_benign"
                    if chain_id == "pch_common"
                    else "unseen_in_verified_benign"
                ),
                "next_process": "",
                "next_process_support": 0,
                "next_process_conditional_frequency": None,
                "evidence_ids": "[]",
                "evidence_count": 0,
                "mapping_status": "resolved",
            }
        )
    t14 = pd.DataFrame(t14_rows, columns=eda7.T14_COLUMNS)

    calls = {"first_evidence": 0}
    original = eda7._first_evidence_record

    def counting_first_evidence(records):
        calls["first_evidence"] += 1
        return original(records)

    monkeypatch.setattr(eda7, "_first_evidence_record", counting_first_evidence)

    selected = eda7.select_bounded_chain_unusual_candidates(
        window_chains.loc[window_chains["period"] == "evaluation"],
        {
            str(row.chain_id): (int(row.benign_count), int(row.evaluation_count))
            for row in t14.itertuples(index=False)
        },
        rare_benign_max_count=5,
        max_unusual_examples=1,
    )
    assert len(selected) == 1
    assert selected[0].chain_id == "pch_eval_0000"

    command_aggregates = {
        "benign_cmd": {"shared-common-command": 12},
        "eval_cmd": {"shared-common-command": n_eval},
        "unusual_command_candidates": pd.DataFrame(),
        "f8_command": pd.DataFrame(),
        "normalization_counts": {},
        "distinct_command_count": 1,
    }
    t15 = eda7._build_t15(
        window_chains,
        command_aggregates,
        t14,
        rare_benign_max_count=5,
        max_unusual_examples=1,
        evidence_cap=20,
    )
    unusual = t15.loc[
        t15["evidence_selection_reason"] == "unusual_evaluation_example"
    ]
    common = t15.loc[
        t15["evidence_selection_reason"] == "common_verified_benign_example"
    ]
    assert len(unusual) == 1
    assert unusual.iloc[0]["raw_event_ids"] == json.dumps(["e0000"])
    assert unusual.iloc[0]["novelty_reason"] == "unusual_chain_common_command"
    assert len(common) >= 1
    # Evidence unpack for unusual chain path is bounded by the selected set,
    # plus at most 10 common examples — never one-per-eval-chain.
    assert calls["first_evidence"] <= 11
    assert calls["first_evidence"] < n_eval


def test_t15_chain_preselection_uses_evidence_locator_not_chain_id(monkeypatch):
    """Tied first_seen_time must prefer earlier archive/member/line/event id.

    chain_id lexical order is intentionally opposite the evidence locator order
    so the old (first_seen_time, host_id, chain_id) key would pick the wrong row.
    """
    stamp = "2020-01-03T00:00:00"
    shared_time = pd.Timestamp(stamp)

    def _eval_chain(
        *,
        chain_id: str,
        parent: str,
        child: str,
        archive_name: str,
        member_name: str,
        line_number: int,
        raw_event_id: str,
    ) -> dict:
        return {
            "period": "evaluation",
            "window_start": shared_time,
            "host_id": "host-a",
            "chain_length": 2,
            "parent_process": parent,
            "child_process": child,
            "full_chain": f"{parent} -> {child}",
            "normalized_chain": f"{parent.casefold()} -> {child.casefold()}",
            "count": 1,
            "first_seen_time": shared_time,
            "last_seen_time": shared_time,
            "construction_type": "observed_same_event",
            "link_status": "observed",
            "ambiguity_count": 0,
            "missing_link_count": 0,
            "supporting_observed_edge_count": 1,
            "parent_process_raw": parent,
            "child_process_raw": child,
            "parent_process_id": f"parent-{raw_event_id}",
            "child_process_id": f"child-{raw_event_id}",
            "mapping_status": "resolved",
            "evidence_ids": [raw_event_id],
            "evidence_records": {
                "event_time": stamp,
                "archive_name": archive_name,
                "member_name": member_name,
                "line_number": line_number,
                "raw_event_id": raw_event_id,
                "command_line_raw": "shared-common-command",
                "actor_id_raw": "",
                "object_id_raw": "",
                "pid_raw": "",
                "ppid_raw": "",
            },
            "normalized_nodes": [parent.casefold(), child.casefold()],
            "chain_id": chain_id,
            "first_evidence_event_time": stamp,
            "first_evidence_archive_name": archive_name,
            "first_evidence_member_name": member_name,
            "first_evidence_line_number": line_number,
            "first_evidence_raw_event_id": raw_event_id,
        }

    # Lexically earlier chain_id has *later* evidence locator fields.
    early_by_id = _eval_chain(
        chain_id="pch_aaa_late",
        parent="C:\\Users\\alice\\late-parent.exe",
        child="C:\\Users\\alice\\late-child.exe",
        archive_name="z-late.tar",
        member_name="z-member.json.gz",
        line_number=99,
        raw_event_id="z-late-event",
    )
    early_by_evidence = _eval_chain(
        chain_id="pch_zzz_early",
        parent="C:\\Users\\alice\\early-parent.exe",
        child="C:\\Users\\alice\\early-child.exe",
        archive_name="a-early.tar",
        member_name="a-member.json.gz",
        line_number=1,
        raw_event_id="a-early-event",
    )
    assert early_by_id["chain_id"] < early_by_evidence["chain_id"]
    assert (
        early_by_evidence["first_evidence_archive_name"]
        < early_by_id["first_evidence_archive_name"]
    )

    window_chains = pd.DataFrame([early_by_id, early_by_evidence])
    chain_counts = {
        "pch_aaa_late": (0, 1),
        "pch_zzz_early": (0, 1),
    }
    t14 = pd.DataFrame(
        [
            {
                "period": "evaluation",
                "host_id": "host-a",
                "chain_length": 2,
                "parent_process": row["parent_process"],
                "child_process": row["child_process"],
                "full_chain": row["full_chain"],
                "count": 1,
                "first_seen_time": shared_time,
                "last_seen_time": shared_time,
                "benign_rank": None,
                "chain_id": row["chain_id"],
                "window_size": "1min",
                "construction_type": "observed_same_event",
                "link_status": "observed",
                "ambiguity_count": 0,
                "missing_link_count": 0,
                "supporting_observed_edge_count": 1,
                "parent_process_raw": row["parent_process_raw"],
                "child_process_raw": row["child_process_raw"],
                "parent_process_id": row["parent_process_id"],
                "child_process_id": row["child_process_id"],
                "normalized_chain": row["normalized_chain"],
                "benign_count": 0,
                "evaluation_count": 1,
                "first_seen_period": "evaluation",
                "novelty_status": "unseen_in_verified_benign",
                "next_process": "",
                "next_process_support": 0,
                "next_process_conditional_frequency": None,
                "evidence_ids": "[]",
                "evidence_count": 0,
                "mapping_status": "resolved",
            }
            for row in (early_by_id, early_by_evidence)
        ],
        columns=eda7.T14_COLUMNS,
    )

    calls = {"first_evidence": 0}
    original = eda7._first_evidence_record

    def counting_first_evidence(records):
        calls["first_evidence"] += 1
        return original(records)

    monkeypatch.setattr(eda7, "_first_evidence_record", counting_first_evidence)

    selected = eda7.select_bounded_chain_unusual_candidates(
        window_chains,
        chain_counts,
        rare_benign_max_count=5,
        max_unusual_examples=1,
    )
    assert len(selected) == 1
    assert selected[0].chain_id == "pch_zzz_early"
    assert selected[0].first_evidence_raw_event_id == "a-early-event"

    t15 = eda7._build_t15(
        window_chains,
        {
            "benign_cmd": {"shared-common-command": 12},
            "eval_cmd": {"shared-common-command": 2},
            "unusual_command_candidates": pd.DataFrame(),
            "f8_command": pd.DataFrame(),
            "normalization_counts": {},
            "distinct_command_count": 1,
        },
        t14,
        rare_benign_max_count=5,
        max_unusual_examples=1,
        evidence_cap=20,
    )
    unusual = t15.loc[
        t15["evidence_selection_reason"] == "unusual_evaluation_example"
    ]
    assert len(unusual) == 1
    assert unusual.iloc[0]["raw_event_ids"] == json.dumps(["a-early-event"])
    assert unusual.iloc[0]["chain_id"] == "pch_zzz_early"
    assert unusual.iloc[0]["novelty_reason"] == "unusual_chain_common_command"
    # Only the selected unusual chain is unpacked (no common rows in this fixture).
    assert calls["first_evidence"] == 1
