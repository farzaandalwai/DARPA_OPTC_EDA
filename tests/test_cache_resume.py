"""
Focused synthetic tests for normalized-cache crash-resume.

Uses only temporary directories and tiny in-memory/on-disk archives.
Does not touch any real Drive cache.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import pathlib
import sys
import tarfile

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src" / "eda"))
import build_normalized_pilot_cache as cache_builder  # type: ignore
import cache_resume as cr  # type: ignore
from optc_streaming_parser import SLIM_EVENT_COLUMNS  # type: ignore


# ── synthetic fixtures ────────────────────────────────────────────────────

def _event_line(eid: str, host: str = "h1") -> str:
    return json.dumps({
        "id": eid,
        "hostname": host,
        "action": "CREATE",
        "object": "PROCESS",
        "objectID": f"oid-{eid}",
        "pid": 1,
        "ppid": 0,
        "tid": 1,
        "principal": "u",
        "timestamp": "2019-09-16T00:00:00Z",
        "properties": {"image_path": f"C:\\\\{eid}.exe"},
    }, separators=(",", ":"))


def _write_json_gz(path: pathlib.Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as f:
        for ln in lines:
            f.write(ln + "\n")


def _make_tar(tar_path: pathlib.Path, members: dict[str, list[str]]) -> None:
    """members: member_name -> list of json lines."""
    tar_path.parent.mkdir(parents=True, exist_ok=True)
    staging = tar_path.parent / f".stage_{tar_path.stem}"
    if staging.exists():
        for p in staging.rglob("*"):
            if p.is_file():
                p.unlink()
    staging.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tar_path, "w") as tf:
        for name, lines in members.items():
            local = staging / name.replace("/", "_")
            _write_json_gz(local, lines)
            tf.add(local, arcname=name)


def _write_manifest(path: pathlib.Path, rows: list[dict]) -> None:
    df = pd.DataFrame(rows)
    for col in (
        "archive_filename", "member_name", "archive_date",
        "inferred_host_or_client", "member_size_gib", "manifest_version",
    ):
        if col not in df.columns:
            if col == "member_size_gib":
                df[col] = 0.001
            elif col == "manifest_version":
                df[col] = "test_resume_v1"
            elif col == "archive_date":
                df[col] = "2019-09-16"
            elif col == "inferred_host_or_client":
                df[col] = "h1"
            else:
                df[col] = ""
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)


def _build_two_member_fixture(root: pathlib.Path, n1: int = 30, n2: int = 20):
    archives = root / "archives"
    archives.mkdir(parents=True, exist_ok=True)
    m1 = [ _event_line(f"m1-{i}") for i in range(1, n1 + 1) ]
    m2 = [ _event_line(f"m2-{i}") for i in range(1, n2 + 1) ]
    tar = archives / "2019-09-16.tar"
    _make_tar(tar, {
        "ecar/hostA.ecar.json.gz": m1,
        "ecar/hostB.ecar.json.gz": m2,
    })
    manifest = root / "manifest.csv"
    _write_manifest(manifest, [
        {
            "archive_filename": "2019-09-16.tar",
            "member_name": "ecar/hostA.ecar.json.gz",
            "archive_date": "2019-09-16",
            "inferred_host_or_client": "h1",
            "member_size_gib": 0.01,
            "manifest_version": "test_resume_v1",
        },
        {
            "archive_filename": "2019-09-16.tar",
            "member_name": "ecar/hostB.ecar.json.gz",
            "archive_date": "2019-09-16",
            "inferred_host_or_client": "h1",
            "member_size_gib": 0.01,
            "manifest_version": "test_resume_v1",
        },
    ])
    return archives, manifest, n1, n2


def _run_builder(root, archives, manifest, cache_dir, **flags):
    argv = [
        "--project-root", str(root),
        "--corrected-dir", str(archives),
        "--manifest-csv", str(manifest),
        "--cache-dir", str(cache_dir),
        "--chunk-size", str(flags.pop("chunk_size", 10)),
        "--compression", "snappy",
        "--trust-preverified-manifest",
    ]
    if flags.pop("overwrite", False):
        argv.append("--overwrite")
    if flags.pop("resume", False):
        argv.append("--resume")
    if "max_events" in flags:
        argv.extend(["--max-events", str(flags.pop("max_events"))])
    if "max_events_per_member" in flags:
        argv.extend(["--max-events-per-member", str(flags.pop("max_events_per_member"))])
    assert not flags, flags
    old = sys.argv
    try:
        sys.argv = ["build_normalized_pilot_cache.py"] + argv
        cache_builder.main()
    finally:
        sys.argv = old


def _chunk_paths(cache_dir: pathlib.Path):
    return sorted(
        p for p in cache_dir.glob("chunk_*.parquet")
        if not p.name.endswith(".tmp")
    )


def _file_bytes(paths):
    return {p.name: p.read_bytes() for p in paths}


def _read_locators(cache_dir: pathlib.Path):
    rows = []
    for p in _chunk_paths(cache_dir):
        t = pq.read_table(
            p,
            columns=["archive_name", "member_name", "line_number", "raw_event_id", "file_id"],
        )
        for i in range(t.num_rows):
            rows.append({
                "archive_name": str(t.column("archive_name")[i].as_py()),
                "member_name": str(t.column("member_name")[i].as_py()),
                "line_number": int(t.column("line_number")[i].as_py()),
                "raw_event_id": str(t.column("raw_event_id")[i].as_py()),
                "file_id": t.column("file_id")[i].as_py(),
            })
    return rows


# ── CLI conflict tests ────────────────────────────────────────────────────

def test_resume_overwrite_conflict(tmp_path):
    args = cache_builder.parse_args([
        "--corrected-dir", str(tmp_path),
        "--manifest-csv", str(tmp_path / "m.csv"),
        "--resume", "--overwrite",
    ])
    assert args.resume and args.overwrite
    with pytest.raises(SystemExit):
        cache_builder._validate_resume_cli(args)


def test_resume_max_events_conflict(tmp_path):
    args = cache_builder.parse_args([
        "--corrected-dir", str(tmp_path),
        "--manifest-csv", str(tmp_path / "m.csv"),
        "--resume", "--max-events", "10",
    ])
    with pytest.raises(SystemExit):
        cache_builder._validate_resume_cli(args)


def test_resume_max_events_per_member_conflict(tmp_path):
    args = cache_builder.parse_args([
        "--corrected-dir", str(tmp_path),
        "--manifest-csv", str(tmp_path / "m.csv"),
        "--resume", "--max-events-per-member", "5",
    ])
    with pytest.raises(SystemExit):
        cache_builder._validate_resume_cli(args)


# ── discovery / validation unit tests ─────────────────────────────────────

def test_noncontiguous_and_duplicate_indexes(tmp_path):
    cache = tmp_path / "c"
    cache.mkdir()
    # Write two valid tiny chunks with indexes 0 and 2 (gap).
    df = pd.DataFrame([{c: "x" for c in SLIM_EVENT_COLUMNS}])
    df["archive_name"] = ["a.tar"]
    df["member_name"] = ["m.json.gz"]
    df["line_number"] = [1]
    df["raw_event_id"] = ["id1"]
    df["file_id"] = [1]
    df = df[list(SLIM_EVENT_COLUMNS)]
    df.to_parquet(cache / "chunk_00000_date_20190916.parquet", index=False)
    df.to_parquet(cache / "chunk_00002_date_20190916.parquet", index=False)
    with pytest.raises(cr.ResumeError, match="Non-contiguous"):
        cr.discover_finalized_chunks(cache)

    # Duplicate index different date tokens
    cache2 = tmp_path / "c2"
    cache2.mkdir()
    df.to_parquet(cache2 / "chunk_00000_date_20190916.parquet", index=False)
    df.to_parquet(cache2 / "chunk_00000_date_20190917.parquet", index=False)
    with pytest.raises(cr.ResumeError, match="Duplicate"):
        cr.discover_finalized_chunks(cache2)


def test_schema_mismatch_and_unreadable(tmp_path):
    cache = tmp_path / "c"
    cache.mkdir()
    bad = cache / "chunk_00000_date_20190916.parquet"
    # Wrong columns
    pd.DataFrame({"foo": [1], "bar": [2]}).to_parquet(bad, index=False)
    with pytest.raises(cr.ResumeError, match="Schema/column mismatch"):
        cr.validate_chunk_schema(bad)

    junk = cache / "chunk_00001_date_20190916.parquet"
    junk.write_bytes(b"not-a-parquet")
    # Make contiguous discovery fail at validation of second file after fixing first
    cache3 = tmp_path / "c3"
    cache3.mkdir()
    df = pd.DataFrame([{c: "v" for c in SLIM_EVENT_COLUMNS}])
    df.to_parquet(cache3 / "chunk_00000_date_20190916.parquet", index=False)
    (cache3 / "chunk_00001_date_20190916.parquet").write_bytes(b"nope")
    chunks = cr.discover_finalized_chunks(cache3)
    with pytest.raises(cr.ResumeError, match="Unreadable"):
        cr.validate_all_chunks(chunks)


# ── end-to-end resume behaviors ───────────────────────────────────────────

def test_fresh_build_unchanged_and_mid_member_resume(tmp_path):
    archives, manifest, n1, n2 = _build_two_member_fixture(tmp_path, n1=25, n2=15)
    full = tmp_path / "full"
    _run_builder(tmp_path, archives, manifest, full, chunk_size=10, overwrite=True)
    full_rows = _read_locators(full)
    assert len(full_rows) == n1 + n2
    keys = [(r["archive_name"], r["member_name"], r["line_number"]) for r in full_rows]
    assert len(keys) == len(set(keys))

    # Interrupted: keep only first 2 chunks (20 events) → mid-member A.
    interrupted = tmp_path / "interrupted"
    interrupted.mkdir()
    full_chunks = _chunk_paths(full)
    assert len(full_chunks) >= 3
    for p in full_chunks[:2]:
        (interrupted / p.name).write_bytes(p.read_bytes())
    before = _file_bytes(_chunk_paths(interrupted))
    assert len(before) == 2

    _run_builder(tmp_path, archives, manifest, interrupted, chunk_size=10, resume=True)
    after_existing = {n: (interrupted / n).read_bytes() for n in before}
    assert after_existing == before  # byte-for-byte unchanged

    resumed_chunks = _chunk_paths(interrupted)
    assert resumed_chunks[0].name.startswith("chunk_00000_")
    assert any(p.name.startswith("chunk_00002_") for p in resumed_chunks)
    # Next index after 0,1 is 2
    indexes = [int(p.name.split("_")[1]) for p in resumed_chunks]
    assert indexes == list(range(len(indexes)))

    resumed_rows = _read_locators(interrupted)
    assert len(resumed_rows) == len(full_rows)
    rkeys = [(r["archive_name"], r["member_name"], r["line_number"]) for r in resumed_rows]
    assert rkeys == keys
    assert len(rkeys) == len(set(rkeys))
    # file_id identity vs clean full build
    assert [r["file_id"] for r in resumed_rows] == [r["file_id"] for r in full_rows]

    meta = json.loads((interrupted / "cache_metadata.json").read_text())
    assert meta["resumed"] is True
    assert meta["resume_first_new_chunk_index"] == 2
    assert meta["resume_preexisting_chunks"] == 2
    assert meta["resume_inferred_from_legacy_cache"] is True
    assert meta["resume_initial_checkpoint"]["raw_event_id"] == cr.read_last_row_checkpoint(
        full_chunks[1]
    )["raw_event_id"]
    assert meta["resume_final_checkpoint"]["raw_event_id"] == resumed_rows[-1]["raw_event_id"]
    assert meta["resume_initial_checkpoint"] != meta["resume_final_checkpoint"]
    assert "resume_checkpoint" not in meta


def test_member_boundary_resume(tmp_path):
    archives, manifest, n1, n2 = _build_two_member_fixture(tmp_path, n1=20, n2=12)
    full = tmp_path / "full"
    _run_builder(tmp_path, archives, manifest, full, chunk_size=10, overwrite=True)
    # Exactly first member (20 events) → 2 chunks; boundary between members.
    interrupted = tmp_path / "interrupted"
    interrupted.mkdir()
    for p in _chunk_paths(full)[:2]:
        (interrupted / p.name).write_bytes(p.read_bytes())
    last = cr.read_last_row_checkpoint(_chunk_paths(interrupted)[-1])
    assert last["member_name"].endswith("hostA.ecar.json.gz")
    assert int(last["line_number"]) == n1

    before = _file_bytes(_chunk_paths(interrupted))
    _run_builder(tmp_path, archives, manifest, interrupted, chunk_size=10, resume=True)
    assert _file_bytes([interrupted / n for n in before]) == before
    rows = _read_locators(interrupted)
    assert len(rows) == n1 + n2
    assert rows[n1]["member_name"].endswith("hostB.ecar.json.gz")


def test_resume_state_consistent_and_lagging(tmp_path):
    archives, manifest, n1, n2 = _build_two_member_fixture(tmp_path, n1=20, n2=10)
    full = tmp_path / "full"
    _run_builder(tmp_path, archives, manifest, full, chunk_size=10, overwrite=True)

    # Consistent state present
    interrupted = tmp_path / "with_state"
    interrupted.mkdir()
    for p in _chunk_paths(full)[:2]:
        (interrupted / p.name).write_bytes(p.read_bytes())
    ckpt = cr.read_last_row_checkpoint(_chunk_paths(interrupted)[-1])
    cr.write_resume_state(
        interrupted,
        last_committed_chunk_index=1,
        combined_events=20,
        checkpoint=ckpt,
    )
    _run_builder(tmp_path, archives, manifest, interrupted, chunk_size=10, resume=True)
    meta = json.loads((interrupted / "cache_metadata.json").read_text())
    assert meta["resume_inferred_from_legacy_cache"] is False
    assert len(_read_locators(interrupted)) == n1 + n2

    # Lagging state (claims index 0 while chunks 0..1 exist) — chunks win
    lag = tmp_path / "lag"
    lag.mkdir()
    for p in _chunk_paths(full)[:2]:
        (lag / p.name).write_bytes(p.read_bytes())
    cr.write_resume_state(
        lag,
        last_committed_chunk_index=0,  # lagging
        combined_events=10,
        checkpoint=cr.read_last_row_checkpoint(_chunk_paths(lag)[0]),
    )
    before = _file_bytes(_chunk_paths(lag))
    _run_builder(tmp_path, archives, manifest, lag, chunk_size=10, resume=True)
    assert _file_bytes([lag / n for n in before]) == before
    assert any(p.name.startswith("chunk_00002_") for p in _chunk_paths(lag))
    assert len(_read_locators(lag)) == n1 + n2


def test_checkpoint_missing_from_manifest(tmp_path):
    archives, manifest, n1, n2 = _build_two_member_fixture(tmp_path, n1=15, n2=10)
    full = tmp_path / "full"
    _run_builder(tmp_path, archives, manifest, full, chunk_size=10, overwrite=True)
    interrupted = tmp_path / "interrupted"
    interrupted.mkdir()
    for p in _chunk_paths(full)[:1]:
        (interrupted / p.name).write_bytes(p.read_bytes())
    # Manifest without the checkpoint member
    bad_manifest = tmp_path / "bad_manifest.csv"
    _write_manifest(bad_manifest, [{
        "archive_filename": "2019-09-16.tar",
        "member_name": "ecar/hostB.ecar.json.gz",
        "archive_date": "2019-09-16",
        "inferred_host_or_client": "h1",
        "member_size_gib": 0.01,
        "manifest_version": "test_resume_v1",
    }])
    before = _file_bytes(_chunk_paths(interrupted))
    with pytest.raises(SystemExit):
        _run_builder(tmp_path, archives, bad_manifest, interrupted, chunk_size=10, resume=True)
    assert _file_bytes(_chunk_paths(interrupted)) == before
    assert len(_chunk_paths(interrupted)) == 1


def test_raw_event_id_mismatch_aborts_without_new_chunk(tmp_path):
    archives, manifest, n1, n2 = _build_two_member_fixture(tmp_path, n1=15, n2=10)
    full = tmp_path / "full"
    _run_builder(tmp_path, archives, manifest, full, chunk_size=10, overwrite=True)
    interrupted = tmp_path / "interrupted"
    interrupted.mkdir()
    src = _chunk_paths(full)[0]
    dst = interrupted / src.name
    # Corrupt last row raw_event_id in a copied chunk so checkpoint ID is wrong
    # relative to source (source unchanged).
    t = pq.read_table(src)
    df = t.to_pandas()
    df.loc[df.index[-1], "raw_event_id"] = "CORRUPTED-ID"
    # Preserve column order
    df = df[list(SLIM_EVENT_COLUMNS)]
    df.to_parquet(dst, index=False)
    before = _file_bytes(_chunk_paths(interrupted))
    with pytest.raises(SystemExit):
        _run_builder(tmp_path, archives, manifest, interrupted, chunk_size=10, resume=True)
    assert _file_bytes(_chunk_paths(interrupted)) == before
    assert len(_chunk_paths(interrupted)) == 1


def test_checkpoint_line_missing_source_shorter(tmp_path):
    # Build interrupted chunk claiming a line beyond source length.
    archives = tmp_path / "archives"
    archives.mkdir()
    lines = [_event_line(f"m1-{i}") for i in range(1, 6)]
    _make_tar(archives / "2019-09-16.tar", {"ecar/hostA.ecar.json.gz": lines})
    manifest = tmp_path / "manifest.csv"
    _write_manifest(manifest, [{
        "archive_filename": "2019-09-16.tar",
        "member_name": "ecar/hostA.ecar.json.gz",
        "archive_date": "2019-09-16",
        "inferred_host_or_client": "h1",
        "member_size_gib": 0.01,
        "manifest_version": "test_resume_v1",
    }])
    cache = tmp_path / "cache"
    cache.mkdir()
    row = {c: "" for c in SLIM_EVENT_COLUMNS}
    row.update({
        "archive_name": "2019-09-16.tar",
        "member_name": "ecar/hostA.ecar.json.gz",
        "line_number": 99,  # beyond source
        "raw_event_id": "m1-1",
        "file_id": 1,
        "parse_status": "ok",
        "source_type": "endpoint",
    })
    pd.DataFrame([row])[list(SLIM_EVENT_COLUMNS)].to_parquet(
        cache / "chunk_00000_date_20190916.parquet", index=False
    )
    before = _file_bytes(_chunk_paths(cache))
    with pytest.raises(SystemExit):
        _run_builder(tmp_path, archives, manifest, cache, chunk_size=10, resume=True)
    assert _file_bytes(_chunk_paths(cache)) == before
    assert len(_chunk_paths(cache)) == 1


def test_file_id_matches_clean_full_build_multi_archive(tmp_path):
    # Two archives to ensure per-archive file_id restart is preserved.
    archives = tmp_path / "archives"
    archives.mkdir()
    _make_tar(archives / "2019-09-16.tar", {
        "ecar/a.json.gz": [_event_line(f"a-{i}") for i in range(1, 12)],
    })
    _make_tar(archives / "2019-09-17.tar", {
        "ecar/b.json.gz": [_event_line(f"b-{i}") for i in range(1, 8)],
    })
    manifest = tmp_path / "manifest.csv"
    _write_manifest(manifest, [
        {
            "archive_filename": "2019-09-16.tar",
            "member_name": "ecar/a.json.gz",
            "archive_date": "2019-09-16",
            "inferred_host_or_client": "h1",
            "member_size_gib": 0.01,
            "manifest_version": "test_resume_v1",
        },
        {
            "archive_filename": "2019-09-17.tar",
            "member_name": "ecar/b.json.gz",
            "archive_date": "2019-09-17",
            "inferred_host_or_client": "h2",
            "member_size_gib": 0.01,
            "manifest_version": "test_resume_v1",
        },
    ])
    full = tmp_path / "full"
    _run_builder(tmp_path, archives, manifest, full, chunk_size=5, overwrite=True)
    interrupted = tmp_path / "interrupted"
    interrupted.mkdir()
    for p in _chunk_paths(full)[:2]:
        (interrupted / p.name).write_bytes(p.read_bytes())
    _run_builder(tmp_path, archives, manifest, interrupted, chunk_size=5, resume=True)
    assert [r["file_id"] for r in _read_locators(interrupted)] == [
        r["file_id"] for r in _read_locators(full)
    ]
    # Second archive file_ids restart at 1
    rows = _read_locators(interrupted)
    b_rows = [r for r in rows if r["archive_name"] == "2019-09-17.tar"]
    assert [int(r["file_id"]) for r in b_rows] == list(range(1, len(b_rows) + 1))


def test_adversarial_file_id_with_malformed_and_nondict_lines(tmp_path):
    """
    Prove resume file_id matches a clean full build when the checkpoint archive
    has 3 members, mid-member interrupt, JSON errors, non-dict JSON skips, and
    a later archive that resets the counter.
    """
    archives = tmp_path / "archives"
    archives.mkdir()

    # Member M1: 5 good events
    m1 = [_event_line(f"m1-{i}") for i in range(1, 6)]
    # Member M2 (checkpoint member): mix of good, blank, malformed, non-dict, good
    m2 = [
        _event_line("m2-1"),
        "",  # blank — skipped, no file_id
        _event_line("m2-2"),
        "{not-json",  # JSONDecodeError — emitted with file_id
        "[1,2,3]",  # non-dict — skipped, no emit, no file_id
        _event_line("m2-3"),
        _event_line("m2-4"),
        _event_line("m2-5"),
        _event_line("m2-6"),
        _event_line("m2-7"),
    ]
    # Member M3: more events after checkpoint member
    m3 = [_event_line(f"m3-{i}") for i in range(1, 5)]
    _make_tar(archives / "2019-09-16.tar", {
        # Tar physical order: m1, m2, m3
        "ecar/m1.json.gz": m1,
        "ecar/m2.json.gz": m2,
        "ecar/m3.json.gz": m3,
    })
    _make_tar(archives / "2019-09-17.tar", {
        "ecar/n1.json.gz": [_event_line(f"n1-{i}") for i in range(1, 4)],
    })

    # Manifest lists members in REVERSE order vs tar — processing must follow tar.
    manifest = tmp_path / "manifest.csv"
    _write_manifest(manifest, [
        {
            "archive_filename": "2019-09-16.tar",
            "member_name": "ecar/m3.json.gz",
            "archive_date": "2019-09-16",
            "inferred_host_or_client": "h1",
            "member_size_gib": 0.01,
            "manifest_version": "test_resume_v1",
        },
        {
            "archive_filename": "2019-09-16.tar",
            "member_name": "ecar/m2.json.gz",
            "archive_date": "2019-09-16",
            "inferred_host_or_client": "h1",
            "member_size_gib": 0.01,
            "manifest_version": "test_resume_v1",
        },
        {
            "archive_filename": "2019-09-16.tar",
            "member_name": "ecar/m1.json.gz",
            "archive_date": "2019-09-16",
            "inferred_host_or_client": "h1",
            "member_size_gib": 0.01,
            "manifest_version": "test_resume_v1",
        },
        {
            "archive_filename": "2019-09-17.tar",
            "member_name": "ecar/n1.json.gz",
            "archive_date": "2019-09-17",
            "inferred_host_or_client": "h2",
            "member_size_gib": 0.01,
            "manifest_version": "test_resume_v1",
        },
    ])

    full = tmp_path / "full"
    _run_builder(tmp_path, archives, manifest, full, chunk_size=4, overwrite=True)
    full_rows = _read_locators(full)

    # Expected emitted order for archive 1 follows TAR order m1→m2→m3.
    a1 = [r for r in full_rows if r["archive_name"] == "2019-09-16.tar"]
    assert [r["member_name"] for r in a1[:5]] == ["ecar/m1.json.gz"] * 5
    # After 5 m1 events, m2 starts. Blank skipped; malformed emitted; non-dict skipped.
    m2_rows = [r for r in a1 if r["member_name"] == "ecar/m2.json.gz"]
    assert [r["raw_event_id"] for r in m2_rows] == [
        "m2-1", "m2-2",
        # malformed uses gen_ stable id
        m2_rows[2]["raw_event_id"],
        "m2-3", "m2-4", "m2-5", "m2-6", "m2-7",
    ]
    assert m2_rows[2]["raw_event_id"].startswith("gen_")
    # file_ids contiguous 1..N for archive 1 (no gaps for skips that don't emit)
    assert [int(r["file_id"]) for r in a1] == list(range(1, len(a1) + 1))
    a2 = [r for r in full_rows if r["archive_name"] == "2019-09-17.tar"]
    assert [int(r["file_id"]) for r in a2] == [1, 2, 3]

    # Interrupt mid m2: choose a chunk whose last row is in m2 but not m2's final event.
    full_chunks = _chunk_paths(full)
    cut = None
    for i, p in enumerate(full_chunks):
        ck = cr.read_last_row_checkpoint(p)
        if (
            ck["member_name"] == "ecar/m2.json.gz"
            and ck["raw_event_id"] != "m2-7"
        ):
            cut = i
            break
    assert cut is not None, "need mid-m2 chunk boundary"

    interrupted = tmp_path / "interrupted"
    interrupted.mkdir()
    for p in full_chunks[: cut + 1]:
        (interrupted / p.name).write_bytes(p.read_bytes())
    before = _file_bytes(_chunk_paths(interrupted))
    ckpt = cr.read_last_row_checkpoint(_chunk_paths(interrupted)[-1])
    assert ckpt["member_name"] == "ecar/m2.json.gz"
    # next_file_id must equal checkpoint.file_id + 1 (not a recount heuristic alone)
    assert cr.next_file_id_from_checkpoint(ckpt) == int(ckpt["file_id"]) + 1

    _run_builder(tmp_path, archives, manifest, interrupted, chunk_size=4, resume=True)
    assert _file_bytes([interrupted / n for n in before]) == before

    resumed = _read_locators(interrupted)
    # Locator equivalence
    full_keys = [(r["archive_name"], r["member_name"], r["line_number"]) for r in full_rows]
    res_keys = [(r["archive_name"], r["member_name"], r["line_number"]) for r in resumed]
    assert res_keys == full_keys
    assert len(res_keys) == len(set(res_keys))
    # file_id equivalence on every row
    assert [r["file_id"] for r in resumed] == [r["file_id"] for r in full_rows]

    def _stable(cache_dir):
        rows = []
        for p in _chunk_paths(cache_dir):
            t = pq.read_table(
                p,
                columns=[
                    "archive_name", "member_name", "line_number", "raw_event_id",
                    "file_id", "host_raw", "action_raw", "object_raw",
                    "parse_status", "process_raw",
                ],
            )
            rows.append(t)
        return pa.concat_tables(rows).to_pydict()

    assert _stable(interrupted) == _stable(full)


def test_state_wrong_checkpoint_or_count_cannot_override_chunks(tmp_path):
    archives, manifest, n1, n2 = _build_two_member_fixture(tmp_path, n1=20, n2=10)
    full = tmp_path / "full"
    _run_builder(tmp_path, archives, manifest, full, chunk_size=10, overwrite=True)
    interrupted = tmp_path / "interrupted"
    interrupted.mkdir()
    for p in _chunk_paths(full)[:2]:
        (interrupted / p.name).write_bytes(p.read_bytes())
    true_ck = cr.read_last_row_checkpoint(_chunk_paths(interrupted)[-1])
    # Same index as highest chunk, but WRONG event count and WRONG checkpoint.
    cr.write_resume_state(
        interrupted,
        last_committed_chunk_index=1,
        combined_events=999999,
        checkpoint={
            "archive_name": true_ck["archive_name"],
            "member_name": true_ck["member_name"],
            "line_number": 1,  # wrong
            "raw_event_id": "TOTALLY-WRONG",
            "file_id": 1,  # wrong
        },
    )
    from manifest_utils import load_manifest  # type: ignore
    ctx = cr.prepare_resume_context(interrupted, load_manifest(manifest))
    assert ctx["checkpoint"]["raw_event_id"] == true_ck["raw_event_id"]
    assert ctx["checkpoint"]["line_number"] == true_ck["line_number"]
    assert ctx["checkpoint"]["file_id"] == true_ck["file_id"]
    assert ctx["preexisting_events"] == 20  # footer-derived, not state
    assert ctx["next_file_id"] == int(true_ck["file_id"]) + 1
    assert "combined_events" in ctx["state_ignored_fields"]
    assert any(x.startswith("checkpoint.") for x in ctx["state_ignored_fields"])

    before = _file_bytes(_chunk_paths(interrupted))
    _run_builder(tmp_path, archives, manifest, interrupted, chunk_size=10, resume=True)
    assert _file_bytes([interrupted / n for n in before]) == before
    assert len(_read_locators(interrupted)) == n1 + n2


def test_no_write_before_verification_on_id_mismatch(tmp_path, monkeypatch):
    archives, manifest, n1, n2 = _build_two_member_fixture(tmp_path, n1=15, n2=8)
    full = tmp_path / "full"
    _run_builder(tmp_path, archives, manifest, full, chunk_size=10, overwrite=True)
    interrupted = tmp_path / "interrupted"
    interrupted.mkdir()
    src = _chunk_paths(full)[0]
    t = pq.read_table(src).to_pandas()
    t.loc[t.index[-1], "raw_event_id"] = "CORRUPTED"
    t[list(SLIM_EVENT_COLUMNS)].to_parquet(interrupted / src.name, index=False)
    before_chunks = _file_bytes(_chunk_paths(interrupted))
    before_state = (interrupted / "cache_resume_state.json").read_bytes() if (
        interrupted / "cache_resume_state.json"
    ).exists() else None
    before_meta = (interrupted / "cache_metadata.json").read_bytes() if (
        interrupted / "cache_metadata.json"
    ).exists() else None

    writes = []
    real_atomic = cr.atomic_write_parquet_chunk

    def guarded(*args, **kwargs):
        writes.append("chunk")
        return real_atomic(*args, **kwargs)

    monkeypatch.setattr(cache_builder, "_write_chunk", guarded)
    with pytest.raises(SystemExit):
        _run_builder(tmp_path, archives, manifest, interrupted, chunk_size=10, resume=True)
    assert writes == []  # no new chunk commit attempted after failed verify
    assert _file_bytes(_chunk_paths(interrupted)) == before_chunks
    after_state = (interrupted / "cache_resume_state.json").read_bytes() if (
        interrupted / "cache_resume_state.json"
    ).exists() else None
    after_meta = (interrupted / "cache_metadata.json").read_bytes() if (
        interrupted / "cache_metadata.json"
    ).exists() else None
    assert after_state == before_state
    assert after_meta == before_meta


def test_original_file_id_semantics_unit():
    """Direct parser semantics: blank skip, error emit, non-dict skip, per-archive reset."""
    import tempfile
    from optc_streaming_parser import stream_from_archives  # type: ignore

    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td)
        archives = root / "archives"
        archives.mkdir()
        lines = [
            _event_line("e1"),
            "",
            "{bad",
            "[]",
            _event_line("e2"),
        ]
        _make_tar(archives / "A.tar", {"m.json.gz": lines})
        _make_tar(archives / "B.tar", {"n.json.gz": [_event_line("b1")]})
        events = list(stream_from_archives(
            [archives / "A.tar", archives / "B.tar"],
            allowed_members_by_archive={
                "A.tar": {"m.json.gz"},
                "B.tar": {"n.json.gz"},
            },
            include_raw_json=False,
            quiet=True,
        ))
        a = [e for e in events if e["archive_name"] == "A.tar"]
        b = [e for e in events if e["archive_name"] == "B.tar"]
        # e1, json_error, e2 — non-dict and blank excluded
        assert len(a) == 3
        assert [int(e["file_id"]) for e in a] == [1, 2, 3]
        assert a[1]["parse_status"] == "json_parse_error"
        assert [int(e["file_id"]) for e in b] == [1]


# ── vectorized preexisting aggregates / commit validation ─────────────────

def _slim_row(**overrides) -> dict:
    row = {c: "" for c in SLIM_EVENT_COLUMNS}
    row.update(overrides)
    return row


def _write_chunk_rows(path: pathlib.Path, rows: list[dict]) -> None:
    df = pd.DataFrame(rows)
    for c in SLIM_EVENT_COLUMNS:
        if c not in df.columns:
            df[c] = ""
    df[list(SLIM_EVENT_COLUMNS)].to_parquet(path, index=False)


def test_aggregate_preexisting_vectorized_counts_and_errors(tmp_path):
    """One pass: member/status counts + error examples; grouped == footer."""
    cache = tmp_path / "cache"
    cache.mkdir()
    rows0 = [
        _slim_row(
            archive_name="A.tar", member_name="m1.json.gz", parse_status="ok",
            line_number=1, raw_event_id="ok-1", file_id=1,
        ),
        _slim_row(
            archive_name="A.tar", member_name="m1.json.gz",
            parse_status="json_parse_error", parse_error="bad json",
            line_number=2, raw_event_id="", file_id=2,
        ),
        _slim_row(
            archive_name="A.tar", member_name="m1.json.gz", parse_status="ok",
            line_number=3, raw_event_id="ok-3", file_id=3,
        ),
    ]
    rows1 = [
        _slim_row(
            archive_name="A.tar", member_name="m2.json.gz", parse_status="ok",
            line_number=1, raw_event_id="ok-b1", file_id=4,
        ),
        _slim_row(
            archive_name="A.tar", member_name="m2.json.gz",
            parse_status="json_parse_error", parse_error="trunc",
            line_number=2, raw_event_id="", file_id=5,
        ),
    ]
    p0 = cache / "chunk_00000_date_20190916.parquet"
    p1 = cache / "chunk_00001_date_20190916.parquet"
    _write_chunk_rows(p0, rows0)
    _write_chunk_rows(p1, rows1)
    chunks = [(0, p0), (1, p1)]
    footer_total = sum(pq.ParquetFile(p).metadata.num_rows for _, p in chunks)

    # Spy: ensure we never fall back to Python row loops via removed APIs.
    assert not hasattr(cr, "summarize_locators_from_chunks")
    assert not hasattr(cr, "collect_error_examples_from_chunks")

    agg = cr.aggregate_preexisting_chunks(
        chunks,
        error_example_limit=10,
        expected_footer_total=footer_total,
    )
    assert agg["footer_total"] == footer_total == 5
    assert agg["grouped_total"] == footer_total
    assert agg["events_ok"] == 3
    assert agg["parse_errors"] == 2
    assert agg["events_per_member"] == {
        "A.tar::m1.json.gz": 3,
        "A.tar::m2.json.gz": 2,
    }
    assert sum(agg["events_per_member"].values()) == footer_total
    assert len(agg["error_examples"]) == 2
    assert agg["error_examples"][0]["parse_error"] == "bad json"
    assert agg["error_examples"][1]["member_name"] == "m2.json.gz"

    # Limit applies without a second full-cache scan API.
    capped = cr.aggregate_preexisting_chunks(
        chunks,
        error_example_limit=1,
        expected_footer_total=footer_total,
    )
    assert len(capped["error_examples"]) == 1
    assert capped["error_examples"][0]["parse_error"] == "bad json"
    assert capped["events_ok"] == 3


def test_aggregate_skips_error_columns_on_clean_row_groups(tmp_path, monkeypatch):
    """Clean RGs read only status cols; error RGs get a selective detail re-read."""
    cache = tmp_path / "cache"
    cache.mkdir()
    status_cols = ["archive_name", "member_name", "parse_status"]
    error_cols = [
        "archive_name", "member_name", "line_number", "raw_event_id",
        "parse_status", "parse_error",
    ]

    clean_rows = [
        _slim_row(
            archive_name="A.tar", member_name="clean.json.gz", parse_status="ok",
            line_number=i, raw_event_id=f"c{i}", file_id=i,
            # Poison detail fields: must never need to be loaded for clean RG.
            parse_error="SHOULD_NOT_LOAD",
        )
        for i in (1, 2, 3)
    ]
    err_rows = [
        _slim_row(
            archive_name="A.tar", member_name="dirty.json.gz", parse_status="ok",
            line_number=1, raw_event_id="d1", file_id=1,
        ),
        _slim_row(
            archive_name="A.tar", member_name="dirty.json.gz",
            parse_status="json_parse_error", parse_error="boom",
            line_number=2, raw_event_id="", file_id=2,
        ),
    ]
    p_clean = cache / "chunk_00000_date_20190916.parquet"
    p_err = cache / "chunk_00001_date_20190916.parquet"
    _write_chunk_rows(p_clean, clean_rows)
    _write_chunk_rows(p_err, err_rows)

    read_calls: list[tuple[str, int, list[str]]] = []
    pf_names: dict[int, str] = {}
    real_init = pq.ParquetFile.__init__
    real_rrg = pq.ParquetFile.read_row_group

    def tracking_init(self, source, *args, **kwargs):
        real_init(self, source, *args, **kwargs)
        pf_names[id(self)] = pathlib.Path(str(source)).name

    def spy_rrg(self, i, columns=None, use_threads=True, **kwargs):
        cols = list(columns) if columns is not None else []
        read_calls.append((pf_names[id(self)], int(i), cols))
        return real_rrg(self, i, columns=columns, use_threads=use_threads, **kwargs)

    monkeypatch.setattr(pq.ParquetFile, "__init__", tracking_init)
    monkeypatch.setattr(pq.ParquetFile, "read_row_group", spy_rrg)

    chunks = [(0, p_clean), (1, p_err)]
    footer_total = sum(pq.ParquetFile(p).metadata.num_rows for _, p in chunks)
    # Clear setup reads from footer_total measurement above.
    read_calls.clear()

    agg = cr.aggregate_preexisting_chunks(
        chunks,
        error_example_limit=10,
        expected_footer_total=footer_total,
    )

    clean_reads = [c for c in read_calls if c[0] == p_clean.name]
    err_reads = [c for c in read_calls if c[0] == p_err.name]

    assert clean_reads == [(p_clean.name, 0, status_cols)]
    assert err_reads == [
        (p_err.name, 0, status_cols),
        (p_err.name, 0, error_cols),
    ]
    assert agg["events_ok"] == 4
    assert agg["parse_errors"] == 1
    assert agg["grouped_total"] == footer_total == 5
    assert len(agg["error_examples"]) == 1
    assert agg["error_examples"][0]["parse_error"] == "boom"
    assert agg["events_per_member"] == {
        "A.tar::clean.json.gz": 3,
        "A.tar::dirty.json.gz": 2,
    }


def test_aggregate_footer_mismatch_raises(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    p = cache / "chunk_00000_date_20190916.parquet"
    _write_chunk_rows(p, [
        _slim_row(
            archive_name="A.tar", member_name="m.json.gz", parse_status="ok",
            line_number=1, raw_event_id="e1", file_id=1,
        ),
    ])
    with pytest.raises(cr.ResumeError, match="footer total"):
        cr.aggregate_preexisting_chunks(
            [(0, p)],
            error_example_limit=5,
            expected_footer_total=99,
        )


def test_merge_preexisting_and_new_counts():
    preexisting = {
        "events_per_member": {"A.tar::m1": 10, "A.tar::m2": 4},
        "events_ok": 12,
        "parse_errors": 2,
        "error_examples": [
            {"raw_event_id": "err-old", "parse_status": "json_parse_error"},
        ],
        "footer_total": 14,
        "grouped_total": 14,
    }
    merged = cr.merge_resume_aggregates(
        preexisting,
        new_events=6,
        new_events_per_member={"A.tar::m2": 3, "A.tar::m3": 3},
        new_ok=5,
        new_err=1,
        new_error_examples=[
            {"raw_event_id": "err-new", "parse_status": "json_parse_error"},
        ],
        error_example_limit=10,
    )
    assert merged["events_per_member"] == {
        "A.tar::m1": 10,
        "A.tar::m2": 7,
        "A.tar::m3": 3,
    }
    assert merged["events_ok"] == 17
    assert merged["parse_errors"] == 3
    assert merged["total_events"] == 20
    assert [e["raw_event_id"] for e in merged["error_examples"]] == [
        "err-old", "err-new",
    ]


def test_require_commit_checkpoint_rejects_invalid_file_id():
    base = {
        "archive_name": "A.tar",
        "member_name": "m.json.gz",
        "line_number": 3,
        "raw_event_id": "e3",
        "file_id": 3,
    }
    assert cr.require_commit_checkpoint(base)["file_id"] == 3
    with pytest.raises(cr.ResumeError, match="invalid file_id"):
        cr.require_commit_checkpoint({**base, "file_id": "NOPE"})
    with pytest.raises(cr.ResumeError, match="file_id must be >= 1"):
        cr.require_commit_checkpoint({**base, "file_id": 0})
    with pytest.raises(cr.ResumeError, match="empty archive_name"):
        cr.require_commit_checkpoint({**base, "archive_name": "  "})


def test_invalid_file_id_aborts_before_committed_chunk(tmp_path, monkeypatch):
    archives, manifest, n1, n2 = _build_two_member_fixture(tmp_path, n1=12, n2=5)
    cache = tmp_path / "cache"
    writes = []
    real_write = cache_builder.atomic_write_parquet_chunk

    def tracking_write(*args, **kwargs):
        writes.append("chunk")
        return real_write(*args, **kwargs)

    monkeypatch.setattr(cache_builder, "atomic_write_parquet_chunk", tracking_write)

    from optc_streaming_parser import stream_from_archives as real_stream

    def bad_stream(*args, **kwargs):
        for i, ev in enumerate(real_stream(*args, **kwargs)):
            if i == 9:  # final row of first chunk when chunk_size=10
                ev = dict(ev)
                ev["file_id"] = "not-an-integer"
            yield ev

    monkeypatch.setattr(cache_builder, "stream_from_archives", bad_stream)
    with pytest.raises(SystemExit):
        _run_builder(tmp_path, archives, manifest, cache, chunk_size=10, overwrite=True)
    assert writes == []
    assert _chunk_paths(cache) == []
    assert not (cache / "cache_resume_state.json").exists()


def test_resume_initial_vs_final_checkpoint_metadata(tmp_path):
    archives, manifest, n1, n2 = _build_two_member_fixture(tmp_path, n1=20, n2=12)
    full = tmp_path / "full"
    _run_builder(tmp_path, archives, manifest, full, chunk_size=10, overwrite=True)
    interrupted = tmp_path / "interrupted"
    interrupted.mkdir()
    keep = _chunk_paths(full)[:2]
    for p in keep:
        (interrupted / p.name).write_bytes(p.read_bytes())
    initial = cr.read_last_row_checkpoint(keep[-1])

    _run_builder(tmp_path, archives, manifest, interrupted, chunk_size=10, resume=True)
    meta = json.loads((interrupted / "cache_metadata.json").read_text())
    final_row = _read_locators(interrupted)[-1]

    assert meta["resume_initial_checkpoint"]["archive_name"] == initial["archive_name"]
    assert meta["resume_initial_checkpoint"]["member_name"] == initial["member_name"]
    assert meta["resume_initial_checkpoint"]["line_number"] == initial["line_number"]
    assert meta["resume_initial_checkpoint"]["raw_event_id"] == initial["raw_event_id"]
    assert meta["resume_initial_checkpoint"]["file_id"] == initial["file_id"]

    assert meta["resume_final_checkpoint"]["archive_name"] == final_row["archive_name"]
    assert meta["resume_final_checkpoint"]["member_name"] == final_row["member_name"]
    assert meta["resume_final_checkpoint"]["line_number"] == final_row["line_number"]
    assert meta["resume_final_checkpoint"]["raw_event_id"] == final_row["raw_event_id"]
    assert int(meta["resume_final_checkpoint"]["file_id"]) == int(final_row["file_id"])

    assert meta["resume_initial_checkpoint"] != meta["resume_final_checkpoint"]
    assert meta["resume_newly_written_events"] > 0
    readme = (interrupted / "README_normalized_pilot_cache.txt").read_text()
    assert "resume_initial_checkpoint:" in readme
    assert "resume_final_checkpoint:" in readme
    assert "resume_checkpoint:" not in readme


def test_fresh_build_uses_live_counters_without_recovery_recount(tmp_path, monkeypatch):
    archives, manifest, n1, n2 = _build_two_member_fixture(tmp_path, n1=15, n2=8)

    def boom(*args, **kwargs):
        raise AssertionError("fresh build must not invoke preexisting recovery recount")

    monkeypatch.setattr(cache_builder, "aggregate_preexisting_chunks", boom)
    monkeypatch.setattr(cr, "aggregate_preexisting_chunks", boom)

    cache = tmp_path / "fresh"
    _run_builder(tmp_path, archives, manifest, cache, chunk_size=10, overwrite=True)
    meta = json.loads((cache / "cache_metadata.json").read_text())
    assert meta["resumed"] is False
    assert meta["total_events_written"] == n1 + n2
    assert meta["events_ok"] == n1 + n2
    assert meta["resume_initial_checkpoint"] is None
    assert meta["resume_final_checkpoint"] is None
