"""
Focused tests for normalized pilot cache smoke-sampling / verification flags
and EDA 3 rejection of capped head sampling.
"""

from __future__ import annotations

import json
import pathlib
import sys
from types import SimpleNamespace
from unittest import mock

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src" / "eda"))
import build_normalized_pilot_cache as cache_builder  # type: ignore
from eda_03_time_window_selection import (  # type: ignore
    apply_sampling_strategy_gate,
    assess_coverage_metrics,
)


def test_sampling_strategy_labels():
    assert cache_builder.sampling_strategy_for(None, None) == "full"
    assert cache_builder.sampling_strategy_for(1000, None) == "global_head"
    assert cache_builder.sampling_strategy_for(None, 500) == "head_per_member"
    # per-member takes precedence when both caps are set
    assert cache_builder.sampling_strategy_for(1000, 500) == "head_per_member"


def test_invalid_max_events_per_member_rejected():
    with pytest.raises(SystemExit):
        cache_builder.validate_positive_optional_int("--max-events-per-member", 0)
    with pytest.raises(SystemExit):
        cache_builder.validate_positive_optional_int("--max-events-per-member", -5)
    cache_builder.validate_positive_optional_int("--max-events-per-member", None)
    cache_builder.validate_positive_optional_int("--max-events-per-member", 10)


def test_parse_args_defaults_and_flags():
    args = cache_builder.parse_args([
        "--corrected-dir", "/tmp/archives",
        "--manifest-csv", "/tmp/m.csv",
    ])
    assert args.max_events is None
    assert args.max_events_per_member is None
    assert args.trust_preverified_manifest is False

    args2 = cache_builder.parse_args([
        "--corrected-dir", "/tmp/archives",
        "--manifest-csv", "/tmp/m.csv",
        "--max-events-per-member", "200",
        "--max-events", "10000",
        "--trust-preverified-manifest",
    ])
    assert args2.max_events_per_member == 200
    assert args2.max_events == 10000
    assert args2.trust_preverified_manifest is True


def _fake_manifest(path: pathlib.Path):
    import pandas as pd
    df = pd.DataFrame({
        "archive_filename": ["2019-09-16.tar", "2019-09-16.tar"],
        "archive_date": ["2019-09-16", "2019-09-16"],
        "member_name": ["m1.json.gz", "m2.json.gz"],
    })
    return SimpleNamespace(
        path=path,
        manifest_version="test_v1",
        member_count=2,
        dates=["2019-09-16"],
        hosts=["h1"],
        total_compressed_gib=0.01,
        allowlist={"2019-09-16.tar": {"m1.json.gz", "m2.json.gz"}},
        df=df,
        all_member_keys=lambda: {
            "2019-09-16.tar::m1.json.gz",
            "2019-09-16.tar::m2.json.gz",
        },
    )


def _slim_event(member: str, n: int) -> dict:
    from optc_streaming_parser import SLIM_EVENT_COLUMNS  # type: ignore
    e = {c: "" for c in SLIM_EVENT_COLUMNS}
    e.update({
        "archive_name": "2019-09-16.tar",
        "member_name": member,
        "line_number": str(n),
        "raw_event_id": f"{member}-{n}",
        "parse_status": "ok",
        "source_type": "endpoint",
        "host_raw": "h1",
        "timestamp_parsed": "2019-09-16T00:00:00",
    })
    return e


def test_default_verification_unchanged(tmp_path):
    manifest_csv = tmp_path / "m.csv"
    manifest_csv.write_text("x\n", encoding="utf-8")
    archives = tmp_path / "archives"
    archives.mkdir()
    cache_dir = tmp_path / "cache"
    project_root = tmp_path

    verify_calls = []

    def fake_verify(manifest, archive_paths):
        verify_calls.append(True)
        return {"matched_member_count": 2, "missing_member_count": 0, "found": {}}

    events = [_slim_event("m1.json.gz", 1), _slim_event("m2.json.gz", 1)]

    with mock.patch.object(cache_builder, "load_manifest", return_value=_fake_manifest(manifest_csv)), \
         mock.patch.object(cache_builder, "resolve_manifest_archives", return_value=[archives / "2019-09-16.tar"]), \
         mock.patch.object(cache_builder, "verify_manifest_members_in_archives", side_effect=fake_verify) as vmock, \
         mock.patch.object(cache_builder, "stream_from_archives", return_value=iter(events)) as smock, \
         mock.patch.object(sys, "argv", [
             "build_normalized_pilot_cache.py",
             "--project-root", str(project_root),
             "--corrected-dir", str(archives),
             "--manifest-csv", str(manifest_csv),
             "--cache-dir", str(cache_dir),
             "--chunk-size", "100",
             "--overwrite",
         ]):
        cache_builder.main()

    assert verify_calls == [True]
    vmock.assert_called_once()
    # default: no per-member cap
    kwargs = smock.call_args.kwargs
    assert kwargs.get("max_events_per_member") is None
    meta = json.loads((cache_dir / "cache_metadata.json").read_text(encoding="utf-8"))
    assert meta["member_verification_performed"] is True
    assert meta["member_verification_mode"] == "verified_this_run"
    assert meta["sampling_strategy"] == "full"
    assert meta["max_events_per_member"] is None


def test_trust_preverified_skips_verification(tmp_path):
    manifest_csv = tmp_path / "m.csv"
    manifest_csv.write_text("x\n", encoding="utf-8")
    archives = tmp_path / "archives"
    archives.mkdir()
    cache_dir = tmp_path / "cache"
    project_root = tmp_path
    events = [_slim_event("m1.json.gz", 1)]

    with mock.patch.object(cache_builder, "load_manifest", return_value=_fake_manifest(manifest_csv)), \
         mock.patch.object(cache_builder, "resolve_manifest_archives", return_value=[archives / "2019-09-16.tar"]), \
         mock.patch.object(cache_builder, "verify_manifest_members_in_archives") as vmock, \
         mock.patch.object(cache_builder, "stream_from_archives", return_value=iter(events)), \
         mock.patch.object(sys, "argv", [
             "build_normalized_pilot_cache.py",
             "--project-root", str(project_root),
             "--corrected-dir", str(archives),
             "--manifest-csv", str(manifest_csv),
             "--cache-dir", str(cache_dir),
             "--trust-preverified-manifest",
             "--overwrite",
         ]):
        cache_builder.main()

    vmock.assert_not_called()
    meta = json.loads((cache_dir / "cache_metadata.json").read_text(encoding="utf-8"))
    assert meta["member_verification_performed"] is False
    assert meta["member_verification_mode"] == "trusted_preverified"
    readme = (cache_dir / "README_normalized_pilot_cache.txt").read_text(encoding="utf-8")
    assert "trusted_preverified" in readme
    assert "member_verification_performed: False" in readme


def test_max_events_per_member_reaches_stream(tmp_path):
    manifest_csv = tmp_path / "m.csv"
    manifest_csv.write_text("x\n", encoding="utf-8")
    archives = tmp_path / "archives"
    archives.mkdir()
    cache_dir = tmp_path / "cache"
    project_root = tmp_path
    events = [_slim_event("m1.json.gz", i) for i in range(3)]

    with mock.patch.object(cache_builder, "load_manifest", return_value=_fake_manifest(manifest_csv)), \
         mock.patch.object(cache_builder, "resolve_manifest_archives", return_value=[archives / "2019-09-16.tar"]), \
         mock.patch.object(
             cache_builder,
             "verify_manifest_members_in_archives",
             return_value={"matched_member_count": 2, "missing_member_count": 0},
         ), \
         mock.patch.object(cache_builder, "stream_from_archives", return_value=iter(events)) as smock, \
         mock.patch.object(sys, "argv", [
             "build_normalized_pilot_cache.py",
             "--project-root", str(project_root),
             "--corrected-dir", str(archives),
             "--manifest-csv", str(manifest_csv),
             "--cache-dir", str(cache_dir),
             "--max-events-per-member", "50",
             "--max-events", "5000",
             "--overwrite",
         ]):
        cache_builder.main()

    kwargs = smock.call_args.kwargs
    assert kwargs["max_events_per_member"] == 50
    assert kwargs["max_events"] == 5000
    meta = json.loads((cache_dir / "cache_metadata.json").read_text(encoding="utf-8"))
    assert meta["sampling_strategy"] == "head_per_member"
    assert meta["max_events_per_member"] == 50
    assert meta["max_events_safety_cap"] == 5000
    assert "not temporally representative" in meta["sampling_limitation"]


def test_eda3_rejects_capped_sampling_for_window_selection():
    base = assess_coverage_metrics(
        n_events=50_000,
        n_parseable=49_500,
        unique_archives=2,
        unique_members=5,
        unique_hosts=3,
        unique_dates=3,
        span_hours=48.0,
    )
    assert base["status"] == "ok"

    for strategy in ("head_per_member", "global_head"):
        gated = apply_sampling_strategy_gate(base, strategy)
        assert gated["status"] == "review_needed"
        assert any("not temporally representative" in c for c in gated["failed_conditions"])
        assert any(strategy in c for c in gated["failed_conditions"])


def test_eda3_full_sampling_can_pass_coverage_gate():
    base = assess_coverage_metrics(
        n_events=50_000,
        n_parseable=49_500,
        unique_archives=2,
        unique_members=5,
        unique_hosts=3,
        unique_dates=3,
        span_hours=48.0,
    )
    gated = apply_sampling_strategy_gate(base, "full")
    assert gated["status"] == "ok"
    assert gated["failed_conditions"] == []
    # Legacy caches without sampling_strategy still use host/member gates only.
    gated_legacy = apply_sampling_strategy_gate(base, None)
    assert gated_legacy["status"] == "ok"
