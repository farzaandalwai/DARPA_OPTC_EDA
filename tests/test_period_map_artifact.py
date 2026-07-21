"""Focused, repository-local tests for the OpTC pilot period-map artifact."""

from __future__ import annotations

import ast
import pathlib
import sys

import pandas as pd

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
PERIOD_MAP = (
    PROJECT_ROOT / "data" / "period_maps" / "optc_pilot_period_map_v1.csv"
)
PROVENANCE = PERIOD_MAP.with_suffix(".md")

sys.path.insert(0, str(PROJECT_ROOT / "src" / "eda"))

import eda_04_event_taxonomy as eda4  # type: ignore


EXPECTED_COLUMNS = ["period", "start_time", "end_time", "period_role"]
EXPECTED_ROWS = [
    {
        "period": "pilot_verified_benign",
        "start_time": "2019-09-16T23:32:49.231000Z",
        "end_time": "2019-09-23T04:00:00.000000Z",
        "period_role": "verified_benign",
    },
    {
        "period": "pilot_evaluation",
        "start_time": "2019-09-23T04:00:00.000000Z",
        "end_time": "2019-09-25T18:38:15.052001Z",
        "period_role": "evaluation",
    },
]


def _read_map() -> pd.DataFrame:
    return pd.read_csv(PERIOD_MAP, dtype=str, keep_default_na=False)


def test_period_map_has_exact_schema_rows_and_roles():
    frame = _read_map()
    assert list(frame.columns) == EXPECTED_COLUMNS
    assert frame.to_dict("records") == EXPECTED_ROWS
    assert set(frame["period_role"]) == {"verified_benign", "evaluation"}
    assert not set(frame["period_role"]).intersection({"attack", "malicious"})


def test_period_map_timestamps_are_utc_ordered_and_half_open():
    frame = _read_map()
    starts = pd.to_datetime(frame["start_time"], errors="raise", utc=True)
    ends = pd.to_datetime(frame["end_time"], errors="raise", utc=True)

    assert all(timestamp.tzinfo is not None for timestamp in starts)
    assert all(timestamp.tzinfo is not None for timestamp in ends)
    assert (ends > starts).all()
    assert starts.is_monotonic_increasing
    assert starts.iloc[1] >= ends.iloc[0]

    # Half-open boundary: benign excludes the shared endpoint and evaluation
    # includes it.
    boundary = ends.iloc[0]
    assert not (starts.iloc[0] <= boundary < ends.iloc[0])
    assert starts.iloc[1] <= boundary < ends.iloc[1]
    assert ends.iloc[0] == starts.iloc[1]


def test_period_map_passes_existing_eda4_validator():
    # EDA 4 requires a threshold whenever verified_benign is present. Zero is
    # supplied only to exercise the existing validator; the artifact itself
    # contains no rarity threshold or fitted result.
    policy = eda4.load_period_policy(str(PERIOD_MAP), 0)

    assert policy.has_verified_benign
    assert policy.has_evaluation
    assert policy.policy_name == "verified_period_map"
    assert policy.path == PERIOD_MAP.resolve()
    assert list(policy.frame.columns) == EXPECTED_COLUMNS
    assert policy.frame.loc[0, "end_time"] == policy.frame.loc[1, "start_time"]
    assert policy.frame["start_time"].dt.tz is None
    assert policy.frame["end_time"].dt.tz is None


def test_provenance_records_sources_hash_totals_and_scientific_limits():
    text = PROVENANCE.read_text(encoding="utf-8")
    normalized_text = " ".join(text.split())

    for required in (
        "pilot_manifest_10gb_v1",
        "optc_normalized_v3",
        "180,648,918",
        "https://github.com/FiveDirections/OpTC-data",
        "https://raw.githubusercontent.com/FiveDirections/OpTC-data/"
        "master/OpTCRedTeamGroundTruth.pdf",
        "https://doi.org/10.57745/UXCWOC",
        "5986d23b81169221a491f7a8302fce140b12638ef4cf9b3a894ed3cb2fad9567",
        "09/23/19 11:23:29",
        "20,183,409",
        "18,423,861",
        "126,400,024",
        "54,248,894",
        "derived, evidence-backed period map",
        "not event-level malicious labels",
        "Ground-truth event alignment remains EDA 10",
        "must not be generalized beyond the fixed pilot",
    ):
        assert required in text

    assert "does not state the timezone" in text
    assert "not used as the period boundary" in text
    assert "three-millisecond data gap" in text
    assert "prevents evaluation-day information from leaking" in text
    assert "does not mean every event is malicious" in normalized_text


def test_focused_tests_use_no_cache_or_google_drive():
    source = pathlib.Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    called_attributes = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    called_names = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }

    assert PERIOD_MAP.is_relative_to(PROJECT_ROOT)
    assert PROVENANCE.is_relative_to(PROJECT_ROOT)
    assert called_attributes.isdisjoint({"read_parquet", "_duck_conn", "run_eda04"})
    assert called_names.isdisjoint({"read_parquet", "_duck_conn", "run_eda04"})
