"""
Focused tests for OpTC timestamp normalization (_parse_timestamp).

Run:
    python3 -m pytest tests/test_parse_timestamp.py -q
or:
    python3 tests/test_parse_timestamp.py
"""

from __future__ import annotations

import datetime
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src" / "eda"))
from optc_streaming_parser import _parse_timestamp  # type: ignore


def test_offset_aware_iso_converted_to_utc():
    """-04:00 offset must be converted (not stripped) before storing naive UTC."""
    result = _parse_timestamp("2019-09-16T19:40:12.43-04:00")
    assert result is not None
    assert result.tzinfo is None
    assert result.isoformat() == "2019-09-16T23:40:12.430000"


def test_zulu_iso_is_utc():
    result = _parse_timestamp("2019-09-16T23:40:12.43Z")
    assert result is not None
    assert result.tzinfo is None
    assert result.isoformat() == "2019-09-16T23:40:12.430000"


def test_naive_iso_assumed_utc_unchanged():
    result = _parse_timestamp("2019-09-16T23:40:12.43")
    assert result is not None
    assert result.tzinfo is None
    assert result.isoformat() == "2019-09-16T23:40:12.430000"


def test_epoch_seconds_unchanged():
    # 2019-09-16 00:00:00 UTC
    result = _parse_timestamp(1568592000)
    assert result == datetime.datetime(2019, 9, 16, 0, 0, 0)


def test_epoch_milliseconds_unchanged():
    result = _parse_timestamp(1568592000000)
    assert result == datetime.datetime(2019, 9, 16, 0, 0, 0)


if __name__ == "__main__":
    test_offset_aware_iso_converted_to_utc()
    test_zulu_iso_is_utc()
    test_naive_iso_assumed_utc_unchanged()
    test_epoch_seconds_unchanged()
    test_epoch_milliseconds_unchanged()
    print("All _parse_timestamp tests passed.")
