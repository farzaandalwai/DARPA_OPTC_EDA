#!/usr/bin/env python3
"""
EDA 6 — evidence-backed benign host, user, and process baselines.

The normalized Parquet cache is read only. Baseline structures are fitted
exclusively from intervals whose validated period_role is verified_benign.
Evaluation events may be scored against those structures but never influence
their sets, frequencies, normal hours, top entities, semantic distributions,
or confidence. Outputs describe baseline deviation, not maliciousness,
anomalies, attacks, or ground-truth event labels.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import math
import os
import pathlib
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from collections import defaultdict
from typing import Any, Iterable, Optional

import eda_04_event_taxonomy as eda4
import eda_05_entity_dictionary as eda5
from optc_streaming_parser import SCHEMA_VERSION


CacheAuditError = eda5.CacheAuditError

WINDOW_SIZE = "1min"
WINDOW_SECONDS = 60
MIN_BENIGN_SECONDS = 24 * 60 * 60
MIN_BENIGN_DATES = 2
EVIDENCE_CAP = 20
PAYLOAD_SCAN_COUNT = 4
PATH_CATEGORY_RULE_VERSION = "eda06_path_category_v2"
DESTINATION_CATEGORY_RULE_VERSION = "eda06_destination_category_v1"
NORMAL_HOUR_RULE_VERSION = "eda06_active_date_support_50pct_v1"
CONFIDENCE_RULE_VERSION = "eda06_coverage_confidence_v1"
CHAIN_RULE_VERSION = "eda06_same_event_parent_child_v1"
DEVIATION_FORMULA = (
    "(I(new_process_count>0)+I(new_chain_count>0)+"
    "I(new_destination_count>0)+I(new_path_category_count>0)+"
    "unusual_hour_flag+semantic_distribution_distance)/6"
)
# Fixed F7 line color for every host-panel segment. Color encodes no
# scientific meaning; using one blue avoids the Matplotlib color cycle
# assigning different colors to inactive-gap segments of the same host.
F7_LINE_COLOR = "#1f77b4"

T11_COLUMNS = [
    "host_id",
    "benign_window_count",
    "top_10_processes",
    "top_10_parent_child_chains",
    "top_5_semantic_groups",
    "top_5_path_categories",
    "top_5_destination_categories",
    "normal_active_hours",
    "baseline_confidence",
]

T12_COLUMNS = [
    "user_or_principal_id",
    "active_hosts",
    "benign_event_count",
    "top_processes",
    "top_semantic_groups",
    "common_active_hours",
    "unusual_behavior_flags_after_baseline",
]

T13_COLUMNS = [
    "window_start",
    "window_end",
    "host_id",
    "new_process_count",
    "new_chain_count",
    "new_destination_count",
    "new_path_category_count",
    "unusual_hour_flag",
    "semantic_distribution_distance",
    "evidence_event_ids",
    "deviation_score",
]

T7_COLUMNS = [
    "raw_object_type",
    "raw_action_type",
    "semantic_group",
    "mapping_rule",
    "keep_raw_fields_yes_no",
    "rationale",
]

T9_REQUIRED_COLUMNS = {
    "canonical_id",
    "entity_type",
    "raw_value",
    "normalized_value",
    "host_if_applicable",
    "reliability_high_medium_low",
    "entity_status",
}

REQUIRED_CACHE_COLUMNS = {
    "timestamp_parsed",
    "parse_status",
    "archive_name",
    "member_name",
    "line_number",
    "raw_event_id",
    "host_raw",
    "user_raw",
    "object_raw",
    "action_raw",
    "image_path_raw",
    "process_raw",
    "parent_image_path_raw",
    "parent_process_raw",
    "file_path_raw",
    "dest_ip_raw",
    "destination_raw",
}

_DRIVE_PATH_PARTS = {"content", "drive", "mydrive"}
_PRIVATE_V4_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_PRIVATE_V6_NETWORK = ipaddress.ip_network("fc00::/7")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="EDA 6 — scale-safe verified-benign baseline (cache only)."
    )
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--normalized-cache-dir", required=True)
    parser.add_argument("--manifest-csv", required=True)
    parser.add_argument("--period-map-csv", required=True)
    parser.add_argument("--entity-dictionary-path", required=True)
    parser.add_argument("--semantic-mapping-csv", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--window-size", default=WINDOW_SIZE)
    parser.add_argument("--duckdb-memory-limit", default="4GB")
    parser.add_argument("--duckdb-temp-dir", default=None)
    parser.add_argument("--duckdb-threads", type=int, default=2)
    return parser


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def _compact_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _looks_like_drive(path: pathlib.Path) -> bool:
    lowered = {part.lower() for part in path.parts}
    text = str(path).lower()
    return _DRIVE_PATH_PARTS.issubset(lowered) or "/content/drive/" in text


def _validate_output_dir(output_dir: pathlib.Path, cache_dir: pathlib.Path) -> None:
    output_resolved = output_dir.expanduser().resolve(strict=False)
    cache_resolved = cache_dir.expanduser().resolve()
    if output_resolved == cache_resolved or cache_resolved in output_resolved.parents:
        raise CacheAuditError("Output directory must not be the cache or inside it")
    if os.path.lexists(os.fspath(output_dir)):
        raise CacheAuditError(
            f"Refusing existing output path (must not pre-exist): {output_dir}"
        )


def _t9_files_and_glob(path: pathlib.Path) -> tuple[list[pathlib.Path], str]:
    if path.is_file() and path.suffix == ".parquet":
        return [path], str(path)
    if not path.is_dir():
        raise CacheAuditError(f"Entity dictionary path not found: {path}")
    partitioned = sorted(path.glob("entity_type=*/*.parquet"))
    direct = sorted(path.glob("*.parquet"))
    files = partitioned or direct
    if not files:
        raise CacheAuditError(
            "Entity dictionary path contains no Parquet files: " f"{path}"
        )
    pattern = (
        str(path / "entity_type=*" / "*.parquet")
        if partitioned
        else str(path / "*.parquet")
    )
    return files, pattern


def load_eda6_period_policy(path: pathlib.Path) -> eda4.PeriodPolicy:
    """
    Reuse EDA 4's validator, then apply EDA 6 coverage requirements.

    EDA 4's API requires a benign count threshold whenever verified_benign is
    present. The value 1 is supplied solely to activate its period validation;
    EDA 6 defines and applies no rarity threshold.
    """
    try:
        policy = eda4.load_period_policy(str(path), 1)
    except eda4.CacheAuditError as exc:
        raise CacheAuditError(str(exc)) from exc
    if not policy.has_verified_benign:
        raise CacheAuditError("EDA 6 requires at least one verified_benign interval")
    if not policy.has_evaluation:
        raise CacheAuditError("EDA 6 requires at least one evaluation interval")

    benign = policy.frame.loc[
        policy.frame["period_role"] == "verified_benign"
    ].copy()
    seconds = float(
        (benign["end_time"] - benign["start_time"]).dt.total_seconds().sum()
    )
    if seconds < MIN_BENIGN_SECONDS:
        raise CacheAuditError(
            "EDA 6 requires at least 24 hours of verified-benign coverage"
        )
    dates: set[dt.date] = set()
    for row in benign.itertuples(index=False):
        first = row.start_time.normalize()
        last = (row.end_time - dt.timedelta(microseconds=1)).normalize()
        dates.update(item.date() for item in _date_range(first, last))
    if len(dates) < MIN_BENIGN_DATES:
        raise CacheAuditError(
            "EDA 6 requires verified-benign coverage on at least two dates"
        )
    return policy


def _date_range(first, last) -> Iterable[Any]:
    current = first
    while current <= last:
        yield current
        current += dt.timedelta(days=1)


def validate_run_config(args: argparse.Namespace) -> dict[str, Any]:
    """Validate all inputs before creating or modifying an output path."""
    project_root = pathlib.Path(args.project_root).expanduser()
    cache_dir = pathlib.Path(args.normalized_cache_dir).expanduser()
    manifest_path = pathlib.Path(args.manifest_csv).expanduser()
    period_map = pathlib.Path(args.period_map_csv).expanduser()
    entity_dictionary = pathlib.Path(args.entity_dictionary_path).expanduser()
    semantic_mapping = pathlib.Path(args.semantic_mapping_csv).expanduser()
    output_dir = pathlib.Path(args.output_dir).expanduser()

    if not project_root.is_dir():
        raise CacheAuditError(f"Project root not found: {project_root}")
    if not cache_dir.is_dir() or not any(cache_dir.glob("*.parquet")):
        raise CacheAuditError(f"No Parquet cache files found at: {cache_dir}")
    if not manifest_path.is_file():
        raise CacheAuditError(f"Manifest CSV not found: {manifest_path}")
    if not period_map.is_file():
        raise CacheAuditError(f"Period-map CSV not found: {period_map}")
    if not semantic_mapping.is_file():
        raise CacheAuditError(f"Semantic mapping CSV not found: {semantic_mapping}")
    t9_files, t9_glob = _t9_files_and_glob(entity_dictionary)
    if args.window_size != WINDOW_SIZE:
        raise CacheAuditError("--window-size currently allows only '1min'")

    memory = eda5._validate_duckdb_memory_limit(args.duckdb_memory_limit)
    threads = eda5._validate_duckdb_threads(args.duckdb_threads)
    if args.duckdb_temp_dir is not None:
        spill = eda5._validate_duckdb_temp_dir(args.duckdb_temp_dir)
        if _looks_like_drive(spill):
            raise CacheAuditError("Google Drive spill paths are refused")
    _validate_output_dir(output_dir, cache_dir)
    cache_metadata = eda5._load_cache_metadata(cache_dir)
    policy = load_eda6_period_policy(period_map)
    semantic_frame = load_semantic_mapping(semantic_mapping)
    manifest = eda5._manifest_metadata(manifest_path)
    return {
        "project_root": project_root,
        "cache_dir": cache_dir,
        "manifest_path": manifest_path,
        "period_map": period_map,
        "entity_dictionary": entity_dictionary,
        "t9_files": t9_files,
        "t9_glob": t9_glob,
        "semantic_mapping": semantic_mapping,
        "semantic_frame": semantic_frame,
        "output_dir": output_dir,
        "memory_limit": memory,
        "threads": threads,
        "cache_metadata": cache_metadata,
        "policy": policy,
        **manifest,
    }


def load_semantic_mapping(path: pathlib.Path):
    import pandas as pd

    frame = pd.read_csv(path, dtype=str, keep_default_na=False)
    missing = set(T7_COLUMNS) - set(frame.columns)
    if missing:
        raise CacheAuditError(
            f"Semantic mapping missing required T7 columns: {sorted(missing)}"
        )
    frame = frame[T7_COLUMNS].copy()
    if frame.empty:
        raise CacheAuditError("Semantic mapping must contain at least one row")
    if frame.duplicated(["raw_object_type", "raw_action_type"]).any():
        raise CacheAuditError("Semantic mapping contains duplicate raw pairs")
    if (frame["keep_raw_fields_yes_no"] != "yes").any():
        raise CacheAuditError("Semantic mapping must preserve raw fields")
    for row in frame.itertuples(index=False):
        expected = eda4.semantic_mapping(
            row.raw_object_type, row.raw_action_type
        )
        if (
            row.semantic_group != expected["semantic_group"]
            or row.mapping_rule != expected["mapping_rule"]
        ):
            raise CacheAuditError(
                "Semantic mapping disagrees with EDA 4 for "
                f"({row.raw_object_type!r}, {row.raw_action_type!r})"
            )
    return frame


def _duck_conn(
    cache_dir: pathlib.Path,
    *,
    memory_limit: str,
    temp_dir: Optional[str],
    threads: int,
):
    import duckdb

    connection = None
    spill: Optional[pathlib.Path] = None
    owned = False
    try:
        if temp_dir is None:
            spill = pathlib.Path(tempfile.mkdtemp(prefix="eda06_duckdb_tmp_"))
            owned = True
        else:
            spill = eda5._validate_duckdb_temp_dir(temp_dir)
            if _looks_like_drive(spill):
                raise CacheAuditError("Google Drive spill paths are refused")
            spill.mkdir(parents=True, exist_ok=True)
        connection = duckdb.connect()
        eda5._configure_duckdb(
            connection,
            memory_limit=memory_limit,
            temp_dir=str(spill),
            threads=threads,
        )
        cache_glob = str(cache_dir / "*.parquet")
        connection.execute(
            "CREATE VIEW events AS SELECT * FROM read_parquet("
            f"{eda5._sql_string_literal(cache_glob)})"
        )
        return connection, str(spill), owned
    except Exception:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
        if owned and spill is not None:
            shutil.rmtree(spill, ignore_errors=True)
        raise


def path_category(raw_value: object) -> str:
    """Closed syntax-only path categorization with specific rules first."""
    if raw_value is None or str(raw_value).strip() == "":
        return "unknown"
    raw = str(raw_value)
    lower = raw.replace("/", "\\").lower()
    if lower.startswith("\\\\?\\unc\\"):
        return "network"
    extended_device_path = lower.startswith("\\\\?\\") or lower.startswith("\\\\.\\")
    if extended_device_path:
        lower = lower[4:]
    if (
        "\\temp\\" in lower
        or lower.startswith("\\tmp\\")
        or lower.startswith("c:\\temp\\")
        or lower.startswith("%temp%")
        or lower.startswith("$tmp")
    ):
        return "temporary"
    if not extended_device_path and (raw.startswith("\\\\") or raw.startswith("//")):
        return "network"
    if (
        "\\windows\\" in lower
        or "\\system32\\" in lower
        or lower.startswith("\\usr\\")
        or lower.startswith("\\bin\\")
        or lower.startswith("\\sbin\\")
        or lower.startswith("\\system\\")
    ):
        return "system"
    if (
        "\\program files\\" in lower
        or "\\programdata\\" in lower
        or lower.startswith("\\opt\\")
        or lower.startswith("\\applications\\")
    ):
        return "program"
    if (
        "\\users\\" in lower
        or lower.startswith("\\home\\")
        or lower.startswith("\\users\\")
    ):
        return "user"
    if re.match(r"^[A-Za-z]:[\\/]", raw) or "/" in raw or "\\" in raw:
        return "other"
    return "unknown"


def destination_category(raw_value: object) -> str:
    """Classify only observable IP/string structure; no reputation semantics."""
    if raw_value is None or str(raw_value).strip() == "":
        return "unknown"
    raw = str(raw_value).strip()
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return "hostname_or_other"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address.is_multicast:
        return "multicast"
    if address.is_unspecified:
        return "unspecified"
    if (
        isinstance(address, ipaddress.IPv4Address)
        and any(address in network for network in _PRIVATE_V4_NETWORKS)
    ) or (
        isinstance(address, ipaddress.IPv6Address)
        and address in _PRIVATE_V6_NETWORK
    ):
        return "private"
    if address.is_reserved or not address.is_global:
        return "reserved"
    return "global_syntax"


def observed_chain_key(
    host_id: str,
    parent_raw: str,
    child_id: str,
) -> str:
    """Stable key for a same-event observed association, not process identity."""
    # The parent component always uses EDA 5's approved normalized path text,
    # even when one raw spelling happens to resolve to a T9 row and another
    # alias does not. This avoids resolution-dependent chain identity.
    parent_component = (
        "parent_normalized:"
        + eda5._normalize_windows_path(str(parent_raw))[0]
    )
    parts = (str(host_id), parent_component, str(child_id))
    framed = "".join(f"{len(part)}:{part}" for part in parts)
    return "chain_" + hashlib.sha256(framed.encode("utf-8")).hexdigest()[:32]


def normal_active_hours(
    support_by_hour: dict[int, int], benign_date_count: int
) -> list[dict[str, Any]]:
    if benign_date_count <= 0:
        return []
    required = math.ceil(benign_date_count * 0.5)
    return [
        {
            "active_date_share": round(count / benign_date_count, 12),
            "hour": int(hour),
            "supporting_date_count": int(count),
        }
        for hour, count in sorted(support_by_hour.items())
        if count >= required
    ]


def baseline_confidence(
    benign_date_count: int,
    benign_window_count: int,
    possible_window_count: int,
) -> dict[str, Any]:
    ratio = (
        benign_window_count / possible_window_count
        if possible_window_count > 0
        else 0.0
    )
    if benign_date_count >= 5 and ratio >= 0.5:
        label = "high"
    elif benign_date_count >= 3 and ratio >= 0.2:
        label = "medium"
    else:
        label = "low"
    return {
        "benign_date_count": int(benign_date_count),
        "benign_window_count": int(benign_window_count),
        "label": label,
        "rule_version": CONFIDENCE_RULE_VERSION,
        "window_coverage_ratio": round(ratio, 12),
    }


def jensen_shannon_divergence(
    baseline_counts: dict[str, int | float],
    window_counts: dict[str, int | float],
) -> float:
    """Base-2 JSD in [0,1], with zero terms omitted (no smoothing)."""
    baseline_total = float(sum(baseline_counts.values()))
    window_total = float(sum(window_counts.values()))
    if baseline_total <= 0 and window_total <= 0:
        return 0.0
    if baseline_total <= 0 or window_total <= 0:
        return 1.0
    keys = set(baseline_counts) | set(window_counts)
    divergence = 0.0
    for key in keys:
        p = float(baseline_counts.get(key, 0.0)) / baseline_total
        q = float(window_counts.get(key, 0.0)) / window_total
        midpoint = (p + q) / 2.0
        if p > 0:
            divergence += 0.5 * p * math.log2(p / midpoint)
        if q > 0:
            divergence += 0.5 * q * math.log2(q / midpoint)
    if not math.isfinite(divergence):
        raise CacheAuditError("Jensen-Shannon divergence is non-finite")
    return min(1.0, max(0.0, float(divergence)))


def deviation_score(
    *,
    new_process_count: int,
    new_chain_count: int,
    new_destination_count: int,
    new_path_category_count: int,
    unusual_hour_flag: int,
    semantic_distribution_distance: float,
) -> float:
    score = (
        int(new_process_count > 0)
        + int(new_chain_count > 0)
        + int(new_destination_count > 0)
        + int(new_path_category_count > 0)
        + int(bool(unusual_hour_flag))
        + float(semantic_distribution_distance)
    ) / 6.0
    if not 0.0 <= score <= 1.0:
        raise CacheAuditError(f"Deviation score outside [0,1]: {score}")
    return score


def _possible_benign_windows(policy: eda4.PeriodPolicy) -> int:
    import pandas as pd

    total = 0
    benign = policy.frame.loc[policy.frame["period_role"] == "verified_benign"]
    for row in benign.itertuples(index=False):
        first = pd.Timestamp(row.start_time).floor(WINDOW_SIZE)
        last = (pd.Timestamp(row.end_time) - pd.Timedelta(microseconds=1)).floor(
            WINDOW_SIZE
        )
        total += int((last - first).total_seconds() // WINDOW_SECONDS) + 1
    return total


def _register_inputs(connection, config: dict[str, Any]) -> None:
    t9_glob = eda5._sql_string_literal(config["t9_glob"])
    connection.execute(
        "CREATE VIEW entity_dictionary AS SELECT * FROM "
        f"read_parquet({t9_glob}, hive_partitioning=false)"
    )
    described = {
        str(row[0]) for row in connection.execute("DESCRIBE entity_dictionary").fetchall()
    }
    missing = T9_REQUIRED_COLUMNS - described
    if missing:
        raise CacheAuditError(
            f"Entity dictionary missing required T9 columns: {sorted(missing)}"
        )
    frame = config["semantic_frame"]
    connection.register("_eda06_semantic_frame", frame)
    connection.execute(
        """
        CREATE TEMP TABLE semantic_mapping AS
        SELECT
            CAST(raw_object_type AS VARCHAR) AS raw_object_type,
            CAST(raw_action_type AS VARCHAR) AS raw_action_type,
            CAST(semantic_group AS VARCHAR) AS semantic_group
        FROM _eda06_semantic_frame
        """
    )
    connection.unregister("_eda06_semantic_frame")
    eda4._register_periods(connection, config["policy"])

    connection.execute(
        """
        CREATE TEMP VIEW host_dim AS
        SELECT canonical_id AS host_id, raw_value
        FROM entity_dictionary WHERE entity_type='host'
        """
    )
    connection.execute(
        """
        CREATE TEMP VIEW user_dim AS
        SELECT canonical_id AS user_id, raw_value, host_if_applicable
        FROM entity_dictionary WHERE entity_type='user_principal'
        """
    )
    connection.execute(
        """
        CREATE TEMP VIEW process_dim AS
        SELECT canonical_id AS process_id, raw_value, normalized_value,
               host_if_applicable, reliability_high_medium_low, entity_status
        FROM entity_dictionary WHERE entity_type='process'
        """
    )
    connection.execute(
        """
        CREATE TEMP VIEW file_dim AS
        SELECT canonical_id AS file_id, raw_value, normalized_value,
               host_if_applicable, reliability_high_medium_low, entity_status
        FROM entity_dictionary WHERE entity_type='file_path'
        """
    )
    connection.execute(
        """
        CREATE TEMP VIEW destination_dim_raw AS
        SELECT canonical_id AS destination_id, raw_value, normalized_value,
               reliability_high_medium_low, entity_status
        FROM entity_dictionary WHERE entity_type='destination'
        """
    )

    connection.create_function(
        "_eda06_path_category", path_category, return_type="VARCHAR"
    )
    connection.create_function(
        "_eda06_destination_category",
        destination_category,
        return_type="VARCHAR",
    )
    connection.create_function(
        "_eda06_parent_normalized",
        lambda value: eda5._normalize_windows_path(str(value))[0],
        return_type="VARCHAR",
    )
    connection.execute(
        """
        CREATE TEMP TABLE file_dim_categorized AS
        SELECT *, _eda06_path_category(raw_value) AS path_category
        FROM file_dim
        """
    )
    connection.execute(
        """
        CREATE TEMP TABLE destination_dim AS
        SELECT *, _eda06_destination_category(raw_value) AS destination_category
        FROM destination_dim_raw
        """
    )


def validate_required_cache_columns(connection) -> set[str]:
    present = {str(row[0]) for row in connection.execute("DESCRIBE events").fetchall()}
    missing = REQUIRED_CACHE_COLUMNS - present
    if missing:
        raise CacheAuditError(
            f"Normalized cache missing required EDA 6 columns: {sorted(missing)}"
        )
    return present


def _period_join() -> str:
    return (
        "LEFT JOIN period_intervals pi ON e.event_time >= pi.start_time "
        "AND e.event_time < pi.end_time"
    )


def _create_core_aggregate(connection) -> None:
    """Payload scan 1/4: all-event period, host/user, semantic, and evidence."""
    connection.execute(
        f"""
        CREATE TEMP TABLE core_agg AS
        WITH projected AS (
            SELECT
                TRY_CAST(timestamp_parsed AS TIMESTAMP) AS event_time,
                CAST(host_raw AS VARCHAR) AS host_raw,
                CAST(user_raw AS VARCHAR) AS user_raw,
                COALESCE(NULLIF(CAST(object_raw AS VARCHAR), ''),
                         '{eda4.MISSING_MARKER}') AS raw_object_type,
                COALESCE(NULLIF(CAST(action_raw AS VARCHAR), ''),
                         '{eda4.MISSING_MARKER}') AS raw_action_type,
                COALESCE(CAST(archive_name AS VARCHAR), '') AS archive_name,
                COALESCE(CAST(member_name AS VARCHAR), '') AS member_name,
                TRY_CAST(line_number AS BIGINT) AS line_number,
                COALESCE(CAST(raw_event_id AS VARCHAR), '') AS raw_event_id
            FROM events
        ),
        assigned AS (
            SELECT
                COALESCE(pi.period_role, 'unassigned') AS period_role,
                date_trunc('minute', e.event_time) AS window_start,
                TRY_CAST(regexp_extract(
                    e.archive_name,
                    '([0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}})',
                    1
                ) AS DATE) AS archive_date,
                EXTRACT(hour FROM e.event_time)::INTEGER AS utc_hour,
                hd.host_id,
                ud.user_id,
                sm.semantic_group,
                e.host_raw,
                e.user_raw,
                e.raw_object_type,
                e.raw_action_type,
                e.event_time,
                e.archive_name,
                e.member_name,
                e.line_number,
                e.raw_event_id
            FROM projected e
            {_period_join()}
            LEFT JOIN host_dim hd ON hd.raw_value=e.host_raw
            LEFT JOIN user_dim ud
              ON ud.raw_value=e.user_raw
             AND ud.host_if_applicable=e.host_raw
            LEFT JOIN semantic_mapping sm
              ON sm.raw_object_type=e.raw_object_type
             AND sm.raw_action_type=e.raw_action_type
        )
        SELECT
            period_role,
            window_start,
            archive_date,
            utc_hour,
            host_id,
            user_id,
            semantic_group,
            COUNT(*)::BIGINT AS event_count,
            SUM(CASE WHEN NULLIF(TRIM(host_raw), '') IS NOT NULL
                      AND host_id IS NULL THEN 1 ELSE 0 END)::BIGINT
                AS missing_host_mapping_count,
            SUM(CASE WHEN NULLIF(TRIM(user_raw), '') IS NOT NULL
                      AND user_id IS NULL THEN 1 ELSE 0 END)::BIGINT
                AS missing_user_mapping_count,
            SUM(CASE WHEN semantic_group IS NULL THEN 1 ELSE 0 END)::BIGINT
                AS missing_semantic_mapping_count,
            arg_min(
                struct_pack(
                    event_time := event_time,
                    archive_name := archive_name,
                    member_name := member_name,
                    line_number := line_number,
                    raw_event_id := raw_event_id
                ),
                struct_pack(
                    event_time := event_time,
                    archive_name := archive_name,
                    member_name := member_name,
                    line_number := line_number,
                    raw_event_id := raw_event_id
                ),
                {EVIDENCE_CAP}
            ) FILTER (WHERE period_role='evaluation') AS evaluation_evidence
        FROM assigned
        GROUP BY
            period_role, window_start, archive_date, utc_hour,
            host_id, user_id, semantic_group
        """
    )


def _chain_sql_expression() -> str:
    # Parent T9 IDs remain output attributes, but association identity uses the
    # approved normalized parent text consistently. Exact T9 joining one slash
    # spelling but not another therefore cannot split one association.
    parent_component = (
        "'parent_normalized:' || _eda06_parent_normalized(e.parent_raw)"
    )
    framed = (
        "concat(length(hd.host_id)::VARCHAR, ':', hd.host_id, "
        f"length({parent_component})::VARCHAR, ':', {parent_component}, "
        "length(pd.process_id)::VARCHAR, ':', pd.process_id)"
    )
    return f"'chain_' || substr(sha256({framed}), 1, 32)"


def _create_process_aggregate(connection) -> None:
    """Payload scan 2/4: canonical processes and same-event parent→child pairs."""
    chain_expression = _chain_sql_expression()
    connection.execute(
        f"""
        CREATE TEMP TABLE process_agg AS
        WITH projected AS (
            SELECT
                TRY_CAST(timestamp_parsed AS TIMESTAMP) AS event_time,
                CAST(host_raw AS VARCHAR) AS host_raw,
                CAST(user_raw AS VARCHAR) AS user_raw,
                UPPER(TRIM(CAST(object_raw AS VARCHAR))) AS object_type,
                COALESCE(NULLIF(CAST(image_path_raw AS VARCHAR), ''),
                         NULLIF(CAST(process_raw AS VARCHAR), ''), '') AS child_raw,
                COALESCE(NULLIF(CAST(parent_image_path_raw AS VARCHAR), ''),
                         NULLIF(CAST(parent_process_raw AS VARCHAR), ''), '')
                    AS parent_raw,
                COALESCE(CAST(archive_name AS VARCHAR), '') AS archive_name,
                COALESCE(CAST(member_name AS VARCHAR), '') AS member_name,
                TRY_CAST(line_number AS BIGINT) AS line_number,
                COALESCE(CAST(raw_event_id AS VARCHAR), '') AS raw_event_id
            FROM events
            WHERE TRY_CAST(timestamp_parsed AS TIMESTAMP) IS NOT NULL
              AND UPPER(TRIM(CAST(object_raw AS VARCHAR))) IN
                  ('PROCESS','FLOW','FILE','MODULE','THREAD','SHELL')
              AND COALESCE(NULLIF(CAST(image_path_raw AS VARCHAR), ''),
                           NULLIF(CAST(process_raw AS VARCHAR), ''), '') <> ''
        ),
        enriched AS (
            SELECT
                COALESCE(pi.period_role, 'unassigned') AS period_role,
                date_trunc('minute', e.event_time) AS window_start,
                hd.host_id,
                ud.user_id,
                pd.process_id,
                pd.normalized_value AS process_label,
                pd.reliability_high_medium_low AS process_reliability,
                pd.entity_status AS process_status,
                e.child_raw,
                e.parent_raw,
                parent_pd.process_id AS parent_process_id,
                COALESCE(
                    parent_pd.normalized_value,
                    _eda06_parent_normalized(e.parent_raw)
                )
                    AS parent_normalized,
                CASE
                    WHEN e.object_type='PROCESS' AND e.parent_raw <> ''
                         AND hd.host_id IS NOT NULL AND pd.process_id IS NOT NULL
                    THEN {chain_expression}
                    ELSE NULL
                END AS chain_key,
                CASE
                    WHEN parent_pd.process_id IS NOT NULL THEN parent_pd.entity_status
                    WHEN e.parent_raw <> '' THEN 'unresolved_not_in_t9'
                    ELSE 'not_applicable'
                END AS parent_status,
                e.event_time, e.archive_name, e.member_name,
                e.line_number, e.raw_event_id
            FROM projected e
            {_period_join()}
            LEFT JOIN host_dim hd ON hd.raw_value=e.host_raw
            LEFT JOIN user_dim ud
              ON ud.raw_value=e.user_raw
             AND ud.host_if_applicable=e.host_raw
            LEFT JOIN process_dim pd
              ON pd.raw_value=e.child_raw
             AND pd.host_if_applicable=e.host_raw
            LEFT JOIN process_dim parent_pd
              ON parent_pd.raw_value=e.parent_raw
             AND parent_pd.host_if_applicable=e.host_raw
        )
        SELECT
            period_role, window_start, host_id, user_id,
            process_id, process_label, process_reliability, process_status,
            child_raw, parent_raw, parent_process_id, parent_normalized,
            chain_key, parent_status,
            COUNT(*)::BIGINT AS event_count,
            FIRST(raw_event_id ORDER BY event_time, archive_name, member_name,
                  line_number, raw_event_id) AS evidence_event_id,
            FIRST(archive_name ORDER BY event_time, archive_name, member_name,
                  line_number, raw_event_id) AS evidence_archive_name,
            FIRST(member_name ORDER BY event_time, archive_name, member_name,
                  line_number, raw_event_id) AS evidence_member_name,
            FIRST(line_number ORDER BY event_time, archive_name, member_name,
                  line_number, raw_event_id) AS evidence_line_number,
            SUM(CASE WHEN process_id IS NULL THEN 1 ELSE 0 END)::BIGINT
                AS missing_process_mapping_count
        FROM enriched
        GROUP BY
            period_role, window_start, host_id, user_id,
            process_id, process_label, process_reliability, process_status,
            child_raw, parent_raw, parent_process_id, parent_normalized,
            chain_key, parent_status
        """
    )


def _create_file_aggregate(connection) -> None:
    """Payload scan 3/4: canonical FILE paths and closed path categories."""
    connection.execute(
        f"""
        CREATE TEMP TABLE file_agg AS
        WITH projected AS (
            SELECT
                TRY_CAST(timestamp_parsed AS TIMESTAMP) AS event_time,
                CAST(host_raw AS VARCHAR) AS host_raw,
                CAST(file_path_raw AS VARCHAR) AS file_raw
            FROM events
            WHERE TRY_CAST(timestamp_parsed AS TIMESTAMP) IS NOT NULL
              AND UPPER(TRIM(CAST(object_raw AS VARCHAR)))='FILE'
              AND NULLIF(TRIM(CAST(file_path_raw AS VARCHAR)), '') IS NOT NULL
        )
        SELECT
            COALESCE(pi.period_role, 'unassigned') AS period_role,
            date_trunc('minute', e.event_time) AS window_start,
            hd.host_id,
            fd.file_id,
            fd.path_category,
            fd.normalized_value AS path_label,
            fd.reliability_high_medium_low AS path_reliability,
            fd.entity_status AS path_status,
            COUNT(*)::BIGINT AS event_count,
            SUM(CASE WHEN fd.file_id IS NULL THEN 1 ELSE 0 END)::BIGINT
                AS missing_file_mapping_count
        FROM projected e
        {_period_join()}
        LEFT JOIN host_dim hd ON hd.raw_value=e.host_raw
        LEFT JOIN file_dim_categorized fd
          ON fd.raw_value=e.file_raw
         AND fd.host_if_applicable=e.host_raw
        GROUP BY
            period_role, window_start, hd.host_id, fd.file_id,
            fd.path_category, fd.normalized_value,
            fd.reliability_high_medium_low, fd.entity_status
        """
    )


def _create_destination_aggregate(connection) -> None:
    """Payload scan 4/4: canonical FLOW destinations and structural categories."""
    connection.execute(
        f"""
        CREATE TEMP TABLE destination_agg AS
        WITH projected AS (
            SELECT
                TRY_CAST(timestamp_parsed AS TIMESTAMP) AS event_time,
                CAST(host_raw AS VARCHAR) AS host_raw,
                COALESCE(NULLIF(CAST(dest_ip_raw AS VARCHAR), ''),
                         NULLIF(CAST(destination_raw AS VARCHAR), ''), '')
                    AS destination_raw
            FROM events
            WHERE TRY_CAST(timestamp_parsed AS TIMESTAMP) IS NOT NULL
              AND UPPER(TRIM(CAST(object_raw AS VARCHAR)))='FLOW'
              AND COALESCE(NULLIF(TRIM(CAST(dest_ip_raw AS VARCHAR)), ''),
                           NULLIF(TRIM(CAST(destination_raw AS VARCHAR)), ''),
                           '') <> ''
        )
        SELECT
            COALESCE(pi.period_role, 'unassigned') AS period_role,
            date_trunc('minute', e.event_time) AS window_start,
            hd.host_id,
            dd.destination_id,
            dd.destination_category,
            dd.normalized_value AS destination_label,
            dd.reliability_high_medium_low AS destination_reliability,
            dd.entity_status AS destination_status,
            COUNT(*)::BIGINT AS event_count,
            SUM(CASE WHEN dd.destination_id IS NULL THEN 1 ELSE 0 END)::BIGINT
                AS missing_destination_mapping_count
        FROM projected e
        {_period_join()}
        LEFT JOIN host_dim hd ON hd.raw_value=e.host_raw
        LEFT JOIN destination_dim dd ON dd.raw_value=e.destination_raw
        GROUP BY
            period_role, window_start, hd.host_id, dd.destination_id,
            dd.destination_category, dd.normalized_value,
            dd.reliability_high_medium_low, dd.entity_status
        """
    )


def _query_frame(connection, sql: str):
    """Materialize only compact post-aggregation results, never cache events."""
    return connection.execute(sql).fetchdf()


def _validate_aggregate_integrity(
    connection, cache_total: int
) -> dict[str, int]:
    period_rows = connection.execute(
        """
        SELECT period_role, SUM(event_count)::BIGINT
        FROM core_agg GROUP BY period_role ORDER BY period_role
        """
    ).fetchall()
    counts = {str(role): int(count) for role, count in period_rows}
    aggregated = sum(counts.values())
    if aggregated != cache_total:
        raise CacheAuditError(
            f"EDA 6 aggregate event count {aggregated:,} != cache metadata "
            f"{cache_total:,}"
        )
    if counts.get("unassigned", 0):
        raise CacheAuditError(
            f"Period reconciliation found {counts['unassigned']:,} unassigned "
            "event(s); the production period map requires complete assignment"
        )
    if counts.get("verified_benign", 0) + counts.get(
        "evaluation", 0
    ) + counts.get("other", 0) != cache_total:
        raise CacheAuditError("Assigned period-role counts do not reconcile")
    for table, column, label in (
        ("core_agg", "missing_host_mapping_count", "host"),
        ("core_agg", "missing_user_mapping_count", "user/principal"),
        ("core_agg", "missing_semantic_mapping_count", "semantic"),
        ("process_agg", "missing_process_mapping_count", "process"),
        ("file_agg", "missing_file_mapping_count", "file"),
        ("destination_agg", "missing_destination_mapping_count", "destination"),
    ):
        value = connection.execute(
            f"SELECT COALESCE(SUM({column}),0)::BIGINT FROM {table}"
        ).fetchone()[0]
        if int(value):
            raise CacheAuditError(
                f"Supplied artifacts do not map {int(value):,} {label} "
                "observation(s)"
            )
    return {
        "verified_benign": counts.get("verified_benign", 0),
        "evaluation": counts.get("evaluation", 0),
        "other": counts.get("other", 0),
        "unassigned": counts.get("unassigned", 0),
        "total": aggregated,
    }


def _top_entry_frames(connection) -> dict[str, Any]:
    return {
        "host_process": _query_frame(
            connection,
            """
            SELECT * EXCLUDE(rank_number) FROM (
                SELECT host_id, process_id AS stable_key,
                       process_label AS label,
                       process_reliability AS reliability,
                       process_status AS status,
                       SUM(event_count)::BIGINT AS event_count,
                       ROW_NUMBER() OVER (
                         PARTITION BY host_id
                         ORDER BY SUM(event_count) DESC, process_id
                       ) AS rank_number
                FROM process_agg
                WHERE period_role='verified_benign' AND host_id IS NOT NULL
                GROUP BY host_id, process_id, process_label,
                         process_reliability, process_status
            ) WHERE rank_number <= 10 ORDER BY host_id, rank_number
            """,
        ),
        "host_chain": _query_frame(
            connection,
            # Every representative field (parent, child, and evidence locator)
            # is carried together from one deterministic earliest observation,
            # while event_count still aggregates across separator aliases.
            # These remain same-event observed associations, not causal chains.
            """
            SELECT * EXCLUDE(rank_number) FROM (
                SELECT host_id,
                       stable_key,
                       representative.parent_raw AS parent_raw,
                       representative.parent_normalized AS parent_normalized,
                       representative.parent_process_id AS parent_process_id,
                       representative.parent_status AS parent_status,
                       representative.child_process_id AS child_process_id,
                       representative.child_raw AS child_raw,
                       representative.child_label AS child_label,
                       representative.reliability AS reliability,
                       representative.status AS status,
                       representative.evidence_event_id AS evidence_event_id,
                       representative.evidence_archive_name
                           AS evidence_archive_name,
                       representative.evidence_member_name
                           AS evidence_member_name,
                       representative.evidence_line_number
                           AS evidence_line_number,
                       event_count,
                       rank_number
                FROM (
                    SELECT host_id, chain_key AS stable_key,
                           arg_min(
                               struct_pack(
                                   parent_raw := parent_raw,
                                   parent_normalized := parent_normalized,
                                   parent_process_id := parent_process_id,
                                   parent_status := parent_status,
                                   child_process_id := process_id,
                                   child_raw := child_raw,
                                   child_label := process_label,
                                   reliability := process_reliability,
                                   status := process_status,
                                   evidence_event_id := evidence_event_id,
                                   evidence_archive_name := evidence_archive_name,
                                   evidence_member_name := evidence_member_name,
                                   evidence_line_number := evidence_line_number
                               ),
                               struct_pack(
                                   window_start := window_start,
                                   evidence_archive_name := evidence_archive_name,
                                   evidence_member_name := evidence_member_name,
                                   evidence_line_number := evidence_line_number,
                                   evidence_event_id := evidence_event_id
                               )
                           ) AS representative,
                           SUM(event_count)::BIGINT AS event_count,
                           ROW_NUMBER() OVER (
                             PARTITION BY host_id
                             ORDER BY SUM(event_count) DESC, chain_key
                           ) AS rank_number
                    FROM process_agg
                    WHERE period_role='verified_benign' AND chain_key IS NOT NULL
                    GROUP BY host_id, chain_key
                )
            ) WHERE rank_number <= 10 ORDER BY host_id, rank_number
            """,
        ),
        "host_semantic": _query_frame(
            connection,
            """
            SELECT * EXCLUDE(rank_number) FROM (
                SELECT host_id, semantic_group AS stable_key,
                       semantic_group AS label, 'exact_eda4_mapping' AS reliability,
                       'resolved' AS status,
                       SUM(event_count)::BIGINT AS event_count,
                       ROW_NUMBER() OVER (
                         PARTITION BY host_id
                         ORDER BY SUM(event_count) DESC, semantic_group
                       ) AS rank_number
                FROM core_agg
                WHERE period_role='verified_benign' AND host_id IS NOT NULL
                GROUP BY host_id, semantic_group
            ) WHERE rank_number <= 5 ORDER BY host_id, rank_number
            """,
        ),
        "host_path": _query_frame(
            connection,
            """
            SELECT * EXCLUDE(rank_number) FROM (
                SELECT host_id, path_category AS stable_key,
                       path_category AS label, 'syntax_rule' AS reliability,
                       CASE WHEN path_category='unknown'
                            THEN 'unresolved' ELSE 'resolved' END AS status,
                       SUM(event_count)::BIGINT AS event_count,
                       ROW_NUMBER() OVER (
                         PARTITION BY host_id
                         ORDER BY SUM(event_count) DESC, path_category
                       ) AS rank_number
                FROM file_agg
                WHERE period_role='verified_benign' AND host_id IS NOT NULL
                GROUP BY host_id, path_category
            ) WHERE rank_number <= 5 ORDER BY host_id, rank_number
            """,
        ),
        "host_destination": _query_frame(
            connection,
            """
            SELECT * EXCLUDE(rank_number) FROM (
                SELECT host_id, destination_category AS stable_key,
                       destination_category AS label,
                       'structural_syntax_rule' AS reliability,
                       CASE WHEN destination_category IN
                                      ('unknown','hostname_or_other')
                            THEN 'unresolved' ELSE 'resolved' END AS status,
                       SUM(event_count)::BIGINT AS event_count,
                       ROW_NUMBER() OVER (
                         PARTITION BY host_id
                         ORDER BY SUM(event_count) DESC, destination_category
                       ) AS rank_number
                FROM destination_agg
                WHERE period_role='verified_benign' AND host_id IS NOT NULL
                GROUP BY host_id, destination_category
            ) WHERE rank_number <= 5 ORDER BY host_id, rank_number
            """,
        ),
        "user_process": _query_frame(
            connection,
            """
            SELECT * EXCLUDE(rank_number) FROM (
                SELECT user_id, process_id AS stable_key,
                       process_label AS label,
                       process_reliability AS reliability,
                       process_status AS status,
                       SUM(event_count)::BIGINT AS event_count,
                       ROW_NUMBER() OVER (
                         PARTITION BY user_id
                         ORDER BY SUM(event_count) DESC, process_id
                       ) AS rank_number
                FROM process_agg
                WHERE period_role='verified_benign' AND user_id IS NOT NULL
                GROUP BY user_id, process_id, process_label,
                         process_reliability, process_status
            ) WHERE rank_number <= 10 ORDER BY user_id, rank_number
            """,
        ),
        "user_semantic": _query_frame(
            connection,
            """
            SELECT * EXCLUDE(rank_number) FROM (
                SELECT user_id, semantic_group AS stable_key,
                       semantic_group AS label, 'exact_eda4_mapping' AS reliability,
                       'resolved' AS status,
                       SUM(event_count)::BIGINT AS event_count,
                       ROW_NUMBER() OVER (
                         PARTITION BY user_id
                         ORDER BY SUM(event_count) DESC, semantic_group
                       ) AS rank_number
                FROM core_agg
                WHERE period_role='verified_benign' AND user_id IS NOT NULL
                GROUP BY user_id, semantic_group
            ) WHERE rank_number <= 5 ORDER BY user_id, rank_number
            """,
        ),
    }


def _frame_entries(frame, group_column: str) -> dict[str, list[dict[str, Any]]]:
    output: dict[str, list[dict[str, Any]]] = defaultdict(list)
    if frame.empty:
        return output
    for row in frame.to_dict("records"):
        group = str(row.pop(group_column))
        clean = {
            key: (None if _is_missing(value) else _python_scalar(value))
            for key, value in row.items()
        }
        output[group].append(clean)
    return output


def _is_missing(value: Any) -> bool:
    """Scalar missing-value check.

    Containers (dict/list/tuple and NumPy/Pandas array-likes with one or more
    dimensions) are never missing and are never passed to ``math.isnan``,
    which deprecates implicit conversion of non-scalar arrays.
    """
    if value is None:
        return True
    if isinstance(value, (dict, list, tuple, set)):
        return False
    shape = getattr(value, "shape", None)
    if shape is not None and shape != ():
        return False
    try:
        return bool(math.isnan(value))
    except (TypeError, ValueError):
        return False


def _python_scalar(value: Any) -> Any:
    return value.item() if hasattr(value, "item") else value


def _build_hour_maps(connection, entity_column: str) -> tuple[dict, dict]:
    stats = _query_frame(
        connection,
        f"""
        SELECT {entity_column} AS entity_id,
               COUNT(DISTINCT archive_date)::BIGINT AS benign_date_count,
               COUNT(DISTINCT window_start)::BIGINT AS benign_window_count,
               SUM(event_count)::BIGINT AS benign_event_count
        FROM core_agg
        WHERE period_role='verified_benign'
          AND {entity_column} IS NOT NULL
        GROUP BY {entity_column} ORDER BY {entity_column}
        """,
    )
    support = _query_frame(
        connection,
        f"""
        SELECT {entity_column} AS entity_id, utc_hour,
               COUNT(DISTINCT archive_date)::BIGINT AS supporting_date_count
        FROM core_agg
        WHERE period_role='verified_benign'
          AND {entity_column} IS NOT NULL
          AND archive_date IS NOT NULL
        GROUP BY {entity_column}, utc_hour
        ORDER BY {entity_column}, utc_hour
        """,
    )
    stat_map = {
        str(row.entity_id): {
            "benign_date_count": int(row.benign_date_count),
            "benign_window_count": int(row.benign_window_count),
            "benign_event_count": int(row.benign_event_count),
        }
        for row in stats.itertuples(index=False)
    }
    support_map: dict[str, dict[int, int]] = defaultdict(dict)
    for row in support.itertuples(index=False):
        support_map[str(row.entity_id)][int(row.utc_hour)] = int(
            row.supporting_date_count
        )
    return stat_map, support_map


def _evaluation_new_counts(connection, table: str, key: str, alias: str):
    return _query_frame(
        connection,
        f"""
        WITH baseline AS (
            SELECT DISTINCT host_id, {key} AS entity_key FROM {table}
            WHERE period_role='verified_benign'
              AND host_id IS NOT NULL AND {key} IS NOT NULL
        )
        SELECT e.host_id, e.window_start,
               COUNT(DISTINCT e.{key})::BIGINT AS {alias}
        FROM {table} e
        LEFT JOIN baseline b
          ON b.host_id=e.host_id AND b.entity_key=e.{key}
        WHERE e.period_role='evaluation' AND e.host_id IS NOT NULL
          AND e.{key} IS NOT NULL AND b.entity_key IS NULL
        GROUP BY e.host_id, e.window_start
        ORDER BY e.window_start, e.host_id
        """,
    )


def _count_lookup(frame, value_column: str) -> dict[tuple[str, Any], int]:
    if frame.empty:
        return {}
    return {
        (str(row.host_id), row.window_start): int(getattr(row, value_column))
        for row in frame.itertuples(index=False)
    }


def _evidence_values(value: Any) -> list[dict[str, Any]]:
    if value is None or _is_missing(value):
        return []
    if hasattr(value, "tolist"):
        value = value.tolist()
    if isinstance(value, dict):
        return [value]
    if isinstance(value, (list, tuple)):
        output: list[dict[str, Any]] = []
        for item in value:
            output.extend(_evidence_values(item))
        return output
    return []


def _ordered_evidence(values: Iterable[Any]) -> list[str]:
    rows: list[dict[str, Any]] = []
    for value in values:
        rows.extend(_evidence_values(value))
    rows.sort(
        key=lambda item: (
            str(item.get("event_time") or item.get("timestamp") or ""),
            str(item.get("archive_name") or ""),
            str(item.get("member_name") or ""),
            int(item.get("line_number") or 0),
            str(item.get("raw_event_id") or ""),
        )
    )
    seen: set[str] = set()
    output: list[str] = []
    for item in rows:
        event_id = str(item.get("raw_event_id") or "")
        if not event_id or event_id in seen:
            continue
        seen.add(event_id)
        output.append(event_id)
        if len(output) == EVIDENCE_CAP:
            break
    return output


def build_outputs(connection, policy: eda4.PeriodPolicy):
    import pandas as pd

    possible_windows = _possible_benign_windows(policy)
    host_stats, host_support = _build_hour_maps(connection, "host_id")
    user_stats, user_support = _build_hour_maps(connection, "user_id")
    tops = _top_entry_frames(connection)
    host_process = _frame_entries(tops["host_process"], "host_id")
    host_chain = _frame_entries(tops["host_chain"], "host_id")
    host_semantic = _frame_entries(tops["host_semantic"], "host_id")
    host_path = _frame_entries(tops["host_path"], "host_id")
    host_destination = _frame_entries(tops["host_destination"], "host_id")
    user_process = _frame_entries(tops["user_process"], "user_id")
    user_semantic = _frame_entries(tops["user_semantic"], "user_id")

    normal_hours_by_host: dict[str, list[dict[str, Any]]] = {}
    t11_rows = []
    for host_id in sorted(host_stats):
        stats = host_stats[host_id]
        hours = normal_active_hours(
            host_support.get(host_id, {}), stats["benign_date_count"]
        )
        normal_hours_by_host[host_id] = hours
        t11_rows.append(
            {
                "host_id": host_id,
                "benign_window_count": stats["benign_window_count"],
                "top_10_processes": _compact_json(host_process.get(host_id, [])),
                "top_10_parent_child_chains": _compact_json(
                    host_chain.get(host_id, [])
                ),
                "top_5_semantic_groups": _compact_json(
                    host_semantic.get(host_id, [])
                ),
                "top_5_path_categories": _compact_json(host_path.get(host_id, [])),
                "top_5_destination_categories": _compact_json(
                    host_destination.get(host_id, [])
                ),
                "normal_active_hours": _compact_json(hours),
                "baseline_confidence": _compact_json(
                    baseline_confidence(
                        stats["benign_date_count"],
                        stats["benign_window_count"],
                        possible_windows,
                    )
                ),
            }
        )

    user_hosts = _query_frame(
        connection,
        """
        SELECT user_id, host_id
        FROM core_agg
        WHERE period_role='verified_benign'
          AND user_id IS NOT NULL AND host_id IS NOT NULL
        GROUP BY user_id, host_id ORDER BY user_id, host_id
        """,
    )
    active_hosts: dict[str, list[str]] = defaultdict(list)
    for row in user_hosts.itertuples(index=False):
        active_hosts[str(row.user_id)].append(str(row.host_id))

    new_host_flags = _query_frame(
        connection,
        """
        WITH baseline AS (
          SELECT DISTINCT user_id, host_id FROM core_agg
          WHERE period_role='verified_benign'
            AND user_id IS NOT NULL AND host_id IS NOT NULL
        )
        SELECT e.user_id, COUNT(DISTINCT e.host_id)::BIGINT AS flag_count
        FROM core_agg e LEFT JOIN baseline b
          ON b.user_id=e.user_id AND b.host_id=e.host_id
        WHERE e.period_role='evaluation' AND e.user_id IS NOT NULL
          AND e.host_id IS NOT NULL AND b.host_id IS NULL
        GROUP BY e.user_id
        """,
    )
    new_pair_flags = _query_frame(
        connection,
        """
        WITH baseline AS (
          SELECT DISTINCT user_id, process_id FROM process_agg
          WHERE period_role='verified_benign'
            AND user_id IS NOT NULL AND process_id IS NOT NULL
        )
        SELECT e.user_id, COUNT(DISTINCT e.process_id)::BIGINT AS flag_count
        FROM process_agg e LEFT JOIN baseline b
          ON b.user_id=e.user_id AND b.process_id=e.process_id
        WHERE e.period_role='evaluation' AND e.user_id IS NOT NULL
          AND e.process_id IS NOT NULL AND b.process_id IS NULL
        GROUP BY e.user_id
        """,
    )
    eval_user_windows = _query_frame(
        connection,
        """
        SELECT DISTINCT user_id, window_start, utc_hour
        FROM core_agg
        WHERE period_role='evaluation' AND user_id IS NOT NULL
        ORDER BY user_id, window_start
        """,
    )
    unusual_user_windows: dict[str, int] = defaultdict(int)
    user_hours: dict[str, list[dict[str, Any]]] = {}
    for user_id, stats in user_stats.items():
        user_hours[user_id] = normal_active_hours(
            user_support.get(user_id, {}), stats["benign_date_count"]
        )
    for row in eval_user_windows.itertuples(index=False):
        user_id = str(row.user_id)
        normal_set = {item["hour"] for item in user_hours.get(user_id, [])}
        if int(row.utc_hour) not in normal_set:
            unusual_user_windows[user_id] += 1
    new_host_map = {
        str(row.user_id): int(row.flag_count)
        for row in new_host_flags.itertuples(index=False)
    }
    new_pair_map = {
        str(row.user_id): int(row.flag_count)
        for row in new_pair_flags.itertuples(index=False)
    }

    t12_rows = []
    for user_id in sorted(user_stats):
        flags = {
            "new_host_after_baseline": new_host_map.get(user_id, 0),
            "new_user_process_pair_after_baseline": new_pair_map.get(user_id, 0),
            "unusual_hour_after_baseline": unusual_user_windows.get(user_id, 0),
        }
        t12_rows.append(
            {
                "user_or_principal_id": user_id,
                "active_hosts": _compact_json(active_hosts.get(user_id, [])),
                "benign_event_count": user_stats[user_id]["benign_event_count"],
                "top_processes": _compact_json(user_process.get(user_id, [])),
                "top_semantic_groups": _compact_json(
                    user_semantic.get(user_id, [])
                ),
                "common_active_hours": _compact_json(user_hours.get(user_id, [])),
                "unusual_behavior_flags_after_baseline": _compact_json(flags),
            }
        )

    eval_core = _query_frame(
        connection,
        """
        SELECT window_start, host_id, semantic_group,
               SUM(event_count)::BIGINT AS event_count,
               list(evaluation_evidence) AS evidence_groups
        FROM core_agg
        WHERE period_role='evaluation' AND host_id IS NOT NULL
        GROUP BY window_start, host_id, semantic_group
        ORDER BY window_start, host_id, semantic_group
        """,
    )
    baseline_semantic = _query_frame(
        connection,
        """
        SELECT host_id, semantic_group, SUM(event_count)::BIGINT AS event_count
        FROM core_agg
        WHERE period_role='verified_benign' AND host_id IS NOT NULL
        GROUP BY host_id, semantic_group
        """,
    )
    baseline_distributions: dict[str, dict[str, int]] = defaultdict(dict)
    for row in baseline_semantic.itertuples(index=False):
        baseline_distributions[str(row.host_id)][str(row.semantic_group)] = int(
            row.event_count
        )

    process_new = _count_lookup(
        _evaluation_new_counts(
            connection, "process_agg", "process_id", "new_process_count"
        ),
        "new_process_count",
    )
    chain_new = _count_lookup(
        _evaluation_new_counts(
            connection, "process_agg", "chain_key", "new_chain_count"
        ),
        "new_chain_count",
    )
    destination_new = _count_lookup(
        _evaluation_new_counts(
            connection,
            "destination_agg",
            "destination_id",
            "new_destination_count",
        ),
        "new_destination_count",
    )
    path_new = _count_lookup(
        _evaluation_new_counts(
            connection, "file_agg", "path_category", "new_path_category_count"
        ),
        "new_path_category_count",
    )

    grouped_eval: dict[tuple[Any, str], dict[str, Any]] = defaultdict(
        lambda: {"semantic": defaultdict(int), "evidence": []}
    )
    for row in eval_core.itertuples(index=False):
        key = (row.window_start, str(row.host_id))
        grouped_eval[key]["semantic"][str(row.semantic_group)] += int(row.event_count)
        grouped_eval[key]["evidence"].append(row.evidence_groups)

    normal_hour_sets = {
        host_id: {item["hour"] for item in hours}
        for host_id, hours in normal_hours_by_host.items()
    }
    t13_rows = []
    for (window_start, host_id), values in sorted(
        grouped_eval.items(), key=lambda item: (item[0][0], item[0][1])
    ):
        key = (host_id, window_start)
        hour = int(window_start.hour)
        unusual = int(hour not in normal_hour_sets.get(host_id, set()))
        distance = jensen_shannon_divergence(
            baseline_distributions.get(host_id, {}), values["semantic"]
        )
        counts = {
            "new_process_count": process_new.get(key, 0),
            "new_chain_count": chain_new.get(key, 0),
            "new_destination_count": destination_new.get(key, 0),
            "new_path_category_count": path_new.get(key, 0),
        }
        score = deviation_score(
            **counts,
            unusual_hour_flag=unusual,
            semantic_distribution_distance=distance,
        )
        start = pd.Timestamp(window_start)
        t13_rows.append(
            {
                "window_start": start.isoformat(),
                "window_end": (start + pd.Timedelta(minutes=1)).isoformat(),
                "host_id": host_id,
                **counts,
                "unusual_hour_flag": unusual,
                "semantic_distribution_distance": round(distance, 12),
                "evidence_event_ids": _compact_json(
                    _ordered_evidence(values["evidence"])
                ),
                "deviation_score": round(score, 12),
            }
        )

    return (
        pd.DataFrame(t11_rows, columns=T11_COLUMNS),
        pd.DataFrame(t12_rows, columns=T12_COLUMNS),
        pd.DataFrame(t13_rows, columns=T13_COLUMNS),
    )


def validate_outputs(t11, t12, t13) -> None:
    if list(t11.columns) != T11_COLUMNS:
        raise CacheAuditError("T11 schema mismatch")
    if list(t12.columns) != T12_COLUMNS:
        raise CacheAuditError("T12 schema mismatch")
    if list(t13.columns) != T13_COLUMNS:
        raise CacheAuditError("T13 schema mismatch")
    if t11["host_id"].duplicated().any():
        raise CacheAuditError("T11 host_id must be unique")
    if t12["user_or_principal_id"].duplicated().any():
        raise CacheAuditError("T12 user/principal ID must be unique")
    if t13.duplicated(["window_start", "host_id"]).any():
        raise CacheAuditError("T13 host-window keys must be unique")
    if not t13.empty:
        if not t13["deviation_score"].between(0, 1).all():
            raise CacheAuditError("T13 deviation_score outside [0,1]")
        if not t13["semantic_distribution_distance"].between(0, 1).all():
            raise CacheAuditError("T13 semantic distance outside [0,1]")
        for value in t13["evidence_event_ids"]:
            ids = json.loads(value)
            if len(ids) > EVIDENCE_CAP or len(ids) != len(set(ids)):
                raise CacheAuditError("T13 evidence cap/uniqueness failure")


def _host_label_map(connection) -> dict[str, str]:
    """Deterministic host_id -> exact T9 raw hostname for F7 panel titles."""
    frame = _query_frame(
        connection,
        """
        SELECT CAST(host_id AS VARCHAR) AS host_id,
               CAST(raw_value AS VARCHAR) AS raw_value
        FROM host_dim
        ORDER BY host_id, raw_value
        """,
    )
    labels: dict[str, str] = {}
    if frame.empty:
        return labels
    for row in frame.itertuples(index=False):
        host_id = str(row.host_id)
        if host_id not in labels:
            labels[host_id] = str(row.raw_value)
    return labels


def create_f7(
    t11,
    t13,
    png_path: pathlib.Path,
    pdf_path: pathlib.Path,
    host_labels: Optional[dict[str, str]] = None,
) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import pandas as pd

    labels = host_labels or {}
    hosts = sorted(
        set(t11["host_id"].astype(str))
        | (set(t13["host_id"].astype(str)) if not t13.empty else set())
    )
    panel_count = max(1, len(hosts))
    columns = 2
    rows = math.ceil(panel_count / columns)
    figure, axes = plt.subplots(
        rows,
        columns,
        figsize=(14, max(4, 3.2 * rows)),
        sharex=True,
        sharey=True,
        constrained_layout=True,
    )
    flat_axes = list(getattr(axes, "flat", [axes]))
    for index, axis in enumerate(flat_axes):
        if index >= len(hosts):
            axis.set_visible(False)
            continue
        host_id = hosts[index]
        host_rows = t13.loc[t13["host_id"].astype(str) == host_id].copy()
        if not host_rows.empty:
            host_rows["window_start"] = pd.to_datetime(host_rows["window_start"])
            host_rows = host_rows.sort_values("window_start")
            # Split at inactive minutes so a line never bridges a gap. No
            # missing host-window is synthesized or converted to zero.
            segment_ids = (
                host_rows["window_start"].diff()
                .ne(pd.Timedelta(minutes=1))
                .cumsum()
            )
            for _, segment in host_rows.groupby(segment_ids, sort=True):
                axis.plot(
                    segment["window_start"],
                    segment["deviation_score"],
                    color=F7_LINE_COLOR,
                    marker=".",
                    linewidth=0.8,
                )
        # Prefer the exact T9 raw hostname; fall back only if unavailable.
        axis.set_title(labels.get(host_id) or host_id)
        axis.set_ylim(0, 1)
        axis.grid(alpha=0.25)
        axis.set_ylabel("Deviation score [0,1]")
        axis.set_xlabel("Evaluation window start (UTC)")
    figure.suptitle(
        "F7 Host Deviation Score Over Time\n"
        "Verified-benign baseline deviations; not attack or malicious labels"
    )
    figure.savefig(png_path, dpi=180, bbox_inches="tight")
    figure.savefig(pdf_path, bbox_inches="tight")
    plt.close(figure)


def _atomic_write_csv(frame, path: pathlib.Path) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        frame.to_csv(temporary, index=False)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_write_text(text: str, path: pathlib.Path) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_write_json(payload: dict[str, Any], path: pathlib.Path) -> None:
    _atomic_write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", path
    )


def _nearest_existing_directory(path: pathlib.Path) -> pathlib.Path:
    candidate = path
    while not candidate.exists():
        if candidate.parent == candidate:
            raise CacheAuditError(f"No existing ancestor for output path: {path}")
        candidate = candidate.parent
    return candidate if candidate.is_dir() else candidate.parent


def _publish_staging(staging: pathlib.Path, output_dir: pathlib.Path) -> None:
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(os.fspath(output_dir)):
        raise CacheAuditError(
            f"Output path appeared before publication; refusing to touch it: "
            f"{output_dir}"
        )
    os.replace(staging, output_dir)


def _assert_no_temp_files(directory: pathlib.Path) -> None:
    leftovers = [
        str(path.relative_to(directory))
        for path in directory.rglob("*")
        if path.name.startswith(".") or path.suffix == ".tmp"
    ]
    if leftovers:
        raise CacheAuditError(f"Temporary output files remain: {leftovers}")


def _peak_rss_mb() -> float:
    value = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    if sys.platform == "darwin":
        return value / (1024 * 1024)
    return value / 1024


def _git_commit(project_root: pathlib.Path) -> Optional[str]:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=project_root,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip() or None
    except Exception:
        return None


def _span(policy: eda4.PeriodPolicy, role: str) -> dict[str, Optional[str]]:
    rows = policy.frame.loc[policy.frame["period_role"] == role]
    return {
        "start": rows["start_time"].min().isoformat() if len(rows) else None,
        "end": rows["end_time"].max().isoformat() if len(rows) else None,
    }


def _readme(metadata: dict[str, Any]) -> str:
    return "\n".join(
        [
            "EDA 6 — Benign Host, User, and Process Baseline",
            "=" * 52,
            "",
            "Scope and period policy",
            "-----------------------",
            "The required evidence-backed period map is validated with the EDA 4",
            "period-policy validator plus EDA 6 requirements: verified-benign and",
            "evaluation roles, >=24 verified-benign hours, >=2 benign dates,",
            "ordered non-overlapping half-open intervals, and complete cache",
            "assignment. Events exactly at an evaluation start belong to",
            "evaluation. Only verified_benign events fit baseline structures.",
            "Evaluation events are scored but never influence baseline sets,",
            "frequencies, normal hours, top lists, semantic distributions, or",
            "coverage confidence.",
            "",
            "Identity and semantics",
            "----------------------",
            "All host, user/principal, process, file, and destination identities",
            "come from the supplied EDA 5 T9 dictionary. No replacement entity",
            "IDs are created. Semantic groups come from the supplied EDA 4 T7",
            "mapping and are verified against EDA 4's deterministic mapper.",
            "Unresolved T9 process entries remain visible in top-list status and",
            "reliability fields.",
            "",
            "Observed parent-child associations",
            "----------------------------------",
            "EDA 6 uses only length-2 parent→child values carried by the same",
            "PROCESS event. These are observed associations, not proven causal",
            "chains. No PID joins, multi-hop inference, or length 3–5 chains are",
            "performed. Parent raw and normalized values and earliest evidence",
            "are retained in deterministic compact JSON.",
            "",
            "Normal hours and confidence",
            "---------------------------",
            "UTC hours are common/normal when active on at least 50% (ceiling) of",
            "an entity's active verified-benign archive dates. Confidence is",
            "coverage confidence only, not detection confidence: high requires",
            ">=5 dates and >=50% nonempty-minute coverage; medium requires >=3",
            "dates and >=20%; low otherwise.",
            "",
            "Categories",
            "----------",
            f"Path rules ({PATH_CATEGORY_RULE_VERSION}): temporary, system,",
            "program, user, network, other, unknown; specific syntax precedes",
            "generic roots. Destination rules",
            f"({DESTINATION_CATEGORY_RULE_VERSION}): loopback, private,",
            "link_local, multicast, unspecified, reserved, global_syntax,",
            "hostname_or_other, unknown. global_syntax is only valid IP syntax;",
            "it is not evidence of a real external/routable destination because",
            "OpTC addresses are fictional.",
            "",
            "T13 and F7",
            "----------",
            "T13 has one row per nonempty evaluation host-minute. New counts are",
            "relative to that host's verified-benign sets. Semantic distance is",
            "base-2 Jensen-Shannon divergence without smoothing, bounded [0,1].",
            f"deviation_score={DEVIATION_FORMULA}. No attack threshold is fitted.",
            f"Evidence contains the earliest {EVIDENCE_CAP} unique raw_event_ids",
            "ordered by timestamp/archive/member/line/id; additional IDs are",
            "deterministically truncated. F7 plots only nonempty windows and",
            "does not zero-fill inactive gaps. Scores are baseline deviations,",
            "not anomalies, maliciousness, attacks, or event-level ground truth.",
            "",
            "Methods",
            "-------",
            f"Exactly {PAYLOAD_SCAN_COUNT} projected cache scans create bounded",
            "DuckDB aggregate tables (core, process, file, destination). All",
            "reported counts, top lists, hours, new-set counts, and evidence",
            "selection are exact. Floating JSD and deviation scores are",
            "deterministic derived metrics, not approximations. The cache remains",
            "read only; spill is local and output publication is atomic.",
            "",
            f"Generated UTC: {metadata['generated_utc']}",
            "",
        ]
    )


def run_eda06(args: argparse.Namespace) -> dict[str, Any]:
    started = time.perf_counter()
    config = validate_run_config(args)
    connection = None
    spill_path = None
    spill_owned = False
    staging: Optional[pathlib.Path] = None
    execution_log: list[str] = []

    def stage(number: int, message: str) -> None:
        line = f"[STAGE {number}/8] {message}"
        execution_log.append(line)
        print(line, flush=True)

    try:
        stage(1, "validated configuration and evidence-backed period map")
        connection, spill_path, spill_owned = _duck_conn(
            config["cache_dir"],
            memory_limit=config["memory_limit"],
            temp_dir=args.duckdb_temp_dir,
            threads=config["threads"],
        )
        validate_required_cache_columns(connection)
        _register_inputs(connection, config)
        stage(2, "registered read-only cache, T9 identities, T7 semantics, periods")

        _create_core_aggregate(connection)
        stage(3, "payload scan 1/4 core complete")
        _create_process_aggregate(connection)
        stage(4, "payload scan 2/4 process/observed-pair complete")
        _create_file_aggregate(connection)
        stage(5, "payload scan 3/4 file/path complete")
        _create_destination_aggregate(connection)
        stage(6, "payload scan 4/4 destination complete")

        cache_total = int(config["cache_metadata"]["total_events_written"])
        period_counts = _validate_aggregate_integrity(connection, cache_total)
        t11, t12, t13 = build_outputs(connection, config["policy"])
        validate_outputs(t11, t12, t13)
        stage(7, "reconciliation and baseline/deviation tables complete")

        parent = _nearest_existing_directory(config["output_dir"].parent)
        staging = pathlib.Path(
            tempfile.mkdtemp(prefix=".eda06_staging_", dir=str(parent))
        )
        _atomic_write_csv(t11, staging / "T11_host_baseline_profile.csv")
        _atomic_write_csv(
            t12, staging / "T12_user_principal_baseline_profile.csv"
        )
        _atomic_write_csv(t13, staging / "T13_deviation_feature_table.csv")
        create_f7(
            t11,
            t13,
            staging / "F7_host_deviation_score_over_time.png",
            staging / "F7_host_deviation_score_over_time.pdf",
            host_labels=_host_label_map(connection),
        )

        generated = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        runtime = time.perf_counter() - started
        metadata = {
            "schema_version": SCHEMA_VERSION,
            "cache_path": str(config["cache_dir"].resolve()),
            "cache_event_count": cache_total,
            "manifest_version": config["manifest_version"],
            "manifest_path": config["manifest_path"],
            "period_map_path": str(config["period_map"].resolve()),
            "period_map_sha256": _sha256_file(config["period_map"]),
            "period_policy": config["policy"].policy_name,
            "verified_benign_event_count": period_counts["verified_benign"],
            "evaluation_event_count": period_counts["evaluation"],
            "other_event_count": period_counts["other"],
            "unassigned_count": period_counts["unassigned"],
            "baseline_span": _span(config["policy"], "verified_benign"),
            "evaluation_span": _span(config["policy"], "evaluation"),
            "window_size": WINDOW_SIZE,
            "payload_scan_count": PAYLOAD_SCAN_COUNT,
            "payload_scans": ["core", "process", "file_path", "destination"],
            "evidence_cap": EVIDENCE_CAP,
            "evidence_truncation_policy": (
                "earliest unique raw_event_ids ordered by timestamp, archive, "
                "member, line, event ID"
            ),
            "path_category_rule_version": PATH_CATEGORY_RULE_VERSION,
            "destination_category_rule_version": DESTINATION_CATEGORY_RULE_VERSION,
            "normal_hour_rule_version": NORMAL_HOUR_RULE_VERSION,
            "baseline_confidence_rule_version": CONFIDENCE_RULE_VERSION,
            "parent_child_rule_version": CHAIN_RULE_VERSION,
            "deviation_score_formula": DEVIATION_FORMULA,
            "metric_status": {
                "event_counts": "exact",
                "top_lists": "exact",
                "normal_hours": "exact",
                "new_entity_and_category_counts": "exact",
                "evidence_selection": "exact_bounded_output",
                "semantic_distribution_distance": "deterministic_float64",
                "deviation_score": "deterministic_float64",
                "approximate_metrics": [],
            },
            "t11_row_count": len(t11),
            "t12_row_count": len(t12),
            "t13_row_count": len(t13),
            "duckdb_memory_limit": config["memory_limit"],
            "duckdb_threads": config["threads"],
            "temporary_directory_policy": (
                "explicit_local_preserved"
                if args.duckdb_temp_dir
                else "owned_local_temp_removed"
            ),
            "peak_rss_mb": round(_peak_rss_mb(), 3),
            "runtime_seconds": round(runtime, 6),
            "generated_utc": generated,
            "code_commit": _git_commit(config["project_root"]),
            "scientific_interpretation": (
                "baseline deviation only; no rarity, anomaly, maliciousness, "
                "attack, or event-level ground-truth claim"
            ),
        }
        _atomic_write_text(_readme(metadata), staging / "README.md")
        stage(8, "outputs staged; publishing atomically")
        _atomic_write_text(
            "\n".join(execution_log) + "\n", staging / "eda06_execution.log"
        )
        _atomic_write_json(metadata, staging / "eda06_run_metadata.json")
        _assert_no_temp_files(staging)
        _publish_staging(staging, config["output_dir"])
        staging = None
        _assert_no_temp_files(config["output_dir"])
        return metadata
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
        if spill_owned and spill_path:
            shutil.rmtree(spill_path, ignore_errors=True)
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)


def main(argv: Optional[list[str]] = None) -> int:
    try:
        metadata = run_eda06(parse_args(argv))
    except CacheAuditError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    print(
        "EDA 6 complete: "
        f"T11={metadata['t11_row_count']:,}, "
        f"T12={metadata['t12_row_count']:,}, "
        f"T13={metadata['t13_row_count']:,}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
