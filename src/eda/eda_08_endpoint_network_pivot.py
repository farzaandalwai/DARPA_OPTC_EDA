#!/usr/bin/env python3
"""
EDA 8 — Endpoint-Network Pivot Analysis.

Measures endpoint→network pivot feasibility before interpreting FLOW behavior.
Baseline destination and port novelty vocabularies are fitted only on
verified_benign intervals. Evaluation rows may be scored against those frozen
structures but never update them. Outputs describe pivot quality and baseline-
relative novelty, not maliciousness, attacks, or ground-truth labels.
Ground-truth alignment remains EDA 10.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from collections import defaultdict
from typing import Any, Optional

import eda_04_event_taxonomy as eda4
import eda_05_entity_dictionary as eda5
from optc_streaming_parser import SCHEMA_VERSION

CacheAuditError = eda5.CacheAuditError

WINDOW_SIZE = "1min"
WINDOW_SECONDS = 60
STRICT_TOLERANCE_SECONDS = 1
RELAXED_TOLERANCE_SECONDS = 15
DEFAULT_EVIDENCE_CAP = 20
PAYLOAD_FLOW_SCAN_COUNT = 1
PAYLOAD_PROCESS_SCAN_COUNT = 1
CACHE_RECONCILIATION_SCAN_COUNT = 1

# Compact cascade status codes (internal; not published schemas).
STATUS_UNMATCHED = 0
STATUS_DIRECT = 1
STATUS_PID_MATCH = 2
STATUS_PID_AMBIG = 3
STATUS_STRICT_MATCH = 4
STATUS_STRICT_AMBIG = 5
STATUS_RELAXED_MATCH = 6
STATUS_RELAXED_AMBIG = 7
T16_COUNT_SEMANTICS = (
    "For each date_label, host_id, and pivot_rule, endpoint_flow_events counts "
    "FLOW rows entering that cascade stage; matched_network_events counts rows "
    "assigned by that rule; ambiguous_match_count counts rows rejected as "
    "ambiguous at that rule; unmatched_count is endpoint_flow_events minus "
    "matched minus ambiguous. The unmatched rule row reports final unmatched "
    "FLOW rows with matched_network_events=0 and match_rate_percent=0."
)
PIVOT_RULE_VERSION = "eda08_pivot_rules_v1"
DESTINATION_CATEGORY_VERSION = "eda08_destination_structure_v1"
LAG_MINUTES = (5, 15, 60)
F9_COLOR = "#2ca02c"
F10_COLORS = ("#1f77b4", "#ff7f0e", "#9467bd")

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
    "object_raw",
    "image_path_raw",
    "process_raw",
    "pid_raw",
    "dest_ip_raw",
    "dest_port_raw",
    "destination_raw",
    "protocol_raw",
}

MISSING_HOST_SENTINEL = "__MISSING_HOST__"
EVENT_LOCATOR_EXPR = """
(CONCAT(
    COALESCE(CAST(archive_name AS VARCHAR), ''), '|',
    COALESCE(CAST(member_name AS VARCHAR), ''), '|',
    COALESCE(CAST(line_number AS BIGINT), 0)::VARCHAR, '|',
    COALESCE(CAST(raw_event_id AS VARCHAR), '')
))
""".strip()

T16_COLUMNS = [
    "date_label",
    "host_id",
    "pivot_rule",
    "endpoint_flow_events",
    "matched_network_events",
    "match_rate_percent",
    "unmatched_count",
    "time_tolerance",
    "false_link_risk_note",
    "ambiguous_match_count",
    "ambiguity_rate_percent",
]

T17_COLUMNS = [
    "period",
    "host_id",
    "process_name",
    "destination_value",
    "destination_category",
    "port",
    "protocol",
    "connection_count",
    "first_seen_time",
    "benign_seen_before_yes_no",
    "raw_event_ids",
]

_DRIVE_PATH_PARTS = {"content", "drive", "mydrive"}
_PRIVATE_V4 = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_PRIVATE_V6 = ipaddress.ip_network("fc00::/7")

PIVOT_RULE_IDS = (
    "direct_same_event",
    "host_process_pid",
    "host_temporal_strict",
    "host_temporal_relaxed",
    "unmatched",
)

PIVOT_RULE_NOTES = {
    "direct_same_event": (
        "Low when the FLOW record itself includes process attribution; "
        "still same-event association only."
    ),
    "host_process_pid": (
        "Medium; host+PID+archive date must resolve to one process identity. "
        "PID reuse within the same archive date remains a documented limitation."
    ),
    "host_temporal_strict": (
        "High unless candidate is unique within ±1 second on the same "
        "host and archive date; ambiguous matches are rejected."
    ),
    "host_temporal_relaxed": (
        "Highest temporal false-link risk; only unique candidates within "
        "±15 seconds on the same host and archive date are accepted."
    ),
    "unmatched": (
        "No auditable pivot rule matched, including missing host, missing "
        "destination, or ambiguous candidates."
    ),
}

PIVOT_RULE_TOLERANCE = {
    "direct_same_event": "0s",
    "host_process_pid": "0s",
    "host_temporal_strict": f"±{STRICT_TOLERANCE_SECONDS}s",
    "host_temporal_relaxed": f"±{RELAXED_TOLERANCE_SECONDS}s",
    "unmatched": "n/a",
}

F10_VALUE_COLUMN = "process_novelty_windows_followed_by_destination_novelty"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "EDA 8 — scale-safe endpoint-network pivot analysis (cache only)."
        )
    )
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--normalized-cache-dir", required=True)
    parser.add_argument("--manifest-csv", required=True)
    parser.add_argument("--period-map-csv", required=True)
    parser.add_argument("--entity-dictionary-path", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--window-size", default=WINDOW_SIZE)
    parser.add_argument("--evidence-cap", type=int, default=DEFAULT_EVIDENCE_CAP)
    parser.add_argument("--duckdb-memory-limit", default="4GB")
    parser.add_argument("--duckdb-temp-dir", default=None)
    parser.add_argument("--duckdb-threads", type=int, default=2)
    parser.add_argument(
        "--cascade-probe-only",
        action="store_true",
        help=(
            "Validate inventories and pivot cascade only; print reconciliation "
            "counts and exit without building T16/T17/F9/F10 or publishing."
        ),
    )
    parser.add_argument(
        "--t17-probe-only",
        action="store_true",
        help=(
            "Build inventories, cascade, T16, and bounded T17 only; print "
            "summary metrics and exit without F9/F10 or publishing."
        ),
    )
    return parser


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def _compact_json(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    )


def _sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _looks_like_drive(path: pathlib.Path) -> bool:
    lowered = {part.lower() for part in path.parts}
    text = str(path).lower().replace("\\", "/")
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
            f"Entity dictionary path contains no Parquet files: {path}"
        )
    pattern = (
        str(path / "entity_type=*" / "*.parquet")
        if partitioned
        else str(path / "*.parquet")
    )
    return files, pattern


def load_eda8_period_policy(path: pathlib.Path) -> eda4.PeriodPolicy:
    try:
        policy = eda4.load_period_policy(str(path), rare_benign_max_count=1)
    except eda4.CacheAuditError as exc:
        raise CacheAuditError(str(exc)) from exc
    if not policy.has_verified_benign:
        raise CacheAuditError("EDA 8 requires at least one verified_benign interval")
    if not policy.has_evaluation:
        raise CacheAuditError("EDA 8 requires at least one evaluation interval")
    return policy


def validate_run_config(args: argparse.Namespace) -> dict[str, Any]:
    project_root = pathlib.Path(args.project_root).expanduser()
    cache_dir = pathlib.Path(args.normalized_cache_dir).expanduser()
    manifest_path = pathlib.Path(args.manifest_csv).expanduser()
    period_map = pathlib.Path(args.period_map_csv).expanduser()
    entity_dictionary = pathlib.Path(args.entity_dictionary_path).expanduser()
    output_dir = pathlib.Path(args.output_dir).expanduser()

    if not project_root.is_dir():
        raise CacheAuditError(f"Project root not found: {project_root}")
    if not cache_dir.is_dir() or not any(cache_dir.glob("*.parquet")):
        raise CacheAuditError(f"No Parquet cache files found at: {cache_dir}")
    if not manifest_path.is_file():
        raise CacheAuditError(f"Manifest CSV not found: {manifest_path}")
    if not period_map.is_file():
        raise CacheAuditError(f"Period-map CSV not found: {period_map}")
    _t9_files, t9_glob = _t9_files_and_glob(entity_dictionary)
    if args.window_size != WINDOW_SIZE:
        raise CacheAuditError("--window-size currently allows only '1min'")

    evidence_cap = eda5._validate_positive("--evidence-cap", args.evidence_cap)
    memory = eda5._validate_duckdb_memory_limit(args.duckdb_memory_limit)
    threads = eda5._validate_duckdb_threads(args.duckdb_threads)
    if args.duckdb_temp_dir is not None:
        spill = eda5._validate_duckdb_temp_dir(args.duckdb_temp_dir)
        if _looks_like_drive(spill):
            raise CacheAuditError("Google Drive spill paths are refused")
    cascade_probe_only = bool(getattr(args, "cascade_probe_only", False))
    t17_probe_only = bool(getattr(args, "t17_probe_only", False))
    if not cascade_probe_only and not t17_probe_only:
        _validate_output_dir(output_dir, cache_dir)
    cache_metadata = eda5._load_cache_metadata(cache_dir)
    policy = load_eda8_period_policy(period_map)
    manifest = eda5._manifest_metadata(manifest_path)
    return {
        "project_root": project_root,
        "cache_dir": cache_dir,
        "manifest_path": manifest_path,
        "period_map": period_map,
        "entity_dictionary": entity_dictionary,
        "t9_glob": t9_glob,
        "output_dir": output_dir,
        "memory_limit": memory,
        "threads": threads,
        "cache_metadata": cache_metadata,
        "policy": policy,
        "evidence_cap": evidence_cap,
        **manifest,
    }


def destination_structural_category(raw_value: object) -> str:
    """Observable destination structure only; no reputation or geolocation."""
    if raw_value is None or str(raw_value).strip() == "":
        return "missing"
    raw = str(raw_value).strip()
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return "invalid_or_unresolved"
    if address.is_loopback:
        return "loopback"
    if address.is_multicast or str(address).endswith(".255"):
        return "multicast_or_broadcast"
    if (
        isinstance(address, ipaddress.IPv4Address)
        and any(address in network for network in _PRIVATE_V4)
    ) or (
        isinstance(address, ipaddress.IPv6Address) and address in _PRIVATE_V6
    ):
        return "internal-looking"
    return "external-looking"


def process_display_name(raw_value: object) -> str:
    if raw_value is None or str(raw_value).strip() == "":
        return ""
    normalized, _status = eda5._normalize_windows_path(str(raw_value))
    return normalized or str(raw_value).strip()


def _period_join(alias: str = "e") -> str:
    return (
        f"LEFT JOIN period_intervals pi "
        f"ON {alias}.event_time >= pi.start_time "
        f"AND {alias}.event_time < pi.end_time"
    )


def validate_required_cache_columns(connection) -> set[str]:
    describe = connection.execute("DESCRIBE SELECT * FROM events").fetchall()
    available = {str(row[0]) for row in describe}
    missing = sorted(REQUIRED_CACHE_COLUMNS - available)
    if missing:
        raise CacheAuditError(f"Cache missing required columns: {missing}")
    return available


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
            spill = pathlib.Path(tempfile.mkdtemp(prefix="eda08_duckdb_tmp_"))
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
        connection.execute("SET preserve_insertion_order = false")
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


def _register_inputs(connection, config: dict[str, Any]) -> None:
    connection.execute(
        "CREATE VIEW entity_dictionary AS SELECT * FROM read_parquet("
        f"{eda5._sql_string_literal(config['t9_glob'])}, "
        "hive_partitioning=false)"
    )
    columns = {
        str(row[0])
        for row in connection.execute(
            "DESCRIBE SELECT * FROM entity_dictionary"
        ).fetchall()
    }
    missing = sorted(T9_REQUIRED_COLUMNS - columns)
    if missing:
        raise CacheAuditError(f"T9 missing required columns: {missing}")
    eda4._register_periods(connection, config["policy"])
    connection.execute(
        """
        CREATE TEMP VIEW host_dim AS
        SELECT canonical_id AS host_id, raw_value
        FROM entity_dictionary WHERE entity_type='host'
        """
    )
    connection.create_function(
        "_eda08_destination_category",
        destination_structural_category,
        return_type="VARCHAR",
    )
    connection.create_function(
        "_eda08_process_display",
        process_display_name,
        return_type="VARCHAR",
    )


def _query_frame(connection, sql: str):
    return connection.execute(sql).fetchdf()


def _create_cache_period_counts(connection) -> None:
    """Narrow cache-wide period reconciliation scan (timestamp only)."""
    connection.execute(
        f"""
        CREATE TEMP TABLE cache_period_counts AS
        WITH projected AS (
            SELECT TRY_CAST(timestamp_parsed AS TIMESTAMP) AS event_time
            FROM events
            WHERE TRY_CAST(timestamp_parsed AS TIMESTAMP) IS NOT NULL
        )
        SELECT
            COALESCE(pi.period_role, 'unassigned') AS period_role,
            COUNT(*)::BIGINT AS event_count
        FROM projected e
        {_period_join("e")}
        GROUP BY 1
        """
    )


def _create_flow_inventory(connection) -> None:
    """FLOW payload scan into a single inventory with numeric flow_id."""
    locator = EVENT_LOCATOR_EXPR
    sentinel = MISSING_HOST_SENTINEL
    connection.execute(
        f"""
        CREATE TEMP TABLE flow_inventory AS
        WITH projected AS (
            SELECT
                TRY_CAST(timestamp_parsed AS TIMESTAMP) AS event_time,
                date_trunc('minute', TRY_CAST(timestamp_parsed AS TIMESTAMP))
                    AS window_start,
                CAST(host_raw AS VARCHAR) AS host_raw,
                COALESCE(
                    NULLIF(CAST(image_path_raw AS VARCHAR), ''),
                    NULLIF(CAST(process_raw AS VARCHAR), ''),
                    ''
                ) AS process_raw,
                COALESCE(CAST(pid_raw AS VARCHAR), '') AS pid_raw,
                COALESCE(
                    NULLIF(CAST(dest_ip_raw AS VARCHAR), ''),
                    NULLIF(CAST(destination_raw AS VARCHAR), ''),
                    ''
                ) AS destination_value,
                COALESCE(CAST(dest_port_raw AS VARCHAR), '') AS port,
                COALESCE(CAST(protocol_raw AS VARCHAR), '') AS protocol,
                COALESCE(CAST(archive_name AS VARCHAR), '') AS archive_name,
                COALESCE(CAST(member_name AS VARCHAR), '') AS member_name,
                TRY_CAST(line_number AS BIGINT) AS line_number,
                COALESCE(CAST(raw_event_id AS VARCHAR), '') AS raw_event_id,
                {locator} AS event_locator
            FROM events
            WHERE TRY_CAST(timestamp_parsed AS TIMESTAMP) IS NOT NULL
              AND UPPER(TRIM(CAST(object_raw AS VARCHAR))) = 'FLOW'
        ),
        enriched AS (
            SELECT
                COALESCE(pi.period_role, 'unassigned') AS period_role,
                e.*,
                hd.host_id AS mapped_host_id
            FROM projected e
            {_period_join("e")}
            LEFT JOIN host_dim hd ON hd.raw_value = e.host_raw
        )
        SELECT
            ROW_NUMBER() OVER ()::BIGINT AS flow_id,
            period_role,
            window_start,
            event_time,
            COALESCE(CAST(mapped_host_id AS VARCHAR), '{sentinel}') AS host_id,
            mapped_host_id IS NULL AS missing_host,
            COALESCE(destination_value, '') = '' AS missing_destination,
            CASE
                WHEN archive_name LIKE '%.tar'
                THEN regexp_replace(archive_name, '\\.tar$', '')
                ELSE strftime(event_time, '%Y-%m-%d')
            END AS date_label,
            event_locator,
            process_raw,
            pid_raw,
            port,
            protocol,
            destination_value,
            archive_name,
            member_name,
            line_number,
            raw_event_id,
            (
                process_raw <> ''
                AND COALESCE(destination_value, '') <> ''
            ) AS is_direct
        FROM enriched
        """
    )
    connection.execute(
        """
        CREATE TEMP TABLE flow_period_counts AS
        SELECT period_role, COUNT(*)::BIGINT AS flow_event_count
        FROM flow_inventory
        GROUP BY 1
        """
    )


def _create_process_inventory(connection) -> None:
    """PROCESS payload scan into a single inventory with numeric process_id."""
    locator = EVENT_LOCATOR_EXPR
    connection.execute(
        f"""
        CREATE TEMP TABLE process_inventory AS
        WITH projected AS (
            SELECT
                TRY_CAST(timestamp_parsed AS TIMESTAMP) AS event_time,
                date_trunc('minute', TRY_CAST(timestamp_parsed AS TIMESTAMP))
                    AS window_start,
                CAST(host_raw AS VARCHAR) AS host_raw,
                COALESCE(
                    NULLIF(CAST(image_path_raw AS VARCHAR), ''),
                    NULLIF(CAST(process_raw AS VARCHAR), ''),
                    ''
                ) AS process_raw,
                COALESCE(CAST(pid_raw AS VARCHAR), '') AS pid_raw,
                COALESCE(CAST(archive_name AS VARCHAR), '') AS archive_name,
                COALESCE(CAST(member_name AS VARCHAR), '') AS member_name,
                TRY_CAST(line_number AS BIGINT) AS line_number,
                COALESCE(CAST(raw_event_id AS VARCHAR), '') AS raw_event_id,
                {locator} AS event_locator
            FROM events
            WHERE TRY_CAST(timestamp_parsed AS TIMESTAMP) IS NOT NULL
              AND UPPER(TRIM(CAST(object_raw AS VARCHAR))) = 'PROCESS'
              AND COALESCE(
                    NULLIF(CAST(image_path_raw AS VARCHAR), ''),
                    NULLIF(CAST(process_raw AS VARCHAR), ''),
                    ''
                ) <> ''
        ),
        enriched AS (
            SELECT
                COALESCE(pi.period_role, 'unassigned') AS period_role,
                e.*,
                hd.host_id
            FROM projected e
            {_period_join("e")}
            LEFT JOIN host_dim hd ON hd.raw_value = e.host_raw
        )
        SELECT
            ROW_NUMBER() OVER ()::BIGINT AS process_id,
            period_role,
            window_start,
            event_time,
            CAST(host_id AS VARCHAR) AS host_id,
            CASE
                WHEN archive_name LIKE '%.tar'
                THEN regexp_replace(archive_name, '\\.tar$', '')
                ELSE strftime(event_time, '%Y-%m-%d')
            END AS date_label,
            event_locator,
            _eda08_process_display(process_raw) AS process_name,
            process_raw,
            pid_raw,
            archive_name,
            member_name,
            line_number,
            raw_event_id
        FROM enriched
        WHERE host_id IS NOT NULL
        """
    )


def _validate_event_locator_uniqueness(connection, table_name: str) -> None:
    row = connection.execute(
        f"""
        SELECT
            COUNT(*)::BIGINT AS row_count,
            COUNT(DISTINCT event_locator)::BIGINT AS locator_count
        FROM {table_name}
        """
    ).fetchone()
    row_count = int(row[0])
    locator_count = int(row[1])
    if row_count != locator_count:
        raise CacheAuditError(
            f"{table_name} event_locator collision: "
            f"rows={row_count} distinct_locators={locator_count}"
        )


def _build_temporal_rule_status(connection) -> None:
    """Ordinal ASOF temporal status without candidate-row expansion."""
    strict_seconds = STRICT_TOLERANCE_SECONDS
    relaxed_seconds = RELAXED_TOLERANCE_SECONDS
    connection.execute(
        """
        CREATE TEMP TABLE process_sorted AS
        SELECT
            host_id,
            date_label,
            event_time,
            event_locator,
            ROW_NUMBER() OVER (
                PARTITION BY host_id, date_label
                ORDER BY event_time, event_locator
            )::BIGINT AS proc_ord
        FROM process_inventory
        """
    )
    connection.execute(
        """
        CREATE TEMP TABLE process_time_bounds AS
        SELECT
            host_id,
            date_label,
            event_time,
            MIN(proc_ord)::BIGINT AS first_ord_at_time,
            MAX(proc_ord)::BIGINT AS last_ord_at_time
        FROM process_sorted
        GROUP BY 1, 2, 3
        """
    )
    connection.execute(
        """
        CREATE TEMP TABLE temporal_input AS
        SELECT
            f.flow_id,
            f.host_id,
            f.date_label,
            f.event_time
        FROM flow_inventory f
        LEFT JOIN cascade_pid_match pm ON pm.flow_id = f.flow_id
        LEFT JOIN cascade_pid_ambiguous pa ON pa.flow_id = f.flow_id
        WHERE NOT f.is_direct
          AND pm.flow_id IS NULL
          AND pa.flow_id IS NULL
          AND NOT f.missing_host
          AND NOT f.missing_destination
        """
    )
    # One CTE construction → one narrow persisted temporal status table.
    connection.execute(
        f"""
        CREATE TEMP TABLE cascade_temporal AS
        WITH
        strict_lo AS (
            SELECT
                f.flow_id,
                lo.first_ord_at_time AS strict_lower_ord
            FROM temporal_input f
            ASOF LEFT JOIN process_time_bounds lo
              ON f.host_id = lo.host_id
             AND f.date_label = lo.date_label
             AND f.event_time - INTERVAL '{strict_seconds} seconds' <= lo.event_time
        ),
        strict_hi AS (
            SELECT
                f.flow_id,
                hi.last_ord_at_time AS strict_upper_ord
            FROM temporal_input f
            ASOF LEFT JOIN process_time_bounds hi
              ON f.host_id = hi.host_id
             AND f.date_label = hi.date_label
             AND f.event_time + INTERVAL '{strict_seconds} seconds' >= hi.event_time
        ),
        relaxed_lo AS (
            SELECT
                f.flow_id,
                lo.first_ord_at_time AS relaxed_lower_ord
            FROM temporal_input f
            ASOF LEFT JOIN process_time_bounds lo
              ON f.host_id = lo.host_id
             AND f.date_label = lo.date_label
             AND f.event_time - INTERVAL '{relaxed_seconds} seconds' <= lo.event_time
        ),
        relaxed_hi AS (
            SELECT
                f.flow_id,
                hi.last_ord_at_time AS relaxed_upper_ord
            FROM temporal_input f
            ASOF LEFT JOIN process_time_bounds hi
              ON f.host_id = hi.host_id
             AND f.date_label = hi.date_label
             AND f.event_time + INTERVAL '{relaxed_seconds} seconds' >= hi.event_time
        ),
        counts AS (
            SELECT
                f.flow_id,
                f.host_id,
                f.date_label,
                CASE
                    WHEN sl.strict_lower_ord IS NULL
                      OR sh.strict_upper_ord IS NULL
                      OR sh.strict_upper_ord < sl.strict_lower_ord
                    THEN 0
                    ELSE sh.strict_upper_ord - sl.strict_lower_ord + 1
                END::BIGINT AS strict_candidate_count,
                CASE
                    WHEN rl.relaxed_lower_ord IS NULL
                      OR rh.relaxed_upper_ord IS NULL
                      OR rh.relaxed_upper_ord < rl.relaxed_lower_ord
                    THEN 0
                    ELSE rh.relaxed_upper_ord - rl.relaxed_lower_ord + 1
                END::BIGINT AS relaxed_candidate_count,
                sl.strict_lower_ord,
                rl.relaxed_lower_ord
            FROM temporal_input f
            LEFT JOIN strict_lo sl ON sl.flow_id = f.flow_id
            LEFT JOIN strict_hi sh ON sh.flow_id = f.flow_id
            LEFT JOIN relaxed_lo rl ON rl.flow_id = f.flow_id
            LEFT JOIN relaxed_hi rh ON rh.flow_id = f.flow_id
        )
        SELECT
            c.flow_id,
            c.strict_candidate_count,
            CASE
                WHEN c.strict_candidate_count = 1 THEN strict_ps.event_locator
            END AS strict_chosen_process_locator,
            c.relaxed_candidate_count,
            CASE
                WHEN c.relaxed_candidate_count = 1 THEN relaxed_ps.event_locator
            END AS relaxed_chosen_process_locator
        FROM counts c
        LEFT JOIN process_sorted strict_ps
          ON strict_ps.host_id = c.host_id
         AND strict_ps.date_label = c.date_label
         AND strict_ps.proc_ord = c.strict_lower_ord
         AND c.strict_candidate_count = 1
        LEFT JOIN process_sorted relaxed_ps
          ON relaxed_ps.host_id = c.host_id
         AND relaxed_ps.date_label = c.date_label
         AND relaxed_ps.proc_ord = c.relaxed_lower_ord
         AND c.relaxed_candidate_count = 1
        """
    )


def _validate_flow_period_counts(connection, cache_total: int) -> dict[str, Any]:
    cache_roles = {
        str(row.period_role): int(row.event_count)
        for row in _query_frame(
            connection, "SELECT period_role, event_count FROM cache_period_counts"
        ).itertuples(index=False)
    }
    assigned = sum(cache_roles.values())
    if assigned != cache_total:
        raise CacheAuditError(
            "Cache event reconciliation failed: "
            f"assigned={assigned} cache_total={cache_total}"
        )
    flow_roles = {
        str(row.period_role): int(row.flow_event_count)
        for row in _query_frame(
            connection,
            "SELECT period_role, flow_event_count FROM flow_period_counts",
        ).itertuples(index=False)
    }
    flow_total = sum(flow_roles.values())
    flow_inventory_total = int(
        connection.execute("SELECT COUNT(*)::BIGINT FROM flow_inventory").fetchone()[0]
    )
    if flow_total != flow_inventory_total:
        raise CacheAuditError(
            "FLOW period reconciliation failed: "
            f"assigned={flow_total} flow_inventory={flow_inventory_total}"
        )
    return {
        "cache_role_counts": cache_roles,
        "unassigned_count": int(cache_roles.get("unassigned", 0)),
        "flow_role_counts": flow_roles,
        "flow_total": flow_total,
    }


def _peak_rss_bytes() -> Optional[int]:
    try:
        import resource

        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if sys.platform == "darwin":
            return int(usage)
        return int(usage) * 1024
    except Exception:
        return None


def _build_pivot_cascade(connection) -> dict[str, Any]:
    """Build inventories and one narrow numeric-id pivot cascade."""
    _validate_event_locator_uniqueness(connection, "flow_inventory")
    _validate_event_locator_uniqueness(connection, "process_inventory")
    connection.execute(
        """
        CREATE TEMP TABLE host_pid_unique_map AS
        SELECT
            host_id,
            date_label,
            pid_raw,
            MIN(event_locator) AS process_locator
        FROM process_inventory
        WHERE pid_raw <> ''
        GROUP BY 1, 2, 3
        HAVING COUNT(DISTINCT process_name) = 1
        """
    )
    connection.execute(
        """
        CREATE TEMP TABLE host_pid_ambiguity AS
        SELECT
            host_id,
            date_label,
            pid_raw,
            COUNT(DISTINCT process_name)::BIGINT AS identity_count
        FROM process_inventory
        WHERE pid_raw <> ''
        GROUP BY 1, 2, 3
        HAVING COUNT(DISTINCT process_name) > 1
        """
    )
    # Narrow PID results keyed by flow_id; direct eligibility is boolean is_direct.
    connection.execute(
        """
        CREATE TEMP TABLE cascade_pid_ambiguous AS
        SELECT f.flow_id
        FROM flow_inventory f
        JOIN host_pid_ambiguity a
          ON a.host_id = f.host_id
         AND a.date_label = f.date_label
         AND a.pid_raw = f.pid_raw
        WHERE NOT f.is_direct
          AND f.pid_raw <> ''
          AND NOT f.missing_host
          AND NOT f.missing_destination
        """
    )
    connection.execute(
        """
        CREATE TEMP TABLE cascade_pid_match AS
        SELECT
            f.flow_id,
            m.process_locator AS chosen_process_locator
        FROM flow_inventory f
        JOIN host_pid_unique_map m
          ON m.host_id = f.host_id
         AND m.date_label = f.date_label
         AND m.pid_raw = f.pid_raw
        LEFT JOIN cascade_pid_ambiguous pa ON pa.flow_id = f.flow_id
        WHERE NOT f.is_direct
          AND f.pid_raw <> ''
          AND NOT f.missing_host
          AND NOT f.missing_destination
          AND pa.flow_id IS NULL
        """
    )
    _build_temporal_rule_status(connection)
    connection.execute(
        f"""
        CREATE TEMP TABLE cascade_result AS
        SELECT
            f.flow_id,
            CASE
                WHEN f.is_direct THEN {STATUS_DIRECT}
                WHEN pa.flow_id IS NOT NULL THEN {STATUS_PID_AMBIG}
                WHEN pm.flow_id IS NOT NULL THEN {STATUS_PID_MATCH}
                WHEN COALESCE(ts.strict_candidate_count, 0) = 1
                    THEN {STATUS_STRICT_MATCH}
                WHEN COALESCE(ts.strict_candidate_count, 0) > 1
                    THEN {STATUS_STRICT_AMBIG}
                WHEN COALESCE(ts.relaxed_candidate_count, 0) = 1
                    THEN {STATUS_RELAXED_MATCH}
                WHEN COALESCE(ts.relaxed_candidate_count, 0) > 1
                    THEN {STATUS_RELAXED_AMBIG}
                ELSE {STATUS_UNMATCHED}
            END::TINYINT AS status_code,
            CASE
                WHEN f.is_direct THEN NULL
                WHEN pm.flow_id IS NOT NULL THEN pm.chosen_process_locator
                WHEN COALESCE(ts.strict_candidate_count, 0) = 1
                    THEN ts.strict_chosen_process_locator
                WHEN COALESCE(ts.relaxed_candidate_count, 0) = 1
                    THEN ts.relaxed_chosen_process_locator
                ELSE NULL
            END AS chosen_process_locator
        FROM flow_inventory f
        LEFT JOIN cascade_pid_match pm ON pm.flow_id = f.flow_id
        LEFT JOIN cascade_pid_ambiguous pa ON pa.flow_id = f.flow_id
        LEFT JOIN cascade_temporal ts ON ts.flow_id = f.flow_id
        """
    )
    # Drop intermediate PID/temporal tables once cascade_result exists.
    for table in (
        "cascade_pid_match",
        "cascade_pid_ambiguous",
        "cascade_temporal",
        "temporal_input",
        "temporal_rule_status_counts",
        "temporal_strict_lo",
        "temporal_strict_hi",
        "temporal_relaxed_lo",
        "temporal_relaxed_hi",
    ):
        connection.execute(f"DROP TABLE IF EXISTS {table}")

    connection.execute(
        f"""
        CREATE TEMP TABLE t16_stage_counts AS
        SELECT
            f.date_label,
            f.host_id,
            COUNT(*)::BIGINT AS enters_direct,
            SUM(CASE WHEN c.status_code = {STATUS_DIRECT} THEN 1 ELSE 0 END)
                ::BIGINT AS direct_matched,
            SUM(CASE WHEN NOT f.is_direct THEN 1 ELSE 0 END)::BIGINT AS enters_pid,
            SUM(CASE WHEN c.status_code = {STATUS_PID_MATCH} THEN 1 ELSE 0 END)
                ::BIGINT AS pid_matched,
            SUM(CASE WHEN c.status_code = {STATUS_PID_AMBIG} THEN 1 ELSE 0 END)
                ::BIGINT AS pid_ambiguous,
            SUM(
                CASE
                    WHEN NOT f.is_direct
                     AND c.status_code NOT IN (
                         {STATUS_PID_MATCH}, {STATUS_PID_AMBIG}
                     )
                    THEN 1 ELSE 0
                END
            )::BIGINT AS enters_strict,
            SUM(CASE WHEN c.status_code = {STATUS_STRICT_MATCH} THEN 1 ELSE 0 END)
                ::BIGINT AS strict_matched,
            SUM(CASE WHEN c.status_code = {STATUS_STRICT_AMBIG} THEN 1 ELSE 0 END)
                ::BIGINT AS strict_ambiguous,
            SUM(
                CASE
                    WHEN NOT f.is_direct
                     AND c.status_code IN (
                        {STATUS_RELAXED_MATCH},
                        {STATUS_RELAXED_AMBIG},
                        {STATUS_UNMATCHED}
                     )
                    THEN 1 ELSE 0
                END
            )::BIGINT AS enters_relaxed,
            SUM(CASE WHEN c.status_code = {STATUS_RELAXED_MATCH} THEN 1 ELSE 0 END)
                ::BIGINT AS relaxed_matched,
            SUM(CASE WHEN c.status_code = {STATUS_RELAXED_AMBIG} THEN 1 ELSE 0 END)
                ::BIGINT AS relaxed_ambiguous,
            SUM(
                CASE
                    WHEN c.status_code IN (
                        {STATUS_UNMATCHED},
                        {STATUS_PID_AMBIG},
                        {STATUS_STRICT_AMBIG},
                        {STATUS_RELAXED_AMBIG}
                    )
                    THEN 1 ELSE 0
                END
            )::BIGINT AS final_unmatched
        FROM flow_inventory f
        JOIN cascade_result c ON c.flow_id = f.flow_id
        GROUP BY 1, 2
        """
    )

    # linked_flows as a VIEW over narrow cascade_result + inventories.
    connection.execute(
        f"""
        CREATE TEMP VIEW linked_flows AS
        SELECT
            f.period_role,
            f.window_start,
            f.event_time,
            f.host_id,
            f.date_label,
            f.event_locator,
            CASE
                WHEN c.status_code = {STATUS_DIRECT}
                THEN _eda08_process_display(f.process_raw)
                ELSE p.process_name
            END AS process_name,
            f.destination_value,
            _eda08_destination_category(f.destination_value) AS destination_category,
            f.port,
            f.protocol,
            CASE c.status_code
                WHEN {STATUS_DIRECT} THEN 'direct_same_event'
                WHEN {STATUS_PID_MATCH} THEN 'host_process_pid'
                WHEN {STATUS_STRICT_MATCH} THEN 'host_temporal_strict'
                WHEN {STATUS_RELAXED_MATCH} THEN 'host_temporal_relaxed'
            END AS pivot_rule,
            f.raw_event_id,
            f.archive_name,
            f.member_name,
            f.line_number
        FROM cascade_result c
        JOIN flow_inventory f ON f.flow_id = c.flow_id
        LEFT JOIN process_inventory p
          ON p.event_locator = c.chosen_process_locator
        WHERE c.status_code IN (
            {STATUS_DIRECT},
            {STATUS_PID_MATCH},
            {STATUS_STRICT_MATCH},
            {STATUS_RELAXED_MATCH}
        )
          AND NOT f.missing_destination
          AND COALESCE(
                CASE
                    WHEN c.status_code = {STATUS_DIRECT}
                    THEN _eda08_process_display(f.process_raw)
                    ELSE p.process_name
                END,
                ''
            ) <> ''
        """
    )

    def _count_status(code: int) -> int:
        return int(
            connection.execute(
                f"""
                SELECT COUNT(*)::BIGINT
                FROM cascade_result
                WHERE status_code = {code}
                """
            ).fetchone()[0]
        )

    direct_count = _count_status(STATUS_DIRECT)
    pid_matched = _count_status(STATUS_PID_MATCH)
    pid_ambiguous = _count_status(STATUS_PID_AMBIG)
    strict_matched = _count_status(STATUS_STRICT_MATCH)
    strict_ambiguous = _count_status(STATUS_STRICT_AMBIG)
    relaxed_matched = _count_status(STATUS_RELAXED_MATCH)
    relaxed_ambiguous = _count_status(STATUS_RELAXED_AMBIG)
    unmatched_plain = _count_status(STATUS_UNMATCHED)
    final_unmatched = (
        unmatched_plain + pid_ambiguous + strict_ambiguous + relaxed_ambiguous
    )
    flow_total = int(
        connection.execute("SELECT COUNT(*)::BIGINT FROM flow_inventory").fetchone()[0]
    )
    reconciled = (
        direct_count
        + pid_matched
        + pid_ambiguous
        + strict_matched
        + strict_ambiguous
        + relaxed_matched
        + relaxed_ambiguous
        + unmatched_plain
    )
    if reconciled != flow_total:
        raise CacheAuditError(
            "Cascade reconciliation failed: "
            f"parts={reconciled} flow_total={flow_total}"
        )

    linked_by_rule = {
        "direct_same_event": direct_count,
        "host_process_pid": pid_matched,
        "host_temporal_strict": strict_matched,
        "host_temporal_relaxed": relaxed_matched,
    }
    ambiguous_by_rule = {
        "host_process_pid": pid_ambiguous,
        "host_temporal_strict": strict_ambiguous,
        "host_temporal_relaxed": relaxed_ambiguous,
    }
    return {
        "flow_total": flow_total,
        "process_total": int(
            connection.execute(
                "SELECT COUNT(*)::BIGINT FROM process_inventory"
            ).fetchone()[0]
        ),
        "missing_host_count": int(
            connection.execute(
                "SELECT COUNT(*)::BIGINT FROM flow_inventory WHERE missing_host"
            ).fetchone()[0]
        ),
        "missing_destination_count": int(
            connection.execute(
                """
                SELECT COUNT(*)::BIGINT
                FROM flow_inventory
                WHERE missing_destination
                """
            ).fetchone()[0]
        ),
        "direct_count": direct_count,
        "pid_matched": pid_matched,
        "pid_ambiguous": pid_ambiguous,
        "strict_matched": strict_matched,
        "strict_ambiguous": strict_ambiguous,
        "relaxed_matched": relaxed_matched,
        "relaxed_ambiguous": relaxed_ambiguous,
        "unmatched_plain": unmatched_plain,
        "linked_by_rule": {k: v for k, v in linked_by_rule.items() if v},
        "unmatched_count": final_unmatched,
        "ambiguous_by_rule": {k: v for k, v in ambiguous_by_rule.items() if v},
        "ambiguous_unique_flow_count": pid_ambiguous
        + strict_ambiguous
        + relaxed_ambiguous,
        "pid_ambiguous_mappings": int(
            connection.execute(
                "SELECT COUNT(*)::BIGINT FROM host_pid_ambiguity"
            ).fetchone()[0]
        ),
        "linked_flow_count": int(
            connection.execute(
                "SELECT COUNT(*)::BIGINT FROM linked_flows"
            ).fetchone()[0]
        ),
    }




def build_t16(connection) -> Any:
    rule_values = ", ".join(f"('{rule_id}')" for rule_id in PIVOT_RULE_IDS)
    frame = _query_frame(
        connection,
        f"""
        WITH stage_metrics AS (
            SELECT
                date_label,
                host_id,
                'direct_same_event' AS pivot_rule,
                enters_direct AS endpoint_flow_events,
                direct_matched AS matched_network_events,
                0::BIGINT AS ambiguous_match_count
            FROM t16_stage_counts
            UNION ALL
            SELECT
                date_label,
                host_id,
                'host_process_pid',
                enters_pid,
                pid_matched,
                pid_ambiguous
            FROM t16_stage_counts
            UNION ALL
            SELECT
                date_label,
                host_id,
                'host_temporal_strict',
                enters_strict,
                strict_matched,
                strict_ambiguous
            FROM t16_stage_counts
            UNION ALL
            SELECT
                date_label,
                host_id,
                'host_temporal_relaxed',
                enters_relaxed,
                relaxed_matched,
                relaxed_ambiguous
            FROM t16_stage_counts
            UNION ALL
            SELECT
                date_label,
                host_id,
                'unmatched',
                final_unmatched,
                0::BIGINT,
                0::BIGINT
            FROM t16_stage_counts
        ),
        rule_dims AS (
            SELECT pivot_rule
            FROM (VALUES {rule_values}) AS rules(pivot_rule)
        ),
        host_dims AS (
            SELECT DISTINCT date_label, host_id
            FROM t16_stage_counts
        ),
        full_dims AS (
            SELECT h.date_label, h.host_id, r.pivot_rule
            FROM host_dims h
            CROSS JOIN rule_dims r
        )
        SELECT
            fd.date_label,
            fd.host_id,
            fd.pivot_rule,
            COALESCE(sm.endpoint_flow_events, 0)::BIGINT AS endpoint_flow_events,
            COALESCE(sm.matched_network_events, 0)::BIGINT AS matched_network_events,
            CASE
                WHEN fd.pivot_rule = 'unmatched' THEN 0.0
                WHEN COALESCE(sm.endpoint_flow_events, 0) = 0 THEN 0.0
                ELSE ROUND(
                    COALESCE(sm.matched_network_events, 0) * 100.0
                    / sm.endpoint_flow_events,
                    6
                )
            END AS match_rate_percent,
            CASE
                WHEN fd.pivot_rule = 'unmatched'
                THEN COALESCE(sm.endpoint_flow_events, 0)::BIGINT
                ELSE (
                    COALESCE(sm.endpoint_flow_events, 0)
                    - COALESCE(sm.matched_network_events, 0)
                    - COALESCE(sm.ambiguous_match_count, 0)
                )::BIGINT
            END AS unmatched_count,
            CASE fd.pivot_rule
                WHEN 'direct_same_event' THEN '{PIVOT_RULE_TOLERANCE["direct_same_event"]}'
                WHEN 'host_process_pid' THEN '{PIVOT_RULE_TOLERANCE["host_process_pid"]}'
                WHEN 'host_temporal_strict' THEN '{PIVOT_RULE_TOLERANCE["host_temporal_strict"]}'
                WHEN 'host_temporal_relaxed' THEN '{PIVOT_RULE_TOLERANCE["host_temporal_relaxed"]}'
                ELSE '{PIVOT_RULE_TOLERANCE["unmatched"]}'
            END AS time_tolerance,
            CASE fd.pivot_rule
                WHEN 'direct_same_event' THEN '{PIVOT_RULE_NOTES["direct_same_event"]}'
                WHEN 'host_process_pid' THEN '{PIVOT_RULE_NOTES["host_process_pid"]}'
                WHEN 'host_temporal_strict' THEN '{PIVOT_RULE_NOTES["host_temporal_strict"]}'
                WHEN 'host_temporal_relaxed' THEN '{PIVOT_RULE_NOTES["host_temporal_relaxed"]}'
                ELSE '{PIVOT_RULE_NOTES["unmatched"]}'
            END AS false_link_risk_note,
            COALESCE(sm.ambiguous_match_count, 0)::BIGINT AS ambiguous_match_count,
            CASE
                WHEN COALESCE(sm.endpoint_flow_events, 0) = 0 THEN 0.0
                ELSE ROUND(
                    COALESCE(sm.ambiguous_match_count, 0) * 100.0
                    / sm.endpoint_flow_events,
                    6
                )
            END AS ambiguity_rate_percent
        FROM full_dims fd
        LEFT JOIN stage_metrics sm
          ON sm.date_label = fd.date_label
         AND sm.host_id = fd.host_id
         AND sm.pivot_rule = fd.pivot_rule
        ORDER BY fd.date_label, fd.host_id, fd.pivot_rule
        """,
    )
    return frame[T16_COLUMNS]



T17_ALLOWED_CATEGORIES = (
    "loopback",
    "internal-looking",
    "external-looking",
    "multicast_or_broadcast",
    "missing",
    "invalid_or_unresolved",
)


def build_t17(
    connection,
    evidence_cap: int,
    *,
    on_behavior_aggregate: Optional[Any] = None,
    on_bounded_evidence: Optional[Any] = None,
) -> dict[str, Any]:
    cap = int(evidence_cap)
    connection.execute(
        f"""
        CREATE TEMP TABLE t17_behavior_aggregate AS
        SELECT
            period_role,
            host_id,
            process_name,
            destination_value,
            destination_category,
            port,
            protocol,
            COUNT(*)::BIGINT AS connection_count,
            MIN(event_time) AS first_seen_time,
            arg_min(
                struct_pack(
                    raw_event_id := raw_event_id,
                    event_locator := event_locator
                ),
                event_locator,
                {cap}
            ) FILTER (WHERE COALESCE(raw_event_id, '') <> '')
                AS bounded_evidence_candidates
        FROM linked_flows
        GROUP BY 1, 2, 3, 4, 5, 6, 7
        """
    )
    if on_behavior_aggregate is not None:
        on_behavior_aggregate()
    connection.execute(
        """
        CREATE TEMP TABLE t17_benign_behavior_keys AS
        SELECT DISTINCT host_id, process_name, destination_value, port
        FROM t17_behavior_aggregate
        WHERE period_role = 'verified_benign'
        """
    )
    connection.execute(
        f"""
        CREATE TEMP TABLE t17_bounded_evidence AS
        WITH unnested AS (
            SELECT
                ba.period_role,
                ba.host_id,
                ba.process_name,
                ba.destination_value,
                ba.destination_category,
                ba.port,
                ba.protocol,
                elem.raw_event_id AS raw_event_id,
                elem.event_locator AS event_locator
            FROM t17_behavior_aggregate ba,
            LATERAL UNNEST(ba.bounded_evidence_candidates) AS u(elem)
            WHERE COALESCE(elem.raw_event_id, '') <> ''
        ),
        deduped AS (
            SELECT
                period_role,
                host_id,
                process_name,
                destination_value,
                destination_category,
                port,
                protocol,
                raw_event_id,
                MIN(event_locator) AS earliest_event_locator
            FROM unnested
            GROUP BY 1, 2, 3, 4, 5, 6, 7, 8
        ),
        ranked AS (
            SELECT
                *,
                ROW_NUMBER() OVER (
                    PARTITION BY
                        period_role,
                        host_id,
                        process_name,
                        destination_value,
                        destination_category,
                        port,
                        protocol
                    ORDER BY earliest_event_locator, raw_event_id
                ) AS evidence_rank
            FROM deduped
        )
        SELECT
            period_role,
            host_id,
            process_name,
            destination_value,
            destination_category,
            port,
            protocol,
            raw_event_id,
            earliest_event_locator
        FROM ranked
        WHERE evidence_rank <= {cap}
        """
    )
    if on_bounded_evidence is not None:
        on_bounded_evidence()
    connection.execute(
        """
        CREATE TEMP TABLE t17_evidence_lists AS
        SELECT
            period_role,
            host_id,
            process_name,
            destination_value,
            destination_category,
            port,
            protocol,
            to_json(
                list(raw_event_id ORDER BY earliest_event_locator, raw_event_id)
            ) AS raw_event_ids
        FROM t17_bounded_evidence
        GROUP BY 1, 2, 3, 4, 5, 6, 7
        """
    )
    connection.execute(
        """
        CREATE TEMP TABLE t17_final AS
        SELECT
            ba.period_role AS period,
            ba.host_id,
            ba.process_name,
            ba.destination_value,
            ba.destination_category,
            ba.port,
            ba.protocol,
            ba.connection_count,
            ba.first_seen_time,
            CASE WHEN b.host_id IS NOT NULL THEN 'yes' ELSE 'no' END
                AS benign_seen_before_yes_no,
            COALESCE(el.raw_event_ids, '[]') AS raw_event_ids
        FROM t17_behavior_aggregate ba
        LEFT JOIN t17_benign_behavior_keys b
          ON b.host_id = ba.host_id
         AND b.process_name = ba.process_name
         AND b.destination_value = ba.destination_value
         AND b.port = ba.port
        LEFT JOIN t17_evidence_lists el
          ON el.period_role = ba.period_role
         AND el.host_id = ba.host_id
         AND el.process_name = ba.process_name
         AND el.destination_value = ba.destination_value
         AND el.destination_category = ba.destination_category
         AND el.port = ba.port
         AND el.protocol = ba.protocol
        """
    )
    return validate_t17_in_duckdb(connection, cap)


def validate_t17_in_duckdb(connection, evidence_cap: int) -> dict[str, Any]:
    cap = int(evidence_cap)
    columns = [
        str(row[0])
        for row in connection.execute("DESCRIBE t17_final").fetchall()
    ]
    if columns != T17_COLUMNS:
        raise CacheAuditError("T17 schema mismatch")
    row_count = int(connection.execute("SELECT COUNT(*) FROM t17_final").fetchone()[0])
    if row_count > 0:
        invalid_counts = int(
            connection.execute(
                "SELECT COUNT(*) FROM t17_final WHERE connection_count <= 0"
            ).fetchone()[0]
        )
        if invalid_counts:
            raise CacheAuditError("T17 connection_count must be > 0")
        null_first_seen = int(
            connection.execute(
                "SELECT COUNT(*) FROM t17_final WHERE first_seen_time IS NULL"
            ).fetchone()[0]
        )
        if null_first_seen:
            raise CacheAuditError("T17 first_seen_time must be nonnull")
        invalid_benign = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM t17_final
                WHERE benign_seen_before_yes_no NOT IN ('yes', 'no')
                """
            ).fetchone()[0]
        )
        if invalid_benign:
            raise CacheAuditError(
                "T17 benign_seen_before_yes_no must contain only yes/no"
            )
        allowed = ", ".join(f"'{value}'" for value in T17_ALLOWED_CATEGORIES)
        invalid_categories = int(
            connection.execute(
                f"""
                SELECT COUNT(*) FROM t17_final
                WHERE destination_category NOT IN ({allowed})
                """
            ).fetchone()[0]
        )
        if invalid_categories:
            raise CacheAuditError("T17 destination_category contains invalid values")
        invalid_json = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM t17_final
                WHERE NOT json_valid(raw_event_ids)
                """
            ).fetchone()[0]
        )
        if invalid_json:
            raise CacheAuditError("T17 raw_event_ids must be valid JSON arrays")
        over_cap = int(
            connection.execute(
                f"""
                SELECT COUNT(*) FROM t17_final
                WHERE json_array_length(raw_event_ids::JSON) > {cap}
                """
            ).fetchone()[0]
        )
        if over_cap:
            raise CacheAuditError(
                f"T17 evidence arrays must contain at most {cap} IDs"
            )
        empty_ids = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM (
                    SELECT UNNEST(
                        from_json(raw_event_ids, '["VARCHAR"]')
                    ) AS event_id
                    FROM t17_final
                )
                WHERE COALESCE(event_id, '') = ''
                """
            ).fetchone()[0]
        )
        if empty_ids:
            raise CacheAuditError("T17 evidence arrays must not contain empty IDs")
    max_evidence = int(
        connection.execute(
            """
            SELECT COALESCE(MAX(json_array_length(raw_event_ids::JSON)), 0)
            FROM t17_final
            """
        ).fetchone()[0]
    )
    missing_evidence = int(
        connection.execute(
            """
            SELECT COUNT(*) FROM t17_final
            WHERE COALESCE(raw_event_ids, '[]') = '[]'
            """
        ).fetchone()[0]
    )
    return {
        "t17_row_count": row_count,
        "t17_evidence_max_count": max_evidence,
        "t17_missing_evidence_row_count": missing_evidence,
    }


def _export_t17_csv(connection, path: pathlib.Path) -> None:
    temp = path.with_suffix(path.suffix + f".{uuid.uuid4().hex}.tmp")
    escaped = str(temp).replace("'", "''")
    columns = ", ".join(T17_COLUMNS)
    connection.execute(
        f"""
        COPY (
            SELECT {columns}
            FROM t17_final
            ORDER BY
                period,
                host_id,
                process_name,
                destination_value,
                port,
                protocol,
                first_seen_time
        ) TO '{escaped}'
        (HEADER, FORMAT CSV)
        """
    )
    os.replace(temp, path)


def build_f9_data(connection) -> Any:
    frame = _query_frame(
        connection,
        """
        WITH eligible_flows AS (
            SELECT
                period_role,
                host_id,
                window_start,
                destination_value,
                event_time,
                event_locator
            FROM flow_inventory
            WHERE NOT missing_host
              AND NOT missing_destination
        ),
        benign_dest_keys AS (
            SELECT DISTINCT host_id, destination_value
            FROM eligible_flows
            WHERE period_role = 'verified_benign'
        ),
        dest_first_seen AS (
            SELECT
                host_id,
                destination_value,
                MIN(event_time) AS first_seen_time
            FROM eligible_flows
            GROUP BY 1, 2
        ),
        eval_host_minutes AS (
            SELECT DISTINCT host_id, window_start
            FROM eligible_flows
            WHERE period_role = 'evaluation'
        ),
        eval_flows AS (
            SELECT *
            FROM eligible_flows
            WHERE period_role = 'evaluation'
        ),
        window_novel AS (
            SELECT
                ef.host_id,
                ef.window_start,
                COUNT(
                    DISTINCT CASE
                        WHEN NOT EXISTS (
                            SELECT 1
                            FROM benign_dest_keys b
                            WHERE b.host_id = ef.host_id
                              AND b.destination_value = ef.destination_value
                        )
                        AND dfs.first_seen_time = ef.event_time
                        THEN ef.destination_value
                    END
                )::BIGINT AS novel_destination_count,
                COUNT(*)::BIGINT AS flow_count
            FROM eval_flows ef
            JOIN dest_first_seen dfs
              ON dfs.host_id = ef.host_id
             AND dfs.destination_value = ef.destination_value
            GROUP BY 1, 2
        )
        SELECT
            ehm.host_id,
            ehm.window_start,
            COALESCE(wn.novel_destination_count, 0)::BIGINT AS novel_destination_count,
            COALESCE(wn.flow_count, 0)::BIGINT AS flow_count,
            CASE
                WHEN COALESCE(wn.flow_count, 0) = 0 THEN 0.0
                ELSE ROUND(
                    COALESCE(wn.novel_destination_count, 0) * 1.0
                    / wn.flow_count,
                    6
                )
            END AS novel_destination_ratio
        FROM eval_host_minutes ehm
        LEFT JOIN window_novel wn
          ON wn.host_id = ehm.host_id
         AND wn.window_start = ehm.window_start
        ORDER BY ehm.host_id, ehm.window_start
        """,
    )
    return frame


def build_f10_data(connection) -> Any:
    frame = _query_frame(
        connection,
        """
        WITH benign_proc_keys AS (
            SELECT DISTINCT host_id, process_name
            FROM process_inventory
            WHERE period_role = 'verified_benign'
              AND process_name <> ''
        ),
        benign_dest_keys AS (
            SELECT DISTINCT host_id, destination_value
            FROM flow_inventory
            WHERE period_role = 'verified_benign'
              AND NOT missing_host
              AND NOT missing_destination
        ),
        eligible_flows AS (
            SELECT
                host_id,
                destination_value,
                event_time,
                period_role
            FROM flow_inventory
            WHERE NOT missing_host
              AND NOT missing_destination
        ),
        novel_process_events AS (
            SELECT
                pi.host_id,
                pi.window_start,
                pi.event_time
            FROM process_inventory pi
            LEFT JOIN benign_proc_keys b
              ON b.host_id = pi.host_id
             AND b.process_name = pi.process_name
            WHERE pi.period_role = 'evaluation'
              AND pi.process_name <> ''
              AND b.host_id IS NULL
        ),
        process_novelty_windows AS (
            SELECT
                host_id,
                window_start AS process_novelty_window,
                MIN(event_time) AS process_novelty_time
            FROM novel_process_events
            GROUP BY 1, 2
        ),
        dest_novelty_events AS (
            SELECT
                ef.host_id,
                ef.destination_value,
                MIN(ef.event_time) AS event_time
            FROM eligible_flows ef
            LEFT JOIN benign_dest_keys b
              ON b.host_id = ef.host_id
             AND b.destination_value = ef.destination_value
            WHERE ef.period_role = 'evaluation'
              AND b.host_id IS NULL
            GROUP BY 1, 2
        ),
        flagged AS (
            SELECT
                pn.host_id,
                pn.process_novelty_window,
                MAX(
                    CASE
                        WHEN dne.event_time >= pn.process_novelty_time
                         AND dne.event_time <= pn.process_novelty_time
                             + INTERVAL '5 minutes'
                        THEN 1 ELSE 0
                    END
                ) AS followed_5,
                MAX(
                    CASE
                        WHEN dne.event_time >= pn.process_novelty_time
                         AND dne.event_time <= pn.process_novelty_time
                             + INTERVAL '15 minutes'
                        THEN 1 ELSE 0
                    END
                ) AS followed_15,
                MAX(
                    CASE
                        WHEN dne.event_time >= pn.process_novelty_time
                         AND dne.event_time <= pn.process_novelty_time
                             + INTERVAL '60 minutes'
                        THEN 1 ELSE 0
                    END
                ) AS followed_60
            FROM process_novelty_windows pn
            LEFT JOIN dest_novelty_events dne
              ON dne.host_id = pn.host_id
             AND dne.event_time >= pn.process_novelty_time
             AND dne.event_time <= pn.process_novelty_time + INTERVAL '60 minutes'
            GROUP BY 1, 2
        )
        SELECT lag_minutes, process_novelty_windows_followed_by_destination_novelty
        FROM (
            SELECT 5 AS lag_minutes,
                   COALESCE(SUM(followed_5), 0)::BIGINT
                       AS process_novelty_windows_followed_by_destination_novelty
            FROM flagged
            UNION ALL
            SELECT 15,
                   COALESCE(SUM(followed_15), 0)::BIGINT
            FROM flagged
            UNION ALL
            SELECT 60,
                   COALESCE(SUM(followed_60), 0)::BIGINT
            FROM flagged
        ) counts
        ORDER BY lag_minutes
        """,
    )
    return frame



def create_f9(
    frame,
    *,
    png_path: pathlib.Path,
    pdf_path: pathlib.Path,
    host_labels: Optional[dict[str, str]] = None,
) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import pandas as pd

    labels = host_labels or {}
    data = (
        frame.copy()
        if frame is not None and not frame.empty
        else pd.DataFrame(
            columns=[
                "host_id",
                "window_start",
                "novel_destination_count",
                "flow_count",
                "novel_destination_ratio",
            ]
        )
    )
    if not data.empty:
        data["window_start"] = pd.to_datetime(data["window_start"])
    hosts = sorted(data["host_id"].astype(str).unique()) if not data.empty else []
    panel_count = max(1, len(hosts))
    columns = 2
    rows = math.ceil(panel_count / columns)
    figure, axes = plt.subplots(
        rows,
        columns,
        figsize=(14, max(4, 3.2 * rows)),
        sharex=True,
        constrained_layout=True,
    )
    flat_axes = list(getattr(axes, "flat", [axes]))
    for index, axis in enumerate(flat_axes):
        if index >= len(hosts):
            axis.set_visible(False)
            continue
        host_id = hosts[index]
        host_data = data.loc[data["host_id"] == host_id].sort_values("window_start")
        axis.plot(
            host_data["window_start"],
            host_data["novel_destination_count"],
            color=F9_COLOR,
            marker=".",
            linewidth=0.8,
            label="Novel destination count",
        )
        axis.set_title(labels.get(host_id) or host_id)
        axis.grid(alpha=0.25)
        axis.set_ylabel("Novel destinations")
        axis.set_xlabel("Evaluation window start (UTC)")
        axis.legend(loc="best", fontsize=8)
    figure.suptitle(
        "F9 Destination Novelty Over Time — 1-Minute Windows\n"
        "Verified-benign frozen novelty; ground-truth intervals not overlaid\n"
        "(EDA 10 pending)"
    )
    figure.savefig(png_path, dpi=180, bbox_inches="tight")
    figure.savefig(pdf_path, bbox_inches="tight")
    plt.close(figure)


def create_f10(
    frame,
    *,
    png_path: pathlib.Path,
    pdf_path: pathlib.Path,
) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import pandas as pd

    data = (
        frame.copy()
        if frame is not None and not frame.empty
        else pd.DataFrame(
            columns=["lag_minutes", F10_VALUE_COLUMN]
        )
    )
    figure, axis = plt.subplots(figsize=(8, 4.5), constrained_layout=True)
    if not data.empty:
        axis.bar(
            data["lag_minutes"].astype(str),
            data[F10_VALUE_COLUMN],
            color=list(F10_COLORS),
        )
    axis.set_xlabel("Lag window (minutes)")
    axis.set_ylabel("Process-novelty windows followed by destination novelty")
    axis.set_title(
        "F10 Process-to-Network Lag — 1-Minute Process-Novelty Windows\n"
        "Cumulative 5/15/60-minute lags; ground-truth intervals not overlaid\n"
        "(EDA 10 pending)"
    )
    axis.grid(alpha=0.25, axis="y")
    figure.savefig(png_path, dpi=180, bbox_inches="tight")
    figure.savefig(pdf_path, bbox_inches="tight")
    plt.close(figure)


def validate_outputs(t16, t17_summary: Optional[dict[str, Any]], f10_data) -> None:
    if list(t16.columns) != T16_COLUMNS:
        raise CacheAuditError("T16 schema mismatch")
    if t17_summary is not None:
        required = {
            "t17_row_count",
            "t17_evidence_max_count",
            "t17_missing_evidence_row_count",
        }
        if not required.issubset(t17_summary):
            raise CacheAuditError("T17 summary object is incomplete")
    if not t16.empty:
        if t16["date_label"].isna().any() or t16["host_id"].isna().any():
            raise CacheAuditError("T16 requires date_label and host_id")
        if not set(t16["pivot_rule"]).issubset(set(PIVOT_RULE_IDS)):
            raise CacheAuditError("T16 contains unknown pivot_rule values")
        arithmetic = (
            t16["matched_network_events"]
            + t16["ambiguous_match_count"]
            + t16["unmatched_count"]
        )
        if not (arithmetic == t16["endpoint_flow_events"]).all():
            raise CacheAuditError("T16 row arithmetic reconciliation failed")
        unmatched_rows = t16.loc[t16["pivot_rule"] == "unmatched"]
        if not unmatched_rows.empty:
            if (unmatched_rows["matched_network_events"] != 0).any():
                raise CacheAuditError("T16 unmatched rows must have zero matches")
            if (unmatched_rows["ambiguous_match_count"] != 0).any():
                raise CacheAuditError("T16 unmatched rows must have zero ambiguity")
            if (unmatched_rows["match_rate_percent"] != 0).any():
                raise CacheAuditError("T16 unmatched rows must have zero match rate")
    if f10_data is not None and not f10_data.empty:
        counts = list(f10_data[F10_VALUE_COLUMN])
        if counts != sorted(counts):
            raise CacheAuditError("F10 cumulative counts must be non-decreasing")


def _atomic_write_csv(frame, path: pathlib.Path) -> None:
    import pandas as pd

    temp = path.with_suffix(path.suffix + f".{uuid.uuid4().hex}.tmp")
    frame.to_csv(temp, index=False)
    os.replace(temp, path)


def _atomic_write_text(text: str, path: pathlib.Path) -> None:
    temp = path.with_suffix(path.suffix + f".{uuid.uuid4().hex}.tmp")
    temp.write_text(text, encoding="utf-8")
    os.replace(temp, path)


def _atomic_write_json(payload: dict, path: pathlib.Path) -> None:
    _atomic_write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", path
    )


def _assert_no_temp_files(directory: pathlib.Path) -> None:
    for path in directory.rglob("*"):
        if path.is_file() and (
            path.name.endswith(".tmp") or ".tmp." in path.name
        ):
            raise CacheAuditError(f"Temporary file left in staging: {path}")


def _publish_staging(staging: pathlib.Path, output_dir: pathlib.Path) -> None:
    parent = output_dir.parent
    parent.mkdir(parents=True, exist_ok=True)
    if output_dir.exists():
        raise CacheAuditError(f"Refusing to overwrite existing output: {output_dir}")
    os.replace(staging, output_dir)


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


def _host_label_map(connection) -> dict[str, str]:
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


def _readme(metadata: dict[str, Any]) -> str:
    return "\n".join(
        [
            "EDA 8 — Endpoint-Network Pivot Analysis",
            "=======================================",
            "",
            "Pivot quality is measured before interpreting FLOW behavior.",
            "Destination and port novelty vocabularies are fitted only on",
            "verified_benign intervals. Evaluation rows are scored against",
            "those frozen structures and never update them.",
            "",
            "This is baseline-relative novelty, not maliciousness, attacks,",
            "or ground-truth labels. Ground-truth alignment remains EDA 10.",
            "",
            f"Schema version: {metadata.get('schema_version')}",
            f"Window size: {metadata.get('window_size')}",
            f"Pivot rule version: {metadata.get('pivot_rule_version')}",
            f"Destination category version: {metadata.get('destination_category_version')}",
            f"FLOW payload scans: {metadata.get('payload_flow_scan_count')}",
            f"PROCESS payload scans: {metadata.get('payload_process_scan_count')}",
            f"Cache reconciliation scans: {metadata.get('cache_reconciliation_scan_count')}",
            f"FLOW events scanned: {metadata.get('flow_event_count')}",
            f"FLOW rows with missing host: {metadata.get('missing_host_count')}",
            f"FLOW rows with missing destination: {metadata.get('missing_destination_count')}",
            f"Linked FLOW rows: {metadata.get('linked_flow_count')}",
            f"Unmatched FLOW rows: {metadata.get('unmatched_count')}",
            f"T16 rows: {metadata.get('t16_row_count')}",
            f"T17 rows: {metadata.get('t17_row_count')}",
            f"F9 evaluation host-minutes: {metadata.get('f9_host_minute_count')}",
            "",
            f"T16 count semantics: {metadata.get('count_semantics')}",
            "",
            "Pivot rules (T16):",
            "  1. direct_same_event",
            "  2. host_process_pid (unique host+PID identity only)",
            "  3. host_temporal_strict",
            "  4. host_temporal_relaxed",
            "  5. unmatched",
            "",
            "Temporal rules require a unique candidate; ambiguous matches are",
            "counted but not accepted as successful pivots.",
            "",
            f"Generated UTC: {metadata.get('generated_utc')}",
            "",
        ]
    )


def run_eda08(args: argparse.Namespace) -> dict[str, Any]:
    started = time.perf_counter()
    config = validate_run_config(args)
    connection = None
    spill_path = None
    spill_owned = False
    staging: Optional[pathlib.Path] = None
    execution_log: list[str] = []
    cascade_probe_only = bool(getattr(args, "cascade_probe_only", False))
    t17_probe_only = bool(getattr(args, "t17_probe_only", False))

    def stage(number: int, message: str) -> None:
        line = f"[STAGE {number}/7] {message}"
        execution_log.append(line)
        print(line, flush=True)

    def substage(label: str, message: str) -> None:
        line = f"[STAGE {label}/7] {message}"
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
        stage(2, "registered read-only cache, T9 identities, and periods")

        _create_cache_period_counts(connection)
        _create_flow_inventory(connection)
        _create_process_inventory(connection)
        cascade_stats = _build_pivot_cascade(connection)
        period_stats = _validate_flow_period_counts(
            connection, int(config["cache_metadata"]["total_events_written"])
        )
        stage(
            3,
            "payload scans complete "
            f"(FLOW={PAYLOAD_FLOW_SCAN_COUNT}, "
            f"PROCESS={PAYLOAD_PROCESS_SCAN_COUNT}, "
            f"reconciliation={CACHE_RECONCILIATION_SCAN_COUNT})",
        )

        if cascade_probe_only:
            elapsed = time.perf_counter() - started
            peak_rss = _peak_rss_bytes()
            print("EDA 8 cascade probe reconciliation:", flush=True)
            print(f"  flow_count={cascade_stats['flow_total']}", flush=True)
            print(f"  process_count={cascade_stats['process_total']}", flush=True)
            print(f"  direct_count={cascade_stats['direct_count']}", flush=True)
            print(
                f"  pid_matched={cascade_stats['pid_matched']} "
                f"pid_ambiguous={cascade_stats['pid_ambiguous']}",
                flush=True,
            )
            print(
                f"  strict_matched={cascade_stats['strict_matched']} "
                f"strict_ambiguous={cascade_stats['strict_ambiguous']}",
                flush=True,
            )
            print(
                f"  relaxed_matched={cascade_stats['relaxed_matched']} "
                f"relaxed_ambiguous={cascade_stats['relaxed_ambiguous']}",
                flush=True,
            )
            print(
                f"  final_unmatched={cascade_stats['unmatched_count']}",
                flush=True,
            )
            print(f"  elapsed_seconds={elapsed:.3f}", flush=True)
            if peak_rss is not None:
                print(f"  peak_rss_bytes={peak_rss}", flush=True)
            return {
                "cascade_probe_only": True,
                "runtime_seconds": round(elapsed, 3),
                "peak_rss_bytes": peak_rss,
                **cascade_stats,
                **period_stats,
                "t16_row_count": 0,
                "t17_row_count": 0,
                "linked_flow_count": cascade_stats["linked_flow_count"],
            }

        t16 = build_t16(connection)
        substage("4A", "T16 constructed")
        t17_summary = build_t17(
            connection,
            config["evidence_cap"],
            on_behavior_aggregate=lambda: substage(
                "4B", "T17 behavior aggregation complete"
            ),
            on_bounded_evidence=lambda: substage(
                "4C", "T17 bounded evidence complete"
            ),
        )

        if t17_probe_only:
            elapsed = time.perf_counter() - started
            peak_rss = _peak_rss_bytes()
            print("EDA 8 T17 probe reconciliation:", flush=True)
            print(f"  t16_row_count={int(len(t16))}", flush=True)
            print(f"  t17_row_count={t17_summary['t17_row_count']}", flush=True)
            print(
                "  t17_evidence_max_count="
                f"{t17_summary['t17_evidence_max_count']}",
                flush=True,
            )
            print(
                f"  linked_flow_count={cascade_stats['linked_flow_count']}",
                flush=True,
            )
            print(f"  elapsed_seconds={elapsed:.3f}", flush=True)
            if peak_rss is not None:
                print(f"  peak_rss_bytes={peak_rss}", flush=True)
            return {
                "t17_probe_only": True,
                "runtime_seconds": round(elapsed, 3),
                "peak_rss_bytes": peak_rss,
                "t16_row_count": int(len(t16)),
                **t17_summary,
                **cascade_stats,
                **period_stats,
            }

        f9_data = build_f9_data(connection)
        substage("4D", "F9 data constructed")
        f10_data = build_f10_data(connection)
        substage("4E", "F10 data constructed")
        validate_outputs(t16, t17_summary, f10_data)
        substage("4F", "post-cascade outputs validated")
        stage(4, "T16/T17 and F9/F10 data constructed and validated")

        host_labels = _host_label_map(connection)
        parent = eda5._nearest_existing_directory(config["output_dir"].parent)
        staging = pathlib.Path(
            tempfile.mkdtemp(prefix=".eda08_staging_", dir=str(parent))
        )
        _atomic_write_csv(t16, staging / "T16_endpoint_network_pivot_success.csv")
        _export_t17_csv(connection, staging / "T17_process_to_destination_behavior.csv")
        create_f9(
            f9_data,
            png_path=staging / "F9_destination_novelty_over_time.png",
            pdf_path=staging / "F9_destination_novelty_over_time.pdf",
            host_labels=host_labels,
        )
        create_f10(
            f10_data,
            png_path=staging / "F10_process_to_network_lag.png",
            pdf_path=staging / "F10_process_to_network_lag.pdf",
        )
        stage(5, "F9/F10 figures written")

        generated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        runtime = time.perf_counter() - started
        deliverable_names = [
            "T16_endpoint_network_pivot_success.csv",
            "T17_process_to_destination_behavior.csv",
            "F9_destination_novelty_over_time.png",
            "F9_destination_novelty_over_time.pdf",
            "F10_process_to_network_lag.png",
            "F10_process_to_network_lag.pdf",
            "README.md",
        ]
        metadata = {
            "schema_version": SCHEMA_VERSION,
            "window_size": WINDOW_SIZE,
            "pivot_rule_version": PIVOT_RULE_VERSION,
            "destination_category_version": DESTINATION_CATEGORY_VERSION,
            "strict_tolerance_seconds": STRICT_TOLERANCE_SECONDS,
            "relaxed_tolerance_seconds": RELAXED_TOLERANCE_SECONDS,
            "lag_minutes": list(LAG_MINUTES),
            "payload_flow_scan_count": PAYLOAD_FLOW_SCAN_COUNT,
            "payload_process_scan_count": PAYLOAD_PROCESS_SCAN_COUNT,
            "cache_reconciliation_scan_count": CACHE_RECONCILIATION_SCAN_COUNT,
            "count_semantics": T16_COUNT_SEMANTICS,
            "flow_event_count": cascade_stats["flow_total"],
            "process_event_count": cascade_stats["process_total"],
            "missing_host_count": cascade_stats["missing_host_count"],
            "missing_destination_count": cascade_stats["missing_destination_count"],
            "cache_role_counts": period_stats["cache_role_counts"],
            "flow_role_counts": period_stats["flow_role_counts"],
            "unassigned_count": period_stats["unassigned_count"],
            "linked_by_rule": cascade_stats["linked_by_rule"],
            "unmatched_count": cascade_stats["unmatched_count"],
            "ambiguous_by_rule": cascade_stats["ambiguous_by_rule"],
            "ambiguous_unique_flow_count": cascade_stats[
                "ambiguous_unique_flow_count"
            ],
            "pid_ambiguous_mappings": cascade_stats["pid_ambiguous_mappings"],
            "linked_flow_count": cascade_stats["linked_flow_count"],
            "t16_row_count": int(len(t16)),
            "t17_row_count": int(t17_summary["t17_row_count"]),
            "t17_evidence_max_count": int(t17_summary["t17_evidence_max_count"]),
            "t17_missing_evidence_row_count": int(
                t17_summary["t17_missing_evidence_row_count"]
            ),
            "f9_host_minute_count": int(len(f9_data)),
            "f10_cumulative_counts": {
                str(int(row.lag_minutes)): int(
                    row.process_novelty_windows_followed_by_destination_novelty
                )
                for row in f10_data.itertuples(index=False)
            }
            if not f10_data.empty
            else {},
            "cache_events": int(config["cache_metadata"]["total_events_written"]),
            "manifest_version": config.get("manifest_version"),
            "period_map_path": str(config["period_map"]),
            "generated_utc": generated,
            "runtime_seconds": round(runtime, 3),
            "duckdb_memory_limit": config["memory_limit"],
            "duckdb_threads": config["threads"],
            "duckdb_temp_dir_policy": (
                "explicit" if args.duckdb_temp_dir else "owned_local_tempfile"
            ),
            "code_commit": _git_commit(config["project_root"]),
            "metadata_self_hash_policy": "excluded_self_reference",
        }
        _atomic_write_text(_readme(metadata), staging / "README.md")
        stage(
            6,
            "README, metadata, hashes, and complete execution log assembled",
        )
        stage(7, "staging validated and ready for atomic publication")
        final_log = "\n".join(execution_log) + "\n"
        _atomic_write_text(final_log, staging / "eda08_execution.log")
        metadata["deliverable_sha256"] = {
            name: _sha256_file(staging / name) for name in deliverable_names
        }
        metadata["deliverable_sha256"]["eda08_execution.log"] = _sha256_file(
            staging / "eda08_execution.log"
        )
        _atomic_write_json(metadata, staging / "eda08_run_metadata.json")
        _assert_no_temp_files(staging)
        _publish_staging(staging, config["output_dir"])
        staging = None
        print(
            f"EDA 8 published deliverables to {config['output_dir']}",
            flush=True,
        )
        return metadata
    except Exception:
        if staging is not None and staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        raise
    finally:
        if staging is not None and staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
        if spill_owned and spill_path:
            shutil.rmtree(spill_path, ignore_errors=True)



def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    try:
        metadata = run_eda08(args)
    except CacheAuditError as exc:
        print(f"EDA 8 failed: {exc}", file=sys.stderr)
        return 1
    if metadata.get("cascade_probe_only"):
        print("EDA 8 cascade probe complete", flush=True)
        return 0
    if metadata.get("t17_probe_only"):
        print("EDA 8 T17 probe complete", flush=True)
        return 0
    print(
        "EDA 8 complete: "
        f"T16={metadata['t16_row_count']}, "
        f"T17={metadata['t17_row_count']}, "
        f"linked_flows={metadata['linked_flow_count']}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
