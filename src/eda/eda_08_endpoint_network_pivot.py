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
PAYLOAD_SCAN_COUNT = 1
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
    "actor_id_raw",
    "object_id_raw",
    "pid_raw",
    "dest_ip_raw",
    "dest_port_raw",
    "destination_raw",
    "protocol_raw",
}

T16_COLUMNS = [
    "pivot_rule_id",
    "pivot_rule_description",
    "endpoint_flow_events",
    "matched_network_events",
    "unmatched_count",
    "match_rate_percent",
    "ambiguous_match_count",
    "ambiguity_rate_percent",
    "time_tolerance_seconds",
    "false_link_risk_note",
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

PIVOT_RULES = (
    {
        "pivot_rule_id": "direct_same_event",
        "pivot_rule_description": (
            "FLOW row carries non-empty process image/path on the same event"
        ),
        "time_tolerance_seconds": 0,
        "false_link_risk_note": (
            "Low when the FLOW record itself includes process attribution; "
            "still same-event association only."
        ),
    },
    {
        "pivot_rule_id": "host_process_pid",
        "pivot_rule_description": (
            "Same host plus exact non-empty pid_raw match to a PROCESS event"
        ),
        "time_tolerance_seconds": 0,
        "false_link_risk_note": (
            "Medium; PID reuse and cross-event timing are not proven causal."
        ),
    },
    {
        "pivot_rule_id": "host_temporal_strict",
        "pivot_rule_description": (
            "Same host plus unique PROCESS candidate within strict tolerance"
        ),
        "time_tolerance_seconds": STRICT_TOLERANCE_SECONDS,
        "false_link_risk_note": (
            "High unless candidate is unique; ambiguous matches are rejected."
        ),
    },
    {
        "pivot_rule_id": "host_temporal_relaxed",
        "pivot_rule_description": (
            "Same host plus unique PROCESS candidate within relaxed tolerance"
        ),
        "time_tolerance_seconds": RELAXED_TOLERANCE_SECONDS,
        "false_link_risk_note": (
            "Highest temporal false-link risk; only unique candidates accepted."
        ),
    },
)


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


def _create_network_scan(connection) -> None:
    """Single bounded payload scan for FLOW and PROCESS events."""
    connection.execute(
        f"""
        CREATE TEMP TABLE network_scan AS
        WITH projected AS (
            SELECT
                TRY_CAST(timestamp_parsed AS TIMESTAMP) AS event_time,
                date_trunc('minute', TRY_CAST(timestamp_parsed AS TIMESTAMP))
                    AS window_start,
                CAST(host_raw AS VARCHAR) AS host_raw,
                UPPER(TRIM(CAST(object_raw AS VARCHAR))) AS object_type,
                COALESCE(
                    NULLIF(CAST(image_path_raw AS VARCHAR), ''),
                    NULLIF(CAST(process_raw AS VARCHAR), ''),
                    ''
                ) AS process_raw,
                COALESCE(CAST(pid_raw AS VARCHAR), '') AS pid_raw,
                COALESCE(CAST(actor_id_raw AS VARCHAR), '') AS actor_id_raw,
                COALESCE(CAST(object_id_raw AS VARCHAR), '') AS object_id_raw,
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
                COALESCE(CAST(raw_event_id AS VARCHAR), '') AS raw_event_id
            FROM events
            WHERE TRY_CAST(timestamp_parsed AS TIMESTAMP) IS NOT NULL
              AND UPPER(TRIM(CAST(object_raw AS VARCHAR))) IN ('FLOW', 'PROCESS')
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
        SELECT * FROM enriched
        WHERE host_id IS NOT NULL
        """
    )
    connection.execute(
        """
        CREATE TEMP TABLE flow_events AS
        SELECT *
        FROM network_scan
        WHERE object_type = 'FLOW'
          AND destination_value <> ''
        """
    )
    connection.execute(
        """
        CREATE TEMP TABLE process_events AS
        SELECT *
        FROM network_scan
        WHERE object_type = 'PROCESS'
          AND process_raw <> ''
        """
    )


def _measure_pivot_rule(
    connection,
    *,
    rule_id: str,
    tolerance_seconds: int,
) -> dict[str, Any]:
    total = int(
        connection.execute("SELECT COUNT(*)::BIGINT FROM flow_events").fetchone()[0]
    )
    if total == 0:
        return {
            "endpoint_flow_events": 0,
            "matched_network_events": 0,
            "unmatched_count": 0,
            "match_rate_percent": 0.0,
            "ambiguous_match_count": 0,
            "ambiguity_rate_percent": 0.0,
        }

    if rule_id == "direct_same_event":
        matched = int(
            connection.execute(
                """
                SELECT COUNT(*)::BIGINT
                FROM flow_events
                WHERE process_raw <> ''
                """
            ).fetchone()[0]
        )
        ambiguous = 0
    elif rule_id == "host_process_pid":
        connection.execute(
            """
            CREATE OR REPLACE TEMP TABLE pid_candidates AS
            SELECT
                f.raw_event_id AS flow_event_id,
                COUNT(DISTINCT p.raw_event_id)::BIGINT AS candidate_count
            FROM flow_events f
            JOIN process_events p
              ON p.host_id = f.host_id
             AND p.pid_raw = f.pid_raw
             AND f.pid_raw <> ''
             AND p.pid_raw <> ''
            GROUP BY 1
            """
        )
        ambiguous = int(
            connection.execute(
                """
                SELECT COUNT(*)::BIGINT
                FROM pid_candidates
                WHERE candidate_count > 1
                """
            ).fetchone()[0]
        )
        matched = int(
            connection.execute(
                """
                SELECT COUNT(*)::BIGINT
                FROM pid_candidates
                WHERE candidate_count = 1
                """
            ).fetchone()[0]
        )
        connection.execute("DROP TABLE IF EXISTS pid_candidates")
    else:
        tol = int(tolerance_seconds)
        connection.execute(
            f"""
            CREATE OR REPLACE TEMP TABLE pivot_candidates AS
            SELECT
                f.raw_event_id AS flow_event_id,
                COUNT(DISTINCT p.raw_event_id)::BIGINT AS candidate_count
            FROM flow_events f
            JOIN process_events p
              ON p.host_id = f.host_id
             AND ABS(
                    date_diff(
                        'millisecond',
                        f.event_time,
                        p.event_time
                    )
                ) <= {tol * 1000}
            GROUP BY 1
            """
        )
        ambiguous = int(
            connection.execute(
                """
                SELECT COUNT(*)::BIGINT
                FROM pivot_candidates
                WHERE candidate_count > 1
                """
            ).fetchone()[0]
        )
        matched = int(
            connection.execute(
                """
                SELECT COUNT(*)::BIGINT
                FROM pivot_candidates
                WHERE candidate_count = 1
                """
            ).fetchone()[0]
        )
        connection.execute("DROP TABLE IF EXISTS pivot_candidates")

    unmatched = max(0, total - matched)
    match_rate = round((matched / total) * 100.0, 6) if total else 0.0
    ambiguity_rate = round((ambiguous / total) * 100.0, 6) if total else 0.0
    return {
        "endpoint_flow_events": total,
        "matched_network_events": matched,
        "unmatched_count": unmatched,
        "match_rate_percent": match_rate,
        "ambiguous_match_count": ambiguous,
        "ambiguity_rate_percent": ambiguity_rate,
    }


def build_t16(connection) -> Any:
    import pandas as pd

    rows: list[dict[str, Any]] = []
    for spec in PIVOT_RULES:
        metrics = _measure_pivot_rule(
            connection,
            rule_id=spec["pivot_rule_id"],
            tolerance_seconds=int(spec["time_tolerance_seconds"]),
        )
        rows.append({**spec, **metrics})
    return pd.DataFrame(rows, columns=T16_COLUMNS)


def _create_linked_flows(connection, evidence_cap: int) -> None:
    """Best-effort pivot cascade: direct → pid → strict temporal → relaxed."""
    connection.execute(
        f"""
        CREATE TEMP TABLE linked_flows AS
        WITH direct AS (
            SELECT
                f.*,
                _eda08_process_display(f.process_raw) AS process_name,
                'direct_same_event' AS pivot_rule_id,
                0 AS pivot_rank
            FROM flow_events f
            WHERE f.process_raw <> ''
        ),
        pid_candidates AS (
            SELECT
                f.raw_event_id AS flow_event_id,
                COUNT(DISTINCT p.raw_event_id)::BIGINT AS candidate_count,
                MIN(p.raw_event_id) AS chosen_process_event_id
            FROM flow_events f
            JOIN process_events p
              ON p.host_id = f.host_id
             AND p.pid_raw = f.pid_raw
             AND f.pid_raw <> ''
             AND p.pid_raw <> ''
            WHERE f.raw_event_id NOT IN (SELECT raw_event_id FROM direct)
            GROUP BY 1
        ),
        pid_match AS (
            SELECT
                f.*,
                _eda08_process_display(p.process_raw) AS process_name,
                'host_process_pid' AS pivot_rule_id,
                1 AS pivot_rank
            FROM flow_events f
            JOIN pid_candidates pc ON pc.flow_event_id = f.raw_event_id
            JOIN process_events p ON p.raw_event_id = pc.chosen_process_event_id
            WHERE pc.candidate_count = 1
        ),
        strict_candidates AS (
            SELECT
                f.raw_event_id AS flow_event_id,
                COUNT(DISTINCT p.raw_event_id)::BIGINT AS candidate_count,
                MIN(p.raw_event_id) AS chosen_process_event_id
            FROM flow_events f
            JOIN process_events p
              ON p.host_id = f.host_id
             AND ABS(
                    date_diff(
                        'millisecond',
                        f.event_time,
                        p.event_time
                    )
                ) <= {STRICT_TOLERANCE_SECONDS * 1000}
            WHERE f.raw_event_id NOT IN (SELECT raw_event_id FROM direct)
              AND f.raw_event_id NOT IN (SELECT raw_event_id FROM pid_match)
            GROUP BY 1
        ),
        strict_match AS (
            SELECT
                f.*,
                _eda08_process_display(p.process_raw) AS process_name,
                'host_temporal_strict' AS pivot_rule_id,
                2 AS pivot_rank
            FROM flow_events f
            JOIN strict_candidates sc ON sc.flow_event_id = f.raw_event_id
            JOIN process_events p ON p.raw_event_id = sc.chosen_process_event_id
            WHERE sc.candidate_count = 1
        ),
        relaxed_candidates AS (
            SELECT
                f.raw_event_id AS flow_event_id,
                COUNT(DISTINCT p.raw_event_id)::BIGINT AS candidate_count,
                MIN(p.raw_event_id) AS chosen_process_event_id
            FROM flow_events f
            JOIN process_events p
              ON p.host_id = f.host_id
             AND ABS(
                    date_diff(
                        'millisecond',
                        f.event_time,
                        p.event_time
                    )
                ) <= {RELAXED_TOLERANCE_SECONDS * 1000}
            WHERE f.raw_event_id NOT IN (SELECT raw_event_id FROM direct)
              AND f.raw_event_id NOT IN (SELECT raw_event_id FROM pid_match)
              AND f.raw_event_id NOT IN (SELECT raw_event_id FROM strict_match)
            GROUP BY 1
        ),
        relaxed_match AS (
            SELECT
                f.*,
                _eda08_process_display(p.process_raw) AS process_name,
                'host_temporal_relaxed' AS pivot_rule_id,
                3 AS pivot_rank
            FROM flow_events f
            JOIN relaxed_candidates rc ON rc.flow_event_id = f.raw_event_id
            JOIN process_events p ON p.raw_event_id = rc.chosen_process_event_id
            WHERE rc.candidate_count = 1
        ),
        combined AS (
            SELECT * FROM direct
            UNION ALL SELECT * FROM pid_match
            UNION ALL SELECT * FROM strict_match
            UNION ALL SELECT * FROM relaxed_match
        )
        SELECT
            period_role,
            window_start,
            host_id,
            event_time,
            process_name,
            destination_value,
            _eda08_destination_category(destination_value) AS destination_category,
            port,
            protocol,
            pivot_rule_id,
            raw_event_id,
            archive_name,
            member_name,
            line_number
        FROM combined
        """
    )


def _ordered_evidence_ids(
    rows: list[dict[str, Any]], evidence_cap: int
) -> list[str]:
    ordered = sorted(
        rows,
        key=lambda item: (
            str(item.get("event_time") or ""),
            str(item.get("archive_name") or ""),
            str(item.get("member_name") or ""),
            int(item.get("line_number") or 0),
            str(item.get("raw_event_id") or ""),
        ),
    )
    ids: list[str] = []
    seen: set[str] = set()
    for item in ordered:
        event_id = str(item.get("raw_event_id") or "")
        if not event_id or event_id in seen:
            continue
        seen.add(event_id)
        ids.append(event_id)
        if len(ids) >= evidence_cap:
            break
    return ids


def build_t17(connection, evidence_cap: int) -> Any:
    import pandas as pd

    frame = _query_frame(
        connection,
        """
        SELECT
            period_role AS period,
            host_id,
            process_name,
            destination_value,
            destination_category,
            port,
            protocol,
            event_time,
            raw_event_id,
            archive_name,
            member_name,
            line_number
        FROM linked_flows
        ORDER BY period_role, host_id, process_name, destination_value,
                 port, protocol, event_time, archive_name, member_name,
                 line_number, raw_event_id
        """,
    )
    if frame.empty:
        return pd.DataFrame(columns=T17_COLUMNS)

    benign_keys: set[tuple[str, str, str, str]] = set()
    benign_rows = frame.loc[frame["period"] == "verified_benign"]
    for row in benign_rows.itertuples(index=False):
        benign_keys.add(
            (
                str(row.host_id),
                str(row.process_name),
                str(row.destination_value),
                str(row.port or ""),
            )
        )

    grouped: dict[tuple, dict[str, Any]] = {}
    for row in frame.itertuples(index=False):
        key = (
            str(row.period),
            str(row.host_id),
            str(row.process_name),
            str(row.destination_value),
            str(row.destination_category),
            str(row.port or ""),
            str(row.protocol or ""),
        )
        item = grouped.setdefault(
            key,
            {
                "period": key[0],
                "host_id": key[1],
                "process_name": key[2],
                "destination_value": key[3],
                "destination_category": key[4],
                "port": key[5],
                "protocol": key[6],
                "connection_count": 0,
                "first_seen_time": row.event_time,
                "evidence_rows": [],
            },
        )
        item["connection_count"] += 1
        if row.event_time < item["first_seen_time"]:
            item["first_seen_time"] = row.event_time
        item["evidence_rows"].append(
            {
                "event_time": row.event_time,
                "archive_name": row.archive_name,
                "member_name": row.member_name,
                "line_number": row.line_number,
                "raw_event_id": row.raw_event_id,
            }
        )

    rows: list[dict[str, Any]] = []
    for item in sorted(
        grouped.values(),
        key=lambda value: (
            str(value["period"]),
            str(value["host_id"]),
            str(value["process_name"]),
            str(value["destination_value"]),
            str(value["port"]),
            str(value["protocol"]),
            str(value["first_seen_time"]),
        ),
    ):
        benign_key = (
            str(item["host_id"]),
            str(item["process_name"]),
            str(item["destination_value"]),
            str(item["port"]),
        )
        rows.append(
            {
                "period": item["period"],
                "host_id": item["host_id"],
                "process_name": item["process_name"],
                "destination_value": item["destination_value"],
                "destination_category": item["destination_category"],
                "port": item["port"],
                "protocol": item["protocol"],
                "connection_count": int(item["connection_count"]),
                "first_seen_time": item["first_seen_time"],
                "benign_seen_before_yes_no": (
                    "yes" if benign_key in benign_keys else "no"
                ),
                "raw_event_ids": _compact_json(
                    _ordered_evidence_ids(item["evidence_rows"], evidence_cap)
                ),
            }
        )
    return pd.DataFrame(rows, columns=T17_COLUMNS)


def _benign_destination_keys(connection) -> set[tuple[str, str]]:
    frame = _query_frame(
        connection,
        """
        SELECT DISTINCT
            CAST(host_id AS VARCHAR) AS host_id,
            CAST(destination_value AS VARCHAR) AS destination_value
        FROM linked_flows
        WHERE period_role = 'verified_benign'
        """,
    )
    if frame.empty:
        return set()
    return {
        (str(row.host_id), str(row.destination_value))
        for row in frame.itertuples(index=False)
    }


def _benign_process_keys(connection) -> set[tuple[str, str]]:
    frame = _query_frame(
        connection,
        """
        SELECT DISTINCT
            CAST(host_id AS VARCHAR) AS host_id,
            CAST(process_name AS VARCHAR) AS process_name
        FROM linked_flows
        WHERE period_role = 'verified_benign'
          AND process_name <> ''
        """,
    )
    if frame.empty:
        return set()
    return {
        (str(row.host_id), str(row.process_name))
        for row in frame.itertuples(index=False)
    }


def build_f9_data(connection) -> Any:
    import pandas as pd

    benign_dest = _benign_destination_keys(connection)
    frame = _query_frame(
        connection,
        """
        SELECT
            period_role AS period,
            window_start,
            host_id,
            destination_value,
            event_time,
            raw_event_id
        FROM linked_flows
        ORDER BY host_id, window_start, event_time, raw_event_id
        """,
    )
    if frame.empty:
        return pd.DataFrame(
            columns=[
                "host_id",
                "window_start",
                "novel_destination_count",
                "flow_count",
                "novel_destination_ratio",
            ]
        )

    first_seen: dict[tuple[str, str], Any] = {}
    for row in frame.itertuples(index=False):
        key = (str(row.host_id), str(row.destination_value))
        stamp = row.event_time
        if key not in first_seen or stamp < first_seen[key]:
            first_seen[key] = stamp

    points: list[dict[str, Any]] = []
    eval_rows = frame.loc[frame["period"] == "evaluation"]
    for row in eval_rows.itertuples(index=False):
        key = (str(row.host_id), str(row.destination_value))
        if key in benign_dest:
            continue
        if first_seen.get(key) != row.event_time:
            continue
        points.append(
            {
                "host_id": str(row.host_id),
                "window_start": pd.to_datetime(row.window_start),
                "novel_destination_count": 1,
            }
        )
    if not points:
        return pd.DataFrame(
            columns=[
                "host_id",
                "window_start",
                "novel_destination_count",
                "flow_count",
                "novel_destination_ratio",
            ]
        )
    novel = (
        pd.DataFrame(points)
        .groupby(["host_id", "window_start"], as_index=False)[
            "novel_destination_count"
        ]
        .sum()
    )
    flow_counts = (
        eval_rows.groupby(["host_id", "window_start"], as_index=False)
        .size()
        .rename(columns={"size": "flow_count"})
    )
    merged = novel.merge(flow_counts, on=["host_id", "window_start"], how="left")
    merged["flow_count"] = merged["flow_count"].fillna(0).astype(int)
    merged["novel_destination_ratio"] = merged.apply(
        lambda item: (
            round(item["novel_destination_count"] / item["flow_count"], 6)
            if item["flow_count"] > 0
            else 0.0
        ),
        axis=1,
    )
    return merged.sort_values(["host_id", "window_start"]).reset_index(drop=True)


def build_f10_data(connection) -> Any:
    import pandas as pd

    benign_proc = _benign_process_keys(connection)
    benign_dest = _benign_destination_keys(connection)
    frame = _query_frame(
        connection,
        """
        SELECT
            period_role AS period,
            host_id,
            process_name,
            destination_value,
            event_time,
            raw_event_id
        FROM linked_flows
        WHERE period_role = 'evaluation'
          AND process_name <> ''
        ORDER BY host_id, event_time, raw_event_id
        """,
    )
    if frame.empty:
        return pd.DataFrame(
            columns=["lag_minutes", "process_to_destination_pairs"]
        )

    process_first: dict[tuple[str, str], Any] = {}
    for row in frame.itertuples(index=False):
        key = (str(row.host_id), str(row.process_name))
        if key in benign_proc:
            continue
        stamp = row.event_time
        if key not in process_first or stamp < process_first[key]:
            process_first[key] = stamp

    dest_first: dict[tuple[str, str], Any] = {}
    for row in frame.itertuples(index=False):
        key = (str(row.host_id), str(row.destination_value))
        if key in benign_dest:
            continue
        stamp = row.event_time
        if key not in dest_first or stamp < dest_first[key]:
            dest_first[key] = stamp

    counts = {lag: 0 for lag in LAG_MINUTES}
    for (host_id, process_name), proc_time in process_first.items():
        for (dest_host, destination_value), dest_time in dest_first.items():
            if dest_host != host_id:
                continue
            if dest_time < proc_time:
                continue
            delta_minutes = (dest_time - proc_time).total_seconds() / 60.0
            for lag in LAG_MINUTES:
                if 0 <= delta_minutes <= lag:
                    counts[lag] += 1
                    break
    return pd.DataFrame(
        [
            {"lag_minutes": lag, "process_to_destination_pairs": counts[lag]}
            for lag in LAG_MINUTES
        ]
    )


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
        "F9 Destination Novelty Over Time\n"
        "Verified-benign frozen novelty; not attack or malicious labels"
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
            columns=["lag_minutes", "process_to_destination_pairs"]
        )
    )
    figure, axis = plt.subplots(figsize=(8, 4.5), constrained_layout=True)
    if not data.empty:
        axis.bar(
            data["lag_minutes"].astype(str),
            data["process_to_destination_pairs"],
            color=list(F10_COLORS),
        )
    axis.set_xlabel("Lag window (minutes)")
    axis.set_ylabel("Process-novelty → destination-novelty pairs")
    axis.set_title(
        "F10 Process-to-Network Lag\n"
        "Frozen verified-benign novelty; not maliciousness"
    )
    axis.grid(alpha=0.25, axis="y")
    figure.savefig(png_path, dpi=180, bbox_inches="tight")
    figure.savefig(pdf_path, bbox_inches="tight")
    plt.close(figure)


def validate_outputs(t16, t17) -> None:
    if list(t16.columns) != T16_COLUMNS:
        raise CacheAuditError("T16 schema mismatch")
    if list(t17.columns) != T17_COLUMNS:
        raise CacheAuditError("T17 schema mismatch")
    if not t16.empty and len(t16) != len(PIVOT_RULES):
        raise CacheAuditError("T16 must contain one row per pivot rule")
    allowed_categories = {
        "loopback",
        "internal-looking",
        "external-looking",
        "multicast_or_broadcast",
        "missing",
        "invalid_or_unresolved",
    }
    if not t17.empty and not set(t17["destination_category"]).issubset(
        allowed_categories
    ):
        raise CacheAuditError("T17 destination_category contains invalid values")


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
            f"FLOW events scanned: {metadata.get('flow_event_count')}",
            f"Linked FLOW rows: {metadata.get('linked_flow_count')}",
            f"T17 rows: {metadata.get('t17_row_count')}",
            "",
            "Pivot rules (T16):",
            "  1. direct_same_event",
            "  2. host_process_pid",
            "  3. host_temporal_strict",
            "  4. host_temporal_relaxed",
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

    def stage(number: int, message: str) -> None:
        line = f"[STAGE {number}/7] {message}"
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

        _create_network_scan(connection)
        flow_count = int(
            connection.execute(
                "SELECT COUNT(*)::BIGINT FROM flow_events"
            ).fetchone()[0]
        )
        stage(3, f"payload scan {PAYLOAD_SCAN_COUNT}/{PAYLOAD_SCAN_COUNT} complete")

        t16 = build_t16(connection)
        _create_linked_flows(connection, config["evidence_cap"])
        linked_count = int(
            connection.execute(
                "SELECT COUNT(*)::BIGINT FROM linked_flows"
            ).fetchone()[0]
        )
        t17 = build_t17(connection, config["evidence_cap"])
        f9_data = build_f9_data(connection)
        f10_data = build_f10_data(connection)
        validate_outputs(t16, t17)
        stage(4, "T16/T17 and F9/F10 data constructed and validated")

        host_labels = _host_label_map(connection)
        parent = eda5._nearest_existing_directory(config["output_dir"].parent)
        staging = pathlib.Path(
            tempfile.mkdtemp(prefix=".eda08_staging_", dir=str(parent))
        )
        _atomic_write_csv(t16, staging / "T16_endpoint_network_pivot_success.csv")
        _atomic_write_csv(t17, staging / "T17_process_to_destination_behavior.csv")
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
            "flow_event_count": flow_count,
            "linked_flow_count": linked_count,
            "t16_row_count": int(len(t16)),
            "t17_row_count": int(len(t17)),
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
        metadata["deliverable_sha256"] = {
            name: _sha256_file(staging / name) for name in deliverable_names
        }
        final_log = "\n".join(execution_log) + "\n"
        _atomic_write_text(final_log, staging / "eda08_execution.log")
        metadata["deliverable_sha256"]["eda08_execution.log"] = _sha256_file(
            staging / "eda08_execution.log"
        )
        _atomic_write_json(metadata, staging / "eda08_run_metadata.json")
        _assert_no_temp_files(staging)
        _publish_staging(staging, config["output_dir"])
        staging = None
        stage(6, f"published deliverables to {config['output_dir']}")
        stage(7, f"completed in {runtime:.1f}s")
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
