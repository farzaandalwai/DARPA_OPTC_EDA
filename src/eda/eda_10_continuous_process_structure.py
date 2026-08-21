#!/usr/bin/env python3
"""
EDA 10 — Continuous Process-Structure Analysis (SysClient0201-first).

Builds compact, full-period process-structure artifacts for one host without
event-level edge explosion. Internal chunking is allowed for memory and I/O
only; chain semantics remain continuous across the analyzed range.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import pathlib
import resource
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from typing import Any, Optional

import pandas as pd

import eda_04_event_taxonomy as eda4
import eda_05_entity_dictionary as eda5
import eda_06_benign_baseline as eda6
import eda_09_provenance_graph as eda9
import eda_07_process_lineage as eda7
import eda_08_endpoint_network_pivot as eda8
from optc_streaming_parser import SCHEMA_VERSION

CacheAuditError = eda5.CacheAuditError

ANALYSIS_RULE_VERSION = "eda10_continuous_process_structure_v1"
PROCESS_INSTANCE_RULE_VERSION = eda9.PROCESS_INSTANCE_RULE_VERSION
PROCESS_INSTANCE_KEY_UUID = "uuid"
PROCESS_INSTANCE_KEY_PATH_PID = "path_pid"
EVENT_LOCATOR_EXPR = eda8.EVENT_LOCATOR_EXPR
MISSING_MARKER = eda4.MISSING_MARKER
_DRIVE_PATH_PARTS = {"content", "drive", "mydrive"}


@dataclass
class ProcessMeta:
    process_id: str
    process_instance_uuid: str
    process_instance_id_source: str
    process_instance_reliability: str
    instance_identity_status: str
    process_comparison_form: str
    image_path_raw: str
    process_name_normalized: str
    first_seen_time: str
    last_seen_time: str
    event_count: int
    first_raw_event_id: str
    last_raw_event_id: str
    first_event_locator: str
    last_event_locator: str
    first_parent_image_path_raw: str
    last_parent_image_path_raw: str
    first_parent_process_raw: str
    last_parent_process_raw: str
    first_ppid_raw: str
    last_ppid_raw: str
    identity_attribute_conflict: bool = False


def _safe_str(value: object) -> str:
    if value is None:
        return ""
    return str(value)


def _compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _parse_timestamp(value: str, flag: str) -> dt.datetime:
    text = str(value).strip()
    if not text:
        raise CacheAuditError(f"{flag} must be nonempty")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise CacheAuditError(f"{flag} must be ISO-8601 compatible: {value!r}") from exc
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return parsed


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


def _atomic_write_text(text: str, path: pathlib.Path) -> None:
    temporary = path.with_suffix(path.suffix + f".{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_write_json(payload: dict[str, Any], path: pathlib.Path) -> None:
    _atomic_write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", path)


def _assert_no_temp_files(directory: pathlib.Path) -> None:
    leftovers = [
        str(path.relative_to(directory))
        for path in directory.rglob("*")
        if path.name.startswith(".") or path.suffix == ".tmp" or ".tmp." in path.name
    ]
    if leftovers:
        raise CacheAuditError(f"Temporary output files remain: {leftovers}")


def _publish_staging(staging: pathlib.Path, output_dir: pathlib.Path) -> None:
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(os.fspath(output_dir)):
        raise CacheAuditError(
            f"Output path appeared before publication; refusing to touch it: {output_dir}"
        )
    os.replace(staging, output_dir)


def _sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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


def _peak_rss_bytes() -> Optional[int]:
    try:
        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except Exception:
        return None
    if sys.platform == "darwin":
        return int(usage)
    return int(usage) * 1024


def _median(values: list[int]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    if n % 2 == 1:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def _weighted_kth_from_counts(length_to_count: dict[int, int], *, kth: int) -> float:
    total = int(sum(length_to_count.values()))
    if total <= 0 or kth <= 0:
        return 0.0
    target = int(min(max(kth, 1), total))
    running = 0
    for length in sorted(length_to_count):
        running += int(length_to_count[length])
        if running >= target:
            return float(length)
    return float(max(length_to_count))


def _weighted_nearest_rank_quantile(
    length_to_count: dict[int, int], *, quantile: float
) -> float:
    total = int(sum(length_to_count.values()))
    if total <= 0:
        return 0.0
    rank = int(math.ceil(float(quantile) * float(total)))
    return _weighted_kth_from_counts(length_to_count, kth=rank)


def _weighted_statistical_median(length_to_count: dict[int, int]) -> float:
    total = int(sum(length_to_count.values()))
    if total <= 0:
        return 0.0
    if total % 2 == 1:
        return _weighted_kth_from_counts(length_to_count, kth=(total + 1) // 2)
    lo = _weighted_kth_from_counts(length_to_count, kth=total // 2)
    hi = _weighted_kth_from_counts(length_to_count, kth=(total // 2) + 1)
    return (float(lo) + float(hi)) / 2.0


def _weighted_stats_from_counts(length_to_count: dict[int, int]) -> dict[str, Any]:
    total = int(sum(length_to_count.values()))
    if total <= 0:
        return {
            "path_count": 0,
            "avg": 0.0,
            "median": 0.0,
            "p90": 0.0,
            "p95": 0.0,
            "max": 0,
            "frequency_by_hops": {},
        }
    weighted_sum = 0
    for length, count in length_to_count.items():
        weighted_sum += int(length) * int(count)
    return {
        "path_count": total,
        "avg": float(weighted_sum) / float(total),
        "median": _weighted_statistical_median(length_to_count),
        "p90": _weighted_nearest_rank_quantile(length_to_count, quantile=0.9),
        "p95": _weighted_nearest_rank_quantile(length_to_count, quantile=0.95),
        "max": int(max(length_to_count)),
        "frequency_by_hops": {str(k): int(v) for k, v in sorted(length_to_count.items())},
    }


def _node_stats_from_hop_counts(hop_to_count: dict[int, int]) -> dict[str, Any]:
    node_to_count = {int(hops) + 1: int(count) for hops, count in hop_to_count.items()}
    stats = _weighted_stats_from_counts(node_to_count)
    stats["frequency_by_nodes"] = stats.pop("frequency_by_hops", {})
    return stats


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="EDA 10 — continuous process-structure analysis (compact outputs)."
    )
    parser.add_argument("--normalized-cache-dir", required=True)
    parser.add_argument("--period-map-csv", required=True)
    parser.add_argument("--semantic-mapping-csv", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--start-time", default=None)
    parser.add_argument("--end-time", default=None)
    parser.add_argument("--project-root", default=None)
    parser.add_argument("--manifest-csv", default=None)
    parser.add_argument(
        "--process-instance-key",
        choices=(PROCESS_INSTANCE_KEY_UUID, PROCESS_INSTANCE_KEY_PATH_PID),
        default=PROCESS_INSTANCE_KEY_UUID,
    )
    parser.add_argument("--batch-size", type=int, default=50_000)
    parser.add_argument("--duckdb-memory-limit", default="4GB")
    parser.add_argument("--duckdb-temp-dir", default=None)
    parser.add_argument("--duckdb-threads", type=int, default=2)
    parser.add_argument("--export-csv", action="store_true")
    return parser


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def validate_run_config(args: argparse.Namespace) -> dict[str, Any]:
    cache_dir = pathlib.Path(args.normalized_cache_dir).expanduser()
    period_map = pathlib.Path(args.period_map_csv).expanduser()
    semantic_map = pathlib.Path(args.semantic_mapping_csv).expanduser()
    output_dir = pathlib.Path(args.output_dir).expanduser()
    project_root = (
        pathlib.Path(args.project_root).expanduser()
        if args.project_root
        else pathlib.Path(__file__).resolve().parents[2]
    )
    manifest_path = pathlib.Path(args.manifest_csv).expanduser() if args.manifest_csv else None

    if not project_root.is_dir():
        raise CacheAuditError(f"Project root not found: {project_root}")
    if not cache_dir.is_dir() or not any(cache_dir.glob("*.parquet")):
        raise CacheAuditError(f"No Parquet cache files found at: {cache_dir}")
    if not period_map.is_file():
        raise CacheAuditError(f"Period-map CSV not found: {period_map}")
    if not semantic_map.is_file():
        raise CacheAuditError(f"Semantic mapping CSV not found: {semantic_map}")
    if manifest_path is not None and not manifest_path.is_file():
        raise CacheAuditError(f"Manifest CSV not found: {manifest_path}")

    if args.duckdb_temp_dir is not None:
        spill = eda5._validate_duckdb_temp_dir(args.duckdb_temp_dir)
        if _looks_like_drive(spill):
            raise CacheAuditError("Google Drive spill paths are refused")

    _validate_output_dir(output_dir, cache_dir)

    start_time = _parse_timestamp(args.start_time, "--start-time") if args.start_time else None
    end_time = _parse_timestamp(args.end_time, "--end-time") if args.end_time else None
    if start_time is not None and end_time is not None and start_time >= end_time:
        raise CacheAuditError("--start-time must be < --end-time")

    batch_size = eda5._validate_positive("--batch-size", args.batch_size)
    memory_limit = eda5._validate_duckdb_memory_limit(args.duckdb_memory_limit)
    threads = eda5._validate_duckdb_threads(args.duckdb_threads)
    period_policy = eda4.load_period_policy(str(period_map), rare_benign_max_count=1)
    semantic_frame = eda6.load_semantic_mapping(semantic_map)
    cache_metadata = eda5._load_cache_metadata(cache_dir)
    manifest_meta = (
        eda5._manifest_metadata(manifest_path)
        if manifest_path is not None
        else {"manifest_version": None, "manifest_path": None}
    )
    return {
        "cache_dir": cache_dir,
        "period_map": period_map,
        "semantic_mapping_csv": semantic_map,
        "semantic_mapping_frame": semantic_frame,
        "output_dir": output_dir,
        "host": str(args.host),
        "start_time": start_time,
        "end_time": end_time,
        "project_root": project_root,
        "manifest_csv": manifest_path,
        "memory_limit": memory_limit,
        "threads": threads,
        "batch_size": batch_size,
        "duckdb_temp_dir": args.duckdb_temp_dir,
        "cache_metadata": cache_metadata,
        "period_policy": period_policy,
        "process_instance_key": str(args.process_instance_key),
        "export_csv": bool(args.export_csv),
        **manifest_meta,
    }


def _duck_conn(
    cache_dir: pathlib.Path,
    *,
    memory_limit: str,
    temp_dir: Optional[str],
    threads: int,
):
    import duckdb

    connection = None
    spill_path: Optional[pathlib.Path] = None
    spill_owned = False
    try:
        if temp_dir is None:
            spill_path = pathlib.Path(tempfile.mkdtemp(prefix="eda10_duckdb_tmp_"))
            spill_owned = True
        else:
            spill_path = eda5._validate_duckdb_temp_dir(temp_dir)
            if _looks_like_drive(spill_path):
                raise CacheAuditError("Google Drive spill paths are refused")
            spill_path.mkdir(parents=True, exist_ok=True)
        connection = duckdb.connect()
        eda5._configure_duckdb(
            connection,
            memory_limit=memory_limit,
            temp_dir=str(spill_path),
            threads=threads,
        )
        connection.execute("SET preserve_insertion_order = false")
        cache_glob = str(cache_dir / "*.parquet")
        connection.execute(
            "CREATE VIEW events AS SELECT * FROM read_parquet("
            f"{eda5._sql_string_literal(cache_glob)})"
        )
        return connection, str(spill_path), spill_owned
    except Exception:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
        if spill_owned and spill_path is not None:
            shutil.rmtree(spill_path, ignore_errors=True)
        raise


def _record_batches(connection, sql: str, batch_size: int):
    relation = connection.execute(sql)
    modern_reader = getattr(relation, "to_arrow_reader", None)
    if callable(modern_reader):
        return modern_reader(batch_size=batch_size)
    legacy_reader = getattr(relation, "fetch_record_batch", None)
    if callable(legacy_reader):
        return legacy_reader(rows_per_batch=batch_size)
    raise CacheAuditError(
        "Installed DuckDB exposes no supported streaming Arrow reader API"
    )


def _projection_reader(connection, sql: str, batch_size: int):
    return _record_batches(connection, sql, batch_size)


def _validate_required_columns(connection) -> None:
    required = {
        "timestamp_parsed",
        "parse_status",
        "archive_name",
        "member_name",
        "line_number",
        "raw_event_id",
        "host_raw",
        "object_raw",
        "action_raw",
        "user_raw",
        "principal_raw",
        "image_path_raw",
        "process_raw",
        "parent_image_path_raw",
        "parent_process_raw",
        "command_line_raw",
        "file_path_raw",
        "module_path_raw",
        "dest_ip_raw",
        "destination_raw",
        "dest_port_raw",
        "protocol_raw",
        "actor_id_raw",
        "object_id_raw",
        "pid_raw",
        "ppid_raw",
        "tid_raw",
    }
    describe = connection.execute("DESCRIBE SELECT * FROM events").fetchall()
    available = {str(row[0]) for row in describe}
    missing = sorted(required - available)
    if missing:
        raise CacheAuditError(f"Cache missing required columns: {missing}")


def _register_inputs(connection, config: dict[str, Any]) -> None:
    eda4._register_periods(connection, config["period_policy"])
    frame = config["semantic_mapping_frame"].copy()
    connection.register("_eda10_semantic_map_df", frame)
    connection.execute(
        """
        CREATE TEMP TABLE semantic_map AS
        SELECT
            CAST(raw_object_type AS VARCHAR) AS raw_object_type,
            CAST(raw_action_type AS VARCHAR) AS raw_action_type,
            CAST(semantic_group AS VARCHAR) AS semantic_group,
            CAST(mapping_rule AS VARCHAR) AS mapping_rule
        FROM _eda10_semantic_map_df
        """
    )
    connection.unregister("_eda10_semantic_map_df")


def _resolve_host_time_bounds(connection, config: dict[str, Any]) -> tuple[dt.datetime, dt.datetime]:
    host_lit = eda5._sql_string_literal(config["host"])
    row = connection.execute(
        f"""
        SELECT
            MIN(TRY_CAST(timestamp_parsed AS TIMESTAMP)) AS min_ts,
            MAX(TRY_CAST(timestamp_parsed AS TIMESTAMP)) AS max_ts
        FROM events
        WHERE LOWER(TRIM(CAST(parse_status AS VARCHAR))) = 'ok'
          AND TRY_CAST(timestamp_parsed AS TIMESTAMP) IS NOT NULL
          AND CAST(host_raw AS VARCHAR) = {host_lit}
        """
    ).fetchone()
    min_ts = row[0] if row else None
    max_ts = row[1] if row else None
    if min_ts is None or max_ts is None:
        raise CacheAuditError(f"No parseable events found for host: {config['host']}")
    start = config["start_time"] or min_ts
    end = config["end_time"] or (max_ts + dt.timedelta(microseconds=1))
    if start >= end:
        raise CacheAuditError("Resolved analysis window is empty (start >= end)")
    return start, end


def _expected_events_in_analysis_range(
    connection,
    *,
    host: str,
    start_time: dt.datetime,
    end_time: dt.datetime,
) -> int:
    host_literal = eda5._sql_string_literal(host)
    start_literal = eda5._sql_string_literal(start_time.isoformat())
    end_literal = eda5._sql_string_literal(end_time.isoformat())
    row = connection.execute(
        f"""
        SELECT COUNT(*) AS expected_events
        FROM events
        WHERE LOWER(TRIM(CAST(parse_status AS VARCHAR))) = 'ok'
          AND TRY_CAST(timestamp_parsed AS TIMESTAMP) IS NOT NULL
          AND CAST(host_raw AS VARCHAR) = {host_literal}
          AND TRY_CAST(timestamp_parsed AS TIMESTAMP) >= CAST({start_literal} AS TIMESTAMP)
          AND TRY_CAST(timestamp_parsed AS TIMESTAMP) < CAST({end_literal} AS TIMESTAMP)
        """
    ).fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def _projection_sql(config: dict[str, Any], *, start_time: dt.datetime, end_time: dt.datetime) -> str:
    host_literal = eda5._sql_string_literal(config["host"])
    start_literal = eda5._sql_string_literal(start_time.isoformat())
    end_literal = eda5._sql_string_literal(end_time.isoformat())
    return f"""
    WITH projected AS (
        SELECT
            TRY_CAST(timestamp_parsed AS TIMESTAMP) AS event_time,
            CAST(host_raw AS VARCHAR) AS host_raw,
            UPPER(TRIM(CAST(object_raw AS VARCHAR))) AS object_type,
            UPPER(TRIM(CAST(action_raw AS VARCHAR))) AS action_raw,
            CAST(user_raw AS VARCHAR) AS user_raw,
            CAST(principal_raw AS VARCHAR) AS principal_raw,
            COALESCE(NULLIF(CAST(image_path_raw AS VARCHAR), ''), NULLIF(CAST(process_raw AS VARCHAR), ''), '') AS image_path_raw,
            COALESCE(NULLIF(CAST(parent_image_path_raw AS VARCHAR), ''), NULLIF(CAST(parent_process_raw AS VARCHAR), ''), '') AS parent_image_path_raw,
            CAST(parent_process_raw AS VARCHAR) AS parent_process_raw,
            CAST(command_line_raw AS VARCHAR) AS command_line_raw,
            CAST(file_path_raw AS VARCHAR) AS file_path_raw,
            CAST(module_path_raw AS VARCHAR) AS module_path_raw,
            CAST(dest_ip_raw AS VARCHAR) AS dest_ip_raw,
            CAST(destination_raw AS VARCHAR) AS destination_raw,
            CAST(dest_port_raw AS VARCHAR) AS dest_port_raw,
            CAST(protocol_raw AS VARCHAR) AS protocol_raw,
            CAST(actor_id_raw AS VARCHAR) AS actor_id_raw,
            CAST(object_id_raw AS VARCHAR) AS object_id_raw,
            CAST(pid_raw AS VARCHAR) AS pid_raw,
            CAST(ppid_raw AS VARCHAR) AS ppid_raw,
            CAST(tid_raw AS VARCHAR) AS tid_raw,
            CAST(archive_name AS VARCHAR) AS archive_name,
            CAST(member_name AS VARCHAR) AS member_name,
            TRY_CAST(line_number AS BIGINT) AS line_number,
            CAST(raw_event_id AS VARCHAR) AS raw_event_id,
            {EVENT_LOCATOR_EXPR} AS event_locator
        FROM events
        WHERE LOWER(TRIM(CAST(parse_status AS VARCHAR))) = 'ok'
          AND TRY_CAST(timestamp_parsed AS TIMESTAMP) IS NOT NULL
          AND CAST(host_raw AS VARCHAR) = {host_literal}
          AND TRY_CAST(timestamp_parsed AS TIMESTAMP) >= CAST({start_literal} AS TIMESTAMP)
          AND TRY_CAST(timestamp_parsed AS TIMESTAMP) < CAST({end_literal} AS TIMESTAMP)
    )
    SELECT
        p.*,
        CASE
            WHEN p.archive_name LIKE '%.tar'
            THEN regexp_replace(p.archive_name, '\\\\.tar$', '')
            ELSE strftime(p.event_time, '%Y-%m-%d')
        END AS date_label,
        COALESCE(pi.period, '') AS period,
        COALESCE(pi.period_role, 'unassigned') AS period_role,
        COALESCE(sm.semantic_group, 'other_activity') AS semantic_group,
        COALESCE(sm.mapping_rule, 'object_type_missing_or_unrecognized') AS mapping_rule
    FROM projected p
    LEFT JOIN period_intervals pi
      ON p.event_time >= pi.start_time AND p.event_time < pi.end_time
    LEFT JOIN semantic_map sm
      ON sm.raw_object_type = COALESCE(NULLIF(p.object_type, ''), '{MISSING_MARKER}')
     AND sm.raw_action_type = COALESCE(NULLIF(p.action_raw, ''), '{MISSING_MARKER}')
    ORDER BY p.event_time, p.archive_name, p.member_name, p.line_number, p.raw_event_id
    """


def _resolve_process_instance(
    *,
    mode: str,
    host_node_id: str,
    uuid_text: str,
    comparison_form: str,
    pid_text: str,
    date_label: str,
) -> Optional[dict[str, str]]:
    resolved = eda9._resolve_process_instance(
        mode=mode,
        host_node_id=host_node_id,
        uuid_text=uuid_text,
        comparison_form=comparison_form,
        pid_text=pid_text,
        date_label=date_label,
    )
    if resolved is None:
        return None
    return {
        "process_id": _safe_str(resolved.get("node_id")),
        "process_instance_uuid": _safe_str(resolved.get("process_instance_uuid")),
        "process_instance_id_source": _safe_str(resolved.get("process_instance_id_source")),
        "process_instance_reliability": _safe_str(
            resolved.get("process_instance_reliability")
        ),
        "instance_identity_status": _safe_str(resolved.get("instance_identity_status")),
    }


def _upsert_process(
    process_nodes: dict[str, ProcessMeta],
    *,
    instance: dict[str, str],
    comparison_form: str,
    image_path_raw: str,
    timestamp: str,
    raw_event_id: str,
    event_locator: str,
    ppid_raw: str,
    parent_image_path_raw: str,
    parent_process_raw: str,
) -> str:
    process_id = instance["process_id"]
    process_name = eda8.process_display_name(image_path_raw)
    row = process_nodes.get(process_id)
    if row is None:
        row = ProcessMeta(
            process_id=process_id,
            process_instance_uuid=_safe_str(instance["process_instance_uuid"]),
            process_instance_id_source=_safe_str(instance["process_instance_id_source"]),
            process_instance_reliability=_safe_str(instance["process_instance_reliability"]),
            instance_identity_status=_safe_str(instance["instance_identity_status"]),
            process_comparison_form=comparison_form,
            image_path_raw=_safe_str(image_path_raw),
            process_name_normalized=_safe_str(process_name),
            first_seen_time=timestamp,
            last_seen_time=timestamp,
            event_count=1,
            first_raw_event_id=raw_event_id,
            last_raw_event_id=raw_event_id,
            first_event_locator=event_locator,
            last_event_locator=event_locator,
            first_parent_image_path_raw=_safe_str(parent_image_path_raw),
            last_parent_image_path_raw=_safe_str(parent_image_path_raw),
            first_parent_process_raw=_safe_str(parent_process_raw),
            last_parent_process_raw=_safe_str(parent_process_raw),
            first_ppid_raw=_safe_str(ppid_raw),
            last_ppid_raw=_safe_str(ppid_raw),
        )
        process_nodes[process_id] = row
        return process_id

    row.event_count += 1
    existing_cmp = _safe_str(row.process_comparison_form).strip()
    incoming_cmp = _safe_str(comparison_form).strip()
    if existing_cmp and incoming_cmp and existing_cmp != incoming_cmp:
        row.identity_attribute_conflict = True
    if timestamp < row.first_seen_time:
        row.first_seen_time = timestamp
        row.first_raw_event_id = raw_event_id
        row.first_event_locator = event_locator
        row.first_parent_image_path_raw = _safe_str(parent_image_path_raw)
        row.first_parent_process_raw = _safe_str(parent_process_raw)
        row.first_ppid_raw = _safe_str(ppid_raw)
    if timestamp > row.last_seen_time:
        row.last_seen_time = timestamp
        row.last_raw_event_id = raw_event_id
        row.last_event_locator = event_locator
        row.last_parent_image_path_raw = _safe_str(parent_image_path_raw)
        row.last_parent_process_raw = _safe_str(parent_process_raw)
        row.last_ppid_raw = _safe_str(ppid_raw)
    if (not row.image_path_raw) and image_path_raw:
        row.image_path_raw = image_path_raw
        row.process_name_normalized = process_name
    if (not row.process_comparison_form) and comparison_form:
        row.process_comparison_form = comparison_form
    return process_id


def _upsert_create_edge(
    create_edges: dict[tuple[str, str], dict[str, Any]],
    *,
    parent_id: str,
    child_id: str,
    timestamp: str,
    raw_event_id: str,
    event_locator: str,
) -> None:
    key = (parent_id, child_id)
    row = create_edges.get(key)
    if row is None:
        create_edges[key] = {
            "parent_process_id": parent_id,
            "child_process_id": child_id,
            "create_event_count": 1,
            "first_seen_time": timestamp,
            "last_seen_time": timestamp,
            "first_raw_event_id": raw_event_id,
            "last_raw_event_id": raw_event_id,
            "first_event_locator": event_locator,
            "last_event_locator": event_locator,
        }
        return
    row["create_event_count"] = int(row["create_event_count"]) + 1
    if timestamp < row["first_seen_time"]:
        row["first_seen_time"] = timestamp
        row["first_raw_event_id"] = raw_event_id
        row["first_event_locator"] = event_locator
    if timestamp > row["last_seen_time"]:
        row["last_seen_time"] = timestamp
        row["last_raw_event_id"] = raw_event_id
        row["last_event_locator"] = event_locator


def _iterative_scc(nodes: set[str], adjacency: dict[str, set[str]]) -> list[list[str]]:
    # Iterative Kosaraju for recursion safety on deep graphs.
    finish_order: list[str] = []
    seen: set[str] = set()

    for start in sorted(nodes):
        if start in seen:
            continue
        stack: list[tuple[str, bool]] = [(start, False)]
        while stack:
            node, expanded = stack.pop()
            if expanded:
                finish_order.append(node)
                continue
            if node in seen:
                continue
            seen.add(node)
            stack.append((node, True))
            for nxt in sorted(adjacency.get(node, set()), reverse=True):
                if nxt not in seen:
                    stack.append((nxt, False))

    reverse_adj: dict[str, set[str]] = {node: set() for node in nodes}
    for src in nodes:
        for dst in adjacency.get(src, set()):
            reverse_adj.setdefault(dst, set()).add(src)

    assigned: set[str] = set()
    sccs: list[list[str]] = []
    for start in reversed(finish_order):
        if start in assigned:
            continue
        component: list[str] = []
        stack = [start]
        assigned.add(start)
        while stack:
            node = stack.pop()
            component.append(node)
            for nxt in sorted(reverse_adj.get(node, set()), reverse=True):
                if nxt not in assigned:
                    assigned.add(nxt)
                    stack.append(nxt)
        sccs.append(sorted(component))
    return sccs


def _component_ids(nodes: set[str], undirected: dict[str, set[str]]) -> list[set[str]]:
    seen: set[str] = set()
    components: list[set[str]] = []
    for start in sorted(nodes):
        if start in seen:
            continue
        queue = deque([start])
        seen.add(start)
        comp = {start}
        while queue:
            cur = queue.popleft()
            for nxt in undirected.get(cur, set()):
                if nxt not in seen:
                    seen.add(nxt)
                    comp.add(nxt)
                    queue.append(nxt)
        components.append(comp)
    return components


def _init_behavior_staging_table(connection) -> None:
    connection.execute(
        """
        CREATE TEMP TABLE behavior_observations (
            process_id VARCHAR,
            event_time TIMESTAMP,
            raw_event_id VARCHAR,
            object_type VARCHAR,
            action_raw VARCHAR,
            file_path_raw VARCHAR,
            module_path_raw VARCHAR,
            dest_ip_raw VARCHAR,
            destination_raw VARCHAR,
            dest_port_raw VARCHAR,
            protocol_raw VARCHAR
        )
        """
    )


def _stage_behavior_observations(connection, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    frame = pd.DataFrame(rows)
    connection.register("_eda10_behavior_batch_df", frame)
    connection.execute(
        """
        INSERT INTO behavior_observations
        SELECT
            CAST(process_id AS VARCHAR) AS process_id,
            TRY_CAST(event_time AS TIMESTAMP) AS event_time,
            CAST(raw_event_id AS VARCHAR) AS raw_event_id,
            CAST(object_type AS VARCHAR) AS object_type,
            CAST(action_raw AS VARCHAR) AS action_raw,
            CAST(file_path_raw AS VARCHAR) AS file_path_raw,
            CAST(module_path_raw AS VARCHAR) AS module_path_raw,
            CAST(dest_ip_raw AS VARCHAR) AS dest_ip_raw,
            CAST(destination_raw AS VARCHAR) AS destination_raw,
            CAST(dest_port_raw AS VARCHAR) AS dest_port_raw,
            CAST(protocol_raw AS VARCHAR) AS protocol_raw
        FROM _eda10_behavior_batch_df
        """
    )
    connection.unregister("_eda10_behavior_batch_df")


def _build_behavior_compact_table(connection) -> None:
    connection.execute(
        """
        CREATE OR REPLACE TEMP TABLE behavior_compact AS
        WITH base AS (
            SELECT
                process_id,
                event_time,
                raw_event_id,
                action_raw,
                CASE
                    WHEN object_type = 'FLOW' THEN 'DESTINATION'
                    WHEN object_type = 'MODULE' THEN 'MODULE'
                    ELSE 'FILE'
                END AS behavior_type,
                CASE
                    WHEN object_type = 'FLOW' THEN
                        COALESCE(NULLIF(dest_ip_raw, ''), NULLIF(destination_raw, ''), '')
                        || CASE
                            WHEN COALESCE(NULLIF(dest_port_raw, ''), '') <> ''
                            THEN ':' || dest_port_raw
                            ELSE ''
                        END
                        || CASE
                            WHEN COALESCE(NULLIF(protocol_raw, ''), '') <> ''
                            THEN '|' || protocol_raw
                            ELSE ''
                        END
                    WHEN object_type = 'MODULE' THEN COALESCE(NULLIF(module_path_raw, ''), NULLIF(file_path_raw, ''), '')
                    ELSE COALESCE(NULLIF(file_path_raw, ''), NULLIF(module_path_raw, ''), '')
                END AS behavior_key
            FROM behavior_observations
            WHERE process_id <> ''
              AND object_type IN ('FILE', 'MODULE', 'FLOW')
        ),
        filtered AS (
            SELECT * FROM base WHERE behavior_key <> ''
        ),
        agg AS (
            SELECT
                process_id,
                behavior_type,
                action_raw,
                behavior_key,
                COUNT(*) AS attach_event_count,
                MIN(event_time) AS first_seen_time,
                MAX(event_time) AS last_seen_time
            FROM filtered
            GROUP BY process_id, behavior_type, action_raw, behavior_key
        ),
        first_events AS (
            SELECT
                f.process_id,
                f.behavior_type,
                f.action_raw,
                f.behavior_key,
                f.raw_event_id AS first_raw_event_id
            FROM filtered f
            JOIN agg a
              ON a.process_id = f.process_id
             AND a.behavior_type = f.behavior_type
             AND a.action_raw = f.action_raw
             AND a.behavior_key = f.behavior_key
             AND a.first_seen_time = f.event_time
            QUALIFY ROW_NUMBER() OVER (
                PARTITION BY f.process_id, f.behavior_type, f.action_raw, f.behavior_key
                ORDER BY f.raw_event_id
            ) = 1
        ),
        last_events AS (
            SELECT
                f.process_id,
                f.behavior_type,
                f.action_raw,
                f.behavior_key,
                f.raw_event_id AS last_raw_event_id
            FROM filtered f
            JOIN agg a
              ON a.process_id = f.process_id
             AND a.behavior_type = f.behavior_type
             AND a.action_raw = f.action_raw
             AND a.behavior_key = f.behavior_key
             AND a.last_seen_time = f.event_time
            QUALIFY ROW_NUMBER() OVER (
                PARTITION BY f.process_id, f.behavior_type, f.action_raw, f.behavior_key
                ORDER BY f.raw_event_id DESC
            ) = 1
        )
        SELECT
            a.process_id,
            a.behavior_type,
            a.action_raw,
            a.behavior_key,
            CAST(a.attach_event_count AS BIGINT) AS attach_event_count,
            CAST(a.first_seen_time AS TIMESTAMP) AS first_seen_time,
            CAST(a.last_seen_time AS TIMESTAMP) AS last_seen_time,
            fe.first_raw_event_id,
            le.last_raw_event_id
        FROM agg a
        LEFT JOIN first_events fe USING (process_id, behavior_type, action_raw, behavior_key)
        LEFT JOIN last_events le USING (process_id, behavior_type, action_raw, behavior_key)
        """
    )


def run_eda10(args: argparse.Namespace) -> dict[str, Any]:
    started = time.perf_counter()
    config = validate_run_config(args)
    stream_connection = None
    stream_spill_path = None
    stream_spill_owned = False
    agg_connection = None
    agg_spill_path = None
    agg_spill_owned = False
    staging: Optional[pathlib.Path] = None

    process_nodes: dict[str, ProcessMeta] = {}
    create_edges: dict[tuple[str, str], dict[str, Any]] = {}
    action_distribution_process: Counter[str] = Counter()

    events_scanned = 0
    observed_time_min: Optional[str] = None
    observed_time_max: Optional[str] = None
    process_create_events_total = 0
    process_create_self_uuid_events = 0
    process_create_self_uuid_edges_suppressed = 0
    chain_supported_from_create: set[str] = set()
    chain_supported_from_behavior: set[str] = set()
    process_seen_in_open_terminate_process_events: set[str] = set()
    create_anchor_times_by_process: dict[str, list[str]] = defaultdict(list)

    try:
        stream_connection, stream_spill_path, stream_spill_owned = _duck_conn(
            config["cache_dir"],
            memory_limit=config["memory_limit"],
            temp_dir=config["duckdb_temp_dir"],
            threads=config["threads"],
        )
        agg_connection, agg_spill_path, agg_spill_owned = _duck_conn(
            config["cache_dir"],
            memory_limit=config["memory_limit"],
            temp_dir=config["duckdb_temp_dir"],
            threads=config["threads"],
        )
        _validate_required_columns(stream_connection)
        _register_inputs(stream_connection, config)
        _init_behavior_staging_table(agg_connection)

        analysis_start, analysis_end = _resolve_host_time_bounds(stream_connection, config)
        expected_events_in_analysis_range = _expected_events_in_analysis_range(
            stream_connection,
            host=config["host"],
            start_time=analysis_start,
            end_time=analysis_end,
        )
        projection_sql = _projection_sql(config, start_time=analysis_start, end_time=analysis_end)
        reader = _projection_reader(stream_connection, projection_sql, config["batch_size"])
        host_node_id = eda5.normalize_entity(
            entity_type="host",
            raw_value=config["host"],
            host_scope="",
            source_field="host_raw",
        )["canonical_id"]

        for batch in reader:
            behavior_batch_rows: list[dict[str, Any]] = []
            for raw_row in batch.to_pylist():
                row = {key: _safe_str(value) for key, value in raw_row.items()}
                events_scanned += 1
                event_time = row.get("event_time", "")
                if event_time:
                    if observed_time_min is None or event_time < observed_time_min:
                        observed_time_min = event_time
                    if observed_time_max is None or event_time > observed_time_max:
                        observed_time_max = event_time

                object_type = row.get("object_type", "")
                action_raw = row.get("action_raw", "").strip().upper()
                is_process_create = object_type == "PROCESS" and action_raw == "CREATE"
                actor_uuid = row.get("actor_id_raw", "").strip()
                object_uuid = row.get("object_id_raw", "").strip()
                is_process_create_self_uuid = bool(
                    is_process_create and actor_uuid and actor_uuid == object_uuid
                )

                if is_process_create:
                    process_create_events_total += 1
                    if is_process_create_self_uuid:
                        process_create_self_uuid_events += 1
                        process_create_self_uuid_edges_suppressed += 1

                # Acting process resolution (same conservative safety policy as EDA9).
                image_path = row.get("image_path_raw", "")
                if object_type == "PROCESS":
                    if is_process_create and not is_process_create_self_uuid:
                        actor_image_path = row.get("parent_image_path_raw", "")
                        actor_pid_text = row.get("ppid_raw", "")
                    else:
                        actor_image_path = ""
                        actor_pid_text = ""
                else:
                    actor_image_path = image_path
                    actor_pid_text = row.get("pid_raw", "")

                actor_cmp = eda7.process_comparison_form(actor_image_path)
                acting_instance = _resolve_process_instance(
                    mode=config["process_instance_key"],
                    host_node_id=host_node_id,
                    uuid_text="" if is_process_create_self_uuid else actor_uuid,
                    comparison_form=actor_cmp,
                    pid_text=actor_pid_text,
                    date_label=row.get("date_label", ""),
                )

                process_id = ""
                if acting_instance is not None:
                    process_id = _upsert_process(
                        process_nodes,
                        instance=acting_instance,
                        comparison_form=actor_cmp,
                        image_path_raw=actor_image_path,
                        timestamp=event_time,
                        raw_event_id=row.get("raw_event_id", ""),
                        event_locator=row.get("event_locator", ""),
                        ppid_raw=row.get("ppid_raw", ""),
                        parent_image_path_raw=row.get("parent_image_path_raw", ""),
                        parent_process_raw=row.get("parent_process_raw", ""),
                    )

                if object_type == "PROCESS":
                    action_distribution_process[action_raw or "<MISSING>"] += 1

                if is_process_create:
                    child_path = row.get("image_path_raw", "")
                    child_cmp = eda7.process_comparison_form(child_path)
                    child_instance = _resolve_process_instance(
                        mode=config["process_instance_key"],
                        host_node_id=host_node_id,
                        uuid_text=row.get("object_id_raw", ""),
                        comparison_form=child_cmp,
                        pid_text=row.get("pid_raw", ""),
                        date_label=row.get("date_label", ""),
                    )
                    child_id = ""
                    if child_instance is not None:
                        child_id = _upsert_process(
                            process_nodes,
                            instance=child_instance,
                            comparison_form=child_cmp,
                            image_path_raw=child_path,
                            timestamp=event_time,
                            raw_event_id=row.get("raw_event_id", ""),
                            event_locator=row.get("event_locator", ""),
                            ppid_raw=row.get("ppid_raw", ""),
                            parent_image_path_raw=row.get("parent_image_path_raw", ""),
                            parent_process_raw=row.get("parent_process_raw", ""),
                        )
                    if (
                        not is_process_create_self_uuid
                        and process_id
                        and child_id
                    ):
                        _upsert_create_edge(
                            create_edges,
                            parent_id=process_id,
                            child_id=child_id,
                            timestamp=event_time,
                            raw_event_id=row.get("raw_event_id", ""),
                            event_locator=row.get("event_locator", ""),
                        )
                    if process_id:
                        chain_supported_from_create.add(process_id)
                        if event_time:
                            create_anchor_times_by_process[process_id].append(event_time)
                    if child_id:
                        chain_supported_from_create.add(child_id)
                        if event_time:
                            create_anchor_times_by_process[child_id].append(event_time)

                if (
                    object_type == "PROCESS"
                    and action_raw in {"OPEN", "TERMINATE"}
                    and process_id
                ):
                    process_seen_in_open_terminate_process_events.add(process_id)

                # Spill-safe behavior aggregation rows are staged per batch to DuckDB.
                if object_type in {"FILE", "MODULE", "FLOW"} and process_id:
                    chain_supported_from_behavior.add(process_id)
                    behavior_batch_rows.append(
                        {
                            "process_id": process_id,
                            "event_time": event_time,
                            "raw_event_id": row.get("raw_event_id", ""),
                            "object_type": object_type,
                            "action_raw": action_raw,
                            "file_path_raw": row.get("file_path_raw", ""),
                            "module_path_raw": row.get("module_path_raw", ""),
                            "dest_ip_raw": row.get("dest_ip_raw", ""),
                            "destination_raw": row.get("destination_raw", ""),
                            "dest_port_raw": row.get("dest_port_raw", ""),
                            "protocol_raw": row.get("protocol_raw", ""),
                        }
                    )
            _stage_behavior_observations(agg_connection, behavior_batch_rows)

        if not process_nodes:
            raise CacheAuditError("No process instances resolved for selected host/range")
        if events_scanned != expected_events_in_analysis_range:
            raise CacheAuditError(
                "Event stream reconciliation failed: "
                f"expected={expected_events_in_analysis_range} scanned={events_scanned}"
            )

        _build_behavior_compact_table(agg_connection)
        process_instances_rows = [vars(v) for v in process_nodes.values()]
        process_instances_df = pd.DataFrame(process_instances_rows).sort_values(
            ["process_id"], kind="stable"
        )
        if not create_edges:
            create_edges_df = pd.DataFrame(
                columns=[
                    "parent_process_id",
                    "child_process_id",
                    "create_event_count",
                    "first_seen_time",
                    "last_seen_time",
                    "first_raw_event_id",
                    "last_raw_event_id",
                    "first_event_locator",
                    "last_event_locator",
                ]
            )
        else:
            create_edges_df = pd.DataFrame(list(create_edges.values())).sort_values(
                ["parent_process_id", "child_process_id"], kind="stable"
            )

        chain_universe_nodes = set(chain_supported_from_create) | set(chain_supported_from_behavior)

        nodes_set = set(chain_universe_nodes)
        adjacency: dict[str, set[str]] = {node: set() for node in nodes_set}
        parents: dict[str, set[str]] = {node: set() for node in nodes_set}
        undirected: dict[str, set[str]] = {node: set() for node in nodes_set}

        self_loop_count = 0
        for _, row in create_edges_df.iterrows():
            parent_id = _safe_str(row["parent_process_id"])
            child_id = _safe_str(row["child_process_id"])
            if not parent_id or not child_id:
                continue
            if parent_id not in nodes_set or child_id not in nodes_set:
                continue
            if parent_id == child_id:
                self_loop_count += 1
            adjacency.setdefault(parent_id, set()).add(child_id)
            parents.setdefault(child_id, set()).add(parent_id)
            undirected.setdefault(parent_id, set()).add(child_id)
            undirected.setdefault(child_id, set()).add(parent_id)
            nodes_set.add(parent_id)
            nodes_set.add(child_id)

        for node in nodes_set:
            adjacency.setdefault(node, set())
            parents.setdefault(node, set())
            undirected.setdefault(node, set())

        outdegree = {node: len(adjacency[node]) for node in nodes_set}
        indegree = {node: len(parents[node]) for node in nodes_set}
        observed_roots = sorted([node for node in nodes_set if indegree[node] == 0])
        leaf_nodes = sorted([node for node in nodes_set if outdegree[node] == 0])
        multi_parent_nodes = sorted([node for node in nodes_set if indegree[node] > 1])

        components = _component_ids(nodes_set, undirected)
        node_to_component: dict[str, int] = {}
        for comp_idx, comp_nodes in enumerate(components):
            for node in comp_nodes:
                node_to_component[node] = comp_idx

        sccs = _iterative_scc(nodes_set, adjacency)
        cyclic_sccs: list[list[str]] = []
        for scc in sccs:
            if len(scc) > 1:
                cyclic_sccs.append(scc)
            elif scc and scc[0] in adjacency.get(scc[0], set()):
                cyclic_sccs.append(scc)
        cyclic_nodes = {node for scc in cyclic_sccs for node in scc}
        graph_is_acyclic = len(cyclic_sccs) == 0 and self_loop_count == 0

        behavior_stats_by_structure: dict[str, dict[str, Any]] = {}

        root_to_leaf_hops_including: Counter[int] = Counter()
        root_to_leaf_hops_excluding: Counter[int] = Counter()
        per_structure_max_hops_including: list[int] = []
        per_structure_max_hops_excluding: list[int] = []
        global_longest_hops = -1
        global_longest_chain_nodes: list[str] = []
        total_root_to_leaf_path_count_including = 0
        total_root_to_leaf_path_count_excluding = 0

        structure_rows: list[dict[str, Any]] = []
        structure_id_by_process: dict[str, str] = {}
        component_zero_roots = 0
        component_single_root = 0
        component_multi_root = 0
        singleton_structure_count = 0
        acyclic_structure_count = 0
        cyclic_structure_count = 0

        create_edges_grouped: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for _, row in create_edges_df.iterrows():
            parent_id = _safe_str(row["parent_process_id"])
            if parent_id in node_to_component:
                create_edges_grouped[node_to_component[parent_id]].append(row.to_dict())

        for comp_idx, comp_nodes in enumerate(components):
            comp_nodes_sorted = sorted(comp_nodes)
            comp_roots = sorted([n for n in comp_nodes_sorted if indegree.get(n, 0) == 0])
            if len(comp_roots) == 0:
                component_zero_roots += 1
            elif len(comp_roots) == 1:
                component_single_root += 1
            else:
                component_multi_root += 1

            comp_is_singleton = (
                len(comp_nodes_sorted) == 1
                and outdegree.get(comp_nodes_sorted[0], 0) == 0
                and indegree.get(comp_nodes_sorted[0], 0) == 0
            )
            if comp_is_singleton:
                singleton_structure_count += 1

            comp_edges = create_edges_grouped.get(comp_idx, [])
            create_times = []
            for edge_row in comp_edges:
                fst = _safe_str(edge_row.get("first_seen_time"))
                lst = _safe_str(edge_row.get("last_seen_time"))
                if fst:
                    create_times.append(fst)
                if lst:
                    create_times.append(lst)
            for node in comp_nodes_sorted:
                create_times.extend([t for t in create_anchor_times_by_process.get(node, []) if t])
            create_start = min(create_times) if create_times else ""
            create_end = max(create_times) if create_times else ""
            create_duration = (
                (
                    dt.datetime.fromisoformat(create_end)
                    - dt.datetime.fromisoformat(create_start)
                ).total_seconds()
                if create_start and create_end
                else 0.0
            )

            full_start = create_start
            full_end = create_end
            full_duration = (
                (
                    dt.datetime.fromisoformat(full_end)
                    - dt.datetime.fromisoformat(full_start)
                ).total_seconds()
                if full_start and full_end
                else 0.0
            )

            comp_adj = {n: adjacency.get(n, set()) & comp_nodes for n in comp_nodes}
            comp_parents = {n: parents.get(n, set()) & comp_nodes for n in comp_nodes}
            comp_has_cycle = any(node in cyclic_nodes for node in comp_nodes)
            if comp_has_cycle:
                cyclic_structure_count += 1
            else:
                acyclic_structure_count += 1

            root_to_leaf_path_count = 0
            longest_hops: Optional[int] = None
            longest_nodes: Optional[int] = None

            if not comp_has_cycle:
                indeg_local = {n: len(comp_parents[n]) for n in comp_nodes}
                queue = deque(sorted([n for n in comp_nodes if indeg_local[n] == 0]))
                topo_order: list[str] = []
                while queue:
                    cur = queue.popleft()
                    topo_order.append(cur)
                    for child in sorted(comp_adj[cur]):
                        indeg_local[child] -= 1
                        if indeg_local[child] == 0:
                            queue.append(child)

                path_count_to: dict[str, Counter[int]] = {n: Counter() for n in comp_nodes}
                depth_hops: dict[str, int] = {n: 0 for n in comp_nodes}
                pred_for_depth: dict[str, Optional[str]] = {n: None for n in comp_nodes}
                for root in comp_roots:
                    path_count_to[root][0] += 1
                    depth_hops[root] = 0
                for node in topo_order:
                    for child in sorted(comp_adj[node]):
                        for hops, count in path_count_to[node].items():
                            path_count_to[child][hops + 1] += int(count)
                        cand = depth_hops[node] + 1
                        if cand > depth_hops[child]:
                            depth_hops[child] = cand
                            pred_for_depth[child] = node

                leaves = sorted([n for n in comp_nodes if len(comp_adj[n]) == 0])
                hops_hist = Counter()
                for leaf in leaves:
                    leaf_hist = path_count_to.get(leaf, Counter())
                    if not leaf_hist and comp_is_singleton and leaf in comp_roots:
                        leaf_hist = Counter({0: 1})
                    for hops, count_paths in leaf_hist.items():
                        if int(count_paths) <= 0:
                            continue
                        hops_hist[int(hops)] += int(count_paths)
                        root_to_leaf_path_count += int(count_paths)

                if comp_is_singleton and root_to_leaf_path_count == 0:
                    root_to_leaf_path_count = 1
                    hops_hist[0] += 1

                for hops, count in hops_hist.items():
                    root_to_leaf_hops_including[hops] += count
                    total_root_to_leaf_path_count_including += int(count)
                    if not comp_is_singleton:
                        root_to_leaf_hops_excluding[hops] += count
                        total_root_to_leaf_path_count_excluding += int(count)

                longest_hops = int(max(hops_hist)) if hops_hist else 0
                longest_nodes = int(longest_hops + 1)
                per_structure_max_hops_including.append(longest_hops)
                if not comp_is_singleton:
                    per_structure_max_hops_excluding.append(longest_hops)

                if longest_hops > global_longest_hops:
                    best_leaf = None
                    for leaf in sorted([n for n in comp_nodes if len(comp_adj[n]) == 0]):
                        if depth_hops.get(leaf, 0) == longest_hops:
                            best_leaf = leaf
                            break
                    if best_leaf is not None:
                        chain_rev = [best_leaf]
                        cur = best_leaf
                        while pred_for_depth[cur] is not None:
                            cur = pred_for_depth[cur]  # type: ignore[assignment]
                            chain_rev.append(cur)
                        global_longest_chain_nodes = list(reversed(chain_rev))
                        global_longest_hops = longest_hops

            structure_payload = _compact_json(
                [ANALYSIS_RULE_VERSION, config["host"], comp_nodes_sorted]
            )
            structure_id = "struct_" + hashlib.sha256(
                structure_payload.encode("utf-8")
            ).hexdigest()[:24]
            for node in comp_nodes_sorted:
                structure_id_by_process[node] = structure_id

            structure_rows.append(
                {
                    "structure_id": structure_id,
                    "observed_root_ids": _compact_json(comp_roots),
                    "observed_root_count": int(len(comp_roots)),
                    "process_count": int(len(comp_nodes_sorted)),
                    "create_edge_count": int(len(comp_edges)),
                    "root_to_leaf_path_count": (
                        int(root_to_leaf_path_count) if not comp_has_cycle else None
                    ),
                    "longest_process_chain_hops": (
                        int(longest_hops) if longest_hops is not None and not comp_has_cycle else None
                    ),
                    "longest_process_chain_nodes": (
                        int(longest_nodes) if longest_nodes is not None and not comp_has_cycle else None
                    ),
                    "max_children": int(max((outdegree[n] for n in comp_nodes_sorted), default=0)),
                    "leaf_count": int(sum(1 for n in comp_nodes_sorted if outdegree[n] == 0)),
                    "create_backbone_start": create_start,
                    "create_backbone_end": create_end,
                    "create_backbone_duration": float(create_duration),
                    "full_activity_start": full_start,
                    "full_activity_end": full_end,
                    "full_activity_duration": float(full_duration),
                    "file_count": 0,
                    "module_count": 0,
                    "destination_count": 0,
                    "dag_metrics_applicable": bool(not comp_has_cycle),
                }
            )

        def _per_structure_depth_stats(values: list[int]) -> dict[str, Any]:
            if not values:
                return {"avg": 0.0, "median": 0.0, "p90": 0.0, "p95": 0.0, "max": 0}
            ordered = sorted(values)
            counts = Counter(ordered)
            return {
                "avg": float(sum(ordered)) / float(len(ordered)),
                "median": _median(ordered),
                "p90": _weighted_nearest_rank_quantile(counts, quantile=0.9),
                "p95": _weighted_nearest_rank_quantile(counts, quantile=0.95),
                "max": int(max(ordered)),
            }

        roots_leaf_including = _weighted_stats_from_counts(dict(root_to_leaf_hops_including))
        roots_leaf_excluding = _weighted_stats_from_counts(dict(root_to_leaf_hops_excluding))
        nodes_leaf_including = _node_stats_from_hop_counts(dict(root_to_leaf_hops_including))
        nodes_leaf_excluding = _node_stats_from_hop_counts(dict(root_to_leaf_hops_excluding))

        per_structure_depth_including = _per_structure_depth_stats(per_structure_max_hops_including)
        per_structure_depth_excluding = _per_structure_depth_stats(per_structure_max_hops_excluding)

        # Assign structure membership to process output.
        process_instances_df["structure_id"] = process_instances_df["process_id"].map(
            lambda value: structure_id_by_process.get(_safe_str(value), "")
        )
        process_instances_df["included_in_chain_universe"] = process_instances_df["process_id"].map(
            lambda value: bool(_safe_str(value) in chain_universe_nodes)
        )

        structure_map_df = pd.DataFrame(
            sorted(
                (
                    {"process_id": process_id, "structure_id": structure_id}
                    for process_id, structure_id in structure_id_by_process.items()
                ),
                key=lambda item: (item["structure_id"], item["process_id"]),
            )
        )
        if structure_map_df.empty:
            structure_map_df = pd.DataFrame(columns=["process_id", "structure_id"])
        agg_connection.register("_eda10_structure_map_df", structure_map_df)
        agg_connection.execute(
            """
            CREATE OR REPLACE TEMP TABLE structure_map AS
            SELECT CAST(process_id AS VARCHAR) AS process_id,
                   CAST(structure_id AS VARCHAR) AS structure_id
            FROM _eda10_structure_map_df
            """
        )
        agg_connection.unregister("_eda10_structure_map_df")
        agg_connection.execute(
            """
            CREATE OR REPLACE TEMP TABLE behavior_compact_with_structure AS
            SELECT
                bc.process_id,
                sm.structure_id,
                bc.behavior_type,
                bc.action_raw,
                bc.behavior_key,
                bc.attach_event_count,
                bc.first_seen_time,
                bc.last_seen_time,
                bc.first_raw_event_id,
                bc.last_raw_event_id
            FROM behavior_compact bc
            LEFT JOIN structure_map sm USING (process_id)
            WHERE COALESCE(sm.structure_id, '') <> ''
            """
        )

        behavior_rows_count = int(
            agg_connection.execute(
                "SELECT COUNT(*) FROM behavior_compact_with_structure"
            ).fetchone()[0]
        )
        structure_behavior_rows = agg_connection.execute(
            """
            SELECT
                structure_id,
                COUNT(DISTINCT CASE WHEN behavior_type='FILE' THEN behavior_key END) AS file_count,
                COUNT(DISTINCT CASE WHEN behavior_type='MODULE' THEN behavior_key END) AS module_count,
                COUNT(DISTINCT CASE WHEN behavior_type='DESTINATION' THEN behavior_key END) AS destination_count,
                MIN(first_seen_time) AS behavior_min_time,
                MAX(last_seen_time) AS behavior_max_time
            FROM behavior_compact_with_structure
            GROUP BY structure_id
            ORDER BY structure_id
            """
        ).fetchall()
        behavior_stats_by_structure = {
            _safe_str(row[0]): {
                "file_count": int(row[1] or 0),
                "module_count": int(row[2] or 0),
                "destination_count": int(row[3] or 0),
                "behavior_min_time": _safe_str(row[4]),
                "behavior_max_time": _safe_str(row[5]),
            }
            for row in structure_behavior_rows
        }
        for row in structure_rows:
            structure_id = _safe_str(row.get("structure_id"))
            stats = behavior_stats_by_structure.get(structure_id)
            if stats is None:
                continue
            row["file_count"] = int(stats["file_count"])
            row["module_count"] = int(stats["module_count"])
            row["destination_count"] = int(stats["destination_count"])
            full_start = _safe_str(row.get("full_activity_start"))
            full_end = _safe_str(row.get("full_activity_end"))
            behavior_min = _safe_str(stats["behavior_min_time"])
            behavior_max = _safe_str(stats["behavior_max_time"])
            if behavior_min and (not full_start or behavior_min < full_start):
                full_start = behavior_min
            if behavior_max and (not full_end or behavior_max > full_end):
                full_end = behavior_max
            row["full_activity_start"] = full_start
            row["full_activity_end"] = full_end
            if full_start and full_end:
                row["full_activity_duration"] = float(
                    (
                        dt.datetime.fromisoformat(full_end)
                        - dt.datetime.fromisoformat(full_start)
                    ).total_seconds()
                )

        conflict_series = process_instances_df["identity_attribute_conflict"] == True
        identity_conflict_ids = sorted(
            process_instances_df.loc[conflict_series, "process_id"].astype(str).tolist()
        )
        identity_attribute_conflict_count = int(len(identity_conflict_ids))

        chain_metrics = {
            "analysis_rule_version": ANALYSIS_RULE_VERSION,
            "graph_is_acyclic": bool(graph_is_acyclic),
            "chain_metrics_scope": (
                "Root-to-leaf and path-depth metrics are computed only for acyclic structures; "
                "cyclic structures are excluded from DAG-only chain metrics."
                if cyclic_structure_count > 0
                else "All observed structures are acyclic; chain metrics apply to all structures."
            ),
            "root_to_leaf_distribution_including_singletons": roots_leaf_including,
            "root_to_leaf_distribution_excluding_singletons": roots_leaf_excluding,
            "root_to_leaf_node_distribution_including_singletons": nodes_leaf_including,
            "root_to_leaf_node_distribution_excluding_singletons": nodes_leaf_excluding,
            "per_structure_max_depth_hops_including_singletons": per_structure_depth_including,
            "per_structure_max_depth_hops_excluding_singletons": per_structure_depth_excluding,
            "total_root_to_leaf_path_count_including_singletons": int(
                total_root_to_leaf_path_count_including
            ),
            "total_root_to_leaf_path_count_excluding_singletons": int(
                total_root_to_leaf_path_count_excluding
            ),
            "global_longest_process_chain_hops": (
                int(global_longest_hops) if global_longest_hops >= 0 else None
            ),
            "global_longest_process_chain_nodes": (
                int(global_longest_hops + 1) if global_longest_hops >= 0 else None
            ),
            "global_longest_process_chain_sequence": (
                global_longest_chain_nodes if global_longest_chain_nodes else []
            ),
            "global_longest_process_chain_definition": (
                "Longest observed acyclic process-creation chain in the analyzed host range."
            ),
        }

        summary = {
            "analysis_rule_version": ANALYSIS_RULE_VERSION,
            "process_instance_rule_version": PROCESS_INSTANCE_RULE_VERSION,
            "eda07_comparison_rule_version": eda7.COMPARISON_RULE_VERSION,
            "schema_version": SCHEMA_VERSION,
            "run_config": {
                "normalized_cache_dir": str(config["cache_dir"]),
                "period_map_csv": str(config["period_map"]),
                "semantic_mapping_csv": str(config["semantic_mapping_csv"]),
                "manifest_csv": str(config["manifest_csv"]) if config["manifest_csv"] else None,
                "output_dir": str(config["output_dir"]),
                "host": config["host"],
                "analysis_start_time": analysis_start.isoformat(),
                "analysis_end_time": analysis_end.isoformat(),
                "requested_start_time": (
                    config["start_time"].isoformat() if config["start_time"] is not None else None
                ),
                "requested_end_time": (
                    config["end_time"].isoformat() if config["end_time"] is not None else None
                ),
                "process_instance_key": config["process_instance_key"],
                "batch_size": config["batch_size"],
                "duckdb_memory_limit": config["memory_limit"],
                "duckdb_threads": config["threads"],
            },
            "manifest_version": config["manifest_version"],
            "cache_events_total": int(config["cache_metadata"]["total_events_written"]),
            "events_scanned": int(events_scanned),
            "expected_events_in_analysis_range": int(expected_events_in_analysis_range),
            "event_stream_reconciliation_matches": bool(
                int(events_scanned) == int(expected_events_in_analysis_range)
            ),
            "observed_time_min": observed_time_min,
            "observed_time_max": observed_time_max,
            "process_instances_observed_total": int(len(process_nodes)),
            "process_instance_count": int(len(chain_universe_nodes)),
            "process_create_edge_count": int(len(create_edges_df)),
            "process_create_events_total": int(process_create_events_total),
            "process_create_self_uuid_events": int(process_create_self_uuid_events),
            "process_create_self_uuid_edges_suppressed": int(
                process_create_self_uuid_edges_suppressed
            ),
            "observed_root_count": int(len(observed_roots)),
            "component_count": int(len(components)),
            "single_root_component_count": int(component_single_root),
            "multi_root_component_count": int(component_multi_root),
            "zero_root_component_count": int(component_zero_roots),
            "singleton_structure_count": int(singleton_structure_count),
            "acyclic_structure_count": int(acyclic_structure_count),
            "cyclic_structure_count": int(cyclic_structure_count),
            "graph_is_acyclic": bool(graph_is_acyclic),
            "self_loop_count": int(self_loop_count),
            "cyclic_strongly_connected_component_count": int(len(cyclic_sccs)),
            "number_of_processes_in_cyclic_sccs": int(len(cyclic_nodes)),
            "multi_parent_process_count": int(len(multi_parent_nodes)),
            "leaf_process_count": int(len(leaf_nodes)),
            "max_children_of_any_process": int(max(outdegree.values()) if outdegree else 0),
            "average_children_among_processes_with_children": (
                float(sum(v for v in outdegree.values() if v > 0))
                / float(sum(1 for v in outdegree.values() if v > 0))
                if any(v > 0 for v in outdegree.values())
                else 0.0
            ),
            "left_boundary_caveat": (
                "Observed roots have indegree 0 only within the analyzed host range; "
                "true historical parents may exist before analysis_start_time."
            ),
            "right_boundary_caveat": (
                "Observed leaves and activity end-times are bounded by analysis_end_time; "
                "a process may continue or create descendants after the available range."
            ),
            "identity_attribute_conflict_count": int(identity_attribute_conflict_count),
            "identity_attribute_conflict_process_ids_sample": identity_conflict_ids[:20],
            "chain_metrics_interpretation_status": (
                "requires_identity_conflict_review"
                if identity_attribute_conflict_count > 0
                else "clean"
            ),
            "process_action_distribution": dict(sorted(action_distribution_process.items())),
            "process_open_terminate_only_observations_excluded_from_chain_universe": int(
                len(
                    process_seen_in_open_terminate_process_events
                    - chain_supported_from_create
                    - chain_supported_from_behavior
                )
            ),
            "chain_universe_definition": (
                "Includes process instances supported by valid CREATE topology or "
                "FILE/MODULE/FLOW acting-process observations; PROCESS OPEN/TERMINATE-only "
                "ambiguous observations are excluded from chain metrics."
            ),
            "future_label_overlay_workflow_note": (
                "For later exact event labels, map raw_event_id to normalized cache event, "
                "resolve deterministic EDA9-compatible process_id, then join to structure_id."
            ),
            "compact_provenance_note": (
                "Compact outputs retain first/last raw_event_id and counts, not every raw_event_id."
            ),
            "chain_metrics": chain_metrics,
            "reconciliation": {
                "process_instances_rows": int(len(process_instances_df)),
                "process_create_edges_rows": int(len(create_edges_df)),
                "process_behavior_rows": int(behavior_rows_count),
                "structure_summary_rows": int(len(structure_rows)),
                "process_instance_count_matches": bool(len(process_instances_df) == len(process_nodes)),
            },
            "git_commit": _git_commit(config["project_root"]),
            "peak_rss_bytes": _peak_rss_bytes(),
            "elapsed_seconds": time.perf_counter() - started,
        }

        parent = eda5._nearest_existing_directory(config["output_dir"].parent)
        staging = pathlib.Path(tempfile.mkdtemp(prefix=".eda10_staging_", dir=str(parent)))
        process_instances_path = staging / "process_instances.parquet"
        create_edges_path = staging / "process_create_edges_compact.parquet"
        behavior_path = staging / "process_behavior_compact.parquet"
        structure_path = staging / "structure_summary.parquet"
        chain_metrics_path = staging / "chain_metrics.json"
        summary_path = staging / "graph_summary.json"

        structure_columns = [
            "structure_id",
            "observed_root_ids",
            "observed_root_count",
            "process_count",
            "create_edge_count",
            "root_to_leaf_path_count",
            "longest_process_chain_hops",
            "longest_process_chain_nodes",
            "max_children",
            "leaf_count",
            "create_backbone_start",
            "create_backbone_end",
            "create_backbone_duration",
            "full_activity_start",
            "full_activity_end",
            "full_activity_duration",
            "file_count",
            "module_count",
            "destination_count",
            "dag_metrics_applicable",
        ]
        structure_df = pd.DataFrame(structure_rows, columns=structure_columns)
        if not structure_df.empty:
            structure_df = structure_df.sort_values(["structure_id"], kind="stable")

        process_instances_df.to_parquet(process_instances_path, index=False)
        create_edges_df.to_parquet(create_edges_path, index=False)
        behavior_path_literal = eda5._sql_string_literal(str(behavior_path))
        agg_connection.execute(
            f"""
            COPY (
                SELECT
                    process_id,
                    structure_id,
                    behavior_type,
                    action_raw,
                    behavior_key,
                    attach_event_count,
                    CAST(first_seen_time AS VARCHAR) AS first_seen_time,
                    CAST(last_seen_time AS VARCHAR) AS last_seen_time,
                    first_raw_event_id,
                    last_raw_event_id
                FROM behavior_compact_with_structure
                ORDER BY process_id, behavior_type, action_raw, behavior_key
            )
            TO {behavior_path_literal} (FORMAT PARQUET)
            """
        )
        structure_df.to_parquet(structure_path, index=False)
        _atomic_write_json(chain_metrics, chain_metrics_path)

        if config["export_csv"]:
            process_instances_df.to_csv(staging / "process_instances.csv", index=False)
            create_edges_df.to_csv(staging / "process_create_edges_compact.csv", index=False)
            behavior_csv_path = staging / "process_behavior_compact.csv"
            behavior_csv_literal = eda5._sql_string_literal(str(behavior_csv_path))
            agg_connection.execute(
                f"""
                COPY (
                    SELECT
                        process_id,
                        structure_id,
                        behavior_type,
                        action_raw,
                        behavior_key,
                        attach_event_count,
                        CAST(first_seen_time AS VARCHAR) AS first_seen_time,
                        CAST(last_seen_time AS VARCHAR) AS last_seen_time,
                        first_raw_event_id,
                        last_raw_event_id
                    FROM behavior_compact_with_structure
                    ORDER BY process_id, behavior_type, action_raw, behavior_key
                )
                TO {behavior_csv_literal} (HEADER, DELIMITER ',')
                """
            )
            structure_df.to_csv(staging / "structure_summary.csv", index=False)

        summary["deliverable_sha256"] = {
            "process_instances.parquet": _sha256_file(process_instances_path),
            "process_create_edges_compact.parquet": _sha256_file(create_edges_path),
            "process_behavior_compact.parquet": _sha256_file(behavior_path),
            "structure_summary.parquet": _sha256_file(structure_path),
            "chain_metrics.json": _sha256_file(chain_metrics_path),
        }
        summary["graph_summary_content_sha256"] = hashlib.sha256(
            _compact_json(summary).encode("utf-8")
        ).hexdigest()
        _atomic_write_json(summary, summary_path)
        _assert_no_temp_files(staging)
        _publish_staging(staging, config["output_dir"])
        staging = None
        return summary
    except Exception:
        if staging is not None and staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        raise
    finally:
        if stream_connection is not None:
            try:
                stream_connection.close()
            except Exception:
                pass
        if agg_connection is not None:
            try:
                agg_connection.close()
            except Exception:
                pass
        if stream_spill_owned and stream_spill_path is not None:
            shutil.rmtree(stream_spill_path, ignore_errors=True)
        if agg_spill_owned and agg_spill_path is not None:
            shutil.rmtree(agg_spill_path, ignore_errors=True)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    run_eda10(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

