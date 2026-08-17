#!/usr/bin/env python3
"""
EDA 9 — Event-Level Provenance Graph (prototype).

Builds a rich master provenance graph from optc_normalized_v3 cache rows for
one host and one bounded time interval. The graph is event-level: no repeated
event aggregation is performed, and every source event remains traceable via
raw_event_id and event locator metadata.

PROCESS node semantics:
- PROCESS nodes represent process instances, not executable identities.
- This module intentionally diverges from EDA 7's identity policy because it
  needs process-instance links, but it preserves the caveat that actor/object
  UUID semantics are not fully proven in this repository.
- The selected instance strategy and assumption block are always recorded in
  graph_summary.json.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import pathlib
import resource
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from collections import Counter, defaultdict
from typing import Any, Optional

import eda_04_event_taxonomy as eda4
import eda_05_entity_dictionary as eda5
import eda_06_benign_baseline as eda6
import eda_07_process_lineage as eda7
import eda_08_endpoint_network_pivot as eda8
from optc_streaming_parser import SCHEMA_VERSION

CacheAuditError = eda5.CacheAuditError

WINDOW_SIZE = "1min"
GRAPH_RULE_VERSION = "eda09_provenance_graph_v1"
PROCESS_INSTANCE_RULE_VERSION = "eda09_process_instance_v1"
PROCESS_INSTANCE_KEY_UUID = "uuid"
PROCESS_INSTANCE_KEY_PATH_PID = "path_pid"
MISSING_HOST_SENTINEL = eda8.MISSING_HOST_SENTINEL
EVENT_LOCATOR_EXPR = eda8.EVENT_LOCATOR_EXPR
PRECHECK_WARNING = (
    "Full-cache preflight showed host/PID groups commonly map to many child and "
    "parent paths and recur across dates. actorID/objectID groups likewise lack "
    "guaranteed process-instance identity."
)
SYSC0201_CREATE_PROBE_EVIDENCE = {
    "host": "SysClient0201",
    "date": "2019-09-23",
    "create_events_total": 8545,
    "create_self_uuid_events": 124,
    "create_self_uuid_rate": 0.01451,
    "self_uuid_prior_process_event_ppid_pid_match_within_60s": {
        "numerator": 124,
        "denominator": 124,
        "rate": 1.0,
    },
    "self_uuid_prior_uuid_candidate_available": {
        "numerator": 124,
        "denominator": 124,
        "rate": 1.0,
    },
    "self_uuid_nearest_prior_timing_ms": {
        "average_ms": 9.854839,
        "maximum_ms": 400.0,
    },
    "parent_uuid_recovery_adopted": False,
    "parent_uuid_recovery_note": (
        "Intentionally not adopted: prior PROCESS OPEN actor/object UUID semantics "
        "were ambiguous in observed candidates."
    ),
    "create_parent_validation": {"numerator": 8387, "denominator": 8545, "rate": 0.9815},
    "create_child_later_file_flow_actor": {
        "numerator": 5492,
        "denominator": 8545,
        "rate": 0.6427,
    },
    "process_uuid_missing_rate": 0.0,
    "observed_process_actions": ["CREATE", "OPEN", "TERMINATE"],
}

NODE_TYPES = ("HOST", "USER", "PROCESS", "FILE", "DESTINATION")
RELATIONS = (
    "host_observed_process_instance",
    "user_ran_process_instance",
    "process_created_process",
    "process_accessed_file",
    "process_connected_destination",
)

REQUIRED_CACHE_COLUMNS = {
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
    "task_process_uuid_raw",
    "thread_tgt_pid_uuid_raw",
}

NODE_COLUMNS = [
    "node_id",
    "node_type",
    "raw_value",
    "normalized_value",
    "host_scope",
    "entity_status",
    "reliability_high_medium_low",
    "normalization_rule_id",
    "structural_category",
    "source_field",
    "first_seen_time",
    "last_seen_time",
    "first_raw_event_id",
    "first_event_locator",
    "event_count",
    "process_instance_uuid",
    "process_instance_id_source",
    "process_instance_reliability",
    "instance_identity_status",
    "process_identity_id",
    "process_comparison_form",
    "process_name_normalized",
    "image_path_raw",
    "command_line_raw",
    "command_line_normalized",
    "command_line_normalization_status",
    "eda07_process_identity",
    "pid_observed_values",
    "ppid_observed_values",
    "identity_attribute_conflict",
]

EDGE_COLUMNS = [
    "edge_id",
    "source_id",
    "source_type",
    "destination_id",
    "destination_type",
    "relation",
    "timestamp",
    "raw_event_id",
    "host",
    "pid",
    "ppid",
    "action",
    "object_type",
    "event_locator",
    "archive_name",
    "member_name",
    "line_number",
    "date_label",
    "host_id",
    "period",
    "period_role",
    "semantic_group",
    "mapping_rule",
    "source_instance_source",
    "destination_instance_source",
    "user_raw",
    "principal_raw",
    "image_path_raw",
    "parent_image_path_raw",
    "command_line_raw",
    "command_line_normalized",
    "file_path_raw",
    "module_path_raw",
    "dest_ip_raw",
    "dest_port_raw",
    "protocol_raw",
    "destination_structural_category",
    "destination_port_key",
    "actor_id_raw",
    "object_id_raw",
    "task_process_uuid_raw",
    "thread_tgt_pid_uuid_raw",
    "tid_raw",
    "graph_rule_version",
]

PROCESS_EVENT_SEMANTICS_V1: dict[str, Any] = {
    "q1_actor_id_raw_on_process_events": {
        "status": "empirically_supported_create_scope",
        "note": (
            "For ordinary PROCESS CREATE events with distinct nonempty actor/object UUIDs, "
            "actor_id_raw is treated as the parent/existing process instance. For "
            "self-UUID CREATE events where actor_id_raw == object_id_raw, parent identity "
            "is treated as unresolved and no parent-child edge is emitted."
        ),
    },
    "q2_object_id_raw_on_process_events": {
        "status": "empirically_supported_create_scope",
        "note": (
            "For normal PROCESS CREATE events, object_id_raw is treated as the child "
            "process UUID. In the observed self-UUID exceptional pattern, the duplicated "
            "UUID is conservatively retained as the child while parent identity remains "
            "unresolved."
        ),
    },
    "q3_pid_raw_owner": {
        "status": "assumed_unverified",
        "note": "Copied from top-level pid; actor-vs-child ownership is unproven.",
    },
    "q4_ppid_raw_owner": {
        "status": "assumed_unverified",
        "note": "Copied from top-level ppid; parent ownership is unproven.",
    },
    "q5_image_path_raw_meaning": {
        "status": "proven_mapping_assumed_meaning",
        "note": "Mapped from properties.image_path; EDA 6/7 convention treats as child.",
    },
    "q6_parent_image_path_raw_meaning": {
        "status": "proven_mapping_assumed_meaning",
        "note": "Mapped from properties.parent_image_path; EDA 6/7 convention treats as parent.",
    },
    "q7_command_line_raw_meaning": {
        "status": "assumed_unverified",
        "note": "Mapped from properties.command_line; target ownership is unproven.",
    },
    "fallback_pid_semantics_assumed": True,
    "eda07_preflight_warning": PRECHECK_WARNING,
    "sysclient0201_one_day_probe_evidence": SYSC0201_CREATE_PROBE_EVIDENCE,
    "not_universally_validated_across_hosts": True,
    "scope_note": (
        "Empirically supported only for SysClient0201 on 2019-09-23; not yet "
        "validated across all six hosts."
    ),
}

_DRIVE_PATH_PARTS = {"content", "drive", "mydrive"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="EDA 9 — event-level provenance graph prototype (cache only)."
    )
    parser.add_argument("--normalized-cache-dir", required=True)
    parser.add_argument("--period-map-csv", required=True)
    parser.add_argument("--semantic-mapping-csv", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--start-time", required=True)
    parser.add_argument("--end-time", required=True)
    parser.add_argument("--project-root", default=None)
    parser.add_argument("--manifest-csv", default=None)
    parser.add_argument(
        "--process-instance-key",
        choices=(PROCESS_INSTANCE_KEY_UUID, PROCESS_INSTANCE_KEY_PATH_PID),
        default=PROCESS_INSTANCE_KEY_UUID,
    )
    parser.add_argument("--probe-process-semantics", action="store_true")
    parser.add_argument("--batch-size", type=int, default=50_000)
    parser.add_argument("--duckdb-memory-limit", default="4GB")
    parser.add_argument("--duckdb-temp-dir", default=None)
    parser.add_argument("--duckdb-threads", type=int, default=2)
    return parser


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def _compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


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


def load_eda9_period_policy(path: pathlib.Path) -> eda4.PeriodPolicy:
    try:
        return eda4.load_period_policy(str(path), rare_benign_max_count=1)
    except eda4.CacheAuditError as exc:
        raise CacheAuditError(str(exc)) from exc


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
    if args.process_instance_key not in (
        PROCESS_INSTANCE_KEY_UUID,
        PROCESS_INSTANCE_KEY_PATH_PID,
    ):
        raise CacheAuditError(
            f"Unsupported --process-instance-key: {args.process_instance_key!r}"
        )
    if args.duckdb_temp_dir is not None:
        spill = eda5._validate_duckdb_temp_dir(args.duckdb_temp_dir)
        if _looks_like_drive(spill):
            raise CacheAuditError("Google Drive spill paths are refused")
    if not args.probe_process_semantics:
        _validate_output_dir(output_dir, cache_dir)
    batch_size = eda5._validate_positive("--batch-size", args.batch_size)
    memory_limit = eda5._validate_duckdb_memory_limit(args.duckdb_memory_limit)
    threads = eda5._validate_duckdb_threads(args.duckdb_threads)
    start_time = _parse_timestamp(args.start_time, "--start-time")
    end_time = _parse_timestamp(args.end_time, "--end-time")
    if start_time >= end_time:
        raise CacheAuditError("--start-time must be < --end-time")
    policy = load_eda9_period_policy(period_map)
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
        "period_policy": policy,
        "process_instance_key": str(args.process_instance_key),
        "probe_process_semantics": bool(args.probe_process_semantics),
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
            spill_path = pathlib.Path(tempfile.mkdtemp(prefix="eda09_duckdb_tmp_"))
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


def validate_required_cache_columns(connection) -> set[str]:
    describe = connection.execute("DESCRIBE SELECT * FROM events").fetchall()
    available = {str(row[0]) for row in describe}
    missing = sorted(REQUIRED_CACHE_COLUMNS - available)
    if missing:
        raise CacheAuditError(f"Cache missing required columns: {missing}")
    return available


def _register_inputs(connection, config: dict[str, Any]) -> None:
    eda4._register_periods(connection, config["period_policy"])
    frame = config["semantic_mapping_frame"].copy()
    connection.register("_eda09_semantic_map_df", frame)
    connection.execute(
        """
        CREATE TEMP TABLE semantic_map AS
        SELECT
            CAST(raw_object_type AS VARCHAR) AS raw_object_type,
            CAST(raw_action_type AS VARCHAR) AS raw_action_type,
            CAST(semantic_group AS VARCHAR) AS semantic_group,
            CAST(mapping_rule AS VARCHAR) AS mapping_rule
        FROM _eda09_semantic_map_df
        """
    )
    connection.unregister("_eda09_semantic_map_df")


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


def _projection_sql(config: dict[str, Any]) -> str:
    host_literal = eda5._sql_string_literal(config["host"])
    start_literal = eda5._sql_string_literal(config["start_time"].isoformat())
    end_literal = eda5._sql_string_literal(config["end_time"].isoformat())
    return f"""
    WITH projected AS (
        SELECT
            TRY_CAST(timestamp_parsed AS TIMESTAMP) AS event_time,
            CAST(host_raw AS VARCHAR) AS host_raw,
            UPPER(TRIM(CAST(object_raw AS VARCHAR))) AS object_type,
            CAST(action_raw AS VARCHAR) AS action_raw,
            CAST(user_raw AS VARCHAR) AS user_raw,
            CAST(principal_raw AS VARCHAR) AS principal_raw,
            COALESCE(NULLIF(CAST(image_path_raw AS VARCHAR), ''), NULLIF(CAST(process_raw AS VARCHAR), ''), '') AS image_path_raw,
            COALESCE(NULLIF(CAST(parent_image_path_raw AS VARCHAR), ''), NULLIF(CAST(parent_process_raw AS VARCHAR), ''), '') AS parent_image_path_raw,
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
            CAST(task_process_uuid_raw AS VARCHAR) AS task_process_uuid_raw,
            CAST(thread_tgt_pid_uuid_raw AS VARCHAR) AS thread_tgt_pid_uuid_raw,
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
      ON sm.raw_object_type = COALESCE(NULLIF(p.object_type, ''), '{eda4.MISSING_MARKER}')
     AND sm.raw_action_type = COALESCE(NULLIF(p.action_raw, ''), '{eda4.MISSING_MARKER}')
    ORDER BY p.event_time, p.archive_name, p.member_name, p.line_number, p.raw_event_id
    """


def _safe_str(value: object) -> str:
    if value is None:
        return ""
    return str(value)


def _process_instance_id(
    *,
    mode: str,
    host_node_id: str,
    uuid_text: str,
    comparison_form: str,
    pid_text: str,
    date_label: str,
) -> dict[str, str]:
    uuid_clean = _safe_str(uuid_text).strip()
    if mode == PROCESS_INSTANCE_KEY_UUID and uuid_clean:
        payload = _compact_json(
            [PROCESS_INSTANCE_RULE_VERSION, host_node_id, "uuid", uuid_clean]
        )
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]
        return {
            "node_id": f"pinst_{digest}",
            "process_instance_uuid": uuid_clean,
            "process_instance_id_source": "uuid",
            "process_instance_reliability": "medium",
            "instance_identity_status": "assumed_uuid_unverified",
        }
    payload = _compact_json(
        [
            PROCESS_INSTANCE_RULE_VERSION,
            host_node_id,
            "provisional",
            _safe_str(comparison_form),
            _safe_str(pid_text),
            _safe_str(date_label),
        ]
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]
    return {
        "node_id": f"pinst_{digest}",
        "process_instance_uuid": "",
        "process_instance_id_source": "provisional_fallback",
        "process_instance_reliability": "low",
        "instance_identity_status": "provisional_path_pid",
    }


def _resolve_process_instance(
    *,
    mode: str,
    host_node_id: str,
    uuid_text: str,
    comparison_form: str,
    pid_text: str,
    date_label: str,
) -> Optional[dict[str, str]]:
    uuid_clean = _safe_str(uuid_text).strip()
    comparison_clean = _safe_str(comparison_form).strip()
    pid_clean = _safe_str(pid_text).strip()
    if mode == PROCESS_INSTANCE_KEY_UUID and uuid_clean:
        return _process_instance_id(
            mode=mode,
            host_node_id=host_node_id,
            uuid_text=uuid_clean,
            comparison_form=comparison_clean,
            pid_text=pid_clean,
            date_label=date_label,
        )
    if comparison_clean and pid_clean:
        return _process_instance_id(
            mode=PROCESS_INSTANCE_KEY_PATH_PID,
            host_node_id=host_node_id,
            uuid_text="",
            comparison_form=comparison_clean,
            pid_text=pid_clean,
            date_label=date_label,
        )
    return None


def _blank_process_identity(source_field: str) -> dict[str, Any]:
    return {
        "canonical_id": "",
        "entity_type": "process",
        "raw_value": "",
        "normalized_value": "",
        "host_if_applicable": "",
        "reliability_high_medium_low": "",
        "normalization_rule_id": "",
        "entity_status": "",
        "reliability_reason": "",
        "source_field": source_field,
        "structural_category": "",
    }


def _node_template(node_id: str, node_type: str) -> dict[str, Any]:
    row = {column: "" for column in NODE_COLUMNS}
    row["node_id"] = node_id
    row["node_type"] = node_type
    row["event_count"] = 0
    row["identity_attribute_conflict"] = "no"
    row["__pid_values"] = set()
    row["__ppid_values"] = set()
    return row


def _upsert_regular_node(
    nodes: dict[str, dict[str, Any]],
    *,
    normalized: dict[str, Any],
    node_type: str,
    timestamp: str,
    raw_event_id: str,
    event_locator: str,
) -> str:
    node_id = str(normalized["canonical_id"])
    row = nodes.get(node_id)
    if row is None:
        row = _node_template(node_id, node_type)
        row.update(
            {
                "raw_value": _safe_str(normalized.get("raw_value")),
                "normalized_value": _safe_str(normalized.get("normalized_value")),
                "host_scope": _safe_str(normalized.get("host_if_applicable")),
                "entity_status": _safe_str(normalized.get("entity_status")),
                "reliability_high_medium_low": _safe_str(
                    normalized.get("reliability_high_medium_low")
                ),
                "normalization_rule_id": _safe_str(normalized.get("normalization_rule_id")),
                "structural_category": _safe_str(normalized.get("structural_category")),
                "source_field": _safe_str(normalized.get("source_field")),
                "first_seen_time": timestamp,
                "last_seen_time": timestamp,
                "first_raw_event_id": raw_event_id,
                "first_event_locator": event_locator,
            }
        )
        nodes[node_id] = row
    row["event_count"] = int(row["event_count"]) + 1
    row["last_seen_time"] = timestamp
    return node_id


def _upsert_process_node(
    nodes: dict[str, dict[str, Any]],
    *,
    instance_meta: dict[str, str],
    normalized_identity: dict[str, Any],
    comparison_form: str,
    process_name: str,
    image_path: str,
    command_line_raw: str,
    command_norm: dict[str, str],
    eda07_identity: str,
    pid_raw: str,
    ppid_raw: str,
    timestamp: str,
    raw_event_id: str,
    event_locator: str,
) -> str:
    def _merge_text(
        row_obj: dict[str, Any], key: str, incoming: str, *, conflict_sensitive: bool
    ) -> None:
        current = _safe_str(row_obj.get(key))
        new_value = _safe_str(incoming)
        if not current and new_value:
            row_obj[key] = new_value
            return
        if conflict_sensitive and current and new_value and current != new_value:
            row_obj["identity_attribute_conflict"] = "yes"

    node_id = instance_meta["node_id"]
    row = nodes.get(node_id)
    if row is None:
        row = _node_template(node_id, "PROCESS")
        row.update(
            {
                "raw_value": _safe_str(normalized_identity.get("raw_value")),
                "normalized_value": _safe_str(normalized_identity.get("normalized_value")),
                "host_scope": _safe_str(normalized_identity.get("host_if_applicable")),
                "entity_status": _safe_str(normalized_identity.get("entity_status")),
                "reliability_high_medium_low": _safe_str(
                    normalized_identity.get("reliability_high_medium_low")
                ),
                "normalization_rule_id": _safe_str(
                    normalized_identity.get("normalization_rule_id")
                ),
                "structural_category": _safe_str(normalized_identity.get("structural_category")),
                "source_field": _safe_str(normalized_identity.get("source_field")),
                "first_seen_time": timestamp,
                "last_seen_time": timestamp,
                "first_raw_event_id": raw_event_id,
                "first_event_locator": event_locator,
                "process_instance_uuid": _safe_str(instance_meta["process_instance_uuid"]),
                "process_instance_id_source": _safe_str(
                    instance_meta["process_instance_id_source"]
                ),
                "process_instance_reliability": _safe_str(
                    instance_meta["process_instance_reliability"]
                ),
                "instance_identity_status": _safe_str(
                    instance_meta["instance_identity_status"]
                ),
                "process_identity_id": _safe_str(normalized_identity["canonical_id"]),
                "process_comparison_form": comparison_form,
                "process_name_normalized": process_name,
                "image_path_raw": image_path,
                "command_line_raw": command_line_raw,
                "command_line_normalized": _safe_str(
                    command_norm.get("command_line_normalized")
                ),
                "command_line_normalization_status": _safe_str(
                    command_norm.get("normalization_status")
                ),
                "eda07_process_identity": eda07_identity,
            }
        )
        nodes[node_id] = row
    else:
        _merge_text(
            row,
            "raw_value",
            _safe_str(normalized_identity.get("raw_value")),
            conflict_sensitive=True,
        )
        _merge_text(
            row,
            "normalized_value",
            _safe_str(normalized_identity.get("normalized_value")),
            conflict_sensitive=True,
        )
        _merge_text(
            row,
            "host_scope",
            _safe_str(normalized_identity.get("host_if_applicable")),
            conflict_sensitive=False,
        )
        _merge_text(
            row,
            "entity_status",
            _safe_str(normalized_identity.get("entity_status")),
            conflict_sensitive=False,
        )
        _merge_text(
            row,
            "reliability_high_medium_low",
            _safe_str(normalized_identity.get("reliability_high_medium_low")),
            conflict_sensitive=False,
        )
        _merge_text(
            row,
            "normalization_rule_id",
            _safe_str(normalized_identity.get("normalization_rule_id")),
            conflict_sensitive=False,
        )
        _merge_text(
            row,
            "structural_category",
            _safe_str(normalized_identity.get("structural_category")),
            conflict_sensitive=False,
        )
        _merge_text(
            row,
            "source_field",
            _safe_str(normalized_identity.get("source_field")),
            conflict_sensitive=False,
        )
        _merge_text(
            row,
            "process_instance_uuid",
            _safe_str(instance_meta["process_instance_uuid"]),
            conflict_sensitive=True,
        )
        _merge_text(
            row,
            "process_instance_id_source",
            _safe_str(instance_meta["process_instance_id_source"]),
            conflict_sensitive=False,
        )
        _merge_text(
            row,
            "process_instance_reliability",
            _safe_str(instance_meta["process_instance_reliability"]),
            conflict_sensitive=False,
        )
        _merge_text(
            row,
            "instance_identity_status",
            _safe_str(instance_meta["instance_identity_status"]),
            conflict_sensitive=False,
        )
        _merge_text(
            row,
            "process_identity_id",
            _safe_str(normalized_identity["canonical_id"]),
            conflict_sensitive=True,
        )
        _merge_text(
            row,
            "process_comparison_form",
            comparison_form,
            conflict_sensitive=True,
        )
        _merge_text(
            row,
            "process_name_normalized",
            process_name,
            conflict_sensitive=True,
        )
        _merge_text(
            row,
            "image_path_raw",
            image_path,
            conflict_sensitive=True,
        )
        _merge_text(
            row,
            "command_line_raw",
            command_line_raw,
            conflict_sensitive=True,
        )
        _merge_text(
            row,
            "command_line_normalized",
            _safe_str(command_norm.get("command_line_normalized")),
            conflict_sensitive=True,
        )
        _merge_text(
            row,
            "command_line_normalization_status",
            _safe_str(command_norm.get("normalization_status")),
            conflict_sensitive=False,
        )
        _merge_text(
            row,
            "eda07_process_identity",
            eda07_identity,
            conflict_sensitive=True,
        )
    row["event_count"] = int(row["event_count"]) + 1
    row["last_seen_time"] = timestamp
    if pid_raw:
        row["__pid_values"].add(pid_raw)
    if ppid_raw:
        row["__ppid_values"].add(ppid_raw)
    return node_id


def _edge_id(edge: dict[str, Any]) -> str:
    payload = _compact_json(
        [
            GRAPH_RULE_VERSION,
            edge["relation"],
            edge["timestamp"],
            edge["raw_event_id"],
            edge["source_id"],
            edge["destination_id"],
            edge["event_locator"],
        ]
    )
    return "edge_" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def _build_common_edge_fields(
    row: dict[str, Any], *,
    relation: str,
    source_id: str,
    source_type: str,
    destination_id: str,
    destination_type: str,
    source_instance_source: str = "",
    destination_instance_source: str = "",
    command_line_normalized: str = "",
) -> dict[str, Any]:
    edge = {column: "" for column in EDGE_COLUMNS}
    edge.update(
        {
            "source_id": source_id,
            "source_type": source_type,
            "destination_id": destination_id,
            "destination_type": destination_type,
            "relation": relation,
            "timestamp": _safe_str(row.get("event_time")),
            "raw_event_id": _safe_str(row.get("raw_event_id")),
            "host": _safe_str(row.get("host_raw")),
            "pid": _safe_str(row.get("pid_raw")),
            "ppid": _safe_str(row.get("ppid_raw")),
            "action": _safe_str(row.get("action_raw")),
            "object_type": _safe_str(row.get("object_type")),
            "event_locator": _safe_str(row.get("event_locator")),
            "archive_name": _safe_str(row.get("archive_name")),
            "member_name": _safe_str(row.get("member_name")),
            "line_number": _safe_str(row.get("line_number")),
            "date_label": _safe_str(row.get("date_label")),
            "host_id": _safe_str(row.get("host_id")),
            "period": _safe_str(row.get("period")),
            "period_role": _safe_str(row.get("period_role")),
            "semantic_group": _safe_str(row.get("semantic_group")),
            "mapping_rule": _safe_str(row.get("mapping_rule")),
            "source_instance_source": source_instance_source,
            "destination_instance_source": destination_instance_source,
            "user_raw": _safe_str(row.get("user_raw")),
            "principal_raw": _safe_str(row.get("principal_raw")),
            "image_path_raw": _safe_str(row.get("image_path_raw")),
            "parent_image_path_raw": _safe_str(row.get("parent_image_path_raw")),
            "command_line_raw": _safe_str(row.get("command_line_raw")),
            "command_line_normalized": command_line_normalized,
            "file_path_raw": _safe_str(row.get("file_path_raw")),
            "module_path_raw": _safe_str(row.get("module_path_raw")),
            "dest_ip_raw": _safe_str(row.get("dest_ip_raw")),
            "dest_port_raw": _safe_str(row.get("dest_port_raw")),
            "protocol_raw": _safe_str(row.get("protocol_raw")),
            "destination_structural_category": _safe_str(
                row.get("destination_structural_category")
            ),
            "destination_port_key": _safe_str(row.get("destination_port_key")),
            "actor_id_raw": _safe_str(row.get("actor_id_raw")),
            "object_id_raw": _safe_str(row.get("object_id_raw")),
            "task_process_uuid_raw": _safe_str(row.get("task_process_uuid_raw")),
            "thread_tgt_pid_uuid_raw": _safe_str(row.get("thread_tgt_pid_uuid_raw")),
            "tid_raw": _safe_str(row.get("tid_raw")),
            "graph_rule_version": GRAPH_RULE_VERSION,
        }
    )
    edge["edge_id"] = _edge_id(edge)
    return edge


def _projection_reader(connection, config: dict[str, Any]):
    sql = _projection_sql(config)
    return _record_batches(connection, sql, config["batch_size"])


def _probe_process_semantics(connection, config: dict[str, Any]) -> dict[str, Any]:
    target_actions = ("CREATE", "OPEN", "TERMINATE")
    by_actor_images: dict[str, set[str]] = defaultdict(set)
    by_object_images: dict[str, set[str]] = defaultdict(set)
    by_actor_pid: dict[str, set[str]] = defaultdict(set)
    by_object_pid: dict[str, set[str]] = defaultdict(set)
    actor_seen_pid: dict[str, set[str]] = defaultdict(set)
    actor_pid_pending_same_time: dict[str, set[str]] = defaultdict(set)
    ppid_matches = 0
    ppid_total = 0

    process_object_ids_seen: set[str] = set()
    process_object_ids_pending_same_time: set[str] = set()
    process_object_ids_seen_by_action: dict[str, set[str]] = defaultdict(set)
    process_object_ids_pending_same_time_by_action: dict[str, set[str]] = defaultdict(set)

    create_object_ids_seen: set[str] = set()
    create_object_ids_pending_same_time: set[str] = set()
    create_total_events = 0
    create_events_with_nonempty_object_id = 0
    create_object_ids_nonempty: set[str] = set()
    create_object_ids_matched_later_file_flow_actor: set[str] = set()
    create_unmatched_event_count_by_object_id: dict[str, int] = defaultdict(int)
    create_unmatched_event_count_pending_same_time_by_object_id: dict[str, int] = defaultdict(int)
    create_events_with_later_file_flow_actor = 0

    create_parent_denominator = 0
    create_parent_numerator = 0
    create_parent_numerator_by_earlier_action: Counter[str] = Counter()

    actor_matches_prior_object = 0
    actor_matches_prior_object_by_action: Counter[str] = Counter()
    actor_total_file_flow_nonempty = 0
    action_counts: Counter[str] = Counter()
    missing_actor_uuid = 0
    missing_object_uuid = 0
    process_rows_scanned = 0
    current_event_time: Optional[str] = None

    def _flush_same_timestamp_state() -> None:
        if process_object_ids_pending_same_time:
            process_object_ids_seen.update(process_object_ids_pending_same_time)
            process_object_ids_pending_same_time.clear()
        if process_object_ids_pending_same_time_by_action:
            for action_name, object_ids in process_object_ids_pending_same_time_by_action.items():
                process_object_ids_seen_by_action[action_name].update(object_ids)
            process_object_ids_pending_same_time_by_action.clear()
        if create_object_ids_pending_same_time:
            create_object_ids_seen.update(create_object_ids_pending_same_time)
            create_object_ids_pending_same_time.clear()
        if create_unmatched_event_count_pending_same_time_by_object_id:
            for (
                object_id,
                count,
            ) in create_unmatched_event_count_pending_same_time_by_object_id.items():
                create_unmatched_event_count_by_object_id[object_id] += count
            create_unmatched_event_count_pending_same_time_by_object_id.clear()
        if actor_pid_pending_same_time:
            for actor_id, pid_values in actor_pid_pending_same_time.items():
                actor_seen_pid[actor_id].update(pid_values)
            actor_pid_pending_same_time.clear()

    for batch in _projection_reader(connection, config):
        for raw_row in batch.to_pylist():
            row = {key: _safe_str(value) for key, value in raw_row.items()}
            event_time = row.get("event_time", "")
            if current_event_time is None:
                current_event_time = event_time
            elif event_time != current_event_time:
                _flush_same_timestamp_state()
                current_event_time = event_time

            object_type = row.get("object_type", "")
            actor = row.get("actor_id_raw", "").strip()
            object_id = row.get("object_id_raw", "").strip()
            pid = row.get("pid_raw", "").strip()

            # Later FILE/FLOW denominator only; compare strictly against EARLIER PROCESS object IDs.
            if object_type in {"FILE", "FLOW"} and actor:
                actor_total_file_flow_nonempty += 1
                if actor in process_object_ids_seen:
                    actor_matches_prior_object += 1
                for action_name in process_object_ids_seen_by_action:
                    if actor in process_object_ids_seen_by_action[action_name]:
                        actor_matches_prior_object_by_action[action_name] += 1

                if actor in create_object_ids_seen:
                    create_object_ids_matched_later_file_flow_actor.add(actor)
                unmatched_count = create_unmatched_event_count_by_object_id.get(actor, 0)
                if unmatched_count:
                    create_events_with_later_file_flow_actor += unmatched_count
                    create_unmatched_event_count_by_object_id[actor] = 0

            # Learn actor->pid from all event types, but strictly from earlier timestamps.
            if actor and pid:
                actor_pid_pending_same_time[actor].add(pid)

            if object_type == "PROCESS":
                process_rows_scanned += 1
                action_name = row.get("action_raw", "").strip().upper() or "<MISSING>"
                action_counts[action_name] += 1
                image = row.get("image_path_raw", "").strip()
                ppid = row.get("ppid_raw", "").strip()
                if not actor:
                    missing_actor_uuid += 1
                if not object_id:
                    missing_object_uuid += 1
                if actor and image:
                    by_actor_images[actor].add(image)
                if object_id and image:
                    by_object_images[object_id].add(image)
                if actor and pid:
                    by_actor_pid[actor].add(pid)
                if object_id and pid:
                    by_object_pid[object_id].add(pid)
                if actor and ppid:
                    ppid_total += 1
                    if ppid in actor_seen_pid[actor]:
                        ppid_matches += 1
                if object_id:
                    process_object_ids_pending_same_time.add(object_id)
                    process_object_ids_pending_same_time_by_action[action_name].add(object_id)

                if action_name == "CREATE":
                    create_total_events += 1
                    if object_id:
                        create_events_with_nonempty_object_id += 1
                        create_object_ids_nonempty.add(object_id)
                        create_object_ids_pending_same_time.add(object_id)
                        create_unmatched_event_count_pending_same_time_by_object_id[
                            object_id
                        ] += 1
                    if actor:
                        create_parent_denominator += 1
                        if actor in process_object_ids_seen:
                            create_parent_numerator += 1
                        for candidate_action in target_actions:
                            if actor in process_object_ids_seen_by_action.get(
                                candidate_action, set()
                            ):
                                create_parent_numerator_by_earlier_action[candidate_action] += 1

    _flush_same_timestamp_state()

    def _cardinality_summary(mapping: dict[str, set[str]]) -> dict[str, Any]:
        counts = [len(values) for values in mapping.values()]
        if not counts:
            return {"groups": 0, "avg_distinct": 0.0, "max_distinct": 0}
        return {
            "groups": len(counts),
            "avg_distinct": sum(counts) / len(counts),
            "max_distinct": max(counts),
        }

    return {
        "graph_rule_version": GRAPH_RULE_VERSION,
        "process_instance_rule_version": PROCESS_INSTANCE_RULE_VERSION,
        "host": config["host"],
        "start_time": config["start_time"].isoformat(),
        "end_time": config["end_time"].isoformat(),
        "process_rows_scanned": process_rows_scanned,
        "image_path_cardinality_per_actor_id": _cardinality_summary(by_actor_images),
        "image_path_cardinality_per_object_id": _cardinality_summary(by_object_images),
        "pid_cardinality_per_actor_id": _cardinality_summary(by_actor_pid),
        "pid_cardinality_per_object_id": _cardinality_summary(by_object_pid),
        "ppid_equals_prior_actor_pid_rate": {
            "numerator": ppid_matches,
            "denominator": ppid_total,
            "rate": (ppid_matches / ppid_total) if ppid_total else 0.0,
        },
        "later_actor_equals_earlier_object_rate": {
            "numerator": actor_matches_prior_object,
            "denominator": actor_total_file_flow_nonempty,
            "rate": (
                actor_matches_prior_object / actor_total_file_flow_nonempty
                if actor_total_file_flow_nonempty
                else 0.0
            ),
        },
        "later_actor_equals_earlier_object_rate_by_process_action": {
            action_name: {
                "numerator": int(actor_matches_prior_object_by_action.get(action_name, 0)),
                "denominator": int(actor_total_file_flow_nonempty),
                "rate": (
                    float(actor_matches_prior_object_by_action.get(action_name, 0))
                    / float(actor_total_file_flow_nonempty)
                    if actor_total_file_flow_nonempty
                    else 0.0
                ),
            }
            for action_name in sorted(set(action_counts) | set(target_actions))
        },
        "create_child_validation": {
            "total_create_events": int(create_total_events),
            "unique_create_object_ids_nonempty": int(len(create_object_ids_nonempty)),
            "unique_create_object_ids_with_later_file_flow_actor": int(
                len(create_object_ids_matched_later_file_flow_actor)
            ),
            "unique_rate": (
                float(len(create_object_ids_matched_later_file_flow_actor))
                / float(len(create_object_ids_nonempty))
                if create_object_ids_nonempty
                else 0.0
            ),
            "create_events_with_nonempty_object_id": int(
                create_events_with_nonempty_object_id
            ),
            "create_events_with_later_file_flow_actor": int(
                create_events_with_later_file_flow_actor
            ),
            "event_rate": (
                float(create_events_with_later_file_flow_actor)
                / float(create_events_with_nonempty_object_id)
                if create_events_with_nonempty_object_id
                else 0.0
            ),
        },
        "create_parent_validation": {
            "denominator": int(create_parent_denominator),
            "numerator": int(create_parent_numerator),
            "rate": (
                float(create_parent_numerator) / float(create_parent_denominator)
                if create_parent_denominator
                else 0.0
            ),
            "by_earlier_process_action": {
                action_name: {
                    "denominator": int(create_parent_denominator),
                    "numerator": int(
                        create_parent_numerator_by_earlier_action.get(action_name, 0)
                    ),
                    "rate": (
                        float(create_parent_numerator_by_earlier_action.get(action_name, 0))
                        / float(create_parent_denominator)
                        if create_parent_denominator
                        else 0.0
                    ),
                }
                for action_name in target_actions
            },
        },
        "process_action_vocabulary": dict(sorted(action_counts.items())),
        "missing_uuid_rates": {
            "missing_actor_uuid_rows": missing_actor_uuid,
            "missing_object_uuid_rows": missing_object_uuid,
            "process_rows": process_rows_scanned,
            "missing_actor_uuid_rate": (
                missing_actor_uuid / process_rows_scanned if process_rows_scanned else 0.0
            ),
            "missing_object_uuid_rate": (
                missing_object_uuid / process_rows_scanned if process_rows_scanned else 0.0
            ),
        },
    }


def run_eda09(args: argparse.Namespace) -> dict[str, Any]:
    started = time.perf_counter()
    config = validate_run_config(args)
    connection = None
    spill_path = None
    spill_owned = False
    staging: Optional[pathlib.Path] = None
    edges_path: Optional[pathlib.Path] = None

    nodes: dict[str, dict[str, Any]] = {}
    edge_counts: Counter[str] = Counter()
    node_counts: Counter[str] = Counter()
    period_role_counts: Counter[str] = Counter()
    skip_counts: Counter[str] = Counter()
    action_distribution_process: Counter[str] = Counter()
    events_scanned = 0
    events_with_edges = 0
    observed_timestamps: list[str] = []
    events_missing_actor_uuid = 0
    events_missing_object_uuid = 0
    emitted_edge_rows = 0
    process_create_events_total = 0
    process_create_self_uuid_events = 0
    process_create_self_uuid_edges_suppressed = 0

    try:
        connection, spill_path, spill_owned = _duck_conn(
            config["cache_dir"],
            memory_limit=config["memory_limit"],
            temp_dir=config["duckdb_temp_dir"],
            threads=config["threads"],
        )
        validate_required_cache_columns(connection)
        _register_inputs(connection, config)

        if config["probe_process_semantics"]:
            summary = _probe_process_semantics(connection, config)
            print(json.dumps(summary, indent=2, sort_keys=True))
            return summary

        parent = eda5._nearest_existing_directory(config["output_dir"].parent)
        staging = pathlib.Path(tempfile.mkdtemp(prefix=".eda09_staging_", dir=str(parent)))
        edges_path = staging / "edges.csv"
        nodes_path = staging / "nodes.csv"
        summary_path = staging / "graph_summary.json"

        with edges_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=EDGE_COLUMNS)
            writer.writeheader()

            for batch in _projection_reader(connection, config):
                for raw_row in batch.to_pylist():
                    row = {key: _safe_str(value) for key, value in raw_row.items()}
                    events_scanned += 1
                    observed_timestamps.append(row.get("event_time", ""))
                    period_role_counts[row.get("period_role", "unassigned")] += 1
                    row["destination_structural_category"] = eda8.destination_structural_category(
                        row.get("dest_ip_raw") or row.get("destination_raw")
                    )
                    row["destination_port_key"] = (
                        f"{row.get('dest_ip_raw') or row.get('destination_raw')}:{row.get('dest_port_raw')}"
                        if (row.get("dest_ip_raw") or row.get("destination_raw"))
                        and row.get("dest_port_raw")
                        else ""
                    )

                    host_raw = row.get("host_raw", "")
                    if not host_raw:
                        skip_counts["missing_host_raw"] += 1
                        continue

                    object_type = row.get("object_type", "")
                    action_raw = row.get("action_raw", "").strip().upper()
                    is_process_create = object_type == "PROCESS" and action_raw == "CREATE"
                    actor_uuid_raw = row.get("actor_id_raw", "").strip()
                    object_uuid_raw = row.get("object_id_raw", "").strip()
                    is_process_create_self_uuid = bool(
                        is_process_create and actor_uuid_raw and actor_uuid_raw == object_uuid_raw
                    )
                    if is_process_create:
                        process_create_events_total += 1
                        if is_process_create_self_uuid:
                            process_create_self_uuid_events += 1
                            process_create_self_uuid_edges_suppressed += 1
                    if object_type == "PROCESS":
                        if not actor_uuid_raw:
                            events_missing_actor_uuid += 1
                        if not object_uuid_raw:
                            events_missing_object_uuid += 1
                    host_norm = eda5.normalize_entity(
                        entity_type="host",
                        raw_value=host_raw,
                        host_scope="",
                        source_field="host_raw",
                    )
                    host_id = _upsert_regular_node(
                        nodes,
                        normalized=host_norm,
                        node_type="HOST",
                        timestamp=row["event_time"],
                        raw_event_id=row["raw_event_id"],
                        event_locator=row["event_locator"],
                    )
                    row["host_id"] = host_id

                    image_path = row.get("image_path_raw", "")
                    if object_type == "PROCESS":
                        if is_process_create and not is_process_create_self_uuid:
                            actor_image_path = row.get("parent_image_path_raw", "")
                            actor_source_field = "parent_image_path_raw/parent_process_raw_alias"
                            actor_command_line_raw = ""
                            actor_pid_text = row.get("ppid_raw", "")
                        elif is_process_create and is_process_create_self_uuid:
                            actor_image_path = ""
                            actor_source_field = "actor_id_raw_suppressed_for_create_self_uuid"
                            actor_command_line_raw = ""
                            actor_pid_text = ""
                        else:
                            actor_image_path = ""
                            actor_source_field = "actor_id_raw_only_for_process_non_create"
                            actor_command_line_raw = ""
                            actor_pid_text = ""
                    else:
                        actor_image_path = image_path
                        actor_source_field = "image_path_raw/process_raw_alias"
                        actor_command_line_raw = row.get("command_line_raw", "")
                        actor_pid_text = row.get("pid_raw", "")

                    comparison_form_actor = eda7.process_comparison_form(actor_image_path)
                    acting_instance = _resolve_process_instance(
                        mode=config["process_instance_key"],
                        host_node_id=host_id,
                        uuid_text="" if is_process_create_self_uuid else row.get("actor_id_raw", ""),
                        comparison_form=comparison_form_actor,
                        pid_text=actor_pid_text,
                        date_label=row.get("date_label", ""),
                    )
                    process_id = ""
                    command_norm = eda7.normalize_command_line(actor_command_line_raw)
                    if acting_instance is not None:
                        process_identity = (
                            eda5.normalize_entity(
                                entity_type="process",
                                raw_value=actor_image_path,
                                host_scope=host_raw,
                                source_field=actor_source_field,
                            )
                            if actor_image_path
                            else _blank_process_identity(actor_source_field)
                        )
                        process_id = _upsert_process_node(
                            nodes,
                            instance_meta=acting_instance,
                            normalized_identity=process_identity,
                            comparison_form=comparison_form_actor,
                            process_name=eda8.process_display_name(actor_image_path),
                            image_path=actor_image_path,
                            command_line_raw=actor_command_line_raw,
                            command_norm=command_norm,
                            eda07_identity=(
                                eda7.unresolved_process_id(host_id, comparison_form_actor)
                                if comparison_form_actor
                                else ""
                            ),
                            pid_raw=actor_pid_text,
                            ppid_raw=row.get("ppid_raw", ""),
                            timestamp=row["event_time"],
                            raw_event_id=row["raw_event_id"],
                            event_locator=row["event_locator"],
                        )

                    has_edge = False
                    # HOST -> PROCESS
                    if process_id:
                        edge = _build_common_edge_fields(
                            row,
                            relation="host_observed_process_instance",
                            source_id=host_id,
                            source_type="HOST",
                            destination_id=process_id,
                            destination_type="PROCESS",
                            destination_instance_source=acting_instance["process_instance_id_source"],
                            command_line_normalized=command_norm.get("command_line_normalized", ""),
                        )
                        writer.writerow(edge)
                        emitted_edge_rows += 1
                        edge_counts[edge["relation"]] += 1
                        has_edge = True

                    # USER -> PROCESS
                    user_raw = row.get("user_raw") or row.get("principal_raw")
                    if user_raw and process_id:
                        user_norm = eda5.normalize_entity(
                            entity_type="user_principal",
                            raw_value=user_raw,
                            host_scope=host_raw,
                            source_field="user_raw",
                        )
                        user_id = _upsert_regular_node(
                            nodes,
                            normalized=user_norm,
                            node_type="USER",
                            timestamp=row["event_time"],
                            raw_event_id=row["raw_event_id"],
                            event_locator=row["event_locator"],
                        )
                        edge = _build_common_edge_fields(
                            row,
                            relation="user_ran_process_instance",
                            source_id=user_id,
                            source_type="USER",
                            destination_id=process_id,
                            destination_type="PROCESS",
                            destination_instance_source=acting_instance[
                                "process_instance_id_source"
                            ],
                            command_line_normalized=command_norm.get(
                                "command_line_normalized", ""
                            ),
                        )
                        writer.writerow(edge)
                        emitted_edge_rows += 1
                        edge_counts[edge["relation"]] += 1
                        has_edge = True

                    if object_type == "PROCESS":
                        action_distribution_process[action_raw or "<MISSING>"] += 1
                        parent_path = row.get("parent_image_path_raw", "")
                        child_path = row.get("image_path_raw", "")
                        if action_raw == "CREATE":
                            parent_cmp = eda7.process_comparison_form(parent_path)
                            parent_instance = acting_instance
                            child_cmp = eda7.process_comparison_form(child_path)
                            child_instance = _resolve_process_instance(
                                mode=config["process_instance_key"],
                                host_node_id=host_id,
                                uuid_text=row.get("object_id_raw", ""),
                                comparison_form=child_cmp,
                                pid_text=row.get("pid_raw", ""),
                                date_label=row.get("date_label", ""),
                            )
                            if child_instance is not None:
                                child_identity = (
                                    eda5.normalize_entity(
                                        entity_type="process",
                                        raw_value=child_path,
                                        host_scope=host_raw,
                                        source_field="image_path_raw/process_raw_alias",
                                    )
                                    if child_path
                                    else _blank_process_identity("image_path_raw/process_raw_alias")
                                )
                                child_command_raw = row.get("command_line_raw", "")
                                child_command_norm = eda7.normalize_command_line(child_command_raw)
                                child_id = _upsert_process_node(
                                    nodes,
                                    instance_meta=child_instance,
                                    normalized_identity=child_identity,
                                    comparison_form=child_cmp,
                                    process_name=eda8.process_display_name(child_path),
                                    image_path=child_path,
                                    command_line_raw=child_command_raw,
                                    command_norm=child_command_norm,
                                    eda07_identity=(
                                        eda7.unresolved_process_id(host_id, child_cmp)
                                        if child_cmp
                                        else ""
                                    ),
                                    pid_raw=row.get("pid_raw", ""),
                                    ppid_raw=row.get("ppid_raw", ""),
                                    timestamp=row["event_time"],
                                    raw_event_id=row["raw_event_id"],
                                    event_locator=row["event_locator"],
                                )

                                edge = _build_common_edge_fields(
                                    row,
                                    relation="host_observed_process_instance",
                                    source_id=host_id,
                                    source_type="HOST",
                                    destination_id=child_id,
                                    destination_type="PROCESS",
                                    destination_instance_source=child_instance[
                                        "process_instance_id_source"
                                    ],
                                    command_line_normalized=child_command_norm.get(
                                        "command_line_normalized", ""
                                    ),
                                )
                                writer.writerow(edge)
                                emitted_edge_rows += 1
                                edge_counts[edge["relation"]] += 1
                                has_edge = True

                            if (
                                not is_process_create_self_uuid
                                and parent_instance is not None
                                and child_instance is not None
                                and process_id
                            ):
                                parent_id = process_id

                                edge = _build_common_edge_fields(
                                    row,
                                    relation="process_created_process",
                                    source_id=parent_id,
                                    source_type="PROCESS",
                                    destination_id=child_id,
                                    destination_type="PROCESS",
                                    source_instance_source=parent_instance[
                                        "process_instance_id_source"
                                    ],
                                    destination_instance_source=child_instance[
                                        "process_instance_id_source"
                                    ],
                                    command_line_normalized=child_command_norm.get(
                                        "command_line_normalized", ""
                                    ),
                                )
                                writer.writerow(edge)
                                emitted_edge_rows += 1
                                edge_counts[edge["relation"]] += 1
                                has_edge = True

                    file_path = row.get("file_path_raw") or row.get("module_path_raw")
                    if object_type in {"FILE", "MODULE"} or file_path:
                        if file_path and process_id and acting_instance is not None:
                            file_norm = eda5.normalize_entity(
                                entity_type="file_path",
                                raw_value=file_path,
                                host_scope=host_raw,
                                source_field="file_path_raw/module_path_raw",
                            )
                            file_id = _upsert_regular_node(
                                nodes,
                                normalized=file_norm,
                                node_type="FILE",
                                timestamp=row["event_time"],
                                raw_event_id=row["raw_event_id"],
                                event_locator=row["event_locator"],
                            )
                            edge = _build_common_edge_fields(
                                row,
                                relation="process_accessed_file",
                                source_id=process_id,
                                source_type="PROCESS",
                                destination_id=file_id,
                                destination_type="FILE",
                                source_instance_source=acting_instance[
                                    "process_instance_id_source"
                                ],
                                command_line_normalized=command_norm.get(
                                    "command_line_normalized", ""
                                ),
                            )
                            writer.writerow(edge)
                            emitted_edge_rows += 1
                            edge_counts[edge["relation"]] += 1
                            has_edge = True

                    if object_type == "FLOW":
                        destination = row.get("dest_ip_raw") or row.get("destination_raw")
                        if destination and process_id and acting_instance is not None:
                            dest_norm = eda5.normalize_entity(
                                entity_type="destination",
                                raw_value=destination,
                                host_scope="",
                                source_field="dest_ip_raw/destination_raw_alias",
                            )
                            dest_id = _upsert_regular_node(
                                nodes,
                                normalized=dest_norm,
                                node_type="DESTINATION",
                                timestamp=row["event_time"],
                                raw_event_id=row["raw_event_id"],
                                event_locator=row["event_locator"],
                            )
                            edge = _build_common_edge_fields(
                                row,
                                relation="process_connected_destination",
                                source_id=process_id,
                                source_type="PROCESS",
                                destination_id=dest_id,
                                destination_type="DESTINATION",
                                source_instance_source=acting_instance[
                                    "process_instance_id_source"
                                ],
                                command_line_normalized=command_norm.get(
                                    "command_line_normalized", ""
                                ),
                            )
                            writer.writerow(edge)
                            emitted_edge_rows += 1
                            edge_counts[edge["relation"]] += 1
                            has_edge = True

                    if has_edge:
                        events_with_edges += 1
                    else:
                        skip_counts["no_emitted_relations"] += 1

        finalized_nodes: list[dict[str, Any]] = []
        for row in nodes.values():
            row["pid_observed_values"] = _compact_json(sorted(row["__pid_values"]))
            row["ppid_observed_values"] = _compact_json(sorted(row["__ppid_values"]))
            for hidden in ("__pid_values", "__ppid_values", "__first_image", "__first_command"):
                row.pop(hidden, None)
            finalized_nodes.append({column: row.get(column, "") for column in NODE_COLUMNS})
            node_counts[row["node_type"]] += 1

        finalized_nodes.sort(key=lambda item: (item["node_type"], item["node_id"]))
        with nodes_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=NODE_COLUMNS)
            writer.writeheader()
            writer.writerows(finalized_nodes)

        edge_rows = int(sum(edge_counts.values()))
        node_rows = len(finalized_nodes)
        node_type_sum_value = int(sum(node_counts.values()))

        summary = {
            "graph_rule_version": GRAPH_RULE_VERSION,
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
                "start_time": config["start_time"].isoformat(),
                "end_time": config["end_time"].isoformat(),
                "process_instance_key": config["process_instance_key"],
                "batch_size": config["batch_size"],
                "duckdb_memory_limit": config["memory_limit"],
                "duckdb_threads": config["threads"],
            },
            "manifest_version": config["manifest_version"],
            "cache_events_total": int(config["cache_metadata"]["total_events_written"]),
            "events_scanned": events_scanned,
            "events_with_edges": events_with_edges,
            "events_skipped": int(sum(skip_counts.values())),
            "skip_reasons": dict(sorted(skip_counts.items())),
            "node_counts_by_type": dict(sorted(node_counts.items())),
            "edge_counts_by_relation": dict(sorted(edge_counts.items())),
            "period_role_counts": dict(sorted(period_role_counts.items())),
            "process_action_distribution": dict(sorted(action_distribution_process.items())),
            "process_create_events_total": int(process_create_events_total),
            "process_create_self_uuid_events": int(process_create_self_uuid_events),
            "process_create_self_uuid_edges_suppressed": int(
                process_create_self_uuid_edges_suppressed
            ),
            "observed_time_min": min(observed_timestamps) if observed_timestamps else None,
            "observed_time_max": max(observed_timestamps) if observed_timestamps else None,
            "process_instance_count": node_counts.get("PROCESS", 0),
            "process_identity_count": len(
                {
                    item["process_identity_id"]
                    for item in finalized_nodes
                    if item["node_type"] == "PROCESS" and item["process_identity_id"]
                }
            ),
            "process_instances_uuid_backed": sum(
                1
                for item in finalized_nodes
                if item["node_type"] == "PROCESS"
                and item["process_instance_id_source"] == "uuid"
            ),
            "process_instances_provisional_fallback": sum(
                1
                for item in finalized_nodes
                if item["node_type"] == "PROCESS"
                and item["process_instance_id_source"] == "provisional_fallback"
            ),
            "events_missing_actor_uuid": int(events_missing_actor_uuid),
            "events_missing_object_uuid": int(events_missing_object_uuid),
            "identity_attribute_conflict_count": sum(
                1
                for item in finalized_nodes
                if item["node_type"] == "PROCESS"
                and item["identity_attribute_conflict"] == "yes"
            ),
            "process_event_semantics_v1": PROCESS_EVENT_SEMANTICS_V1,
            "fallback_pid_semantics_assumed": True,
            "reconciliation": {
                "edge_rows": edge_rows,
                "node_rows": node_rows,
                "edge_relation_sum_value": edge_rows,
                "edge_relation_sum_matches": bool(edge_rows == emitted_edge_rows),
                "node_type_sum_value": node_type_sum_value,
                "node_type_sum_matches": bool(node_type_sum_value == node_rows),
            },
            "git_commit": _git_commit(config["project_root"]),
            "peak_rss_bytes": _peak_rss_bytes(),
            "elapsed_seconds": time.perf_counter() - started,
        }

        if summary["process_instance_count"] < summary["process_identity_count"]:
            raise CacheAuditError(
                "Reconciliation failure: process_instance_count < process_identity_count"
            )

        summary["deliverable_sha256"] = {
            "nodes.csv": _sha256_file(nodes_path),
            "edges.csv": _sha256_file(edges_path),
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
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
        if spill_owned and spill_path is not None:
            shutil.rmtree(spill_path, ignore_errors=True)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    run_eda09(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
