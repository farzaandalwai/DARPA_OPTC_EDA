"""
EDA 5 — Canonical Entity Dictionary (DARPA OpTC)
==================================================

Cache-only, scale-safe entity extraction from optc_normalized_v3 Parquet.
Five bounded DuckDB payload scans produce partitioned T9 Parquet. T10 and F6
are derived from staged T9 without rescanning the normalized cache.

No verified baseline or ground-truth overlay is applied. Outputs are
descriptive identity artifacts for EDA 6 onward, not behavioral labels.
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
import shutil
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from typing import Iterator, Optional

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from optc_streaming_parser import SCHEMA_VERSION  # type: ignore


ENTITY_TYPES = ("host", "user_principal", "process", "file_path", "destination")
F6_ENTITY_TYPES = ("process", "file_path", "destination", "user_principal")
PAYLOAD_SCAN_COUNT = 5
DEFAULT_MAX_T9_ROWS = 5_000_000
DEFAULT_BATCH_SIZE = 50_000
DEFAULT_MAX_UNRESOLVED_EXAMPLES = 1_000
MAX_DENSE_PLOT_BUCKETS = 1_000_000
PERIOD_POLICY = "full_pilot_unassigned"
BASELINE_STATUS = "deferred_no_verified_baseline"
MISSING_HOST_SCOPE = "<MISSING_HOST_SCOPE>"

REQUIRED_CACHE_COLUMNS = {
    "timestamp_parsed",
    "parse_status",
    "archive_name",
    "member_name",
    "line_number",
    "raw_event_id",
    "object_raw",
    "host_raw",
    "user_raw",
    "principal_raw",
    "image_path_raw",
    "process_raw",
    "file_path_raw",
    "dest_ip_raw",
    "destination_raw",
}

T9_COLUMNS = [
    "canonical_id",
    "entity_type",
    "raw_value",
    "normalized_value",
    "host_if_applicable",
    "first_seen_time",
    "last_seen_time",
    "source_count",
    "reliability_high_medium_low",
    "normalization_rule_id",
    "observation_count",
    "entity_status",
    "reliability_reason",
    "source_field",
    "structural_category",
    "raw_event_example_id",
    "archive_name",
    "member_name",
    "line_number",
]

T10_COLUMNS = [
    "entity_type",
    "total_unique_raw_values",
    "total_unique_canonical_ids",
    "merged_count",
    "unresolved_count",
    "first_seen_after_baseline_count",
    "baseline_status",
    "missing_observation_count",
]

D1_COLUMNS = [
    "rule_id",
    "entity_type",
    "transformation",
    "example_before",
    "example_after",
    "risk_of_error",
]

_DUCKDB_MEMORY_LIMIT_RE = re.compile(
    r"^\d+(\.\d+)?\s*(B|KB|MB|GB|TB|KiB|MiB|GiB|TiB)$",
    re.IGNORECASE,
)
_WINDOWS_DRIVE_PREFIX_RE = re.compile(r"^[A-Za-z]:[\\/]")
_PRIVATE_V4 = tuple(
    ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_PRIVATE_V6 = ipaddress.ip_network("fc00::/7")


class CacheAuditError(Exception):
    """Fatal EDA 5 configuration, cache, resource, or integrity failure."""


@dataclass(frozen=True)
class ScanSpec:
    entity_type: str
    raw_expression: str
    scope_expression: str
    where_expression: str
    projected_expressions: tuple[str, ...] = ()
    aggregate_expressions: tuple[str, ...] = ()


@dataclass
class ExtractionStats:
    entity_type: str
    raw_group_count: int = 0
    observation_count: int = 0
    missing_observation_count: int = 0
    written_rows: int = 0
    unresolved_rows: int = 0
    alias_mismatch_count: int = 0


SCAN_SPECS = (
    ScanSpec(
        "host",
        "CAST(host_raw AS VARCHAR)",
        "''",
        "TRUE",
    ),
    ScanSpec(
        "user_principal",
        "CAST(user_raw AS VARCHAR)",
        "CAST(host_raw AS VARCHAR)",
        "TRUE",
        projected_expressions=(
            "CASE WHEN principal_raw IS NOT NULL "
            "AND CAST(principal_raw AS VARCHAR) <> '' "
            "AND CAST(principal_raw AS VARCHAR) = "
            "COALESCE(CAST(user_raw AS VARCHAR), '') "
            "THEN 1 ELSE 0 END AS principal_preferred_flag",
            # Parser invariant: nonempty principal must equal user_raw.
            "CASE WHEN principal_raw IS NOT NULL "
            "AND CAST(principal_raw AS VARCHAR) <> '' "
            "AND COALESCE(CAST(user_raw AS VARCHAR), '') <> "
            "CAST(principal_raw AS VARCHAR) "
            "THEN 1 ELSE 0 END AS alias_mismatch_flag",
        ),
        aggregate_expressions=(
            "SUM(principal_preferred_flag)::BIGINT AS principal_preferred_count",
            "SUM(alias_mismatch_flag)::BIGINT AS alias_mismatch_count",
        ),
    ),
    ScanSpec(
        "process",
        "COALESCE(NULLIF(CAST(image_path_raw AS VARCHAR), ''), "
        "NULLIF(CAST(process_raw AS VARCHAR), ''), '')",
        "CAST(host_raw AS VARCHAR)",
        "UPPER(TRIM(CAST(object_raw AS VARCHAR))) IN "
        "('PROCESS','FLOW','FILE','MODULE','THREAD','SHELL')",
        projected_expressions=(
            # Coalesced comparison rejects one-sided and two-sided mismatches.
            "CASE WHEN COALESCE(CAST(image_path_raw AS VARCHAR), '') <> "
            "COALESCE(CAST(process_raw AS VARCHAR), '') "
            "THEN 1 ELSE 0 END AS alias_mismatch_flag",
        ),
        aggregate_expressions=(
            "SUM(alias_mismatch_flag)::BIGINT AS alias_mismatch_count",
        ),
    ),
    ScanSpec(
        "file_path",
        "CAST(file_path_raw AS VARCHAR)",
        "CAST(host_raw AS VARCHAR)",
        "UPPER(TRIM(CAST(object_raw AS VARCHAR))) = 'FILE'",
    ),
    ScanSpec(
        "destination",
        "COALESCE(NULLIF(CAST(dest_ip_raw AS VARCHAR), ''), "
        "NULLIF(CAST(destination_raw AS VARCHAR), ''), '')",
        "''",
        "UPPER(TRIM(CAST(object_raw AS VARCHAR))) = 'FLOW'",
        projected_expressions=(
            "CASE WHEN COALESCE(CAST(dest_ip_raw AS VARCHAR), '') <> "
            "COALESCE(CAST(destination_raw AS VARCHAR), '') "
            "THEN 1 ELSE 0 END AS alias_mismatch_flag",
        ),
        aggregate_expressions=(
            "SUM(alias_mismatch_flag)::BIGINT AS alias_mismatch_count",
        ),
    ),
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="EDA 5 — scale-safe canonical entity dictionary (cache only)."
    )
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--normalized-cache-dir", required=True)
    parser.add_argument("--manifest-csv", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--duckdb-memory-limit", default="4GB")
    parser.add_argument("--duckdb-temp-dir", default=None)
    parser.add_argument("--duckdb-threads", type=int, default=2)
    parser.add_argument("--window-size", default="1min")
    parser.add_argument("--max-t9-rows", type=int, default=DEFAULT_MAX_T9_ROWS)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument(
        "--max-unresolved-example-rows",
        type=int,
        default=DEFAULT_MAX_UNRESOLVED_EXAMPLES,
    )
    return parser


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def _sql_string_literal(value: str) -> str:
    if "\x00" in value:
        raise CacheAuditError("DuckDB config value must not contain NUL bytes")
    return "'" + value.replace("'", "''") + "'"


def _validate_duckdb_memory_limit(memory_limit: str) -> str:
    if memory_limit is None:
        raise CacheAuditError("--duckdb-memory-limit is required")
    value = str(memory_limit).strip()
    if not value or not _DUCKDB_MEMORY_LIMIT_RE.fullmatch(value):
        raise CacheAuditError(
            f"Invalid --duckdb-memory-limit={memory_limit!r}; expected '4GB', "
            "'512MB', or similar"
        )
    if any(char in value for char in ";\n\r\\"):
        raise CacheAuditError("Invalid --duckdb-memory-limit: disallowed characters")
    return value


def _validate_duckdb_threads(threads: int) -> int:
    try:
        value = int(threads)
    except (TypeError, ValueError) as exc:
        raise CacheAuditError("--duckdb-threads must be an integer >= 1") from exc
    if value < 1:
        raise CacheAuditError("--duckdb-threads must be >= 1")
    return value


def _validate_nonnegative(name: str, value: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise CacheAuditError(f"{name} must be an integer >= 0") from exc
    if number < 0:
        raise CacheAuditError(f"{name} must be >= 0")
    return number


def _validate_positive(name: str, value: int) -> int:
    number = _validate_nonnegative(name, value)
    if number < 1:
        raise CacheAuditError(f"{name} must be >= 1")
    return number


def _looks_like_drive(path: pathlib.Path) -> bool:
    lowered = str(path).replace("\\", "/").lower()
    return (
        "/content/drive/" in lowered
        or "/google drive/" in lowered
        or "/google drive-" in lowered
        or "/my drive/" in lowered
    )


def _validate_duckdb_temp_dir(temp_dir: str) -> pathlib.Path:
    if temp_dir is None or not str(temp_dir).strip():
        raise CacheAuditError("--duckdb-temp-dir must be nonempty")
    value = str(temp_dir)
    if "\x00" in value or any(char in value for char in ";\n\r"):
        raise CacheAuditError("--duckdb-temp-dir contains disallowed characters")
    path = pathlib.Path(value).expanduser()
    if _looks_like_drive(path):
        raise CacheAuditError("Google Drive spill paths are refused; use local storage")
    return path


def _output_path_preexists(path: pathlib.Path) -> bool:
    """True for all entries, including dangling symlinks."""
    return os.path.lexists(os.fspath(path))


def _validate_output_dir(output_dir: pathlib.Path, cache_dir: pathlib.Path) -> None:
    output_resolved = output_dir.expanduser().resolve(strict=False)
    cache_resolved = cache_dir.expanduser().resolve()
    if output_resolved == cache_resolved or cache_resolved in output_resolved.parents:
        raise CacheAuditError("Output directory must not be the cache or inside it")
    if _output_path_preexists(output_dir):
        raise CacheAuditError(
            f"Refusing existing output path (must not pre-exist): {output_dir}"
        )


def _load_cache_metadata(cache_dir: pathlib.Path) -> dict:
    path = cache_dir / "cache_metadata.json"
    if not path.is_file():
        raise CacheAuditError(f"Required cache metadata missing: {path}")
    try:
        metadata = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CacheAuditError(f"Invalid cache metadata: {path}") from exc
    if metadata.get("schema_version") != SCHEMA_VERSION:
        raise CacheAuditError(
            f"Cache schema mismatch: expected {SCHEMA_VERSION!r}, found "
            f"{metadata.get('schema_version')!r}"
        )
    try:
        total = int(metadata["total_events_written"])
    except (KeyError, TypeError, ValueError) as exc:
        raise CacheAuditError(
            "cache_metadata.json requires integer total_events_written"
        ) from exc
    if total < 0:
        raise CacheAuditError("cache metadata event count must be nonnegative")
    return metadata


def _manifest_metadata(path: pathlib.Path) -> dict:
    import pandas as pd

    frame = pd.read_csv(path, usecols=lambda column: column == "manifest_version")
    if "manifest_version" not in frame.columns or frame.empty:
        raise CacheAuditError("Manifest requires a nonempty manifest_version column")
    versions = sorted(
        set(frame["manifest_version"].dropna().astype(str).str.strip()) - {""}
    )
    if len(versions) != 1:
        raise CacheAuditError(
            f"Manifest must contain exactly one manifest_version; found {versions}"
        )
    return {
        "manifest_version": versions[0],
        "manifest_path": str(path.resolve()),
    }


def validate_run_config(args: argparse.Namespace) -> dict:
    """Validate all configuration before creating/modifying output paths."""
    project_root = pathlib.Path(args.project_root).expanduser()
    cache_dir = pathlib.Path(args.normalized_cache_dir).expanduser()
    manifest_path = pathlib.Path(args.manifest_csv).expanduser()
    output_dir = pathlib.Path(args.output_dir).expanduser()
    if not project_root.is_dir():
        raise CacheAuditError(f"Project root not found: {project_root}")
    if not cache_dir.is_dir() or not any(cache_dir.glob("*.parquet")):
        raise CacheAuditError(f"No Parquet cache files found at: {cache_dir}")
    if not manifest_path.is_file():
        raise CacheAuditError(f"Manifest CSV not found: {manifest_path}")
    if args.window_size != "1min":
        raise CacheAuditError("--window-size currently allows only '1min'")
    memory = _validate_duckdb_memory_limit(args.duckdb_memory_limit)
    threads = _validate_duckdb_threads(args.duckdb_threads)
    if args.duckdb_temp_dir is not None:
        _validate_duckdb_temp_dir(args.duckdb_temp_dir)
    max_t9_rows = _validate_positive("--max-t9-rows", args.max_t9_rows)
    batch_size = _validate_positive("--batch-size", args.batch_size)
    max_unresolved = _validate_nonnegative(
        "--max-unresolved-example-rows", args.max_unresolved_example_rows
    )
    _validate_output_dir(output_dir, cache_dir)
    metadata = _load_cache_metadata(cache_dir)
    return {
        "project_root": project_root,
        "cache_dir": cache_dir,
        "manifest_path": manifest_path,
        "output_dir": output_dir,
        "memory_limit": memory,
        "threads": threads,
        "max_t9_rows": max_t9_rows,
        "batch_size": batch_size,
        "max_unresolved": max_unresolved,
        "cache_metadata": metadata,
    }


def _configure_duckdb(
    connection,
    *,
    memory_limit: str,
    temp_dir: str,
    threads: int,
) -> None:
    memory = _validate_duckdb_memory_limit(memory_limit)
    spill = _validate_duckdb_temp_dir(temp_dir)
    thread_count = _validate_duckdb_threads(threads)
    connection.execute(f"SET memory_limit={_sql_string_literal(memory)}")
    connection.execute(f"SET temp_directory={_sql_string_literal(str(spill))}")
    connection.execute(f"SET threads={thread_count}")
    connection.execute("SET preserve_insertion_order=false")


def _duck_conn(
    cache_dir: pathlib.Path,
    *,
    memory_limit: str = "4GB",
    temp_dir: Optional[str] = None,
    threads: int = 2,
):
    import duckdb

    memory = _validate_duckdb_memory_limit(memory_limit)
    thread_count = _validate_duckdb_threads(threads)
    connection = None
    spill: Optional[pathlib.Path] = None
    owned = False
    try:
        if temp_dir is None:
            spill = pathlib.Path(tempfile.mkdtemp(prefix="eda05_duckdb_tmp_"))
            owned = True
        else:
            spill = _validate_duckdb_temp_dir(temp_dir)
            spill.mkdir(parents=True, exist_ok=True)
        connection = duckdb.connect()
        _configure_duckdb(
            connection,
            memory_limit=memory,
            temp_dir=str(spill),
            threads=thread_count,
        )
        parquet_glob = str(pathlib.Path(cache_dir) / "*.parquet")
        connection.execute(
            "CREATE VIEW events AS SELECT * FROM read_parquet("
            f"{_sql_string_literal(parquet_glob)})"
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


def validate_required_cache_columns(connection) -> set[str]:
    rows = connection.execute("DESCRIBE events").fetchall()
    present = {str(row[0]) for row in rows}
    missing = REQUIRED_CACHE_COLUMNS - present
    if missing:
        raise CacheAuditError(
            f"Normalized cache missing required EDA 5 columns: {sorted(missing)}"
        )
    return present


def _scan_sql(spec: ScanSpec) -> str:
    projected_sql = "".join(
        f",\n            {expression}" for expression in spec.projected_expressions
    )
    aggregate_sql = "".join(
        f",\n        {expression}" for expression in spec.aggregate_expressions
    )
    return f"""
    WITH projected AS (
        SELECT
            {spec.raw_expression} AS raw_value,
            COALESCE({spec.scope_expression}, '') AS host_scope,
            TRY_CAST(timestamp_parsed AS TIMESTAMP) AS event_time,
            COALESCE(CAST(archive_name AS VARCHAR), '') AS archive_name,
            COALESCE(CAST(member_name AS VARCHAR), '') AS member_name,
            TRY_CAST(line_number AS BIGINT) AS line_number,
            COALESCE(CAST(raw_event_id AS VARCHAR), '') AS raw_event_id
            {projected_sql}
        FROM events
        WHERE LOWER(TRIM(CAST(parse_status AS VARCHAR))) = 'ok'
          AND TRY_CAST(timestamp_parsed AS TIMESTAMP) IS NOT NULL
          AND ({spec.where_expression})
    )
    SELECT
        raw_value,
        host_scope,
        COUNT(*)::BIGINT AS observation_count,
        COUNT(DISTINCT struct_pack(
            archive_name := archive_name,
            member_name := member_name
        ))::BIGINT AS source_count,
        MIN(event_time) AS first_seen_time,
        MAX(event_time) AS last_seen_time,
        FIRST(raw_event_id ORDER BY event_time, archive_name, member_name,
              line_number, raw_event_id) AS raw_event_example_id,
        FIRST(archive_name ORDER BY event_time, archive_name, member_name,
              line_number, raw_event_id) AS evidence_archive_name,
        FIRST(member_name ORDER BY event_time, archive_name, member_name,
              line_number, raw_event_id) AS evidence_member_name,
        FIRST(line_number ORDER BY event_time, archive_name, member_name,
              line_number, raw_event_id) AS evidence_line_number
        {aggregate_sql}
    FROM projected
    GROUP BY raw_value, host_scope
    """


def _record_batches(connection, spec: ScanSpec, batch_size: int):
    """Execute one payload scan and return a bounded Arrow RecordBatchReader."""
    relation = connection.execute(_scan_sql(spec))

    modern_reader = getattr(relation, "to_arrow_reader", None)
    if callable(modern_reader):
        return modern_reader(batch_size=batch_size)

    legacy_reader = getattr(relation, "fetch_record_batch", None)
    if callable(legacy_reader):
        return legacy_reader(rows_per_batch=batch_size)

    raise CacheAuditError(
        "Installed DuckDB exposes no supported streaming Arrow reader API"
    )


def _canonical_json(parts: list[str]) -> bytes:
    return json.dumps(
        parts, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def canonical_id(
    entity_type: str,
    scope_token: str,
    normalization_rule_id: str,
    normalized_value: str,
) -> str:
    payload = _canonical_json(
        [
            SCHEMA_VERSION,
            entity_type,
            scope_token,
            normalization_rule_id,
            normalized_value,
        ]
    )
    return "ent_" + hashlib.sha256(payload).hexdigest()[:32]


def _is_windows_looking_path(raw_value: str) -> bool:
    """
    Windows-looking is decided on the raw value BEFORE any transformation:
    drive-letter prefixes (C:/ or C:\\), UNC prefixes (\\\\ or //), or any
    backslash. POSIX-style or bare literals are never transformed.
    """
    return bool(
        _WINDOWS_DRIVE_PREFIX_RE.match(raw_value)
        or raw_value.startswith("\\\\")
        or raw_value.startswith("//")
        or "\\" in raw_value
    )


def _normalize_windows_path(raw_value: str) -> tuple[str, bool]:
    """
    Identity-preserving v1 path normalization for unambiguously
    Windows-looking values only: separator conversion, nothing else.
    Ambiguous/POSIX literals are preserved exactly and reported unresolved.
    """
    if not _is_windows_looking_path(raw_value):
        return raw_value, False
    return raw_value.replace("/", "\\"), True


def classify_ip(value: ipaddress._BaseAddress) -> str:
    """Observable structural classification with explicit precedence."""
    if value.is_loopback:
        return "loopback"
    if value.is_multicast:
        return "multicast"
    if isinstance(value, ipaddress.IPv4Address) and value == ipaddress.ip_address(
        "255.255.255.255"
    ):
        return "limited_broadcast"
    if isinstance(value, ipaddress.IPv4Address) and any(
        value in network for network in _PRIVATE_V4
    ):
        return "internal-looking"
    if isinstance(value, ipaddress.IPv6Address) and value in _PRIVATE_V6:
        return "internal-looking"
    if value.is_global:
        return "external-looking"
    return "other_non_global"


def _scope_token(entity_type: str, host_scope: str, missing_scope: bool) -> str:
    """
    Structured canonical-hash scope token. A missing host scope can never
    collide with any real hostname, including one literally named
    <MISSING_HOST_SCOPE>, because the token is a typed JSON encoding.
    """
    if entity_type in ("host", "destination"):
        return json.dumps(["global"], separators=(",", ":"))
    if missing_scope:
        return json.dumps(["missing_host_scope"], separators=(",", ":"))
    return json.dumps(["host", host_scope], ensure_ascii=False, separators=(",", ":"))


def normalize_entity(
    *,
    entity_type: str,
    raw_value: str,
    host_scope: str,
    source_field: str,
) -> dict:
    """Pure, deterministic, idempotent v1 normalization."""
    raw = str(raw_value)
    scope = "" if entity_type in ("host", "destination") else str(host_scope)
    missing_scope = entity_type not in ("host", "destination") and not scope
    scope_token = _scope_token(entity_type, scope, missing_scope)
    if missing_scope:
        scope = MISSING_HOST_SCOPE

    structural_category = ""
    status = "resolved"
    if entity_type == "host":
        normalized = raw
        rule = "host_exact_v1"
        reliability = "high"
        reason = "Exact nonempty stored host value; no case/FQDN alias merging."
    elif entity_type == "user_principal":
        normalized = raw
        rule = "user_host_scoped_exact_v1"
        reliability = "high" if not missing_scope else "low"
        status = "resolved" if not missing_scope else "unresolved"
        reason = (
            "Exact stored combined user value scoped by exact host; no splitting "
            "or case folding."
            if not missing_scope
            else "User value is present but host scope is missing."
        )
    elif entity_type in ("process", "file_path"):
        normalized, windows_looking = _normalize_windows_path(raw)
        if windows_looking:
            rule = (
                "process_path_separator_v1"
                if entity_type == "process"
                else "file_path_separator_v1"
            )
        else:
            rule = (
                "process_path_literal_unresolved_v1"
                if entity_type == "process"
                else "file_path_literal_unresolved_v1"
            )
        if windows_looking and not missing_scope:
            status = "resolved"
            reliability = "medium" if entity_type == "process" else "high"
            reason = (
                "Event-associated image path normalized by separator only; it "
                "may not always identify the target process."
                if entity_type == "process"
                else "FILE-applicable path normalized by separator only."
            )
        elif not windows_looking:
            status = "unresolved"
            reliability = "low"
            reason = (
                "Ambiguous/POSIX-style or bare literal preserved exactly; no "
                "separator, fuzzy, basename, dot-segment, or case merging."
            )
        else:
            status = "unresolved"
            reliability = "low"
            reason = (
                "Windows-looking path with missing host scope; retained "
                "without fuzzy, basename, dot-segment, or case merging."
            )
    elif entity_type == "destination":
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            normalized = raw
            rule = "destination_literal_unresolved_v1"
            reliability = "low"
            status = "unresolved"
            structural_category = "other_non_global/unresolved"
            reason = "Nonempty destination text is not a valid IPv4/IPv6 address."
        else:
            normalized = str(address)
            rule = "destination_ip_v1"
            reliability = "high"
            status = "resolved"
            structural_category = classify_ip(address)
            reason = (
                "Valid IP canonical text; structural category uses address "
                "properties only, without subnet, reputation, or enrichment."
            )
    else:
        raise CacheAuditError(f"Unknown entity_type: {entity_type}")

    return {
        "canonical_id": canonical_id(entity_type, scope_token, rule, normalized),
        "entity_type": entity_type,
        "raw_value": raw,
        "normalized_value": normalized,
        "host_if_applicable": scope,
        "reliability_high_medium_low": reliability,
        "normalization_rule_id": rule,
        "entity_status": status,
        "reliability_reason": reason,
        "source_field": source_field,
        "structural_category": structural_category,
    }


def _source_field(spec: ScanSpec, row: dict) -> str:
    if spec.entity_type == "host":
        return "host_raw"
    if spec.entity_type == "user_principal":
        preferred = int(row.get("principal_preferred_count") or 0)
        total = int(row["observation_count"])
        if preferred == total:
            return "user_raw:principal_preferred"
        if preferred == 0:
            return "user_raw:property_user_fallback"
        return "user_raw:mixed_principal_and_fallback"
    if spec.entity_type == "process":
        return "image_path_raw/process_raw_alias"
    if spec.entity_type == "file_path":
        return "file_path_raw"
    return "dest_ip_raw/destination_raw_alias"


def _arrow_schema():
    import pyarrow as pa

    return pa.schema(
        [
            pa.field("canonical_id", pa.string(), nullable=False),
            pa.field("entity_type", pa.string(), nullable=False),
            pa.field("raw_value", pa.string(), nullable=False),
            pa.field("normalized_value", pa.string(), nullable=False),
            pa.field("host_if_applicable", pa.string(), nullable=False),
            # Native naive-UTC timestamps, consistent with optc_normalized_v3.
            pa.field("first_seen_time", pa.timestamp("us"), nullable=False),
            pa.field("last_seen_time", pa.timestamp("us"), nullable=False),
            pa.field("source_count", pa.int64(), nullable=False),
            pa.field("reliability_high_medium_low", pa.string(), nullable=False),
            pa.field("normalization_rule_id", pa.string(), nullable=False),
            pa.field("observation_count", pa.int64(), nullable=False),
            pa.field("entity_status", pa.string(), nullable=False),
            pa.field("reliability_reason", pa.string(), nullable=False),
            pa.field("source_field", pa.string(), nullable=False),
            pa.field("structural_category", pa.string(), nullable=False),
            pa.field("raw_event_example_id", pa.string(), nullable=False),
            pa.field("archive_name", pa.string(), nullable=False),
            pa.field("member_name", pa.string(), nullable=False),
            pa.field("line_number", pa.int64(), nullable=False),
        ]
    )


def _write_t9_batch(
    rows: list[dict],
    partition_dir: pathlib.Path,
    part_index: int,
) -> pathlib.Path:
    import pyarrow as pa
    import pyarrow.parquet as pq

    partition_dir.mkdir(parents=True, exist_ok=True)
    path = partition_dir / f"part-{part_index:05d}.parquet"
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    table = pa.Table.from_pylist(rows, schema=_arrow_schema())
    try:
        pq.write_table(table, temporary, compression="snappy")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def extract_t9(
    connection,
    t9_root: pathlib.Path,
    *,
    batch_size: int,
    max_t9_rows: int,
    max_unresolved_examples: int,
) -> tuple[dict[str, ExtractionStats], list[dict], int]:
    """Run exactly five payload scans and incrementally write partitioned T9."""
    stats = {entity_type: ExtractionStats(entity_type) for entity_type in ENTITY_TYPES}
    unresolved_examples: list[dict] = []
    total_written = 0
    scan_count = 0

    for scan_index, spec in enumerate(SCAN_SPECS, start=1):
        scan_count += 1
        print(
            f"[SCAN {scan_index}/{PAYLOAD_SCAN_COUNT}] {spec.entity_type} ...",
            flush=True,
        )
        partition = t9_root / f"entity_type={spec.entity_type}"
        part_index = 0
        for batch in _record_batches(connection, spec, batch_size):
            output_rows: list[dict] = []
            for row in batch.to_pylist():
                observation_count = int(row["observation_count"])
                current = stats[spec.entity_type]
                current.raw_group_count += 1
                current.observation_count += observation_count
                current.alias_mismatch_count += int(
                    row.get("alias_mismatch_count") or 0
                )
                raw_value = row.get("raw_value")
                if raw_value is None or str(raw_value).strip() == "":
                    # Null, empty, and whitespace-only values are missing
                    # observations; they never enter T9 or F6.
                    current.missing_observation_count += observation_count
                    continue
                entity = normalize_entity(
                    entity_type=spec.entity_type,
                    raw_value=str(raw_value),
                    host_scope=str(row.get("host_scope") or ""),
                    source_field=_source_field(spec, row),
                )
                evidence_event_id = str(row.get("raw_event_example_id") or "")
                evidence_archive = str(row.get("evidence_archive_name") or "")
                evidence_member = str(row.get("evidence_member_name") or "")
                evidence_line = row.get("evidence_line_number")
                if (
                    not evidence_event_id
                    or not evidence_archive
                    or not evidence_member
                    or evidence_line is None
                ):
                    raise CacheAuditError(
                        f"{spec.entity_type} raw identity key "
                        f"{str(raw_value)!r} has an incomplete evidence "
                        "locator (raw_event_id/archive/member/line_number); "
                        "no output will be published"
                    )
                entity.update(
                    {
                        "first_seen_time": row["first_seen_time"],
                        "last_seen_time": row["last_seen_time"],
                        "source_count": int(row["source_count"]),
                        "observation_count": observation_count,
                        "raw_event_example_id": evidence_event_id,
                        "archive_name": evidence_archive,
                        "member_name": evidence_member,
                        "line_number": int(evidence_line),
                    }
                )
                # Reindex explicitly to preserve the required schema order.
                entity = {column: entity[column] for column in T9_COLUMNS}
                output_rows.append(entity)
                current.written_rows += 1
                if entity["entity_status"] == "unresolved":
                    current.unresolved_rows += 1
                    if len(unresolved_examples) < max_unresolved_examples:
                        unresolved_examples.append(entity.copy())

            if output_rows:
                if total_written + len(output_rows) > max_t9_rows:
                    required_at_least = total_written + len(output_rows)
                    raise CacheAuditError(
                        f"T9 requires at least {required_at_least:,} rows, "
                        f"exceeding --max-t9-rows={max_t9_rows:,}; no output "
                        "will be published"
                    )
                _write_t9_batch(output_rows, partition, part_index)
                part_index += 1
                total_written += len(output_rows)

        if part_index == 0:
            # Guarantee a schema-valid empty partition so downstream T10/F6
            # read_parquet globs never fail on an all-missing/empty cache.
            _write_t9_batch([], partition, part_index)

        if stats[spec.entity_type].alias_mismatch_count:
            raise CacheAuditError(
                f"{spec.entity_type} alias integrity failed: "
                f"{stats[spec.entity_type].alias_mismatch_count:,} event(s) "
                "contain conflicting alias/principal fields"
            )
        scan_stats = stats[spec.entity_type]
        print(
            f"[SCAN {scan_index}/{PAYLOAD_SCAN_COUNT}] {spec.entity_type} "
            f"complete: observations={scan_stats.observation_count:,}, "
            f"missing={scan_stats.missing_observation_count:,}, "
            f"T9 rows={scan_stats.written_rows:,}",
            flush=True,
        )

    if scan_count != PAYLOAD_SCAN_COUNT:
        raise CacheAuditError(
            f"Payload scan count {scan_count} != required {PAYLOAD_SCAN_COUNT}"
        )
    return stats, unresolved_examples, scan_count


def _t9_glob(t9_root: pathlib.Path) -> str:
    return str(t9_root / "entity_type=*" / "*.parquet")


def build_t10(connection, t9_root: pathlib.Path, stats: dict[str, ExtractionStats]):
    import pandas as pd

    glob = _sql_string_literal(_t9_glob(t9_root))
    rows = connection.execute(
        f"""
        SELECT
            entity_type,
            COUNT(*)::BIGINT AS total_unique_raw_values,
            COUNT(DISTINCT canonical_id)::BIGINT AS total_unique_canonical_ids,
            SUM(CASE WHEN entity_status = 'unresolved' THEN 1 ELSE 0 END)::BIGINT
                AS unresolved_count
        FROM read_parquet({glob}, hive_partitioning=false)
        GROUP BY entity_type
        """
    ).fetchall()
    by_type = {
        str(row[0]): {
            "total_unique_raw_values": int(row[1]),
            "total_unique_canonical_ids": int(row[2]),
            "unresolved_count": int(row[3]),
        }
        for row in rows
    }
    output = []
    for entity_type in ENTITY_TYPES:
        values = by_type.get(
            entity_type,
            {
                "total_unique_raw_values": 0,
                "total_unique_canonical_ids": 0,
                "unresolved_count": 0,
            },
        )
        merged = (
            values["total_unique_raw_values"]
            - values["total_unique_canonical_ids"]
        )
        if merged < 0:
            raise CacheAuditError(f"Negative merged_count for {entity_type}")
        output.append(
            {
                "entity_type": entity_type,
                **values,
                "merged_count": merged,
                "first_seen_after_baseline_count": None,
                "baseline_status": BASELINE_STATUS,
                "missing_observation_count": stats[
                    entity_type
                ].missing_observation_count,
            }
        )
    return pd.DataFrame(output, columns=T10_COLUMNS)


def fetch_f6_sparse(connection, t9_root: pathlib.Path):
    """Query staged T9 only. This never references the normalized-cache view."""
    glob = _sql_string_literal(_t9_glob(t9_root))
    placeholders = ",".join(_sql_string_literal(value) for value in F6_ENTITY_TYPES)
    return connection.execute(
        f"""
        WITH canonical_first AS (
            SELECT
                entity_type,
                canonical_id,
                MIN(first_seen_time) AS first_seen_time
            FROM read_parquet({glob}, hive_partitioning=false)
            WHERE entity_type IN ({placeholders})
            GROUP BY entity_type, canonical_id
        )
        SELECT
            entity_type,
            date_trunc('minute', first_seen_time) AS bucket,
            COUNT(*)::BIGINT AS new_entity_count
        FROM canonical_first
        WHERE first_seen_time IS NOT NULL
        GROUP BY entity_type, bucket
        ORDER BY bucket, entity_type
        """
    ).fetchdf()


def _minute_grid_count(first, last) -> int:
    seconds = (last - first).total_seconds()
    if seconds < 0:
        raise CacheAuditError(f"Invalid F6 timestamp span: first={first}, last={last}")
    return int(seconds // 60) + 1


def build_dense_f6(sparse):
    """Zero-fill a common one-minute grid after a hard pre-allocation cap."""
    import pandas as pd

    if sparse.empty:
        return pd.DataFrame(
            columns=["bucket", *F6_ENTITY_TYPES]
        )
    work = sparse.copy()
    work["bucket"] = pd.to_datetime(work["bucket"])
    first = work["bucket"].min()
    last = work["bucket"].max()
    requested = _minute_grid_count(first, last)
    if requested > MAX_DENSE_PLOT_BUCKETS:
        raise CacheAuditError(
            "Refusing F6 dense one-minute grid before pd.date_range: "
            f"first_bucket={first}, last_bucket={last}, "
            f"requested_bucket_count={requested:,}, "
            f"MAX_DENSE_PLOT_BUCKETS={MAX_DENSE_PLOT_BUCKETS:,}. Review a "
            "timestamp outlier or unexpectedly large span."
        )
    grid = pd.DataFrame(
        {"bucket": pd.date_range(first, last, freq="1min")}
    )
    pivot = work.pivot_table(
        index="bucket",
        columns="entity_type",
        values="new_entity_count",
        aggfunc="sum",
        fill_value=0,
    ).reset_index()
    dense = grid.merge(pivot, how="left", on="bucket")
    for entity_type in F6_ENTITY_TYPES:
        if entity_type not in dense:
            dense[entity_type] = 0
        dense[entity_type] = dense[entity_type].fillna(0).astype("int64")
    return dense[["bucket", *F6_ENTITY_TYPES]]


def validate_t9_t10_f6(
    connection,
    t9_root: pathlib.Path,
    t10,
    sparse_f6,
    dense_f6,
    stats: dict[str, ExtractionStats],
) -> None:
    glob = _sql_string_literal(_t9_glob(t9_root))
    duplicates = connection.execute(
        f"""
        SELECT COUNT(*) FROM (
            SELECT entity_type, host_if_applicable, raw_value
            FROM read_parquet({glob}, hive_partitioning=false)
            GROUP BY entity_type, host_if_applicable, raw_value
            HAVING COUNT(*) <> 1 OR COUNT(DISTINCT canonical_id) <> 1
        )
        """
    ).fetchone()[0]
    if int(duplicates):
        raise CacheAuditError("T9 composite raw identity keys are not unique")
    invalid_aliases = connection.execute(
        f"""
        SELECT COUNT(*) FROM (
            SELECT canonical_id
            FROM read_parquet({glob}, hive_partitioning=false)
            GROUP BY canonical_id
            HAVING COUNT(DISTINCT struct_pack(
                entity_type := entity_type,
                scope_token := host_if_applicable,
                rule_id := normalization_rule_id,
                normalized_value := normalized_value
            )) <> 1
        )
        """
    ).fetchone()[0]
    if int(invalid_aliases):
        raise CacheAuditError(
            "A canonical_id repeats across non-equivalent normalized identity keys"
        )

    t10_by_type = t10.set_index("entity_type")
    for entity_type in ENTITY_TYPES:
        row = t10_by_type.loc[entity_type]
        if int(row["total_unique_raw_values"]) != stats[entity_type].written_rows:
            raise CacheAuditError(f"T10 raw count mismatch for {entity_type}")
        expected_merged = int(row["total_unique_raw_values"]) - int(
            row["total_unique_canonical_ids"]
        )
        if int(row["merged_count"]) != expected_merged or expected_merged < 0:
            raise CacheAuditError(f"T10 merged_count mismatch for {entity_type}")
        if int(row["unresolved_count"]) != stats[entity_type].unresolved_rows:
            raise CacheAuditError(f"T10 unresolved_count mismatch for {entity_type}")
        if not (
            row["first_seen_after_baseline_count"] is None
            or (
                isinstance(row["first_seen_after_baseline_count"], float)
                and math.isnan(row["first_seen_after_baseline_count"])
            )
        ):
            raise CacheAuditError("Baseline count must remain null/deferred")

    f6_expected_rows = connection.execute(
        f"""
        SELECT entity_type, COUNT(DISTINCT canonical_id)::BIGINT
        FROM read_parquet({glob}, hive_partitioning=false)
        WHERE entity_type IN (
            {",".join(_sql_string_literal(value) for value in F6_ENTITY_TYPES)}
        )
        GROUP BY entity_type
        """
    ).fetchall()
    expected = {str(row[0]): int(row[1]) for row in f6_expected_rows}
    sparse_totals = (
        sparse_f6.groupby("entity_type")["new_entity_count"].sum().to_dict()
        if not sparse_f6.empty
        else {}
    )
    for entity_type in F6_ENTITY_TYPES:
        if int(sparse_totals.get(entity_type, 0)) != expected.get(entity_type, 0):
            raise CacheAuditError(f"F6 sparse reconciliation failed: {entity_type}")
        if int(dense_f6[entity_type].sum()) != expected.get(entity_type, 0):
            raise CacheAuditError(f"F6 dense reconciliation failed: {entity_type}")


def create_f6(dense, png_path: pathlib.Path, pdf_path: pathlib.Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axis = plt.subplots(figsize=(13, 6), constrained_layout=True)
    colors = {
        "process": "#4472C4",
        "file_path": "#ED7D31",
        "destination": "#70AD47",
        "user_principal": "#A5A5A5",
    }
    for entity_type in F6_ENTITY_TYPES:
        axis.plot(
            dense["bucket"],
            dense[entity_type],
            label=entity_type,
            color=colors[entity_type],
            linewidth=1.1,
        )
    axis.set_xlabel("Timestamp window (1 minute, naive UTC)")
    axis.set_ylabel("First-seen canonical entities per minute")
    axis.set_title(
        "F6 New Entity Rate — period=full_pilot_unassigned\n"
        "No verified baseline | ground-truth/attack overlay absent"
    )
    axis.legend()
    axis.grid(alpha=0.25)
    fig.savefig(png_path, dpi=180, bbox_inches="tight")
    fig.savefig(pdf_path, bbox_inches="tight")
    plt.close(fig)


def d1_rows() -> list[dict]:
    return [
        {
            "rule_id": "host_exact_v1",
            "entity_type": "host",
            "transformation": "Preserve exact nonempty stored host string.",
            "example_before": "HostA.example",
            "example_after": "HostA.example",
            "risk_of_error": "Aliases/case variants deliberately remain separate.",
        },
        {
            "rule_id": "user_host_scoped_exact_v1",
            "entity_type": "user_principal",
            "transformation": "Preserve exact stored user string; scope by exact host.",
            "example_before": "DOMAIN\\Alice",
            "example_after": "DOMAIN\\Alice",
            "risk_of_error": "Cross-host/domain aliases deliberately remain separate.",
        },
        {
            "rule_id": "process_path_separator_v1",
            "entity_type": "process",
            "transformation": (
                "For unambiguously Windows-looking raw values only (drive-letter "
                "prefix, \\\\ or // UNC prefix, or any backslash): convert / to "
                "\\; preserve case, dots, UNC, basename."
            ),
            "example_before": "C:/Tools/App.exe",
            "example_after": "C:\\Tools\\App.exe",
            "risk_of_error": "Separator aliases merge; target-process meaning may vary.",
        },
        {
            "rule_id": "process_path_literal_unresolved_v1",
            "entity_type": "process",
            "transformation": (
                "Preserve exact ambiguous/POSIX-style or bare literal; no "
                "separator conversion; mark unresolved with low reliability."
            ),
            "example_before": "/usr/bin/tool",
            "example_after": "/usr/bin/tool",
            "risk_of_error": "Distinct-looking literals never merge; duplicates may remain.",
        },
        {
            "rule_id": "file_path_separator_v1",
            "entity_type": "file_path",
            "transformation": (
                "For unambiguously Windows-looking raw values only (drive-letter "
                "prefix, \\\\ or // UNC prefix, or any backslash): convert / to "
                "\\; preserve case, dots, UNC, basename."
            ),
            "example_before": "C:/Temp/a.txt",
            "example_after": "C:\\Temp\\a.txt",
            "risk_of_error": "Separator aliases merge; no filesystem resolution occurs.",
        },
        {
            "rule_id": "file_path_literal_unresolved_v1",
            "entity_type": "file_path",
            "transformation": (
                "Preserve exact ambiguous/POSIX-style or bare literal; no "
                "separator conversion; mark unresolved with low reliability."
            ),
            "example_before": "relative/path/file.txt",
            "example_after": "relative/path/file.txt",
            "risk_of_error": "Distinct-looking literals never merge; duplicates may remain.",
        },
        {
            "rule_id": "destination_ip_v1",
            "entity_type": "destination",
            "transformation": "Canonical Python ipaddress IPv4/IPv6 text.",
            "example_before": "2001:0db8::1",
            "example_after": "2001:db8::1",
            "risk_of_error": "Only syntactically equivalent IP aliases merge.",
        },
        {
            "rule_id": "destination_literal_unresolved_v1",
            "entity_type": "destination",
            "transformation": "Preserve exact nonempty invalid-IP text; mark unresolved.",
            "example_before": "not-an-ip",
            "example_after": "not-an-ip",
            "risk_of_error": "No inferred destination identity or reputation.",
        },
    ]


def d1_text(rows: list[dict]) -> str:
    lines = [
        "D1 — Entity Normalization Rulebook",
        "=" * 40,
        "",
        "All rules are deterministic and idempotent. Raw values remain in T9.",
        "Prohibited: fuzzy/similarity matching, case folding, basename-only merging,",
        "dot-segment resolution, environment expansion, PID/command-line/parent",
        "identity merging, directed-broadcast inference without subnet context,",
        "reputation, threat intelligence, geolocation, or behavioral labels.",
        "Prohibited: separator conversion of ambiguous/POSIX-style or bare",
        "literals; only unambiguously Windows-looking values are transformed.",
        "",
        "Deferred: module/new/generic paths, registry keys, process lineage,",
        "command-line entities, port/protocol identity, and verified baselines.",
        "",
    ]
    for row in rows:
        lines.extend(
            [
                f"{row['rule_id']} [{row['entity_type']}]",
                f"  transformation : {row['transformation']}",
                f"  example        : {row['example_before']} -> {row['example_after']}",
                f"  risk_of_error  : {row['risk_of_error']}",
                "",
            ]
        )
    return "\n".join(lines)


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


def _atomic_write_json(payload: dict, path: pathlib.Path) -> None:
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
    if _output_path_preexists(output_dir):
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


def _build_readme(metadata: dict) -> str:
    return "\n".join(
        [
            "EDA 5 — Canonical Entity Dictionary",
            "=" * 42,
            f"Generated UTC: {metadata['generated_utc']}",
            "",
            "Scope",
            "-----",
            "Cache-only analysis of optc_normalized_v3. Period is",
            "full_pilot_unassigned. No verified baseline exists, so",
            "first_seen_after_baseline_count is null/deferred, never zero.",
            "No ground-truth overlay. No rarity, anomaly, maliciousness, attack,",
            "reputation, threat-intelligence, or geolocation interpretation.",
            "Canonical IDs are intended for EDA 6 onward; EDA 1–4 and the cache",
            "are not retrofitted or rewritten.",
            "",
            "T9 grain and counts",
            "-------------------",
            "Global key: (entity_type, raw_value). Host-scoped key:",
            "(entity_type, exact host_if_applicable, raw_value). raw_value is",
            "the exact string stored in Parquet. source_count is exact distinct",
            "(archive_name, member_name) provenance members; observation_count",
            "is exact contributing cache events. Null, empty, and",
            "whitespace-only values are missing observations: they are excluded",
            "from T9 and F6 and counted by entity type in T10/run metadata.",
            "first_seen_time and last_seen_time are stored as native Parquet",
            "timestamp[us] values in naive UTC, consistent with",
            "optc_normalized_v3. Every T9 row carries a deterministic earliest",
            "evidence locator (raw_event_example_id, archive_name, member_name,",
            "line_number), selected by ordering on timestamp, archive_name,",
            "member_name, line_number, raw_event_id.",
            "T9 is partitioned Parquet by entity_type and written incrementally.",
            f"The conservative publication cap is {metadata['max_t9_rows']:,} "
            f"T9 rows; Arrow normalization batches contain at most "
            f"{metadata['batch_size']:,} compact groups.",
            "",
            "Entities",
            "--------",
            "host=host_raw (global, exact); user_principal=user_raw (host-scoped;",
            "principal_raw only documents preferred provenance; actor/logon IDs",
            "are excluded); process=image_path_raw/process_raw alias (host-scoped;",
            "event-associated image path, not always the target process);",
            "file_path=file_path_raw on FILE records (host-scoped);",
            "destination=dest_ip_raw/destination_raw alias on FLOW records",
            "(global; port/protocol/direction are not identity components).",
            "",
            "Normalization and IDs",
            "---------------------",
            "See D1. Separator conversion (forward slash to backslash) applies",
            "only to unambiguously Windows-looking raw values (drive-letter",
            "prefix, \\\\ or // UNC prefix, or any backslash); ambiguous/POSIX",
            "literals are preserved exactly and marked unresolved under the",
            "*_literal_unresolved_v1 rules. Case, UNC, dot segments, basename,",
            "and environment text are always preserved. IPs use Python ipaddress",
            "canonical text; invalid literals remain unresolved.",
            "No fuzzy matching. canonical_id hashes schema, entity type, a",
            "structured JSON scope token (global / host+exact value / missing",
            "host scope, so a missing scope can never collide with a real",
            "hostname), stable rule ID, and normalized value. Approved slash/IP",
            "aliases may share a canonical_id; each raw identity key maps once.",
            "",
            "T10",
            "---",
            "total_unique_raw_values counts scoped raw keys; canonical count is",
            "exact distinct IDs; merged_count=raw-canonical; unresolved_count",
            "counts raw keys marked unresolved; baseline count is deferred/null.",
            "",
            "F6",
            "---",
            "Four lines (process, file_path, destination, user_principal), fixed",
            "one-minute window selected by EDA 3. Canonical first-seen is MIN T9",
            "first_seen_time per entity_type/canonical_id. Eligibility: F6",
            "includes every nonmissing canonical entity, both resolved and",
            "unresolved; missing observations never enter F6. Missing minutes are",
            "zero-filled after a hard allocation cap. F6 does not rescan cache.",
            "EDA 3's five-minute window remains backup/sensitivity only.",
            "",
            "Resource design",
            "---------------",
            "Exactly five projected cache payload scans: host, user, process,",
            "file, destination. DuckDB uses bounded buffer memory, configured",
            "threads, local spill, and read-only Parquet access. T10/F6 query",
            "staged T9 only. Outputs publish with one atomic directory rename.",
            "The fixed pilot is not the complete OpTC corpus.",
            "",
        ]
    )


def run_eda05(args: argparse.Namespace) -> dict:
    import pandas as pd

    config = validate_run_config(args)
    manifest = _manifest_metadata(config["manifest_path"])
    connection = None
    spill_path = None
    spill_owned = False
    staging: Optional[pathlib.Path] = None
    try:
        connection, spill_path, spill_owned = _duck_conn(
            config["cache_dir"],
            memory_limit=config["memory_limit"],
            temp_dir=args.duckdb_temp_dir,
            threads=config["threads"],
        )
        validate_required_cache_columns(connection)

        staging_parent = _nearest_existing_directory(config["output_dir"].parent)
        staging = pathlib.Path(
            tempfile.mkdtemp(prefix=".eda05_staging_", dir=str(staging_parent))
        )
        t9_root = staging / "T9_canonical_entity_dictionary"
        stats, unresolved, scan_count = extract_t9(
            connection,
            t9_root,
            batch_size=config["batch_size"],
            max_t9_rows=config["max_t9_rows"],
            max_unresolved_examples=config["max_unresolved"],
        )
        # The all-event scans must account for every metadata event in the
        # full, fully parseable pilot. Object-applicable scans have smaller bases.
        expected_total = int(config["cache_metadata"]["total_events_written"])
        for entity_type in ("host", "user_principal"):
            if stats[entity_type].observation_count != expected_total:
                raise CacheAuditError(
                    f"{entity_type} extraction observations "
                    f"{stats[entity_type].observation_count:,} != cache metadata "
                    f"{expected_total:,}"
                )

        t10 = build_t10(connection, t9_root, stats)
        sparse_f6 = fetch_f6_sparse(connection, t9_root)
        dense_f6 = build_dense_f6(sparse_f6)
        validate_t9_t10_f6(
            connection, t9_root, t10, sparse_f6, dense_f6, stats
        )

        _atomic_write_csv(t10, staging / "T10_entity_count_summary.csv")
        unresolved_frame = pd.DataFrame(unresolved, columns=T9_COLUMNS)
        _atomic_write_csv(
            unresolved_frame, staging / "T9_unresolved_examples.csv"
        )
        create_f6(
            dense_f6,
            staging / "F6_new_entity_rate_over_time.png",
            staging / "F6_new_entity_rate_over_time.pdf",
        )
        rules = d1_rows()
        _atomic_write_csv(
            pd.DataFrame(rules, columns=D1_COLUMNS),
            staging / "D1_entity_normalization_rulebook.csv",
        )
        _atomic_write_text(
            d1_text(rules),
            staging / "D1_entity_normalization_rulebook.txt",
        )
        generated = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        metadata = {
            "schema_version": SCHEMA_VERSION,
            "cache_path": str(config["cache_dir"].resolve()),
            **manifest,
            "cache_metadata_event_count": expected_total,
            "period_policy": PERIOD_POLICY,
            "baseline_status": BASELINE_STATUS,
            "first_seen_after_baseline_count": None,
            "duckdb_memory_limit": config["memory_limit"],
            "duckdb_threads": config["threads"],
            "temporary_directory_policy": (
                "explicit_local_preserved"
                if args.duckdb_temp_dir
                else "owned_local_temp_removed"
            ),
            "payload_scan_count": scan_count,
            "payload_scan_entity_types": list(ENTITY_TYPES),
            "window_size": "1min",
            "t9_timestamp_type": "timestamp[us] naive UTC (optc_normalized_v3)",
            "f6_eligibility": (
                "includes all nonmissing canonical entities, resolved and "
                "unresolved; missing observations are excluded"
            ),
            "max_t9_rows": config["max_t9_rows"],
            "batch_size": config["batch_size"],
            "t9_row_count": int(sum(item.written_rows for item in stats.values())),
            "t9_partition_format": "Parquet partitioned by entity_type",
            "t10_row_count": len(t10),
            "unresolved_example_row_count": len(unresolved),
            "unresolved_examples_capped": (
                sum(item.unresolved_rows for item in stats.values()) > len(unresolved)
            ),
            "extraction_by_entity_type": {
                key: {
                    "observation_count": value.observation_count,
                    "missing_observation_count": value.missing_observation_count,
                    "t9_rows": value.written_rows,
                    "unresolved_rows": value.unresolved_rows,
                    "alias_mismatch_count": value.alias_mismatch_count,
                }
                for key, value in stats.items()
            },
            "method_notes": {
                "exact": [
                    "observation counts",
                    "distinct provenance member source counts",
                    "first/last timestamps",
                    "raw and canonical entity counts",
                    "F6 first-seen canonical counts",
                    "deterministic earliest evidence locators",
                ],
                "approximate": [],
                "missing_values": (
                    "null/empty/whitespace-only values are excluded from T9/F6 "
                    "and counted exactly"
                ),
            },
            "generated_utc": generated,
            "code_commit": _git_commit(config["project_root"]),
        }
        _atomic_write_text(
            _build_readme(metadata),
            staging / "README_eda05_entity_dictionary.txt",
        )
        _atomic_write_json(metadata, staging / "eda05_run_metadata.json")
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
        metadata = run_eda05(parse_args(argv))
    except CacheAuditError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    print(
        "EDA 5 complete: "
        f"T9={metadata['t9_row_count']:,}, "
        f"T10={metadata['t10_row_count']:,}, "
        f"payload_scans={metadata['payload_scan_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
