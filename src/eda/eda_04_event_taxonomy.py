"""
EDA 4 — Event Taxonomy and Object-Action Behavior (DARPA OpTC)
================================================================

Normalized-cache-only, bounded DuckDB analysis. The Parquet cache is opened
read-only and exactly one payload aggregation query is used. No attack,
anomaly, maliciousness, benign-classification, or MITRE claims are made.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
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
from typing import Optional

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from optc_streaming_parser import SCHEMA_VERSION  # type: ignore


MISSING_MARKER = "<MISSING>"
DEFAULT_PERIOD = "full_pilot_unassigned"
DEFERRED_RARITY_STATUS = "deferred_no_verified_benign_period"
PAYLOAD_SCAN_BUDGET = 1

REQUIRED_CACHE_COLUMNS = {
    "timestamp_parsed",
    "host_raw",
    "object_raw",
    "action_raw",
    "parse_status",
    "archive_name",
    "member_name",
    "line_number",
    "raw_event_id",
}
PERIOD_MAP_COLUMNS = ["period", "start_time", "end_time", "period_role"]
ALLOWED_PERIOD_ROLES = {"verified_benign", "evaluation", "other"}

T6_COLUMNS = [
    "period",
    "host",
    "object_type",
    "action_type",
    "object_action_pair",
    "event_count",
    "percent_of_period_events",
    "first_seen_time",
    "last_seen_time",
]
T7_COLUMNS = [
    "raw_object_type",
    "raw_action_type",
    "semantic_group",
    "mapping_rule",
    "keep_raw_fields_yes_no",
    "rationale",
]
T8_COLUMNS = [
    "pattern_id",
    "object_action_pair",
    "host",
    "first_seen_time",
    "benign_frequency",
    "evaluation_frequency",
    "rare_reason",
    "raw_event_example_id",
    "archive_name",
    "member_name",
    "line_number",
    "period",
    "semantic_group",
    "rarity_status",
]

_SEMANTIC_GROUPS = {
    "PROCESS": ("process_activity", "object_type_in_PROCESS_THREAD"),
    "THREAD": ("process_activity", "object_type_in_PROCESS_THREAD"),
    "FILE": ("file_activity", "object_type_FILE"),
    "MODULE": ("module_activity", "object_type_MODULE"),
    "FLOW": ("network_activity", "object_type_FLOW"),
    "REGISTRY": (
        "configuration_activity",
        "object_type_in_REGISTRY_SERVICE_TASK",
    ),
    "SERVICE": (
        "configuration_activity",
        "object_type_in_REGISTRY_SERVICE_TASK",
    ),
    "TASK": (
        "configuration_activity",
        "object_type_in_REGISTRY_SERVICE_TASK",
    ),
    "USER_SESSION": (
        "identity_session_activity",
        "object_type_USER_SESSION",
    ),
}

_DUCKDB_MEMORY_LIMIT_RE = re.compile(
    r"^\d+(\.\d+)?\s*(B|KB|MB|GB|TB|KiB|MiB|GiB|TiB)$",
    re.IGNORECASE,
)


class CacheAuditError(Exception):
    """Fatal EDA 4 configuration, cache, or integrity failure."""


@dataclass(frozen=True)
class PeriodPolicy:
    frame: object
    has_verified_benign: bool
    has_evaluation: bool
    policy_name: str
    path: Optional[pathlib.Path]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "EDA 4 — scale-safe object/action taxonomy over a normalized "
            "OpTC Parquet cache."
        )
    )
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--normalized-cache-dir", required=True)
    parser.add_argument("--manifest-csv", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--duckdb-memory-limit", default="4GB")
    parser.add_argument("--duckdb-temp-dir", default=None)
    parser.add_argument("--duckdb-threads", type=int, default=2)
    parser.add_argument("--period-map-csv", default=None)
    parser.add_argument("--rare-benign-max-count", type=int, default=None)
    parser.add_argument("--max-pattern-rows", type=int, default=100_000)
    parser.add_argument("--heatmap-top-objects", type=int, default=30)
    parser.add_argument("--heatmap-top-actions", type=int, default=30)
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
            f"Invalid --duckdb-memory-limit={memory_limit!r}; expected a size "
            "such as '4GB', '512MB', or '1.5GiB'"
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
        raise CacheAuditError(
            "--duckdb-temp-dir must be local; Google Drive spill paths are refused"
        )
    return path


def _validate_positive(name: str, value: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise CacheAuditError(f"{name} must be an integer >= 1") from exc
    if number < 1:
        raise CacheAuditError(f"{name} must be >= 1")
    return number


def _output_path_preexists(output_dir: pathlib.Path) -> bool:
    """
    True for every existing filesystem entry, including a broken symlink
    (Path.exists() follows links and would miss dangling ones).
    """
    return os.path.lexists(os.fspath(output_dir))


def _validate_output_dir(output_dir: pathlib.Path, cache_dir: pathlib.Path) -> None:
    output_resolved = output_dir.expanduser().resolve()
    cache_resolved = cache_dir.expanduser().resolve()
    if output_resolved == cache_resolved or cache_resolved in output_resolved.parents:
        raise CacheAuditError("Output directory must not be the cache or inside it")
    if _output_path_preexists(output_dir):
        # Any pre-existing entry — empty/nonempty directory, regular file,
        # valid symlink, or broken symlink — is refused so the final
        # publication can be a single atomic directory rename.
        raise CacheAuditError(
            f"Refusing existing output path (must not pre-exist): {output_dir}"
        )


def _load_cache_metadata(cache_dir: pathlib.Path) -> dict:
    metadata_path = cache_dir / "cache_metadata.json"
    if not metadata_path.is_file():
        raise CacheAuditError(f"Required cache metadata missing: {metadata_path}")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CacheAuditError(f"Invalid cache metadata: {metadata_path}") from exc
    if metadata.get("schema_version") != SCHEMA_VERSION:
        raise CacheAuditError(
            "Cache schema mismatch: expected "
            f"{SCHEMA_VERSION!r}, found {metadata.get('schema_version')!r}"
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


def validate_run_config(args: argparse.Namespace) -> dict:
    """Validate all CLI configuration before output-dir creation/modification."""
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

    memory_limit = _validate_duckdb_memory_limit(args.duckdb_memory_limit)
    threads = _validate_duckdb_threads(args.duckdb_threads)
    if args.duckdb_temp_dir is not None:
        _validate_duckdb_temp_dir(args.duckdb_temp_dir)
    max_pattern_rows = _validate_positive(
        "--max-pattern-rows", args.max_pattern_rows
    )
    top_objects = _validate_positive(
        "--heatmap-top-objects", args.heatmap_top_objects
    )
    top_actions = _validate_positive(
        "--heatmap-top-actions", args.heatmap_top_actions
    )
    if args.rare_benign_max_count is not None:
        try:
            rarity_threshold = int(args.rare_benign_max_count)
        except (TypeError, ValueError) as exc:
            raise CacheAuditError(
                "--rare-benign-max-count must be an integer >= 0"
            ) from exc
        if rarity_threshold < 0:
            raise CacheAuditError("--rare-benign-max-count must be >= 0")
        if not args.period_map_csv:
            raise CacheAuditError(
                "--rare-benign-max-count is valid only with --period-map-csv"
            )
    if args.period_map_csv and not pathlib.Path(args.period_map_csv).is_file():
        raise CacheAuditError(f"Period-map CSV not found: {args.period_map_csv}")

    _validate_output_dir(output_dir, cache_dir)
    metadata = _load_cache_metadata(cache_dir)
    return {
        "project_root": project_root,
        "cache_dir": cache_dir,
        "manifest_path": manifest_path,
        "output_dir": output_dir,
        "memory_limit": memory_limit,
        "threads": threads,
        "max_pattern_rows": max_pattern_rows,
        "top_objects": top_objects,
        "top_actions": top_actions,
        "cache_metadata": metadata,
    }


def load_period_policy(
    period_map_csv: Optional[str],
    rare_benign_max_count: Optional[int],
) -> PeriodPolicy:
    """Load validated half-open [start_time, end_time) verified intervals."""
    import pandas as pd

    if period_map_csv is None:
        frame = pd.DataFrame(
            columns=["period", "start_time", "end_time", "period_role"]
        )
        return PeriodPolicy(frame, False, False, "full_pilot_unassigned", None)

    path = pathlib.Path(period_map_csv)
    try:
        frame = pd.read_csv(path)
    except Exception as exc:
        raise CacheAuditError(f"Cannot read period map: {path}") from exc
    missing = set(PERIOD_MAP_COLUMNS) - set(frame.columns)
    if missing:
        raise CacheAuditError(f"Period map missing required columns: {sorted(missing)}")
    frame = frame[PERIOD_MAP_COLUMNS].copy()
    if frame.empty:
        raise CacheAuditError("Period map must contain at least one interval")

    for column in ("period", "period_role"):
        frame[column] = frame[column].fillna("").astype(str).str.strip()
        if (frame[column] == "").any():
            raise CacheAuditError(f"Period map contains blank {column}")
    bad_roles = sorted(set(frame["period_role"]) - ALLOWED_PERIOD_ROLES)
    if bad_roles:
        raise CacheAuditError(
            f"Invalid period_role values {bad_roles}; allowed: "
            f"{sorted(ALLOWED_PERIOD_ROLES)}"
        )
    if (frame["period"] == DEFAULT_PERIOD).any():
        raise CacheAuditError(
            f"Period name {DEFAULT_PERIOD!r} is reserved for unmatched events"
        )
    role_counts = frame.groupby("period")["period_role"].nunique()
    if (role_counts > 1).any():
        raise CacheAuditError("Each period name must have exactly one period_role")

    for column in ("start_time", "end_time"):
        parsed = pd.to_datetime(frame[column], errors="coerce", utc=True)
        if parsed.isna().any():
            raise CacheAuditError(f"Period map contains invalid {column}")
        frame[column] = parsed.dt.tz_convert(None)
    if (frame["end_time"] <= frame["start_time"]).any():
        raise CacheAuditError("Period intervals must have end_time > start_time")
    ordered = frame.sort_values(["start_time", "end_time", "period"]).reset_index(
        drop=True
    )
    for index in range(1, len(ordered)):
        if ordered.loc[index, "start_time"] < ordered.loc[index - 1, "end_time"]:
            raise CacheAuditError("Period-map intervals must not overlap")

    has_benign = bool((ordered["period_role"] == "verified_benign").any())
    has_evaluation = bool((ordered["period_role"] == "evaluation").any())
    if has_benign and has_evaluation:
        earliest_evaluation_start = ordered.loc[
            ordered["period_role"] == "evaluation", "start_time"
        ].min()
        benign_end_times = ordered.loc[
            ordered["period_role"] == "verified_benign", "end_time"
        ]
        # Half-open [start, end): a benign end equal to the evaluation start
        # is chronologically prior and therefore valid.
        if (benign_end_times > earliest_evaluation_start).any():
            raise CacheAuditError(
                "verified_benign intervals must end at or before the earliest "
                "evaluation interval begins; benign data occurring after or "
                "interleaved with evaluation is rejected to prevent future "
                "benign data from fitting an earlier evaluation baseline"
            )
    if has_benign and rare_benign_max_count is None:
        raise CacheAuditError(
            "Verified benign periods require --rare-benign-max-count; "
            "evaluation/unassigned rows are never used to fit this threshold"
        )
    if rare_benign_max_count is not None and not has_benign:
        raise CacheAuditError(
            "--rare-benign-max-count requires at least one verified_benign interval"
        )
    return PeriodPolicy(
        ordered,
        has_benign,
        has_evaluation,
        "verified_period_map" if has_benign else "period_map_without_verified_benign",
        path.resolve(),
    )


def semantic_mapping(raw_object: object, raw_action: object) -> dict:
    """
    Pure closed mapping. Group selection uses a normalized internal copy
    (trim + uppercase); the returned raw labels are the exact supplied
    strings (None/empty become the missing marker, never trimmed/case-folded).
    """
    object_text = "" if raw_object is None else str(raw_object)
    action_text = "" if raw_action is None else str(raw_action)
    normalized_object = object_text.strip().upper() or MISSING_MARKER
    group, rule = _SEMANTIC_GROUPS.get(
        normalized_object, ("other_activity", "object_type_missing_or_unrecognized")
    )
    return {
        "raw_object_type": object_text or MISSING_MARKER,
        "raw_action_type": action_text or MISSING_MARKER,
        "semantic_group": group,
        "mapping_rule": rule,
        "keep_raw_fields_yes_no": "yes",
        "rationale": (
            "Closed object-type rule; raw object/action retained; action text "
            "does not imply maliciousness or any behavioral classification."
        ),
    }


def object_action_pair(object_type: object, action_type: object) -> str:
    """Unambiguous deterministic representation of a normalized pair."""
    return json.dumps(
        [str(object_type), str(action_type)],
        ensure_ascii=False,
        separators=(",", ":"),
    )


def deterministic_pattern_id(host: object, pair: object) -> str:
    payload = json.dumps(
        [str(host), str(pair)], ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return "pattern_" + hashlib.sha256(payload).hexdigest()[:24]


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
    """Return (connection, spill_path, owned); caller closes/removes in finally."""
    import duckdb

    memory = _validate_duckdb_memory_limit(memory_limit)
    thread_count = _validate_duckdb_threads(threads)
    connection = None
    spill: Optional[pathlib.Path] = None
    owned = False
    try:
        if temp_dir is None:
            spill = pathlib.Path(tempfile.mkdtemp(prefix="eda04_duckdb_tmp_"))
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
    """DESCRIBE is setup/schema inspection and does not scan payload rows."""
    rows = connection.execute("DESCRIBE events").fetchall()
    present = {str(row[0]) for row in rows}
    missing = REQUIRED_CACHE_COLUMNS - present
    if missing:
        raise CacheAuditError(
            f"Normalized cache missing required EDA 4 columns: {sorted(missing)}"
        )
    return present


def _register_periods(connection, policy: PeriodPolicy) -> None:
    """Register the tiny validated period map without touching cache payload."""
    import pandas as pd

    frame = policy.frame
    if len(frame):
        connection.register("_eda04_period_frame", frame)
        connection.execute(
            """
            CREATE TEMP TABLE period_intervals AS
            SELECT
                CAST(period AS VARCHAR) AS period,
                CAST(start_time AS TIMESTAMP) AS start_time,
                CAST(end_time AS TIMESTAMP) AS end_time,
                CAST(period_role AS VARCHAR) AS period_role
            FROM _eda04_period_frame
            """
        )
        connection.unregister("_eda04_period_frame")
    else:
        connection.execute(
            """
            CREATE TEMP TABLE period_intervals (
                period VARCHAR,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                period_role VARCHAR
            )
            """
        )


def primary_aggregate_sql() -> str:
    """
    The sole full-cache payload query.

    It projects only required fields, assigns periods, and retains one
    deterministic earliest evidence locator in each compact raw-pair group.
    """
    return f"""
    WITH projected AS (
        SELECT
            TRY_CAST(timestamp_parsed AS TIMESTAMP) AS event_time,
            COALESCE(NULLIF(TRIM(CAST(host_raw AS VARCHAR)), ''), '{MISSING_MARKER}') AS host,
            COALESCE(NULLIF(CAST(object_raw AS VARCHAR), ''), '{MISSING_MARKER}') AS raw_object_type,
            COALESCE(NULLIF(CAST(action_raw AS VARCHAR), ''), '{MISSING_MARKER}') AS raw_action_type,
            COALESCE(NULLIF(UPPER(TRIM(CAST(object_raw AS VARCHAR))), ''), '{MISSING_MARKER}') AS object_type,
            COALESCE(NULLIF(UPPER(TRIM(CAST(action_raw AS VARCHAR))), ''), '{MISSING_MARKER}') AS action_type,
            COALESCE(CAST(archive_name AS VARCHAR), '') AS archive_name,
            COALESCE(CAST(member_name AS VARCHAR), '') AS member_name,
            TRY_CAST(line_number AS BIGINT) AS line_number,
            COALESCE(CAST(raw_event_id AS VARCHAR), '') AS raw_event_id
        FROM events
        WHERE LOWER(TRIM(CAST(parse_status AS VARCHAR))) = 'ok'
          AND TRY_CAST(timestamp_parsed AS TIMESTAMP) IS NOT NULL
    ),
    assigned AS (
        SELECT
            COALESCE(period_intervals.period, '{DEFAULT_PERIOD}') AS period,
            projected.*
        FROM projected
        LEFT JOIN period_intervals
          ON projected.event_time >= period_intervals.start_time
         AND projected.event_time < period_intervals.end_time
    )
    SELECT
        period,
        host,
        raw_object_type,
        raw_action_type,
        object_type,
        action_type,
        COUNT(*)::BIGINT AS event_count,
        MIN(event_time) AS first_seen_time,
        MAX(event_time) AS last_seen_time,
        FIRST(raw_event_id ORDER BY event_time, archive_name, member_name,
              line_number, raw_event_id) AS raw_event_example_id,
        FIRST(archive_name ORDER BY event_time, archive_name, member_name,
              line_number, raw_event_id) AS archive_name,
        FIRST(member_name ORDER BY event_time, archive_name, member_name,
              line_number, raw_event_id) AS member_name,
        FIRST(line_number ORDER BY event_time, archive_name, member_name,
              line_number, raw_event_id) AS line_number
    FROM assigned
    GROUP BY
        period, host, raw_object_type, raw_action_type, object_type, action_type
    """


def fetch_primary_aggregate(connection):
    """Execute exactly one full-cache payload aggregation query."""
    return connection.execute(primary_aggregate_sql()).fetchdf()


def _iso_timestamp(value: object) -> str:
    import pandas as pd

    if value is None or pd.isna(value):
        return ""
    return pd.Timestamp(value).isoformat()


def build_t6(compact):
    """Collapse raw case variants into normalized exact T6 groups."""
    import pandas as pd

    if compact.empty:
        return pd.DataFrame(columns=T6_COLUMNS)
    keys = ["period", "host", "object_type", "action_type"]
    grouped = (
        compact.groupby(keys, dropna=False, sort=True)
        .agg(
            event_count=("event_count", "sum"),
            first_seen_time=("first_seen_time", "min"),
            last_seen_time=("last_seen_time", "max"),
        )
        .reset_index()
    )
    grouped["event_count"] = grouped["event_count"].astype("int64")
    period_totals = grouped.groupby("period")["event_count"].transform("sum")
    grouped["percent_of_period_events"] = (
        grouped["event_count"] / period_totals * 100.0
    )
    grouped["object_action_pair"] = [
        object_action_pair(obj, action)
        for obj, action in zip(grouped["object_type"], grouped["action_type"])
    ]
    grouped["first_seen_time"] = grouped["first_seen_time"].map(_iso_timestamp)
    grouped["last_seen_time"] = grouped["last_seen_time"].map(_iso_timestamp)
    return grouped[T6_COLUMNS].sort_values(
        ["period", "host", "object_type", "action_type"], kind="mergesort"
    ).reset_index(drop=True)


def build_t7(compact):
    """Map each observed exact raw pair once; no additional cache scan."""
    import pandas as pd

    rows = []
    if not compact.empty:
        pairs = compact[["raw_object_type", "raw_action_type"]].drop_duplicates()
        pairs = pairs.sort_values(
            ["raw_object_type", "raw_action_type"], kind="mergesort"
        )
        for pair in pairs.itertuples(index=False):
            rows.append(semantic_mapping(pair.raw_object_type, pair.raw_action_type))
    return pd.DataFrame(rows, columns=T7_COLUMNS)


def _period_roles(policy: PeriodPolicy) -> dict[str, str]:
    roles = {
        str(row.period): str(row.period_role)
        for row in policy.frame.itertuples(index=False)
    }
    roles[DEFAULT_PERIOD] = "unassigned"
    return roles


def build_t8(
    compact,
    policy: PeriodPolicy,
    rare_benign_max_count: Optional[int],
    max_pattern_rows: int,
):
    """Build deterministic host/pair first-seen rows from compact aggregates."""
    import pandas as pd

    if compact.empty:
        return pd.DataFrame(columns=T8_COLUMNS)
    work = compact.copy()
    work["object_action_pair"] = [
        object_action_pair(obj, action)
        for obj, action in zip(work["object_type"], work["action_type"])
    ]
    work = work.sort_values(
        [
            "first_seen_time",
            "archive_name",
            "member_name",
            "line_number",
            "raw_event_example_id",
        ],
        kind="mergesort",
        na_position="last",
    )
    pattern_keys = ["host", "object_action_pair"]
    required_count = int(work[pattern_keys].drop_duplicates().shape[0])
    if required_count > int(max_pattern_rows):
        raise CacheAuditError(
            f"T8 requires {required_count:,} rows, exceeding "
            f"--max-pattern-rows={int(max_pattern_rows):,}; no final outputs written"
        )

    roles = _period_roles(policy)
    work["_role"] = work["period"].map(roles).fillna("unassigned")
    rows: list[dict] = []
    for (host, pair), group in work.groupby(pattern_keys, sort=True):
        evidence = group.iloc[0]
        for locator in (
            "raw_event_example_id",
            "archive_name",
            "member_name",
            "line_number",
        ):
            value = evidence[locator]
            if pd.isna(value) or str(value).strip() == "":
                raise CacheAuditError(
                    f"T8 earliest evidence has incomplete locator: {locator}"
                )
        normalized_object = str(evidence["object_type"])
        semantic = semantic_mapping(normalized_object, evidence["action_type"])[
            "semantic_group"
        ]
        if not policy.has_verified_benign:
            benign_frequency = None
            evaluation_frequency = None
            status = DEFERRED_RARITY_STATUS
            reason = (
                "Frequency-threshold fitting was deferred because no verified "
                "benign period was provided; this row is descriptive first-seen "
                "evidence only."
            )
        else:
            benign_frequency = int(
                group.loc[group["_role"] == "verified_benign", "event_count"].sum()
            )
            evaluation_frequency = int(
                group.loc[group["_role"] == "evaluation", "event_count"].sum()
            )
            # Conservative outside-verified frequency: every role that is not
            # verified_benign or evaluation (includes 'other' and unassigned).
            outside_verified_frequency = int(
                group.loc[
                    ~group["_role"].isin(["verified_benign", "evaluation"]),
                    "event_count",
                ].sum()
            )
            earliest_role = str(evidence["_role"])
            threshold = int(rare_benign_max_count)
            if earliest_role not in ("verified_benign", "evaluation"):
                # Earliest evidence lies in an 'other' or unassigned span, so
                # no threshold status may be claimed — even if the pattern
                # also appears in evaluation later.
                status = "unresolved_unassigned"
                reason = (
                    "Earliest evidence occurs outside verified benign and "
                    f"evaluation intervals ({outside_verified_frequency} "
                    "event(s) outside those roles); threshold status is "
                    "unresolved and descriptive only."
                )
            elif earliest_role == "evaluation" and benign_frequency == 0:
                status = "first_seen_in_evaluation"
                reason = (
                    "First observed in an evaluation interval and absent from "
                    "verified benign intervals; descriptive status only."
                )
            elif benign_frequency <= threshold:
                status = "rare_in_verified_benign"
                reason = (
                    f"Verified-benign frequency {benign_frequency} is at or "
                    f"below configured threshold {threshold}; descriptive only."
                )
            else:
                status = "common_in_verified_benign"
                reason = (
                    f"Verified-benign frequency {benign_frequency} exceeds "
                    f"configured threshold {threshold}; descriptive only."
                )
        rows.append(
            {
                "pattern_id": deterministic_pattern_id(host, pair),
                "object_action_pair": pair,
                "host": host,
                "first_seen_time": _iso_timestamp(evidence["first_seen_time"]),
                "benign_frequency": benign_frequency,
                "evaluation_frequency": evaluation_frequency,
                "rare_reason": reason,
                "raw_event_example_id": str(evidence["raw_event_example_id"]),
                "archive_name": str(evidence["archive_name"]),
                "member_name": str(evidence["member_name"]),
                "line_number": int(evidence["line_number"]),
                "period": str(evidence["period"]),
                "semantic_group": semantic,
                "rarity_status": status,
            }
        )
    return pd.DataFrame(rows, columns=T8_COLUMNS).sort_values(
        ["host", "object_action_pair"], kind="mergesort"
    ).reset_index(drop=True)


def validate_integrity(
    compact,
    t6,
    t7,
    t8,
    cache_metadata: dict,
    *,
    percentage_tolerance: float = 1e-7,
) -> int:
    expected = int(cache_metadata["total_events_written"])
    aggregated = int(compact["event_count"].sum()) if len(compact) else 0
    if aggregated != expected:
        raise CacheAuditError(
            f"Primary aggregate represents {aggregated:,} events but "
            f"cache_metadata.json total_events_written={expected:,}"
        )
    t6_total = int(t6["event_count"].sum()) if len(t6) else 0
    if t6_total != aggregated:
        raise CacheAuditError(
            f"T6 event_count sum {t6_total:,} does not equal aggregate "
            f"count {aggregated:,}"
        )
    for period, group in t6.groupby("period", sort=False):
        percent_sum = float(group["percent_of_period_events"].sum())
        if not math.isclose(
            percent_sum, 100.0, rel_tol=0.0, abs_tol=percentage_tolerance
        ):
            raise CacheAuditError(
                f"T6 percentages for period {period!r} sum to "
                f"{percent_sum:.12f}, not 100%"
            )

    observed_raw = compact[
        ["raw_object_type", "raw_action_type"]
    ].drop_duplicates()
    mapped_raw = t7[["raw_object_type", "raw_action_type"]]
    if len(t7) != len(observed_raw) or mapped_raw.duplicated().any():
        raise CacheAuditError(
            "T7 must map every observed raw object/action pair exactly once"
        )
    if len(t7) and not (t7["keep_raw_fields_yes_no"] == "yes").all():
        raise CacheAuditError("T7 raw-field preservation flag must always be yes")

    if len(t8):
        if t8["pattern_id"].duplicated().any() or t8["pattern_id"].isna().any():
            raise CacheAuditError("T8 pattern_id values must be unique and complete")
        for column in (
            "raw_event_example_id",
            "archive_name",
            "member_name",
            "line_number",
        ):
            if t8[column].isna().any() or (
                t8[column].astype(str).str.strip() == ""
            ).any():
                raise CacheAuditError(
                    f"T8 evidence locator column {column} must be complete"
                )
    return aggregated


def _selected_heatmap_categories(t6, top_objects: int, top_actions: int):
    object_totals = (
        t6.groupby("object_type", sort=False)["event_count"]
        .sum()
        .sort_values(ascending=False, kind="mergesort")
    )
    action_totals = (
        t6.groupby("action_type", sort=False)["event_count"]
        .sum()
        .sort_values(ascending=False, kind="mergesort")
    )
    objects = list(object_totals.head(top_objects).index)
    actions = list(action_totals.head(top_actions).index)
    return objects, actions


def create_f5(
    t6,
    png_path: pathlib.Path,
    pdf_path: pathlib.Path,
    *,
    top_objects: int,
    top_actions: int,
) -> dict:
    """Render period panels from exact T6 counts; no cache scan."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    if t6.empty:
        raise CacheAuditError("Cannot create F5 from empty T6")
    objects, actions = _selected_heatmap_categories(
        t6, top_objects, top_actions
    )
    periods = sorted(t6["period"].astype(str).unique())
    fig, axes = plt.subplots(
        len(periods),
        1,
        figsize=(
            max(9.0, min(24.0, 0.42 * len(actions) + 5)),
            max(5.5, 4.8 * len(periods)),
        ),
        squeeze=False,
        constrained_layout=True,
    )
    image = None
    for index, period in enumerate(periods):
        panel = t6[t6["period"] == period]
        counts = (
            panel.pivot_table(
                index="object_type",
                columns="action_type",
                values="event_count",
                aggfunc="sum",
                fill_value=0,
            )
            .reindex(index=objects, columns=actions, fill_value=0)
        )
        values = np.log1p(counts.to_numpy(dtype=float))
        axis = axes[index][0]
        image = axis.imshow(values, aspect="auto", cmap="viridis")
        axis.set_xticks(range(len(actions)), actions, rotation=60, ha="right")
        axis.set_yticks(range(len(objects)), objects)
        axis.set_xlabel("action_type")
        axis.set_ylabel("object_type")
        axis.set_title(
            f"period = {period} | ground-truth/attack overlay = absent\n"
            f"log1p(exact event count); displayed top objects={len(objects)} "
            f"of {t6['object_type'].nunique()}, top actions={len(actions)} "
            f"of {t6['action_type'].nunique()}"
        )
    if image is not None:
        fig.colorbar(image, ax=axes.ravel().tolist(), label="log1p(exact event count)")
    fig.suptitle("F5 Object-Action Heatmap", fontsize=14)
    fig.savefig(png_path, dpi=180, bbox_inches="tight")
    fig.savefig(pdf_path, bbox_inches="tight")
    plt.close(fig)
    return {
        "configured_top_objects": int(top_objects),
        "configured_top_actions": int(top_actions),
        "displayed_objects": len(objects),
        "displayed_actions": len(actions),
        "total_objects": int(t6["object_type"].nunique()),
        "total_actions": int(t6["action_type"].nunique()),
    }


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


def _git_commit(project_root: pathlib.Path) -> Optional[str]:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=project_root,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip() or None
    except Exception:
        return None


def _manifest_metadata(manifest_path: pathlib.Path) -> dict:
    import pandas as pd

    frame = pd.read_csv(manifest_path, usecols=lambda c: c == "manifest_version")
    if "manifest_version" not in frame.columns or frame.empty:
        raise CacheAuditError("Manifest requires a nonempty manifest_version column")
    versions = sorted(
        set(frame["manifest_version"].dropna().astype(str).str.strip()) - {""}
    )
    if len(versions) != 1:
        raise CacheAuditError(
            f"Manifest must contain exactly one manifest_version; found {versions}"
        )
    return {"manifest_version": versions[0], "manifest_path": str(manifest_path.resolve())}


def _build_readme(
    *,
    metadata: dict,
    policy: PeriodPolicy,
    heatmap: dict,
) -> str:
    if policy.has_verified_benign:
        period_text = (
            "Verified period-map mode was used. The configured frequency "
            "threshold was applied only to verified_benign rows; evaluation and "
            "unassigned rows did not fit that threshold."
        )
    else:
        period_text = (
            "Current policy: period=full_pilot_unassigned unless a supplied "
            "period map assigns an interval. No verified benign period was "
            "provided, so benign/evaluation comparison and frequency-threshold "
            "fitting are deferred. T8 is descriptive first-seen evidence only."
        )
    return "\n".join(
        [
            "EDA 4 — Event Taxonomy and Object-Action Behavior",
            "=" * 55,
            f"Generated UTC: {metadata['generated_utc']}",
            "",
            period_text,
            "No ground-truth overlay was applied. These outputs are not an "
            "attack-detection result and make no anomaly, maliciousness, or "
            "MITRE attribution.",
            "",
            "T6 Object-Action Frequency",
            "--------------------------",
            "Object/action grouping uses normalized trim + uppercase fields; "
            f"missing values become {MISSING_MARKER}. T6 therefore collapses "
            "case/whitespace variants of the same object or action.",
            "T7 preserves the exact original raw object/action strings, "
            "including surrounding whitespace and letter case; only NULL/empty "
            f"values are represented as {MISSING_MARKER}.",
            "percent_of_period_events denominator: exact total events across all "
            "hosts in the same period. Counts, percentages, and first/last times "
            "are exact.",
            "",
            "T7 Semantic Mapping",
            "-------------------",
            "Closed deterministic object rules:",
            "  PROCESS, THREAD -> process_activity",
            "  FILE -> file_activity",
            "  MODULE -> module_activity",
            "  FLOW -> network_activity",
            "  REGISTRY, SERVICE, TASK -> configuration_activity",
            "  USER_SESSION -> identity_session_activity",
            "  missing/unrecognized -> other_activity",
            "Actions are retained but do not control or imply harmful semantics.",
            "keep_raw_fields_yes_no is always yes. EDA 2 'drop' decisions only "
            "exclude default modeling features; they do not delete raw columns.",
            "",
            "T8 Rare / First-Seen Patterns",
            "-----------------------------",
            "Evidence retains raw_event_id, archive_name, member_name, and "
            "line_number. Pattern IDs are deterministic hashes of host and the "
            "normalized object/action pair.",
            "",
            "Frequency semantics",
            "-------------------",
            "benign_frequency is the exact event count for the same host and "
            "normalized object/action pair across verified_benign intervals "
            "only. evaluation_frequency is the equivalent exact count across "
            "evaluation intervals only. Events in period_role=other or "
            "unassigned spans never fit the benign rarity threshold; patterns "
            "whose earliest evidence lies in such spans are reported as "
            "unresolved_unassigned. Verified-benign intervals must "
            "chronologically end at or before the earliest evaluation interval "
            "begins, so future benign data cannot fit an earlier evaluation "
            "baseline.",
            "",
            "F5 Heatmap",
            "----------",
            "Cell value is log1p(exact event count). "
            f"Configured limits: top objects={heatmap['configured_top_objects']}, "
            f"top actions={heatmap['configured_top_actions']}; displayed "
            f"{heatmap['displayed_objects']} objects and "
            f"{heatmap['displayed_actions']} actions. Limits affect F5 only, "
            "never T6.",
            "",
            "Methods and scope",
            "-----------------",
            "All EDA 4 metrics are exact; no approximate metric controls any "
            "classification. The normalized Parquet cache was read only. One "
            "full-cache payload aggregation query was used.",
            "EDA 3 selected 1 minute as primary and 5 minutes as backup. F5 is "
            "not time-windowed.",
            "Within-process-tree transition analysis is deferred until canonical "
            "entities and process lineage are developed in EDA 5/EDA 7; this "
            "analysis does not claim transitions were completed.",
            "The fixed 10 GB pilot is not the complete OpTC corpus.",
            "",
        ]
    )


def _assert_no_temp_files(directory: pathlib.Path) -> None:
    leftovers = [
        path.name
        for path in directory.iterdir()
        if path.name.startswith(".") or path.suffix == ".tmp"
    ]
    if leftovers:
        raise CacheAuditError(f"Temporary output files remain: {leftovers}")


def _publish_staging(staging: pathlib.Path, output_dir: pathlib.Path) -> None:
    """
    Publish the complete staged output set with one atomic directory rename.
    An output path that exists at publication time (even empty) is refused;
    existing user directories are never deleted or replaced.
    """
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    if _output_path_preexists(output_dir):
        raise CacheAuditError(
            f"Output path appeared before publication; refusing to touch it: "
            f"{output_dir}"
        )
    os.replace(staging, output_dir)


def _nearest_existing_directory(path: pathlib.Path) -> pathlib.Path:
    """Find a same-filesystem staging parent without creating output paths."""
    candidate = path
    while not candidate.exists():
        if candidate.parent == candidate:
            raise CacheAuditError(f"No existing ancestor for output path: {path}")
        candidate = candidate.parent
    if not candidate.is_dir():
        candidate = candidate.parent
    return candidate


def run_eda04(args: argparse.Namespace) -> dict:
    """Execute EDA 4. All validation precedes output-directory modification."""
    config = validate_run_config(args)
    policy = load_period_policy(
        args.period_map_csv, args.rare_benign_max_count
    )
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
        _register_periods(connection, policy)
        compact = fetch_primary_aggregate(connection)
        t6 = build_t6(compact)
        t7 = build_t7(compact)
        t8 = build_t8(
            compact,
            policy,
            args.rare_benign_max_count,
            config["max_pattern_rows"],
        )
        aggregated = validate_integrity(
            compact, t6, t7, t8, config["cache_metadata"]
        )

        parent = _nearest_existing_directory(config["output_dir"].parent)
        staging = pathlib.Path(
            tempfile.mkdtemp(prefix=".eda04_staging_", dir=str(parent))
        )
        _atomic_write_csv(t6, staging / "T6_object_action_frequency.csv")
        _atomic_write_csv(t7, staging / "T7_semantic_event_mapping.csv")
        _atomic_write_csv(t8, staging / "T8_rare_first_seen_patterns.csv")
        heatmap = create_f5(
            t6,
            staging / "F5_object_action_heatmap.png",
            staging / "F5_object_action_heatmap.pdf",
            top_objects=config["top_objects"],
            top_actions=config["top_actions"],
        )
        generated = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        rarity_status = (
            "verified_benign_threshold_applied"
            if policy.has_verified_benign
            else DEFERRED_RARITY_STATUS
        )
        metadata = {
            "schema_version": SCHEMA_VERSION,
            "cache_path": str(config["cache_dir"].resolve()),
            **manifest,
            "cache_metadata_event_count": int(
                config["cache_metadata"]["total_events_written"]
            ),
            "aggregated_event_count": aggregated,
            "period_policy": policy.policy_name,
            "period_map_path": str(policy.path) if policy.path else None,
            "rarity_status": rarity_status,
            "rarity_threshold": args.rare_benign_max_count,
            "duckdb_memory_limit": config["memory_limit"],
            "duckdb_threads": config["threads"],
            "temporary_directory_policy": (
                "explicit_local_preserved"
                if args.duckdb_temp_dir
                else "owned_local_temp_removed"
            ),
            "number_of_payload_scans": PAYLOAD_SCAN_BUDGET,
            "t6_row_count": len(t6),
            "t7_row_count": len(t7),
            "t8_row_count": len(t8),
            "heatmap_limits": heatmap,
            "method_notes": {
                "exact": [
                    "event counts",
                    "period percentages",
                    "first/last timestamps",
                    "deterministic earliest evidence",
                ],
                "approximate": [],
            },
            "generated_utc": generated,
            "code_commit": _git_commit(config["project_root"]),
        }
        _atomic_write_text(
            _build_readme(metadata=metadata, policy=policy, heatmap=heatmap),
            staging / "README_eda04_event_taxonomy.txt",
        )
        _atomic_write_json(metadata, staging / "eda04_run_metadata.json")
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
        args = parse_args(argv)
        metadata = run_eda04(args)
    except CacheAuditError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    print(
        "EDA 4 complete: "
        f"events={metadata['aggregated_event_count']:,}, "
        f"T6={metadata['t6_row_count']:,}, "
        f"T7={metadata['t7_row_count']:,}, "
        f"T8={metadata['t8_row_count']:,}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
