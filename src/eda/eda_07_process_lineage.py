#!/usr/bin/env python3
"""
EDA 7 — Process Lineage and Command-Sequence Analysis.

Constructs directly observed same-event parent→child PROCESS edges and
conservative inferred path compositions of lengths 3–5 within the same
canonical host, configured time window, and period role. Baseline chain and
command vocabularies are fitted only on verified_benign intervals. Evaluation
rows may be scored for novelty but never alter baseline counts, ranks, or
normalization policy.

Length-2 rows are observed associations from a single PROCESS event.
Lengths 3–5 are inferred path compositions, not proven causal, process-
instance, attack, or malicious lineage. Numeric PID/PPID and actor/object IDs
are retained as supporting evidence only and are never used as global identity
keys. Ground-truth alignment remains EDA 10.
"""

from __future__ import annotations

import argparse
import hashlib
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
from typing import Any, Optional

import eda_04_event_taxonomy as eda4
import eda_05_entity_dictionary as eda5
from optc_streaming_parser import SCHEMA_VERSION

CacheAuditError = eda5.CacheAuditError

WINDOW_SIZE = "1min"
WINDOW_SECONDS = 60
DEFAULT_RARE_BENIGN_MAX_COUNT = 5
DEFAULT_EVIDENCE_CAP = 20
DEFAULT_MAX_UNUSUAL_EXAMPLES = 1000
MAX_CHAIN_LENGTH = 5
PAYLOAD_SCAN_COUNT = 1
COMMAND_RULE_VERSION = "eda07_command_normalize_v1"
CHAIN_RULE_VERSION = "eda07_observed_and_inferred_path_v1"
COMPARISON_RULE_VERSION = "eda07_process_comparison_v1"
GROUND_TRUTH_OVERLAP = "not_evaluated_eda10"
F8_CHAIN_COLOR = "#1f77b4"
F8_COMMAND_COLOR = "#ff7f0e"

PRODUCTION_CACHE_EVENTS = 180_648_918
PRODUCTION_PROCESS_TOTAL = 19_505_315
PRODUCTION_PROCESS_BENIGN = 16_880_552
PRODUCTION_PROCESS_EVALUATION = 2_624_763

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
    "parent_image_path_raw",
    "parent_process_raw",
    "command_line_raw",
    "actor_id_raw",
    "object_id_raw",
    "pid_raw",
    "ppid_raw",
}

T14_COLUMNS = [
    "period",
    "host_id",
    "chain_length",
    "parent_process",
    "child_process",
    "full_chain",
    "count",
    "first_seen_time",
    "last_seen_time",
    "benign_rank",
    "chain_id",
    "window_size",
    "construction_type",
    "link_status",
    "ambiguity_count",
    "missing_link_count",
    "supporting_observed_edge_count",
    "parent_process_raw",
    "child_process_raw",
    "parent_process_id",
    "child_process_id",
    "normalized_chain",
    "benign_count",
    "evaluation_count",
    "first_seen_period",
    "novelty_status",
    "next_process",
    "next_process_support",
    "next_process_conditional_frequency",
    "evidence_ids",
    "evidence_count",
    "mapping_status",
]

T15_COLUMNS = [
    "evidence_id",
    "timestamp",
    "host_id",
    "parent_process",
    "child_process",
    "command_line_raw",
    "command_line_normalized",
    "novelty_reason",
    "raw_event_ids",
    "ground_truth_overlap_yes_no",
    "archive_name",
    "member_name",
    "line_number",
    "period",
    "chain_id",
    "construction_type",
    "link_status",
    "actor_id_raw",
    "object_id_raw",
    "pid_raw",
    "ppid_raw",
    "normalization_status",
    "benign_chain_count",
    "benign_command_count",
    "evaluation_chain_count",
    "evaluation_command_count",
    "evidence_selection_reason",
]

D2_COLUMNS = [
    "rule_id",
    "transformation",
    "example_before",
    "example_after",
    "preserved_tokens",
    "risk",
]

_DRIVE_PATH_PARTS = {"content", "drive", "mydrive"}
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HEX_TOKEN_RE = re.compile(r"^0[xX][0-9a-fA-F]{8,}$")
_LONG_DECIMAL_RE = re.compile(r"^[0-9]{8,}$")
_TOKEN_RE = re.compile(r'"([^"\\]|\\.)*"|\'([^\'\\]|\\.)*\'|[^\s"\']+')

D2_RULEBOOK = [
    {
        "rule_id": "cmd_outer_whitespace_v1",
        "transformation": (
            "Strip only leading and trailing whitespace on the normalized "
            "copy; never rewrite command_line_raw."
        ),
        "example_before": "  tool.exe /flag value  ",
        "example_after": "tool.exe /flag value",
        "preserved_tokens": "executable name, flags, arguments, order",
        "risk": "Low; does not alter token identity inside the command.",
    },
    {
        "rule_id": "cmd_full_token_uuid_v1",
        "transformation": (
            "Replace a standalone canonical UUID token with <UUID>. "
            "Do not replace partial UUID-looking substrings."
        ),
        "example_before": (
            "tool.exe /id 123e4567-e89b-12d3-a456-426614174000 /x"
        ),
        "example_after": "tool.exe /id <UUID> /x",
        "preserved_tokens": "tool.exe, /id, /x",
        "risk": (
            "Medium; collapses distinct UUID instances into one placeholder."
        ),
    },
    {
        "rule_id": "cmd_full_token_long_hex_v1",
        "transformation": (
            "Replace only a complete 0x-prefixed hexadecimal token of length "
            ">= 8 hex digits with <HEX>. Preserve short values and flags."
        ),
        "example_before": "tool.exe /h 0xdeadbeefcafebabe /v 0x1",
        "example_after": "tool.exe /h <HEX> /v 0x1",
        "preserved_tokens": "tool.exe, /h, /v, 0x1",
        "risk": "Medium; long hex identifiers become indistinguishable.",
    },
    {
        "rule_id": "cmd_full_token_long_decimal_v1",
        "transformation": (
            "Replace only a complete decimal token of length >= 8 with "
            "<NUMBER>. Preserve ports, small numbers, and short flag values."
        ),
        "example_before": "tool.exe /pid 12345678 /port 445",
        "example_after": "tool.exe /pid <NUMBER> /port 445",
        "preserved_tokens": "tool.exe, /pid, /port, 445",
        "risk": "Medium; long numeric IDs collapse to one placeholder.",
    },
    {
        "rule_id": "cmd_quoted_ephemeral_token_v1",
        "transformation": (
            "Preserve quote boundaries. Replace a complete quoted token only "
            "when the entire inner value matches an approved ephemeral "
            "pattern (UUID, long 0x-hex, or long decimal)."
        ),
        "example_before": (
            'tool.exe --guid "123e4567-e89b-12d3-a456-426614174000"'
        ),
        "example_after": 'tool.exe --guid "<UUID>"',
        "preserved_tokens": "tool.exe, --guid, quote characters",
        "risk": (
            "Medium; quoted ephemeral IDs collapse while quote style remains."
        ),
    },
    {
        "rule_id": "cmd_fallback_preserved_v1",
        "transformation": (
            "If safe quote-aware tokenization cannot preserve structure, "
            "return the trimmed raw value and mark normalization_status as "
            "fallback_preserved."
        ),
        "example_before": 'tool.exe "unterminated',
        "example_after": 'tool.exe "unterminated',
        "preserved_tokens": "entire trimmed command text",
        "risk": (
            "Low for identity preservation; higher for vocabulary collapse "
            "because ephemeral IDs may remain."
        ),
    },
]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "EDA 7 — scale-safe process lineage and command-sequence analysis "
            "(cache only)."
        )
    )
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--normalized-cache-dir", required=True)
    parser.add_argument("--manifest-csv", required=True)
    parser.add_argument("--period-map-csv", required=True)
    parser.add_argument("--entity-dictionary-path", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--window-size", default=WINDOW_SIZE)
    parser.add_argument(
        "--rare-benign-max-count",
        type=int,
        default=DEFAULT_RARE_BENIGN_MAX_COUNT,
    )
    parser.add_argument("--evidence-cap", type=int, default=DEFAULT_EVIDENCE_CAP)
    parser.add_argument(
        "--max-unusual-examples",
        type=int,
        default=DEFAULT_MAX_UNUSUAL_EXAMPLES,
    )
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


def load_eda7_period_policy(
    path: pathlib.Path, rare_benign_max_count: int
) -> eda4.PeriodPolicy:
    if rare_benign_max_count < 1:
        raise CacheAuditError(
            "--rare-benign-max-count must be >= 1 (EDA 7 rarity is never zero)"
        )
    try:
        policy = eda4.load_period_policy(str(path), rare_benign_max_count)
    except eda4.CacheAuditError as exc:
        raise CacheAuditError(str(exc)) from exc
    if not policy.has_verified_benign:
        raise CacheAuditError("EDA 7 requires at least one verified_benign interval")
    if not policy.has_evaluation:
        raise CacheAuditError("EDA 7 requires at least one evaluation interval")
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
    t9_files, t9_glob = _t9_files_and_glob(entity_dictionary)
    if args.window_size != WINDOW_SIZE:
        raise CacheAuditError("--window-size currently allows only '1min'")

    rare = eda5._validate_positive(
        "--rare-benign-max-count", args.rare_benign_max_count
    )
    if rare < 1:
        raise CacheAuditError("--rare-benign-max-count must be >= 1")
    evidence_cap = eda5._validate_positive("--evidence-cap", args.evidence_cap)
    max_unusual = eda5._validate_positive(
        "--max-unusual-examples", args.max_unusual_examples
    )
    memory = eda5._validate_duckdb_memory_limit(args.duckdb_memory_limit)
    threads = eda5._validate_duckdb_threads(args.duckdb_threads)
    if args.duckdb_temp_dir is not None:
        spill = eda5._validate_duckdb_temp_dir(args.duckdb_temp_dir)
        if _looks_like_drive(spill):
            raise CacheAuditError("Google Drive spill paths are refused")
    _validate_output_dir(output_dir, cache_dir)
    cache_metadata = eda5._load_cache_metadata(cache_dir)
    policy = load_eda7_period_policy(period_map, rare)
    manifest = eda5._manifest_metadata(manifest_path)
    return {
        "project_root": project_root,
        "cache_dir": cache_dir,
        "manifest_path": manifest_path,
        "period_map": period_map,
        "entity_dictionary": entity_dictionary,
        "t9_files": t9_files,
        "t9_glob": t9_glob,
        "output_dir": output_dir,
        "memory_limit": memory,
        "threads": threads,
        "cache_metadata": cache_metadata,
        "policy": policy,
        "rare_benign_max_count": rare,
        "evidence_cap": evidence_cap,
        "max_unusual_examples": max_unusual,
        **manifest,
    }


def process_comparison_form(raw_value: object) -> str:
    """Full-path comparison key; never basename-only identity."""
    if raw_value is None:
        return ""
    text = str(raw_value).strip()
    if not text:
        return ""
    normalized, windows_looking = eda5._normalize_windows_path(text)
    if windows_looking:
        return normalized.casefold()
    return normalized


def process_display_normalized(raw_value: object) -> str:
    if raw_value is None:
        return ""
    text = str(raw_value).strip()
    if not text:
        return ""
    normalized, _windows = eda5._normalize_windows_path(text)
    return normalized


def unresolved_process_id(host_id: str, comparison_form: str) -> str:
    payload = json.dumps(
        [COMPARISON_RULE_VERSION, str(host_id), str(comparison_form)],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return "unresolved_" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def make_chain_id(
    *,
    host_id: str,
    construction_type: str,
    normalized_nodes: list[str],
) -> str:
    payload = json.dumps(
        [
            CHAIN_RULE_VERSION,
            str(host_id),
            str(construction_type),
            list(normalized_nodes),
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return "pch_" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def _replace_ephemeral_inner(token: str) -> str:
    if _UUID_RE.fullmatch(token):
        return "<UUID>"
    if _HEX_TOKEN_RE.fullmatch(token):
        return "<HEX>"
    if _LONG_DECIMAL_RE.fullmatch(token):
        return "<NUMBER>"
    return token


def _replace_ephemeral_token(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] and token[0] in {'"', "'"}:
        quote = token[0]
        inner = token[1:-1]
        replaced = _replace_ephemeral_inner(inner)
        if replaced != inner:
            return f"{quote}{replaced}{quote}"
        return token
    return _replace_ephemeral_inner(token)


def normalize_command_line(raw_value: object) -> dict[str, str]:
    """Conservative command normalization; never rewrites command_line_raw."""
    raw = "" if raw_value is None else str(raw_value)
    trimmed = raw.strip()
    if trimmed == "":
        return {
            "command_line_normalized": "",
            "normalization_status": "insufficient_or_missing_command",
        }
    if trimmed.count('"') % 2 == 1 or trimmed.count("'") % 2 == 1:
        return {
            "command_line_normalized": trimmed,
            "normalization_status": "fallback_preserved",
        }
    matches = list(_TOKEN_RE.finditer(trimmed))
    if not matches:
        return {
            "command_line_normalized": trimmed,
            "normalization_status": "fallback_preserved",
        }
    pieces: list[str] = []
    cursor = 0
    for match in matches:
        if match.start() < cursor:
            return {
                "command_line_normalized": trimmed,
                "normalization_status": "fallback_preserved",
            }
        pieces.append(trimmed[cursor : match.start()])
        pieces.append(_replace_ephemeral_token(match.group(0)))
        cursor = match.end()
    pieces.append(trimmed[cursor:])
    return {
        "command_line_normalized": "".join(pieces),
        "normalization_status": "normalized_v1",
    }


def novelty_status_for_count(
    benign_count: int,
    *,
    rare_benign_max_count: int,
    mapping_status: str = "resolved",
    construction_type: str = "observed_same_event",
) -> str:
    if mapping_status == "unresolved":
        return "unresolved_mapping"
    if construction_type == "inferred_path_composition" and benign_count <= 0:
        return "inferred_chain_only"
    if benign_count <= 0:
        return "unseen_in_verified_benign"
    if benign_count <= rare_benign_max_count:
        return "rare_in_verified_benign"
    return "common_in_verified_benign"


def novelty_status_for_command(
    benign_count: int,
    *,
    rare_benign_max_count: int,
    command_raw: str,
) -> str:
    if command_raw is None or str(command_raw).strip() == "":
        return "insufficient_or_missing_command"
    if benign_count <= 0:
        return "unseen_in_verified_benign"
    if benign_count <= rare_benign_max_count:
        return "rare_in_verified_benign"
    return "common_in_verified_benign"


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
            spill = pathlib.Path(tempfile.mkdtemp(prefix="eda07_duckdb_tmp_"))
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


def _period_join() -> str:
    return (
        "LEFT JOIN period_intervals pi "
        "ON e.event_time >= pi.start_time AND e.event_time < pi.end_time"
    )


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
    connection.execute(
        """
        CREATE TEMP VIEW process_dim AS
        SELECT canonical_id AS process_id, raw_value, normalized_value,
               host_if_applicable, reliability_high_medium_low, entity_status
        FROM entity_dictionary WHERE entity_type='process'
        """
    )
    connection.create_function(
        "_eda07_process_cmp", process_comparison_form, return_type="VARCHAR"
    )
    connection.create_function(
        "_eda07_process_display",
        process_display_normalized,
        return_type="VARCHAR",
    )


def _query_frame(connection, sql: str):
    return connection.execute(sql).fetchdf()


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


def _create_process_edge_aggregate(connection, evidence_cap: int) -> None:
    """One PROCESS payload scan: observed edges, commands, and reconciliation."""
    connection.execute(
        f"""
        CREATE TEMP TABLE process_scan AS
        WITH projected AS (
            SELECT
                TRY_CAST(timestamp_parsed AS TIMESTAMP) AS event_time,
                CAST(host_raw AS VARCHAR) AS host_raw,
                UPPER(TRIM(CAST(object_raw AS VARCHAR))) AS object_type,
                COALESCE(
                    NULLIF(CAST(image_path_raw AS VARCHAR), ''),
                    NULLIF(CAST(process_raw AS VARCHAR), ''),
                    ''
                ) AS child_raw,
                COALESCE(
                    NULLIF(CAST(parent_image_path_raw AS VARCHAR), ''),
                    NULLIF(CAST(parent_process_raw AS VARCHAR), ''),
                    ''
                ) AS parent_raw,
                COALESCE(CAST(command_line_raw AS VARCHAR), '') AS command_line_raw,
                COALESCE(CAST(actor_id_raw AS VARCHAR), '') AS actor_id_raw,
                COALESCE(CAST(object_id_raw AS VARCHAR), '') AS object_id_raw,
                COALESCE(CAST(pid_raw AS VARCHAR), '') AS pid_raw,
                COALESCE(CAST(ppid_raw AS VARCHAR), '') AS ppid_raw,
                COALESCE(CAST(archive_name AS VARCHAR), '') AS archive_name,
                COALESCE(CAST(member_name AS VARCHAR), '') AS member_name,
                TRY_CAST(line_number AS BIGINT) AS line_number,
                COALESCE(CAST(raw_event_id AS VARCHAR), '') AS raw_event_id
            FROM events
            WHERE TRY_CAST(timestamp_parsed AS TIMESTAMP) IS NOT NULL
              AND UPPER(TRIM(CAST(object_raw AS VARCHAR))) = 'PROCESS'
        ),
        enriched AS (
            SELECT
                COALESCE(pi.period_role, 'unassigned') AS period_role,
                date_trunc('minute', e.event_time) AS window_start,
                hd.host_id,
                e.parent_raw,
                e.child_raw,
                _eda07_process_cmp(e.parent_raw) AS parent_cmp,
                _eda07_process_cmp(e.child_raw) AS child_cmp,
                COALESCE(
                    parent_pd.normalized_value,
                    _eda07_process_display(e.parent_raw)
                ) AS parent_display,
                COALESCE(
                    child_pd.normalized_value,
                    _eda07_process_display(e.child_raw)
                ) AS child_display,
                parent_pd.process_id AS parent_process_id,
                child_pd.process_id AS child_process_id,
                CASE
                    WHEN parent_pd.process_id IS NOT NULL
                         AND child_pd.process_id IS NOT NULL
                    THEN 'resolved'
                    ELSE 'unresolved'
                END AS mapping_status,
                e.command_line_raw,
                e.actor_id_raw,
                e.object_id_raw,
                e.pid_raw,
                e.ppid_raw,
                e.event_time,
                e.archive_name,
                e.member_name,
                e.line_number,
                e.raw_event_id
            FROM projected e
            {_period_join()}
            LEFT JOIN host_dim hd ON hd.raw_value = e.host_raw
            LEFT JOIN process_dim parent_pd
              ON parent_pd.raw_value = e.parent_raw
             AND parent_pd.host_if_applicable = e.host_raw
            LEFT JOIN process_dim child_pd
              ON child_pd.raw_value = e.child_raw
             AND child_pd.host_if_applicable = e.host_raw
        )
        SELECT * FROM enriched
        """
    )

    connection.execute(
        """
        CREATE TEMP TABLE process_period_counts AS
        SELECT period_role, COUNT(*)::BIGINT AS process_event_count
        FROM process_scan
        GROUP BY period_role
        ORDER BY period_role
        """
    )

    connection.execute(
        """
        CREATE TEMP TABLE cache_period_counts AS
        WITH stamped AS (
            SELECT
                TRY_CAST(timestamp_parsed AS TIMESTAMP) AS event_time
            FROM events
            WHERE TRY_CAST(timestamp_parsed AS TIMESTAMP) IS NOT NULL
        )
        SELECT
            COALESCE(pi.period_role, 'unassigned') AS period_role,
            COUNT(*)::BIGINT AS event_count
        FROM stamped e
        LEFT JOIN period_intervals pi
          ON e.event_time >= pi.start_time AND e.event_time < pi.end_time
        GROUP BY 1
        ORDER BY 1
        """
    )

    connection.execute(
        f"""
        CREATE TEMP TABLE observed_edges AS
        SELECT
            period_role,
            window_start,
            host_id,
            parent_cmp,
            child_cmp,
            FIRST(parent_raw ORDER BY event_time, archive_name, member_name,
                  line_number, raw_event_id) AS parent_raw,
            FIRST(child_raw ORDER BY event_time, archive_name, member_name,
                  line_number, raw_event_id) AS child_raw,
            FIRST(parent_display ORDER BY event_time, archive_name, member_name,
                  line_number, raw_event_id) AS parent_display,
            FIRST(child_display ORDER BY event_time, archive_name, member_name,
                  line_number, raw_event_id) AS child_display,
            FIRST(parent_process_id ORDER BY event_time, archive_name,
                  member_name, line_number, raw_event_id)
                  AS parent_process_id,
            FIRST(child_process_id ORDER BY event_time, archive_name,
                  member_name, line_number, raw_event_id)
                  AS child_process_id,
            FIRST(mapping_status ORDER BY event_time, archive_name, member_name,
                  line_number, raw_event_id) AS mapping_status,
            COUNT(*)::BIGINT AS event_count,
            MIN(event_time) AS first_seen_time,
            MAX(event_time) AS last_seen_time,
            FIRST(event_time ORDER BY event_time, archive_name, member_name,
                  line_number, raw_event_id) AS first_evidence_event_time,
            FIRST(archive_name ORDER BY event_time, archive_name, member_name,
                  line_number, raw_event_id) AS first_evidence_archive_name,
            FIRST(member_name ORDER BY event_time, archive_name, member_name,
                  line_number, raw_event_id) AS first_evidence_member_name,
            FIRST(line_number ORDER BY event_time, archive_name, member_name,
                  line_number, raw_event_id) AS first_evidence_line_number,
            FIRST(raw_event_id ORDER BY event_time, archive_name, member_name,
                  line_number, raw_event_id) AS first_evidence_raw_event_id,
            arg_min(
                struct_pack(
                    event_time := event_time,
                    archive_name := archive_name,
                    member_name := member_name,
                    line_number := line_number,
                    raw_event_id := raw_event_id,
                    command_line_raw := command_line_raw,
                    actor_id_raw := actor_id_raw,
                    object_id_raw := object_id_raw,
                    pid_raw := pid_raw,
                    ppid_raw := ppid_raw
                ),
                struct_pack(
                    event_time := event_time,
                    archive_name := archive_name,
                    member_name := member_name,
                    line_number := line_number,
                    raw_event_id := raw_event_id
                ),
                {int(evidence_cap)}
            ) AS evidence_records
        FROM process_scan
        WHERE host_id IS NOT NULL
          AND parent_raw <> ''
          AND child_raw <> ''
          AND parent_cmp <> ''
          AND child_cmp <> ''
        GROUP BY period_role, window_start, host_id, parent_cmp, child_cmp
        """
    )

    # Keep command_observations in DuckDB only. Never fetch this table wholesale
    # into pandas; normalize via DISTINCT vocabulary + joined aggregates.
    connection.execute(
        """
        CREATE TEMP TABLE command_observations AS
        SELECT
            period_role,
            window_start,
            host_id,
            parent_cmp,
            child_cmp,
            parent_raw,
            child_raw,
            parent_display,
            child_display,
            parent_process_id,
            child_process_id,
            mapping_status,
            command_line_raw,
            actor_id_raw,
            object_id_raw,
            pid_raw,
            ppid_raw,
            event_time,
            archive_name,
            member_name,
            line_number,
            raw_event_id
        FROM process_scan
        WHERE host_id IS NOT NULL
          AND parent_raw <> ''
          AND child_raw <> ''
        """
    )

    connection.execute(
        """
        CREATE TEMP TABLE missing_link_stats AS
        SELECT
            SUM(CASE WHEN host_id IS NULL THEN 1 ELSE 0 END)::BIGINT
                AS missing_host_count,
            SUM(
                CASE
                    WHEN host_id IS NOT NULL AND parent_raw = '' THEN 1
                    ELSE 0
                END
            )::BIGINT AS missing_parent_process_count,
            SUM(
                CASE
                    WHEN host_id IS NOT NULL AND child_raw = '' THEN 1
                    ELSE 0
                END
            )::BIGINT AS missing_child_process_count,
            SUM(
                CASE
                    WHEN host_id IS NOT NULL
                         AND parent_raw <> ''
                         AND parent_cmp = ''
                    THEN 1 ELSE 0
                END
            )::BIGINT AS missing_parent_comparison_count,
            SUM(
                CASE
                    WHEN host_id IS NOT NULL
                         AND child_raw <> ''
                         AND child_cmp = ''
                    THEN 1 ELSE 0
                END
            )::BIGINT AS missing_child_comparison_count,
            SUM(
                CASE
                    WHEN host_id IS NOT NULL
                         AND parent_raw <> ''
                         AND parent_process_id IS NULL
                    THEN 1 ELSE 0
                END
            )::BIGINT AS unresolved_parent_mapping_count,
            SUM(
                CASE
                    WHEN host_id IS NOT NULL
                         AND child_raw <> ''
                         AND child_process_id IS NULL
                    THEN 1 ELSE 0
                END
            )::BIGINT AS unresolved_child_mapping_count,
            SUM(
                CASE
                    WHEN host_id IS NOT NULL
                         AND parent_raw <> ''
                         AND child_raw <> ''
                         AND parent_cmp <> ''
                         AND child_cmp <> ''
                    THEN 1 ELSE 0
                END
            )::BIGINT AS observed_pair_eligible_count
        FROM process_scan
        """
    )


def _missing_link_metadata(connection) -> dict[str, int]:
    frame = _query_frame(connection, "SELECT * FROM missing_link_stats")
    if frame.empty:
        zeros = {
            "missing_host_count": 0,
            "missing_parent_process_count": 0,
            "missing_child_process_count": 0,
            "missing_parent_comparison_count": 0,
            "missing_child_comparison_count": 0,
            "unresolved_parent_mapping_count": 0,
            "unresolved_child_mapping_count": 0,
            "observed_pair_eligible_count": 0,
            "missing_link_count_total": 0,
        }
        return zeros
    row = frame.iloc[0]
    missing_parent = int(row.missing_parent_process_count or 0)
    missing_child = int(row.missing_child_process_count or 0)
    return {
        "missing_host_count": int(row.missing_host_count or 0),
        "missing_parent_process_count": missing_parent,
        "missing_child_process_count": missing_child,
        "missing_parent_comparison_count": int(
            row.missing_parent_comparison_count or 0
        ),
        "missing_child_comparison_count": int(
            row.missing_child_comparison_count or 0
        ),
        "unresolved_parent_mapping_count": int(
            row.unresolved_parent_mapping_count or 0
        ),
        "unresolved_child_mapping_count": int(
            row.unresolved_child_mapping_count or 0
        ),
        "observed_pair_eligible_count": int(row.observed_pair_eligible_count or 0),
        "missing_link_count_total": missing_parent + missing_child,
    }


def _validate_period_and_process_counts(
    connection, cache_total: int
) -> dict[str, Any]:
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
    unassigned = int(cache_roles.get("unassigned", 0))
    process_roles = {
        str(row.period_role): int(row.process_event_count)
        for row in _query_frame(
            connection,
            "SELECT period_role, process_event_count FROM process_period_counts",
        ).itertuples(index=False)
    }
    process_total = sum(process_roles.values())
    benign = int(process_roles.get("verified_benign", 0))
    evaluation = int(process_roles.get("evaluation", 0))
    other = int(process_roles.get("other", 0))
    process_unassigned = int(process_roles.get("unassigned", 0))
    if benign + evaluation + other + process_unassigned != process_total:
        raise CacheAuditError("PROCESS period counts do not sum to PROCESS total")
    if cache_total == PRODUCTION_CACHE_EVENTS:
        if process_total != PRODUCTION_PROCESS_TOTAL:
            raise CacheAuditError(
                "Production PROCESS total mismatch: "
                f"{process_total} != {PRODUCTION_PROCESS_TOTAL}"
            )
        if benign != PRODUCTION_PROCESS_BENIGN:
            raise CacheAuditError(
                "Production verified-benign PROCESS mismatch: "
                f"{benign} != {PRODUCTION_PROCESS_BENIGN}"
            )
        if evaluation != PRODUCTION_PROCESS_EVALUATION:
            raise CacheAuditError(
                "Production evaluation PROCESS mismatch: "
                f"{evaluation} != {PRODUCTION_PROCESS_EVALUATION}"
            )
        if unassigned != 0:
            raise CacheAuditError(
                "Production pilot requires unassigned events = 0"
            )
    return {
        "cache_role_counts": cache_roles,
        "unassigned_count": unassigned,
        "process_total": process_total,
        "process_verified_benign": benign,
        "process_evaluation": evaluation,
        "process_other": other,
        "process_unassigned": process_unassigned,
    }


def _ordered_evidence_ids(records: Any, evidence_cap: int) -> list[str]:
    rows: list[dict[str, Any]] = []

    def _consume(value: Any) -> None:
        if value is None:
            return
        if hasattr(value, "tolist"):
            value = value.tolist()
        if isinstance(value, dict):
            rows.append(value)
            return
        if isinstance(value, (list, tuple)):
            for item in value:
                _consume(item)

    _consume(records)
    rows.sort(
        key=lambda item: (
            str(item.get("event_time") or ""),
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
        if len(output) >= evidence_cap:
            break
    return output


def _first_evidence_record(records: Any) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []

    def _consume(value: Any) -> None:
        if value is None:
            return
        if hasattr(value, "tolist"):
            value = value.tolist()
        if isinstance(value, dict):
            rows.append(value)
            return
        if isinstance(value, (list, tuple)):
            for item in value:
                _consume(item)

    _consume(records)
    if not rows:
        return {}
    rows.sort(
        key=lambda item: (
            str(item.get("event_time") or ""),
            str(item.get("archive_name") or ""),
            str(item.get("member_name") or ""),
            int(item.get("line_number") or 0),
            str(item.get("raw_event_id") or ""),
        )
    )
    return rows[0]


def _edge_first_evidence_locator(edge: Any) -> dict[str, Any]:
    """Earliest evidence locator fields from an observed edge row."""
    return {
        "first_evidence_event_time": getattr(
            edge, "first_evidence_event_time", None
        ),
        "first_evidence_archive_name": getattr(
            edge, "first_evidence_archive_name", None
        )
        or "",
        "first_evidence_member_name": getattr(
            edge, "first_evidence_member_name", None
        )
        or "",
        "first_evidence_line_number": int(
            getattr(edge, "first_evidence_line_number", None) or 0
        ),
        "first_evidence_raw_event_id": getattr(
            edge, "first_evidence_raw_event_id", None
        )
        or "",
    }


def _earliest_edge_first_evidence_locator(edges: list[Any]) -> dict[str, Any]:
    """Pick the earliest locator across supporting edges without unpacking."""

    def _key(edge: Any) -> tuple:
        locator = _edge_first_evidence_locator(edge)
        return (
            str(
                locator["first_evidence_event_time"]
                or getattr(edge, "first_seen_time", "")
                or ""
            ),
            str(locator["first_evidence_archive_name"] or ""),
            str(locator["first_evidence_member_name"] or ""),
            int(locator["first_evidence_line_number"] or 0),
            str(locator["first_evidence_raw_event_id"] or ""),
        )

    return _edge_first_evidence_locator(min(edges, key=_key))


def _chain_first_evidence_sort_key(row: Any) -> tuple:
    """Evidence-locator order for T15 chain preselection (no evidence unpack)."""
    event_time = getattr(row, "first_evidence_event_time", None)
    if event_time is None or str(event_time) == "" or str(event_time) == "NaT":
        event_time = getattr(row, "first_seen_time", "") or ""
    return (
        str(event_time),
        str(getattr(row, "first_evidence_archive_name", None) or ""),
        str(getattr(row, "first_evidence_member_name", None) or ""),
        int(getattr(row, "first_evidence_line_number", None) or 0),
        str(getattr(row, "first_evidence_raw_event_id", None) or ""),
        # Defensive only after the complete evidence locator key.
        str(getattr(row, "host_id", None) or ""),
        str(getattr(row, "chain_id", None) or ""),
    )


def _build_window_chains(connection, evidence_cap: int):
    """Build length-2 observed and length 3–5 inferred chains per window."""
    import pandas as pd

    edges = _query_frame(
        connection,
        """
        SELECT period_role, window_start, host_id, parent_cmp, child_cmp,
               parent_raw, child_raw, parent_display, child_display,
               parent_process_id, child_process_id, mapping_status,
               event_count, first_seen_time, last_seen_time,
               first_evidence_event_time, first_evidence_archive_name,
               first_evidence_member_name, first_evidence_line_number,
               first_evidence_raw_event_id, evidence_records
        FROM observed_edges
        ORDER BY period_role, window_start, host_id, parent_cmp, child_cmp
        """,
    )
    if edges.empty:
        return pd.DataFrame()

    # Out-degree for ambiguity: distinct children per parent in host/window/period
    out_degree: dict[tuple, set[str]] = defaultdict(set)
    for row in edges.itertuples(index=False):
        key = (row.period_role, row.window_start, row.host_id, row.parent_cmp)
        out_degree[key].add(row.child_cmp)

    # Index edges for composition
    by_group: dict[tuple, list[Any]] = defaultdict(list)
    for row in edges.itertuples(index=False):
        by_group[(row.period_role, row.window_start, row.host_id)].append(row)

    chain_rows: list[dict[str, Any]] = []

    def emit_chain(
        *,
        period_role: str,
        window_start,
        host_id: str,
        nodes_cmp: list[str],
        nodes_display: list[str],
        parent_raw: str,
        child_raw: str,
        parent_id: Optional[str],
        child_id: Optional[str],
        mapping_status: str,
        construction_type: str,
        link_status: str,
        supporting: int,
        ambiguity: int,
        missing: int,
        count: int,
        first_seen,
        last_seen,
        evidence_records,
        first_evidence_event_time,
        first_evidence_archive_name,
        first_evidence_member_name,
        first_evidence_line_number,
        first_evidence_raw_event_id,
    ) -> None:
        if len(nodes_cmp) != len(set(nodes_cmp)):
            return
        if len(nodes_cmp) < 2 or len(nodes_cmp) > MAX_CHAIN_LENGTH:
            return
        if parent_id is None:
            parent_id = unresolved_process_id(host_id, nodes_cmp[0])
        if child_id is None:
            child_id = unresolved_process_id(host_id, nodes_cmp[-1])
        evidence_ids = _ordered_evidence_ids(evidence_records, evidence_cap)
        chain_rows.append(
            {
                "period": period_role,
                "window_start": window_start,
                "host_id": host_id,
                "chain_length": len(nodes_cmp),
                "parent_process": nodes_display[0],
                "child_process": nodes_display[-1],
                "full_chain": " -> ".join(nodes_display),
                "normalized_chain": " -> ".join(nodes_cmp),
                "count": int(count),
                "first_seen_time": first_seen,
                "last_seen_time": last_seen,
                "construction_type": construction_type,
                "link_status": link_status,
                "ambiguity_count": int(ambiguity),
                "missing_link_count": int(missing),
                "supporting_observed_edge_count": int(supporting),
                "parent_process_raw": parent_raw,
                "child_process_raw": child_raw,
                "parent_process_id": parent_id,
                "child_process_id": child_id,
                "mapping_status": mapping_status,
                "evidence_ids": evidence_ids,
                "evidence_records": evidence_records,
                "normalized_nodes": list(nodes_cmp),
                # Internal T15 preselection fields (not part of T14/T15 schemas).
                "first_evidence_event_time": first_evidence_event_time,
                "first_evidence_archive_name": first_evidence_archive_name,
                "first_evidence_member_name": first_evidence_member_name,
                "first_evidence_line_number": int(
                    first_evidence_line_number or 0
                ),
                "first_evidence_raw_event_id": first_evidence_raw_event_id,
            }
        )

    for group_key, group_edges in by_group.items():
        period_role, window_start, host_id = group_key
        # adjacency: parent_cmp -> list of edge rows
        adjacency: dict[str, list[Any]] = defaultdict(list)
        for edge in group_edges:
            adjacency[edge.parent_cmp].append(edge)

        # Length 2
        for edge in group_edges:
            ambiguity = max(0, len(out_degree[
                (period_role, window_start, host_id, edge.parent_cmp)
            ]) - 1)
            locator = _edge_first_evidence_locator(edge)
            emit_chain(
                period_role=period_role,
                window_start=window_start,
                host_id=str(host_id),
                nodes_cmp=[edge.parent_cmp, edge.child_cmp],
                nodes_display=[edge.parent_display, edge.child_display],
                parent_raw=edge.parent_raw,
                child_raw=edge.child_raw,
                parent_id=edge.parent_process_id,
                child_id=edge.child_process_id,
                mapping_status=edge.mapping_status,
                construction_type="observed_same_event",
                link_status="observed",
                supporting=1,
                ambiguity=ambiguity,
                missing=0,
                count=edge.event_count,
                first_seen=edge.first_seen_time,
                last_seen=edge.last_seen_time,
                evidence_records=edge.evidence_records,
                first_evidence_event_time=locator["first_evidence_event_time"],
                first_evidence_archive_name=locator[
                    "first_evidence_archive_name"
                ],
                first_evidence_member_name=locator[
                    "first_evidence_member_name"
                ],
                first_evidence_line_number=locator[
                    "first_evidence_line_number"
                ],
                first_evidence_raw_event_id=locator[
                    "first_evidence_raw_event_id"
                ],
            )

        # Lengths 3-5: extend distinct edge paths when child_cmp matches the
        # next parent_cmp. Reject cycles/repeated nodes; dedupe node tuples.
        paths: list[tuple[list[Any], set[str]]] = []
        for edge in group_edges:
            paths.append(([edge], {edge.parent_cmp, edge.child_cmp}))

        for target_len in range(3, MAX_CHAIN_LENGTH + 1):
            next_paths: list[tuple[list[Any], set[str]]] = []
            seen_node_tuples: set[tuple[str, ...]] = set()
            for edge_list, used in paths:
                # Paths entering this round have target_len-2 edges (target_len-1
                # nodes) and extend by one observed edge.
                if len(edge_list) != target_len - 2:
                    continue
                last = edge_list[-1]
                for nxt in adjacency.get(last.child_cmp, []):
                    if nxt.child_cmp in used:
                        continue
                    nodes = [edge_list[0].parent_cmp]
                    for edge in edge_list:
                        nodes.append(edge.child_cmp)
                    nodes.append(nxt.child_cmp)
                    if len(nodes) != target_len or len(nodes) != len(set(nodes)):
                        continue
                    node_tuple = tuple(nodes)
                    if node_tuple in seen_node_tuples:
                        continue
                    seen_node_tuples.add(node_tuple)
                    new_list = edge_list + [nxt]
                    new_used = set(used)
                    new_used.add(nxt.child_cmp)
                    next_paths.append((new_list, new_used))

                    displays = [new_list[0].parent_display]
                    for edge in new_list:
                        displays.append(edge.child_display)
                    ambiguity = 0
                    for edge in new_list:
                        ambiguity += max(
                            0,
                            len(
                                out_degree[
                                    (
                                        period_role,
                                        window_start,
                                        host_id,
                                        edge.parent_cmp,
                                    )
                                ]
                            )
                            - 1,
                        )
                    merged_evidence = [
                        edge.evidence_records for edge in new_list
                    ]
                    # Inferred compositions have no reliable process-instance
                    # linkage, so per-window count is presence (1), not
                    # min(edge event counts). Aggregated T14 count therefore
                    # equals the number of supporting windows.
                    count = 1
                    first_seen = min(edge.first_seen_time for edge in new_list)
                    last_seen = max(edge.last_seen_time for edge in new_list)
                    locator = _earliest_edge_first_evidence_locator(new_list)
                    mapping = (
                        "resolved"
                        if all(
                            edge.mapping_status == "resolved" for edge in new_list
                        )
                        else "unresolved"
                    )
                    emit_chain(
                        period_role=period_role,
                        window_start=window_start,
                        host_id=str(host_id),
                        nodes_cmp=nodes,
                        nodes_display=displays,
                        parent_raw=new_list[0].parent_raw,
                        child_raw=new_list[-1].child_raw,
                        parent_id=new_list[0].parent_process_id,
                        child_id=new_list[-1].child_process_id,
                        mapping_status=mapping,
                        construction_type="inferred_path_composition",
                        link_status="inferred_not_causal",
                        supporting=len(new_list),
                        ambiguity=ambiguity,
                        missing=0,
                        count=count,
                        first_seen=first_seen,
                        last_seen=last_seen,
                        evidence_records=merged_evidence,
                        first_evidence_event_time=locator[
                            "first_evidence_event_time"
                        ],
                        first_evidence_archive_name=locator[
                            "first_evidence_archive_name"
                        ],
                        first_evidence_member_name=locator[
                            "first_evidence_member_name"
                        ],
                        first_evidence_line_number=locator[
                            "first_evidence_line_number"
                        ],
                        first_evidence_raw_event_id=locator[
                            "first_evidence_raw_event_id"
                        ],
                    )
            paths = next_paths

    if not chain_rows:
        return pd.DataFrame()
    frame = pd.DataFrame(chain_rows)
    frame["chain_id"] = [
        make_chain_id(
            host_id=str(row.host_id),
            construction_type=str(row.construction_type),
            normalized_nodes=list(row.normalized_nodes),
        )
        for row in frame.itertuples(index=False)
    ]
    return frame


def _aggregate_t14(
    window_chains,
    *,
    rare_benign_max_count: int,
    evidence_cap: int,
    connection,
):
    import pandas as pd

    if window_chains is None or window_chains.empty:
        return pd.DataFrame(columns=T14_COLUMNS)

    # Baseline counts from verified_benign only, keyed by host+normalized_chain
    benign = window_chains.loc[
        window_chains["period"] == "verified_benign"
    ].copy()
    benign_stats: dict[tuple[str, str], dict[str, Any]] = {}
    for row in benign.itertuples(index=False):
        key = (str(row.host_id), str(row.normalized_chain))
        stats = benign_stats.setdefault(
            key,
            {
                "benign_count": 0,
                "first": row.first_seen_time,
                "last": row.last_seen_time,
            },
        )
        stats["benign_count"] += int(row.count)
        if row.first_seen_time < stats["first"]:
            stats["first"] = row.first_seen_time
        if row.last_seen_time > stats["last"]:
            stats["last"] = row.last_seen_time

    # Rank by benign_count desc, then chain_id
    rank_items = sorted(
        (
            (key, stats["benign_count"], make_chain_id(
                host_id=key[0],
                construction_type=(
                    "observed_same_event"
                    if key[1].count(" -> ") == 1
                    else "inferred_path_composition"
                ),
                normalized_nodes=key[1].split(" -> "),
            ))
            for key, stats in benign_stats.items()
        ),
        key=lambda item: (-item[1], item[2]),
    )
    benign_rank: dict[tuple[str, str], int] = {}
    for index, (key, _count, _cid) in enumerate(rank_items, start=1):
        benign_rank[key] = index

    # Next-process transitions from verified_benign observed edges only
    transitions = _query_frame(
        connection,
        """
        SELECT host_id, parent_cmp, child_display, child_cmp,
               SUM(event_count)::BIGINT AS support
        FROM observed_edges
        WHERE period_role = 'verified_benign'
        GROUP BY host_id, parent_cmp, child_display, child_cmp
        ORDER BY host_id, parent_cmp, support DESC, child_cmp
        """,
    )
    next_map: dict[tuple[str, str], tuple[str, int, float]] = {}
    if not transitions.empty:
        totals: dict[tuple[str, str], int] = defaultdict(int)
        for row in transitions.itertuples(index=False):
            totals[(str(row.host_id), str(row.parent_cmp))] += int(row.support)
        best: dict[tuple[str, str], tuple[str, str, int]] = {}
        for row in transitions.itertuples(index=False):
            key = (str(row.host_id), str(row.parent_cmp))
            current = best.get(key)
            child_cmp = str(row.child_cmp)
            support = int(row.support)
            if current is None or support > current[2] or (
                support == current[2] and child_cmp < current[1]
            ):
                best[key] = (str(row.child_display), child_cmp, support)
        for key, (label, _child_cmp, support) in best.items():
            total = totals[key]
            freq = (support / total) if total > 0 else None
            next_map[key] = (label, support, freq)

    # Aggregate window rows to period x host x chain_id
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in window_chains.itertuples(index=False):
        key = (str(row.period), str(row.host_id), str(row.chain_id))
        item = grouped.get(key)
        if item is None:
            grouped[key] = {
                "period": str(row.period),
                "host_id": str(row.host_id),
                "chain_length": int(row.chain_length),
                "parent_process": row.parent_process,
                "child_process": row.child_process,
                "full_chain": row.full_chain,
                "count": int(row.count),
                "first_seen_time": row.first_seen_time,
                "last_seen_time": row.last_seen_time,
                "chain_id": str(row.chain_id),
                "window_size": WINDOW_SIZE,
                "construction_type": row.construction_type,
                "link_status": row.link_status,
                "ambiguity_count": int(row.ambiguity_count),
                "missing_link_count": int(row.missing_link_count),
                "supporting_observed_edge_count": int(
                    row.supporting_observed_edge_count
                ),
                "parent_process_raw": row.parent_process_raw,
                "child_process_raw": row.child_process_raw,
                "parent_process_id": row.parent_process_id,
                "child_process_id": row.child_process_id,
                "normalized_chain": row.normalized_chain,
                "mapping_status": row.mapping_status,
                "evidence_ids": list(row.evidence_ids),
                "normalized_nodes": list(row.normalized_nodes),
            }
        else:
            item["count"] += int(row.count)
            if row.first_seen_time < item["first_seen_time"]:
                item["first_seen_time"] = row.first_seen_time
            if row.last_seen_time > item["last_seen_time"]:
                item["last_seen_time"] = row.last_seen_time
            item["ambiguity_count"] = max(
                item["ambiguity_count"], int(row.ambiguity_count)
            )
            # Merge evidence deterministically
            merged = list(item["evidence_ids"]) + list(row.evidence_ids)
            seen: set[str] = set()
            ordered: list[str] = []
            for event_id in merged:
                if event_id in seen:
                    continue
                seen.add(event_id)
                ordered.append(event_id)
                if len(ordered) >= evidence_cap:
                    break
            item["evidence_ids"] = ordered

    # Evaluation counts by host+normalized_chain
    eval_counts: dict[tuple[str, str], int] = defaultdict(int)
    for row in window_chains.itertuples(index=False):
        if row.period == "evaluation":
            eval_counts[
                (str(row.host_id), str(row.normalized_chain))
            ] += int(row.count)

    # First-seen period across all observations of the chain
    first_period: dict[tuple[str, str], tuple[Any, str]] = {}
    for row in window_chains.itertuples(index=False):
        key = (str(row.host_id), str(row.normalized_chain))
        current = first_period.get(key)
        if current is None or row.first_seen_time < current[0]:
            first_period[key] = (row.first_seen_time, str(row.period))

    rows: list[dict[str, Any]] = []
    for item in grouped.values():
        key = (item["host_id"], item["normalized_chain"])
        b_count = int(benign_stats.get(key, {}).get("benign_count", 0))
        e_count = int(eval_counts.get(key, 0))
        last_cmp = item["normalized_nodes"][-1]
        nxt = next_map.get((item["host_id"], last_cmp))
        if nxt is None:
            next_process, next_support, next_freq = "", 0, None
        else:
            next_process, next_support, next_freq = nxt
        novelty = novelty_status_for_count(
            b_count,
            rare_benign_max_count=rare_benign_max_count,
            mapping_status=item["mapping_status"],
            construction_type=item["construction_type"],
        )
        evidence_ids = item["evidence_ids"][:evidence_cap]
        rows.append(
            {
                "period": item["period"],
                "host_id": item["host_id"],
                "chain_length": item["chain_length"],
                "parent_process": item["parent_process"],
                "child_process": item["child_process"],
                "full_chain": item["full_chain"],
                "count": item["count"],
                "first_seen_time": item["first_seen_time"],
                "last_seen_time": item["last_seen_time"],
                "benign_rank": benign_rank.get(key),
                "chain_id": item["chain_id"],
                "window_size": WINDOW_SIZE,
                "construction_type": item["construction_type"],
                "link_status": item["link_status"],
                "ambiguity_count": item["ambiguity_count"],
                "missing_link_count": item["missing_link_count"],
                "supporting_observed_edge_count": item[
                    "supporting_observed_edge_count"
                ],
                "parent_process_raw": item["parent_process_raw"],
                "child_process_raw": item["child_process_raw"],
                "parent_process_id": item["parent_process_id"],
                "child_process_id": item["child_process_id"],
                "normalized_chain": item["normalized_chain"],
                "benign_count": b_count,
                "evaluation_count": e_count,
                "first_seen_period": first_period.get(key, (None, None))[1],
                "novelty_status": novelty,
                "next_process": next_process,
                "next_process_support": next_support,
                "next_process_conditional_frequency": next_freq,
                "evidence_ids": _compact_json(evidence_ids),
                "evidence_count": len(evidence_ids),
                "mapping_status": item["mapping_status"],
            }
        )

    frame = pd.DataFrame(rows, columns=T14_COLUMNS)
    if frame.empty:
        return frame
    return frame.sort_values(
        by=["period", "host_id", "chain_length", "chain_id"],
        kind="mergesort",
    ).reset_index(drop=True)


def _build_bounded_command_aggregates(
    connection,
    *,
    rare_benign_max_count: int,
    max_unusual_examples: int,
):
    """Normalize DISTINCT commands once; aggregate in DuckDB only.

    Never fetch wholesale command_observations into pandas.
    """
    import pandas as pd

    distinct = _query_frame(
        connection,
        """
        SELECT DISTINCT CAST(command_line_raw AS VARCHAR) AS command_line_raw
        FROM command_observations
        ORDER BY command_line_raw
        """,
    )
    mapping_rows: list[dict[str, str]] = []
    for value in distinct["command_line_raw"].tolist() if not distinct.empty else []:
        raw = "" if value is None else str(value)
        normalized = normalize_command_line(raw)
        mapping_rows.append(
            {
                "command_line_raw": raw,
                "command_line_normalized": normalized["command_line_normalized"],
                "normalization_status": normalized["normalization_status"],
            }
        )
    mapping = pd.DataFrame(
        mapping_rows,
        columns=[
            "command_line_raw",
            "command_line_normalized",
            "normalization_status",
        ],
    )
    connection.register("_eda07_command_norm_frame", mapping)
    connection.execute(
        """
        CREATE OR REPLACE TEMP TABLE command_norm_map AS
        SELECT
            CAST(command_line_raw AS VARCHAR) AS command_line_raw,
            CAST(command_line_normalized AS VARCHAR) AS command_line_normalized,
            CAST(normalization_status AS VARCHAR) AS normalization_status
        FROM _eda07_command_norm_frame
        """
    )
    connection.unregister("_eda07_command_norm_frame")

    connection.execute(
        """
        CREATE OR REPLACE TEMP TABLE command_obs_enriched AS
        SELECT
            o.*,
            COALESCE(m.command_line_normalized, '') AS command_line_normalized,
            COALESCE(m.normalization_status, 'insufficient_or_missing_command')
                AS normalization_status
        FROM command_observations o
        LEFT JOIN command_norm_map m
          ON m.command_line_raw = o.command_line_raw
        """
    )

    benign_frame = _query_frame(
        connection,
        """
        SELECT command_line_normalized,
               COUNT(*)::BIGINT AS benign_count
        FROM command_obs_enriched
        WHERE period_role = 'verified_benign'
          AND command_line_normalized <> ''
        GROUP BY command_line_normalized
        ORDER BY command_line_normalized
        """,
    )
    eval_frame = _query_frame(
        connection,
        """
        SELECT command_line_normalized,
               COUNT(*)::BIGINT AS evaluation_count
        FROM command_obs_enriched
        WHERE period_role = 'evaluation'
          AND command_line_normalized <> ''
        GROUP BY command_line_normalized
        ORDER BY command_line_normalized
        """,
    )
    benign_cmd = {
        str(row.command_line_normalized): int(row.benign_count)
        for row in benign_frame.itertuples(index=False)
    }
    eval_cmd = {
        str(row.command_line_normalized): int(row.evaluation_count)
        for row in eval_frame.itertuples(index=False)
    }

    connection.register(
        "_eda07_benign_cmd_frame",
        pd.DataFrame(
            [
                {"command_line_normalized": key, "benign_count": value}
                for key, value in sorted(benign_cmd.items())
            ],
            columns=["command_line_normalized", "benign_count"],
        ),
    )
    connection.execute(
        """
        CREATE OR REPLACE TEMP TABLE benign_command_counts AS
        SELECT CAST(command_line_normalized AS VARCHAR) AS command_line_normalized,
               CAST(benign_count AS BIGINT) AS benign_count
        FROM _eda07_benign_cmd_frame
        """
    )
    connection.unregister("_eda07_benign_cmd_frame")

    f8_command = _query_frame(
        connection,
        f"""
        SELECT e.host_id, e.window_start,
               COUNT(*)::BIGINT AS command_novelty_count
        FROM command_obs_enriched e
        LEFT JOIN benign_command_counts b
          ON b.command_line_normalized = e.command_line_normalized
        WHERE e.period_role = 'evaluation'
          AND e.command_line_normalized <> ''
          AND COALESCE(b.benign_count, 0) <= {int(rare_benign_max_count)}
        GROUP BY e.host_id, e.window_start
        ORDER BY e.host_id, e.window_start
        """,
    )

    # Bounded unusual-command evaluation evidence candidates only.
    unusual_command_candidates = _query_frame(
        connection,
        f"""
        SELECT * EXCLUDE(rank_number) FROM (
            SELECT
                e.event_time AS timestamp,
                e.host_id,
                e.parent_display AS parent_process,
                e.child_display AS child_process,
                e.parent_cmp,
                e.child_cmp,
                e.command_line_raw,
                e.command_line_normalized,
                e.normalization_status,
                e.archive_name,
                e.member_name,
                e.line_number,
                e.raw_event_id,
                e.actor_id_raw,
                e.object_id_raw,
                e.pid_raw,
                e.ppid_raw,
                COALESCE(b.benign_count, 0)::BIGINT AS benign_command_count,
                ROW_NUMBER() OVER (
                    ORDER BY e.event_time, e.archive_name, e.member_name,
                             e.line_number, e.raw_event_id
                ) AS rank_number
            FROM command_obs_enriched e
            LEFT JOIN benign_command_counts b
              ON b.command_line_normalized = e.command_line_normalized
            WHERE e.period_role = 'evaluation'
              AND (
                    e.command_line_normalized = ''
                    OR COALESCE(b.benign_count, 0) <= {int(rare_benign_max_count)}
              )
        )
        WHERE rank_number <= {int(max_unusual_examples)}
        ORDER BY timestamp, archive_name, member_name, line_number, raw_event_id
        """,
    )

    normalization_counts = _query_frame(
        connection,
        """
        SELECT normalization_status, COUNT(*)::BIGINT AS observation_count
        FROM command_obs_enriched
        GROUP BY normalization_status
        ORDER BY normalization_status
        """,
    )

    return {
        "benign_cmd": benign_cmd,
        "eval_cmd": eval_cmd,
        "f8_command": f8_command,
        "unusual_command_candidates": unusual_command_candidates,
        "normalization_counts": {
            str(row.normalization_status): int(row.observation_count)
            for row in normalization_counts.itertuples(index=False)
        },
        "distinct_command_count": int(len(mapping)),
    }


def _t15_novelty_reason(
    *,
    chain_unusual: bool,
    command_unusual: bool,
    command_missing: bool,
) -> str:
    if command_missing and chain_unusual:
        return "unusual_chain_insufficient_command"
    if command_missing:
        return "insufficient_or_missing_command"
    if chain_unusual and command_unusual:
        return "unusual_chain_unusual_command"
    if chain_unusual:
        return "unusual_chain_common_command"
    if command_unusual:
        return "common_chain_unusual_command"
    return "common_in_verified_benign"


def _evidence_order_key(evidence: dict[str, Any], fallback_time: Any = "") -> tuple:
    return (
        str(evidence.get("event_time") or fallback_time or ""),
        str(evidence.get("archive_name") or ""),
        str(evidence.get("member_name") or ""),
        int(evidence.get("line_number") or 0),
        str(evidence.get("raw_event_id") or ""),
    )


def select_bounded_chain_unusual_candidates(
    window_chains,
    chain_counts: dict[str, tuple[int, int]],
    *,
    rare_benign_max_count: int,
    max_unusual_examples: int,
) -> list[Any]:
    """Return at most max_unusual_examples evaluation chain rows.

    Pre-selects by chain novelty and the established evidence-locator order
    (event_time, archive_name, member_name, line_number, raw_event_id)
    using internal ``first_evidence_*`` fields — without unpacking evidence
    or building T15 dictionaries. Full evidence extraction happens only for
    this bounded result set.
    """
    if (
        window_chains is None
        or getattr(window_chains, "empty", True)
        or max_unusual_examples < 1
    ):
        return []

    ranked: list[tuple[tuple, Any]] = []
    eval_obs = window_chains.loc[
        (window_chains["period"] == "evaluation")
        & (window_chains["construction_type"] == "observed_same_event")
    ]
    for row in eval_obs.itertuples(index=False):
        chain_id = str(row.chain_id)
        b_chain = int(chain_counts.get(chain_id, (0, 0))[0])
        if b_chain > rare_benign_max_count:
            # Common chains with unusual commands are covered by the bounded
            # DuckDB command-candidate path, not by unpacking every chain.
            continue
        ranked.append((_chain_first_evidence_sort_key(row), row))
    ranked.sort(key=lambda item: item[0])
    return [row for _key, row in ranked[:max_unusual_examples]]


def _build_unusual_row_from_chain(
    row,
    *,
    chain_counts: dict[str, tuple[int, int]],
    benign_cmd: dict[str, int],
    eval_cmd: dict[str, int],
    rare_benign_max_count: int,
    evidence_cap: int,
) -> Optional[dict[str, Any]]:
    chain_id = str(row.chain_id)
    b_chain, e_chain = chain_counts.get(chain_id, (0, 0))
    chain_unusual = b_chain <= rare_benign_max_count
    evidence = _first_evidence_record(row.evidence_records)
    cmd_raw = (
        ""
        if evidence.get("command_line_raw") is None
        else str(evidence.get("command_line_raw"))
    )
    cmd_norm = normalize_command_line(cmd_raw)
    cmd_key = cmd_norm["command_line_normalized"]
    b_cmd = int(benign_cmd.get(cmd_key, 0))
    command_missing = cmd_raw.strip() == ""
    command_unusual = command_missing or b_cmd <= rare_benign_max_count
    if not chain_unusual and not command_unusual:
        return None
    event_id = str(evidence.get("raw_event_id") or "")
    if not event_id:
        return None
    return {
        "evidence_id": "",
        "timestamp": evidence.get("event_time") or row.first_seen_time,
        "host_id": row.host_id,
        "parent_process": row.parent_process,
        "child_process": row.child_process,
        "command_line_raw": cmd_raw,
        "command_line_normalized": cmd_key,
        "novelty_reason": _t15_novelty_reason(
            chain_unusual=chain_unusual,
            command_unusual=(
                (not command_missing) and b_cmd <= rare_benign_max_count
            ),
            command_missing=command_missing,
        ),
        "raw_event_ids": _compact_json(
            _ordered_evidence_ids(row.evidence_records, evidence_cap)
        ),
        "ground_truth_overlap_yes_no": GROUND_TRUTH_OVERLAP,
        "archive_name": evidence.get("archive_name") or "",
        "member_name": evidence.get("member_name") or "",
        "line_number": evidence.get("line_number") or 0,
        "period": "evaluation",
        "chain_id": chain_id,
        "construction_type": row.construction_type,
        "link_status": row.link_status,
        "actor_id_raw": evidence.get("actor_id_raw") or "",
        "object_id_raw": evidence.get("object_id_raw") or "",
        "pid_raw": evidence.get("pid_raw") or "",
        "ppid_raw": evidence.get("ppid_raw") or "",
        "normalization_status": cmd_norm["normalization_status"],
        "benign_chain_count": b_chain,
        "benign_command_count": b_cmd,
        "evaluation_chain_count": e_chain,
        "evaluation_command_count": int(eval_cmd.get(cmd_key, 0)),
        "evidence_selection_reason": "unusual_evaluation_example",
        "_sort": _evidence_order_key(evidence, row.first_seen_time),
    }


def _build_unusual_row_from_command_candidate(
    row,
    *,
    chain_counts: dict[str, tuple[int, int]],
    eval_cmd: dict[str, int],
    rare_benign_max_count: int,
) -> Optional[dict[str, Any]]:
    nodes = [str(row.parent_cmp), str(row.child_cmp)]
    chain_id = make_chain_id(
        host_id=str(row.host_id),
        construction_type="observed_same_event",
        normalized_nodes=nodes,
    )
    b_chain, e_chain = chain_counts.get(chain_id, (0, 0))
    chain_unusual = b_chain <= rare_benign_max_count
    cmd_raw = "" if row.command_line_raw is None else str(row.command_line_raw)
    command_missing = cmd_raw.strip() == ""
    b_cmd = int(row.benign_command_count)
    command_unusual = command_missing or b_cmd <= rare_benign_max_count
    if not chain_unusual and not command_unusual:
        return None
    event_id = str(row.raw_event_id)
    return {
        "evidence_id": "",
        "timestamp": row.timestamp,
        "host_id": row.host_id,
        "parent_process": row.parent_process,
        "child_process": row.child_process,
        "command_line_raw": cmd_raw,
        "command_line_normalized": row.command_line_normalized,
        "novelty_reason": _t15_novelty_reason(
            chain_unusual=chain_unusual,
            command_unusual=(
                (not command_missing) and b_cmd <= rare_benign_max_count
            ),
            command_missing=command_missing,
        ),
        "raw_event_ids": _compact_json([event_id]),
        "ground_truth_overlap_yes_no": GROUND_TRUTH_OVERLAP,
        "archive_name": row.archive_name,
        "member_name": row.member_name,
        "line_number": int(row.line_number or 0),
        "period": "evaluation",
        "chain_id": chain_id,
        "construction_type": "observed_same_event",
        "link_status": "observed",
        "actor_id_raw": row.actor_id_raw,
        "object_id_raw": row.object_id_raw,
        "pid_raw": row.pid_raw,
        "ppid_raw": row.ppid_raw,
        "normalization_status": row.normalization_status,
        "benign_chain_count": b_chain,
        "benign_command_count": b_cmd,
        "evaluation_chain_count": e_chain,
        "evaluation_command_count": int(
            eval_cmd.get(str(row.command_line_normalized), 0)
        ),
        "evidence_selection_reason": "unusual_evaluation_example",
        "_sort": (
            str(row.timestamp),
            str(row.archive_name),
            str(row.member_name),
            int(row.line_number or 0),
            event_id,
        ),
    }


def _build_t15(
    window_chains,
    command_aggregates: dict[str, Any],
    t14,
    *,
    rare_benign_max_count: int,
    max_unusual_examples: int,
    evidence_cap: int,
):
    import pandas as pd

    benign_cmd = command_aggregates["benign_cmd"]
    eval_cmd = command_aggregates["eval_cmd"]
    unusual_command_candidates = command_aggregates["unusual_command_candidates"]

    chain_counts: dict[str, tuple[int, int]] = {}
    if t14 is not None and not t14.empty:
        for row in t14.itertuples(index=False):
            chain_counts[str(row.chain_id)] = (
                int(row.benign_count),
                int(row.evaluation_count),
            )

    common_rows: list[dict[str, Any]] = []
    if window_chains is not None and not window_chains.empty:
        benign_obs = window_chains.loc[
            (window_chains["period"] == "verified_benign")
            & (window_chains["construction_type"] == "observed_same_event")
        ].copy()
        if not benign_obs.empty:
            scored = []
            for row in benign_obs.itertuples(index=False):
                b_count = chain_counts.get(str(row.chain_id), (0, 0))[0]
                scored.append(
                    (b_count, str(row.first_seen_time), str(row.chain_id), row)
                )
            scored.sort(key=lambda item: (-item[0], item[1], item[2]))
            seen_chains: set[str] = set()
            for b_count, _ts, chain_id, row in scored:
                if chain_id in seen_chains:
                    continue
                if b_count <= rare_benign_max_count:
                    continue
                seen_chains.add(chain_id)
                evidence = _first_evidence_record(row.evidence_records)
                cmd_raw = (
                    ""
                    if evidence.get("command_line_raw") is None
                    else str(evidence.get("command_line_raw"))
                )
                cmd_norm = normalize_command_line(cmd_raw)
                event_id = str(evidence.get("raw_event_id") or "")
                if not event_id:
                    continue
                common_rows.append(
                    {
                        "evidence_id": "",
                        "timestamp": evidence.get("event_time")
                        or row.first_seen_time,
                        "host_id": row.host_id,
                        "parent_process": row.parent_process,
                        "child_process": row.child_process,
                        "command_line_raw": cmd_raw,
                        "command_line_normalized": cmd_norm[
                            "command_line_normalized"
                        ],
                        "novelty_reason": "common_in_verified_benign",
                        "raw_event_ids": _compact_json(
                            _ordered_evidence_ids(
                                row.evidence_records, evidence_cap
                            )
                        ),
                        "ground_truth_overlap_yes_no": GROUND_TRUTH_OVERLAP,
                        "archive_name": evidence.get("archive_name") or "",
                        "member_name": evidence.get("member_name") or "",
                        "line_number": evidence.get("line_number") or 0,
                        "period": "verified_benign",
                        "chain_id": chain_id,
                        "construction_type": row.construction_type,
                        "link_status": row.link_status,
                        "actor_id_raw": evidence.get("actor_id_raw") or "",
                        "object_id_raw": evidence.get("object_id_raw") or "",
                        "pid_raw": evidence.get("pid_raw") or "",
                        "ppid_raw": evidence.get("ppid_raw") or "",
                        "normalization_status": cmd_norm["normalization_status"],
                        "benign_chain_count": b_count,
                        "benign_command_count": int(
                            benign_cmd.get(
                                cmd_norm["command_line_normalized"], 0
                            )
                        ),
                        "evaluation_chain_count": chain_counts.get(
                            chain_id, (0, 0)
                        )[1],
                        "evaluation_command_count": int(
                            eval_cmd.get(cmd_norm["command_line_normalized"], 0)
                        ),
                        "evidence_selection_reason": (
                            "common_verified_benign_example"
                        ),
                    }
                )
                if len(common_rows) >= 10:
                    break

    # Bound each source independently before combining.
    chain_source_rows = select_bounded_chain_unusual_candidates(
        window_chains,
        chain_counts,
        rare_benign_max_count=rare_benign_max_count,
        max_unusual_examples=max_unusual_examples,
    )
    chain_candidates: list[dict[str, Any]] = []
    for row in chain_source_rows:
        built = _build_unusual_row_from_chain(
            row,
            chain_counts=chain_counts,
            benign_cmd=benign_cmd,
            eval_cmd=eval_cmd,
            rare_benign_max_count=rare_benign_max_count,
            evidence_cap=evidence_cap,
        )
        if built is not None:
            chain_candidates.append(built)

    command_candidates: list[dict[str, Any]] = []
    if (
        unusual_command_candidates is not None
        and not unusual_command_candidates.empty
        and max_unusual_examples >= 1
    ):
        # DuckDB already limited the frame; still cap construction explicitly.
        for row in unusual_command_candidates.head(
            max_unusual_examples
        ).itertuples(index=False):
            built = _build_unusual_row_from_command_candidate(
                row,
                chain_counts=chain_counts,
                eval_cmd=eval_cmd,
                rare_benign_max_count=rare_benign_max_count,
            )
            if built is not None:
                command_candidates.append(built)

    unusual_by_event: dict[str, dict[str, Any]] = {}
    for candidate in chain_candidates + command_candidates:
        event_ids = json.loads(candidate["raw_event_ids"])
        if not event_ids:
            continue
        event_id = event_ids[0]
        if event_id not in unusual_by_event:
            unusual_by_event[event_id] = candidate

    unusual_rows = sorted(
        unusual_by_event.values(), key=lambda item: item["_sort"]
    )[:max_unusual_examples]
    for item in unusual_rows:
        item.pop("_sort", None)

    # Common and unusual limits are independent: 10 + max_unusual_examples.
    rows = common_rows + unusual_rows
    for index, row in enumerate(rows):
        event_ids = json.loads(row["raw_event_ids"])
        first = event_ids[0] if event_ids else f"missing_{index}"
        row["evidence_id"] = f"t15_{index:04d}_{first}"

    return pd.DataFrame(rows, columns=T15_COLUMNS)


def _build_f8_chain_novelty(
    window_chains,
    *,
    rare_benign_max_count: int,
):
    """Window-level evaluation chain novelty for F8 (not period-aggregated)."""
    import pandas as pd

    if window_chains is None or window_chains.empty:
        return pd.DataFrame(
            columns=["host_id", "window_start", "chain_novelty_count"]
        )

    benign_counts: dict[tuple[str, str], int] = defaultdict(int)
    benign = window_chains.loc[window_chains["period"] == "verified_benign"]
    for row in benign.itertuples(index=False):
        benign_counts[(str(row.host_id), str(row.normalized_chain))] += int(
            row.count
        )

    points: list[dict[str, Any]] = []
    evaluation = window_chains.loc[window_chains["period"] == "evaluation"]
    for row in evaluation.itertuples(index=False):
        b_count = int(
            benign_counts.get((str(row.host_id), str(row.normalized_chain)), 0)
        )
        novelty = novelty_status_for_count(
            b_count,
            rare_benign_max_count=rare_benign_max_count,
            mapping_status=str(row.mapping_status),
            construction_type=str(row.construction_type),
        )
        if novelty not in {
            "unseen_in_verified_benign",
            "rare_in_verified_benign",
            "inferred_chain_only",
        }:
            continue
        points.append(
            {
                "host_id": str(row.host_id),
                "window_start": pd.to_datetime(row.window_start),
                "chain_novelty_count": 1,
            }
        )
    if not points:
        return pd.DataFrame(
            columns=["host_id", "window_start", "chain_novelty_count"]
        )
    frame = pd.DataFrame(points)
    return (
        frame.groupby(["host_id", "window_start"], as_index=False)[
            "chain_novelty_count"
        ]
        .sum()
        .sort_values(["host_id", "window_start"])
        .reset_index(drop=True)
    )


def create_f8(
    chain_novelty_frame,
    command_novelty_frame,
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
    chain_df = (
        chain_novelty_frame.copy()
        if chain_novelty_frame is not None and not chain_novelty_frame.empty
        else pd.DataFrame(
            columns=["host_id", "window_start", "chain_novelty_count"]
        )
    )
    cmd_df = (
        command_novelty_frame.copy()
        if command_novelty_frame is not None and not command_novelty_frame.empty
        else pd.DataFrame(
            columns=["host_id", "window_start", "command_novelty_count"]
        )
    )
    if not chain_df.empty:
        chain_df["window_start"] = pd.to_datetime(chain_df["window_start"])
    if not cmd_df.empty:
        cmd_df["window_start"] = pd.to_datetime(cmd_df["window_start"])

    hosts = sorted(
        set(chain_df["host_id"].astype(str) if not chain_df.empty else [])
        | set(cmd_df["host_id"].astype(str) if not cmd_df.empty else [])
    )
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

    def _plot_segments(axis, frame, value_column: str, color: str, label: str):
        if frame.empty:
            return
        ordered = frame.sort_values("window_start")
        segment_ids = (
            ordered["window_start"].diff().ne(pd.Timedelta(minutes=1)).cumsum()
        )
        first = True
        for _, segment in ordered.groupby(segment_ids, sort=True):
            axis.plot(
                segment["window_start"],
                segment[value_column],
                color=color,
                marker=".",
                linewidth=0.8,
                label=label if first else None,
            )
            first = False

    for index, axis in enumerate(flat_axes):
        if index >= len(hosts):
            axis.set_visible(False)
            continue
        host_id = hosts[index]
        host_chains = (
            chain_df.loc[chain_df["host_id"] == host_id]
            if not chain_df.empty
            else pd.DataFrame()
        )
        host_cmds = (
            cmd_df.loc[cmd_df["host_id"] == host_id]
            if not cmd_df.empty
            else pd.DataFrame()
        )
        _plot_segments(
            axis,
            host_chains,
            "chain_novelty_count",
            F8_CHAIN_COLOR,
            "Chain novelty count",
        )
        _plot_segments(
            axis,
            host_cmds,
            "command_novelty_count",
            F8_COMMAND_COLOR,
            "Command novelty count",
        )
        axis.set_title(labels.get(host_id) or host_id)
        axis.grid(alpha=0.25)
        axis.set_ylabel("Novelty count")
        axis.set_xlabel("Evaluation window start (UTC)")
        handles, _legend_labels = axis.get_legend_handles_labels()
        if handles:
            axis.legend(loc="best", fontsize=8)
    figure.suptitle(
        "F8 Process/Command Novelty Over Time\n"
        "Verified-benign baseline novelty; not attack or malicious labels"
    )
    figure.savefig(png_path, dpi=180, bbox_inches="tight")
    figure.savefig(pdf_path, bbox_inches="tight")
    plt.close(figure)


def event_placeholder(raw_event_id: object) -> str:
    return str(raw_event_id or "missing")


def build_d2_frame():
    import pandas as pd

    return pd.DataFrame(D2_RULEBOOK, columns=D2_COLUMNS)


def validate_outputs(t14, t15, d2, evidence_cap: int) -> None:
    if list(t14.columns) != T14_COLUMNS:
        raise CacheAuditError("T14 column order mismatch")
    if list(t15.columns) != T15_COLUMNS:
        raise CacheAuditError("T15 column order mismatch")
    if list(d2.columns) != D2_COLUMNS:
        raise CacheAuditError("D2 column order mismatch")
    if not t14.empty:
        lengths = set(int(value) for value in t14["chain_length"])
        if not lengths.issubset({2, 3, 4, 5}):
            raise CacheAuditError(f"Invalid T14 chain lengths: {sorted(lengths)}")
        length2 = t14.loc[t14["chain_length"] == 2]
        if not length2.empty and (
            length2["construction_type"] != "observed_same_event"
        ).any():
            raise CacheAuditError("Length-2 chains must be observed_same_event")
        longer = t14.loc[t14["chain_length"] > 2]
        if not longer.empty and (
            longer["construction_type"] != "inferred_path_composition"
        ).any():
            raise CacheAuditError(
                "Lengths 3-5 must be inferred_path_composition"
            )
        if (t14["evidence_count"] > evidence_cap).any():
            raise CacheAuditError("T14 evidence_count exceeds evidence cap")
        # No repeated nodes in inferred chains
        for row in longer.itertuples(index=False):
            nodes = str(row.normalized_chain).split(" -> ")
            if len(nodes) != len(set(nodes)):
                raise CacheAuditError("Inferred chain contains repeated nodes")
    if not t15.empty:
        if t15["command_line_raw"].isna().any():
            raise CacheAuditError("T15 lost command_line_raw")
        if (t15["ground_truth_overlap_yes_no"] != GROUND_TRUTH_OVERLAP).any():
            raise CacheAuditError("T15 ground-truth column incorrect")
        if t15["timestamp"].isna().any():
            raise CacheAuditError("T15 missing timestamp")
        for value in t15["raw_event_ids"]:
            parsed = json.loads(value)
            if not parsed:
                raise CacheAuditError("T15 missing raw event IDs")
        banned = re.compile(
            r"\b(malicious|attack|compromised|exploit|threat|adversarial)\b",
            re.IGNORECASE,
        )
        for column in ("novelty_reason", "evidence_selection_reason"):
            for value in t15[column].astype(str):
                if banned.search(value):
                    raise CacheAuditError(
                        f"Unsupported classification language in T15 {column}"
                    )


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
            "EDA 7 — Process Lineage and Command-Sequence Analysis",
            "=" * 56,
            "",
            "Scientific scope",
            "----------------",
            "EDA 7 builds length-2 directly observed same-event parent→child",
            "PROCESS edges and conservative inferred path compositions of",
            "lengths 3–5 within one canonical host, one configured time window,",
            "and one period role. Novelty means absent or rare relative to the",
            "verified-benign baseline. Novelty does not mean attack, malicious,",
            "compromised, or ground-truth overlap. Ground-truth alignment remains",
            "EDA 10.",
            "",
            "Observed versus inferred",
            "------------------------",
            "Length 2 uses construction_type=observed_same_event and",
            "link_status=observed when parent and child are present on the same",
            "PROCESS event. Lengths 3–5 use",
            "construction_type=inferred_path_composition and",
            "link_status=inferred_not_causal. Inferred rows compose multiple",
            "directly observed edges when the full normalized process path",
            "matches; they are not proven causal lineage, process-instance",
            "lineage, execution truth, or attack chains.",
            "",
            "Count semantics",
            "---------------",
            "Observed length-2 count is the exact same-event observation count.",
            "Inferred length 3–5 per-window count is 1 when the composition is",
            "supported in that host/window/period; aggregated T14 count equals",
            "the number of supporting windows. min(edge event counts) is not",
            "used because there is no reliable process-instance linkage.",
            "",
            "Period-map meaning",
            "------------------",
            "Intervals are half-open [start_time, end_time). verified_benign",
            "fits baseline vocabulary only. evaluation is scored for novelty",
            "but never alters benign counts, ranks, or normalization policy.",
            "",
            "PID and actor/object identity limitations",
            "-----------------------------------------",
            "Full-cache preflight showed host/PID groups commonly map to many",
            "child and parent paths and recur across dates. actorID/objectID",
            "groups likewise lack guaranteed process-instance identity. EDA 7",
            "therefore never joins raw pid_raw/ppid_raw as identity and never",
            "treats actor_id_raw/object_id_raw as guaranteed causal keys. Those",
            "fields are retained only as supporting evidence on T15 rows.",
            "",
            "Chain construction",
            "------------------",
            f"Rule version: {CHAIN_RULE_VERSION}. Comparison uses trimmed,",
            "slash-normalized, Windows case-insensitive full paths",
            f"({COMPARISON_RULE_VERSION}). Basename-only matching is rejected.",
            "Cycles and repeated nodes are rejected. Length is capped at 5.",
            "Distinct host/window/edge rows are aggregated before composition.",
            "",
            "Command normalization",
            "---------------------",
            f"Rule version: {COMMAND_RULE_VERSION}. command_line_raw is always",
            "preserved exactly. Distinct command strings are normalized once and",
            "joined in DuckDB; raw command-observation rows are never fetched",
            "wholesale into pandas. Normalized copies may strip outer whitespace",
            "and replace only complete UUID, long 0x-hex, or long decimal tokens,",
            "including complete quoted ephemeral tokens. Unsafe quote structure",
            "falls back to trimmed raw text. See D2.",
            "",
            "Novelty interpretation",
            "----------------------",
            "Closed statuses: unseen_in_verified_benign,",
            "rare_in_verified_benign, common_in_verified_benign,",
            "insufficient_or_missing_command, unresolved_mapping,",
            "inferred_chain_only. T15 unusual reasons also identify",
            "unusual_chain_common_command, common_chain_unusual_command, and",
            "unusual_chain_unusual_command. The rarity threshold is",
            f"{metadata.get('rare_benign_max_count')}.",
            "",
            "Evidence and ground truth",
            "-------------------------",
            "Evidence IDs are deterministic, unique, and capped. T15",
            f"ground_truth_overlap_yes_no is always {GROUND_TRUTH_OVERLAP}.",
            "Common verified-benign examples are capped at 10 independently of",
            "--max-unusual-examples unusual evaluation examples.",
            "",
            "Reconciliation",
            "--------------",
            f"PROCESS total={metadata.get('process_total')};",
            f" verified_benign={metadata.get('process_verified_benign')};",
            f" evaluation={metadata.get('process_evaluation')};",
            f" unassigned_cache={metadata.get('unassigned_count')}.",
            "Missing-link scan counts:",
            f" missing_host={metadata.get('missing_host_count')},",
            f" missing_parent={metadata.get('missing_parent_process_count')},",
            f" missing_child={metadata.get('missing_child_process_count')},",
            f" missing_link_count_total={metadata.get('missing_link_count_total')},",
            f" observed_pair_eligible={metadata.get('observed_pair_eligible_count')}.",
            "",
            "Limitations",
            "-----------",
            "Inferred compositions can be ambiguous when a parent has multiple",
            "observed children in the same window. Missing parents create no",
            "observed edge and are counted in missing-link reconciliation.",
            "Results apply to the supplied cache and period map only.",
            "",
            f"Generated UTC: {metadata.get('generated_utc')}",
            "",
        ]
    )


def run_eda07(args: argparse.Namespace) -> dict[str, Any]:
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
        stage(2, "registered read-only cache, T9 identities, and periods")

        _create_process_edge_aggregate(connection, config["evidence_cap"])
        stage(3, "payload scan 1/1 PROCESS edges and commands complete")

        cache_total = int(config["cache_metadata"]["total_events_written"])
        reconciliation = _validate_period_and_process_counts(
            connection, cache_total
        )
        stage(4, "period and PROCESS reconciliation complete")

        window_chains = _build_window_chains(connection, config["evidence_cap"])
        t14 = _aggregate_t14(
            window_chains,
            rare_benign_max_count=config["rare_benign_max_count"],
            evidence_cap=config["evidence_cap"],
            connection=connection,
        )
        command_aggregates = _build_bounded_command_aggregates(
            connection,
            rare_benign_max_count=config["rare_benign_max_count"],
            max_unusual_examples=config["max_unusual_examples"],
        )
        t15 = _build_t15(
            window_chains,
            command_aggregates,
            t14,
            rare_benign_max_count=config["rare_benign_max_count"],
            max_unusual_examples=config["max_unusual_examples"],
            evidence_cap=config["evidence_cap"],
        )
        d2 = build_d2_frame()
        validate_outputs(t14, t15, d2, config["evidence_cap"])
        stage(5, "T14/T15/D2 constructed and validated")

        host_labels = _host_label_map(connection)
        f8_chain = _build_f8_chain_novelty(
            window_chains,
            rare_benign_max_count=config["rare_benign_max_count"],
        )
        missing_links = _missing_link_metadata(connection)
        parent = _nearest_existing_directory(config["output_dir"].parent)
        staging = pathlib.Path(
            tempfile.mkdtemp(prefix=".eda07_staging_", dir=str(parent))
        )
        _atomic_write_csv(t14, staging / "T14_process_chain_frequency.csv")
        _atomic_write_csv(
            t15, staging / "T15_unusual_command_process_examples.csv"
        )
        _atomic_write_csv(d2, staging / "D2_command_normalization_rulebook.csv")
        create_f8(
            f8_chain,
            command_aggregates["f8_command"],
            png_path=staging / "F8_process_command_novelty_over_time.png",
            pdf_path=staging / "F8_process_command_novelty_over_time.pdf",
            host_labels=host_labels,
        )
        stage(6, "F8 figures written")

        generated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        runtime = time.perf_counter() - started
        chain_by_length = (
            {
                str(int(key)): int(value)
                for key, value in t14["chain_length"].value_counts().items()
            }
            if not t14.empty
            else {}
        )
        chain_by_construction = (
            {
                str(key): int(value)
                for key, value in t14["construction_type"].value_counts().items()
            }
            if not t14.empty
            else {}
        )
        metadata = {
            "schema_version": SCHEMA_VERSION,
            "code_commit": _git_commit(config["project_root"]),
            "cache_path": str(config["cache_dir"].resolve()),
            "cache_event_count": cache_total,
            "manifest_version": config.get("manifest_version"),
            "manifest_path": str(config["manifest_path"]),
            "period_map_path": str(config["period_map"].resolve()),
            "period_map_sha256": _sha256_file(config["period_map"]),
            "entity_dictionary_path": str(config["entity_dictionary"].resolve()),
            "period_policy": config["policy"].policy_name,
            "baseline_span": _span(config["policy"], "verified_benign"),
            "evaluation_span": _span(config["policy"], "evaluation"),
            "window_size": WINDOW_SIZE,
            "rare_benign_max_count": config["rare_benign_max_count"],
            "evidence_cap": config["evidence_cap"],
            "max_unusual_examples": config["max_unusual_examples"],
            "payload_scan_count": PAYLOAD_SCAN_COUNT,
            "chain_rule_version": CHAIN_RULE_VERSION,
            "command_rule_version": COMMAND_RULE_VERSION,
            "comparison_rule_version": COMPARISON_RULE_VERSION,
            "duckdb_memory_limit": config["memory_limit"],
            "duckdb_threads": config["threads"],
            "duckdb_temp_dir_policy": (
                "explicit" if args.duckdb_temp_dir else "owned_local_tempfile"
            ),
            "t14_row_count": int(len(t14)),
            "t15_row_count": int(len(t15)),
            "d2_row_count": int(len(d2)),
            "chain_counts_by_length": chain_by_length,
            "chain_counts_by_construction_type": chain_by_construction,
            "ambiguity_count_total": (
                int(t14["ambiguity_count"].sum()) if not t14.empty else 0
            ),
            "distinct_command_count": command_aggregates["distinct_command_count"],
            "normalization_status_counts": command_aggregates[
                "normalization_counts"
            ],
            "count_semantics": {
                "observed_same_event": (
                    "Exact same-event observation count; aggregated T14 count "
                    "sums exact event observations across windows."
                ),
                "inferred_path_composition": (
                    "Per-window presence count is 1 when the composition is "
                    "supported in that host/window/period; aggregated T14 count "
                    "equals the number of supporting windows. Not a lower-bound "
                    "or exact process-instance occurrence count."
                ),
            },
            "metadata_self_hash_policy": "excluded_self_reference",
            "ground_truth_overlap_yes_no": GROUND_TRUTH_OVERLAP,
            "peak_rss_mb": round(_peak_rss_mb(), 3),
            "runtime_seconds": round(runtime, 3),
            "generated_utc": generated,
            "scientific_interpretation": (
                "Novelty is relative to verified-benign vocabulary only; "
                "not attack or malicious labels. Ground-truth alignment is "
                "deferred to EDA 10."
            ),
            **reconciliation,
            **missing_links,
        }
        _atomic_write_text(_readme(metadata), staging / "README.md")
        stage(7, "README and metadata assembled")

        # Hash published non-metadata deliverables, then write log and hash it.
        # Never store a self-hash of eda07_run_metadata.json inside itself.
        deliverable_names = [
            "T14_process_chain_frequency.csv",
            "T15_unusual_command_process_examples.csv",
            "F8_process_command_novelty_over_time.png",
            "F8_process_command_novelty_over_time.pdf",
            "D2_command_normalization_rulebook.csv",
            "README.md",
        ]
        metadata["deliverable_sha256"] = {
            name: _sha256_file(staging / name) for name in deliverable_names
        }
        final_log = "\n".join(
            execution_log
            + [f"[STAGE 8/8] T14={len(t14)} T15={len(t15)} D2={len(d2)}"]
        ) + "\n"
        _atomic_write_text(final_log, staging / "eda07_execution.log")
        metadata["deliverable_sha256"]["eda07_execution.log"] = _sha256_file(
            staging / "eda07_execution.log"
        )
        _atomic_write_json(metadata, staging / "eda07_run_metadata.json")
        _assert_no_temp_files(staging)
        _publish_staging(staging, config["output_dir"])
        staging = None
        stage(8, f"published outputs T14={len(t14)} T15={len(t15)} D2={len(d2)}")
        return metadata
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
    run_eda07(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
