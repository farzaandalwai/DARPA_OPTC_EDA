"""
Crash-resume helpers for the normalized pilot cache builder.

Finalized Parquet chunks are authoritative. Resume-state JSON may assist
validation but never overrides chunk-derived truth.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

from optc_streaming_parser import SLIM_EVENT_COLUMNS  # type: ignore

RESUME_VERSION = "cache_resume_v1"
RESUME_STATE_NAME = "cache_resume_state.json"
CHUNK_NAME_RE = re.compile(r"^chunk_(\d{5})_date_.+\.parquet$")
TEMP_CHUNK_SUFFIX = ".parquet.tmp"


class ResumeError(Exception):
    """Fatal resume validation / verification failure (no chunk mutation)."""


def chunk_filename(chunk_idx: int, archive_date_hint: str) -> str:
    date_token = archive_date_hint.replace("-", "") if archive_date_hint else "unknown"
    return f"chunk_{chunk_idx:05d}_date_{date_token}.parquet"


def discover_finalized_chunks(cache_dir: pathlib.Path) -> List[Tuple[int, pathlib.Path]]:
    """
    Discover finalized chunk_NNNNN_date_*.parquet files.
    Ignores temporary *.parquet.tmp files.
    Raises ResumeError on duplicate or non-contiguous indexes.
    """
    cache_dir = pathlib.Path(cache_dir)
    found: Dict[int, pathlib.Path] = {}
    for path in sorted(cache_dir.iterdir()):
        if not path.is_file():
            continue
        name = path.name
        if name.endswith(TEMP_CHUNK_SUFFIX) or name.startswith("."):
            continue
        m = CHUNK_NAME_RE.match(name)
        if not m:
            continue
        idx = int(m.group(1))
        if idx in found:
            raise ResumeError(
                f"Duplicate chunk index {idx}: {found[idx].name} and {name}"
            )
        found[idx] = path

    if not found:
        raise ResumeError(
            f"No finalized Parquet chunks found in {cache_dir} "
            f"(resume requires committed chunk_NNNNN_date_*.parquet files)"
        )

    indexes = sorted(found.keys())
    expected = list(range(0, indexes[-1] + 1))
    if indexes != expected:
        missing = sorted(set(expected) - set(indexes))
        raise ResumeError(
            f"Non-contiguous chunk indexes. Found {indexes[:20]}"
            f"{'...' if len(indexes) > 20 else ''}; "
            f"missing {missing[:20]}{'...' if len(missing) > 20 else ''}"
        )
    return [(i, found[i]) for i in indexes]


def validate_chunk_schema(path: pathlib.Path) -> int:
    """
    Open Parquet footer/schema; require non-empty and exact SLIM_EVENT_COLUMNS
    order. Returns row count. Does not modify the file.
    """
    import pyarrow.parquet as pq

    try:
        pf = pq.ParquetFile(path)
    except Exception as exc:
        raise ResumeError(f"Unreadable Parquet chunk {path.name}: {exc}") from exc

    names = list(pf.schema_arrow.names)
    if names != list(SLIM_EVENT_COLUMNS):
        raise ResumeError(
            f"Schema/column mismatch in {path.name}: "
            f"expected {len(SLIM_EVENT_COLUMNS)} SLIM_EVENT_COLUMNS in order; "
            f"got {len(names)} columns"
        )
    n = pf.metadata.num_rows if pf.metadata is not None else 0
    if n <= 0:
        raise ResumeError(f"Empty/invalid Parquet chunk {path.name}: num_rows={n}")
    return int(n)


def validate_all_chunks(
    chunks: List[Tuple[int, pathlib.Path]],
) -> Dict[str, Any]:
    """
    Validate every chunk via Parquet footers/schema only.
    Uses metadata.num_rows — does not materialize row payloads.
    """
    total_rows = 0
    for _idx, path in chunks:
        n = validate_chunk_schema(path)
        total_rows += n
    return {
        "total_rows": total_rows,
        "n_chunks": len(chunks),
        "highest_index": chunks[-1][0],
    }


def read_last_row_checkpoint(path: pathlib.Path) -> Dict[str, Any]:
    """
    Read locator + file_id from the final row of a Parquet chunk.

    Memory-bounded: reads only the last row group, then slices one row.
    Projected columns: archive_name, member_name, line_number, raw_event_id, file_id.
    """
    import pyarrow.parquet as pq

    cols = [
        "archive_name", "member_name", "line_number", "raw_event_id", "file_id",
    ]
    try:
        pf = pq.ParquetFile(path)
        if pf.metadata is None or pf.metadata.num_rows <= 0:
            raise ResumeError(f"Cannot infer checkpoint from empty chunk {path.name}")
        rg = pf.num_row_groups - 1
        table = pf.read_row_group(rg, columns=cols)
        if table.num_rows <= 0:
            raise ResumeError(f"Empty last row group in {path.name}")
        last = table.slice(table.num_rows - 1, 1)
    except ResumeError:
        raise
    except Exception as exc:
        raise ResumeError(
            f"Cannot read checkpoint columns from {path.name}: {exc}"
        ) from exc

    out: Dict[str, Any] = {}
    for c in cols:
        val = last.column(c)[0].as_py()
        out[c] = "" if val is None else val
    try:
        out["line_number"] = int(out["line_number"])
    except (TypeError, ValueError) as exc:
        raise ResumeError(
            f"Unusable checkpoint line_number in {path.name}: {out['line_number']!r}"
        ) from exc
    try:
        out["file_id"] = int(out["file_id"])
    except (TypeError, ValueError) as exc:
        raise ResumeError(
            f"Unusable checkpoint file_id in {path.name}: {out['file_id']!r}"
        ) from exc
    if out["file_id"] < 1:
        raise ResumeError(
            f"Unusable checkpoint file_id in {path.name}: {out['file_id']!r}"
        )
    for key in ("archive_name", "member_name", "raw_event_id"):
        if not str(out[key]).strip():
            raise ResumeError(
                f"Unusable checkpoint field {key}={out[key]!r} in {path.name}"
            )
    out["archive_name"] = str(out["archive_name"]).strip()
    out["member_name"] = str(out["member_name"]).strip()
    out["raw_event_id"] = str(out["raw_event_id"]).strip()
    return out


def next_file_id_from_checkpoint(checkpoint: dict) -> int:
    """
    Exact next per-archive file_id for resume.

    Original semantics: file_id is the per-archive emitted-event counter
    (ok + json_parse_error). The checkpoint row is the last emitted event
    for that archive in the cache, so the next emit must use file_id+1.
    This does not renumber from a resumed suffix and does not rely on a
    full-archive row recount (though for sequential emission,
    count(archive rows) == checkpoint.file_id).
    """
    return int(checkpoint["file_id"]) + 1


def require_commit_checkpoint(last_row: dict) -> Dict[str, Any]:
    """
    Validate the final in-memory row before committing a Parquet chunk.

    Requires nonempty archive_name, member_name, raw_event_id; line_number >= 1;
    integer file_id >= 1. Never invents file_id. Raises ResumeError on failure
    so callers can abort before writing Parquet or resume-state.
    """
    arch = str(last_row.get("archive_name", "") or "").strip()
    mem = str(last_row.get("member_name", "") or "").strip()
    raw = str(last_row.get("raw_event_id", "") or "").strip()
    if not arch:
        raise ResumeError(
            "Refusing to commit chunk: final row has empty archive_name"
        )
    if not mem:
        raise ResumeError(
            "Refusing to commit chunk: final row has empty member_name"
        )
    if not raw:
        raise ResumeError(
            "Refusing to commit chunk: final row has empty raw_event_id"
        )
    try:
        line = int(last_row.get("line_number"))
    except (TypeError, ValueError) as exc:
        raise ResumeError(
            f"Refusing to commit chunk: invalid line_number="
            f"{last_row.get('line_number')!r}"
        ) from exc
    if line < 1:
        raise ResumeError(
            f"Refusing to commit chunk: line_number must be >= 1, got {line}"
        )
    fid_raw = last_row.get("file_id", "")
    try:
        fid = int(fid_raw)
    except (TypeError, ValueError) as exc:
        raise ResumeError(
            f"Refusing to commit chunk: invalid file_id={fid_raw!r} "
            f"(file_id must be an integer >= 1; never invented)"
        ) from exc
    if fid < 1:
        raise ResumeError(
            f"Refusing to commit chunk: file_id must be >= 1, got {fid}"
        )
    return {
        "archive_name": arch,
        "member_name": mem,
        "line_number": line,
        "raw_event_id": raw,
        "file_id": fid,
    }


def validate_checkpoint_in_manifest(checkpoint: dict, manifest) -> None:
    """Require the checkpoint archive/member to appear exactly once in the manifest."""
    df = manifest.df
    mask = (
        (df["archive_filename"].astype(str) == checkpoint["archive_name"])
        & (df["member_name"].astype(str) == checkpoint["member_name"])
    )
    n = int(mask.sum())
    if n == 0:
        raise ResumeError(
            f"Checkpoint archive/member not in active manifest: "
            f"{checkpoint['archive_name']} :: {checkpoint['member_name']}"
        )
    if n > 1:
        raise ResumeError(
            f"Checkpoint archive/member is ambiguous in manifest "
            f"({n} rows): {checkpoint['archive_name']} :: {checkpoint['member_name']}"
        )


def load_resume_state(cache_dir: pathlib.Path) -> Optional[dict]:
    path = pathlib.Path(cache_dir) / RESUME_STATE_NAME
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ResumeError(f"Unreadable {RESUME_STATE_NAME}: {exc}") from exc


def atomic_write_text(path: pathlib.Path, text: str) -> None:
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    try:
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def atomic_write_json(path: pathlib.Path, payload: dict) -> None:
    atomic_write_text(path, json.dumps(payload, indent=2) + "\n")


def write_resume_state(
    cache_dir: pathlib.Path,
    *,
    last_committed_chunk_index: int,
    combined_events: int,
    checkpoint: dict,
) -> pathlib.Path:
    path = pathlib.Path(cache_dir) / RESUME_STATE_NAME
    payload = {
        "resume_version": RESUME_VERSION,
        "last_committed_chunk_index": int(last_committed_chunk_index),
        "combined_events": int(combined_events),
        "checkpoint": {
            "archive_name": checkpoint["archive_name"],
            "member_name": checkpoint["member_name"],
            "line_number": int(checkpoint["line_number"]),
            "raw_event_id": checkpoint["raw_event_id"],
            "file_id": int(checkpoint["file_id"]),
        },
    }
    atomic_write_json(path, payload)
    return path


def atomic_write_parquet_chunk(
    rows: list,
    cache_dir: pathlib.Path,
    chunk_idx: int,
    archive_date_hint: str,
    compression: str,
) -> pathlib.Path:
    """
    Write rows to a unique same-dir temp Parquet, validate, then atomically
    rename to the final chunk name. Refuses if the destination already exists.
    Leaves temp files in place on failure (never silently deleted as committed).
    """
    import pandas as pd
    import pyarrow.parquet as pq

    cache_dir = pathlib.Path(cache_dir)
    final_name = chunk_filename(chunk_idx, archive_date_hint)
    final_path = cache_dir / final_name
    if final_path.exists():
        raise ResumeError(
            f"Refusing to overwrite existing finalized chunk {final_name}"
        )

    df = pd.DataFrame(rows)
    for col in SLIM_EVENT_COLUMNS:
        if col not in df.columns:
            df[col] = ""
    df = df[list(SLIM_EVENT_COLUMNS)]

    tmp = cache_dir / f".chunk_{chunk_idx:05d}_{uuid.uuid4().hex}{TEMP_CHUNK_SUFFIX}"
    comp = None if compression == "none" else compression
    try:
        df.to_parquet(tmp, index=False, compression=comp, engine="pyarrow")
        names = list(pq.ParquetFile(tmp).schema_arrow.names)
        if names != list(SLIM_EVENT_COLUMNS):
            raise ResumeError(
                f"Temp chunk schema mismatch before rename for index {chunk_idx}"
            )
        n = pq.ParquetFile(tmp).metadata.num_rows
        if n <= 0:
            raise ResumeError(f"Temp chunk empty before rename for index {chunk_idx}")
        if final_path.exists():
            raise ResumeError(
                f"Final destination appeared before rename: {final_name}"
            )
        os.replace(tmp, final_path)
    except Exception:
        # Leave tmp for diagnosis when commit did not succeed.
        raise
    if not final_path.exists():
        raise ResumeError(f"Atomic chunk commit failed for {final_name}")
    return final_path


def warn_leftover_temps(cache_dir: pathlib.Path) -> List[str]:
    """Report leftover temp chunk files without deleting them."""
    leftovers = []
    cache_dir = pathlib.Path(cache_dir)
    for path in sorted(cache_dir.glob(f"*{TEMP_CHUNK_SUFFIX}")):
        leftovers.append(path.name)
    return leftovers


def aggregate_preexisting_chunks(
    chunks: List[Tuple[int, pathlib.Path]],
    *,
    error_example_limit: int,
    expected_footer_total: int,
) -> Dict[str, Any]:
    """
    Single vectorized pass over preexisting finalized chunks.

    Per row-group (memory-bounded):
      1. Always read only archive_name, member_name, parse_status
      2. Aggregate member/status counts via DuckDB GROUP BY
      3. If the grouped result shows any non-ok status AND error examples
         remain under the limit, selectively re-read locator/error columns
         for that row group only and filter errors vectorially
      4. Clean row groups never load line_number, raw_event_id, or parse_error

    expected_footer_total (from Parquet footers) is authoritative.
    Raises ResumeError if grouped counts do not sum to that total.
    """
    import duckdb
    import pyarrow.parquet as pq
    from collections import OrderedDict

    if error_example_limit < 0:
        raise ValueError("error_example_limit must be >= 0")

    counts: "OrderedDict[str, int]" = OrderedDict()
    ok = 0
    err = 0
    error_examples: List[dict] = []
    grouped_total = 0
    con = duckdb.connect()

    status_cols = ["archive_name", "member_name", "parse_status"]
    error_cols = [
        "archive_name", "member_name", "line_number", "raw_event_id",
        "parse_status", "parse_error",
    ]

    try:
        for _, path in chunks:
            pf = pq.ParquetFile(path)
            footer_n = int(pf.metadata.num_rows) if pf.metadata is not None else 0
            scanned = 0
            for rg in range(pf.num_row_groups):
                status_table = pf.read_row_group(rg, columns=status_cols)
                scanned += status_table.num_rows
                con.register("rg", status_table)
                try:
                    agg = con.execute(
                        """
                        SELECT
                          COALESCE(CAST(archive_name AS VARCHAR), '') AS archive_name,
                          COALESCE(CAST(member_name AS VARCHAR), '') AS member_name,
                          COALESCE(CAST(parse_status AS VARCHAR), '') AS parse_status,
                          COUNT(*)::BIGINT AS n
                        FROM rg
                        GROUP BY 1, 2, 3
                        """
                    ).fetchall()
                finally:
                    con.unregister("rg")

                rg_has_errors = False
                for arch, mem, status, n in agg:
                    n_i = int(n)
                    key = f"{arch}::{mem}"
                    counts[key] = counts.get(key, 0) + n_i
                    grouped_total += n_i
                    if status == "ok":
                        ok += n_i
                    else:
                        err += n_i
                        rg_has_errors = True

                if (
                    rg_has_errors
                    and len(error_examples) < error_example_limit
                ):
                    detail_table = pf.read_row_group(rg, columns=error_cols)
                    con.register("rg_err", detail_table)
                    try:
                        remaining = error_example_limit - len(error_examples)
                        err_batch = con.execute(
                            """
                            SELECT
                              COALESCE(CAST(archive_name AS VARCHAR), '') AS archive_name,
                              COALESCE(CAST(member_name AS VARCHAR), '') AS member_name,
                              line_number,
                              COALESCE(CAST(raw_event_id AS VARCHAR), '') AS raw_event_id,
                              COALESCE(CAST(parse_status AS VARCHAR), '') AS parse_status,
                              COALESCE(CAST(parse_error AS VARCHAR), '') AS parse_error
                            FROM rg_err
                            WHERE COALESCE(CAST(parse_status AS VARCHAR), '') != 'ok'
                            LIMIT ?
                            """,
                            [remaining],
                        ).fetchall()
                    finally:
                        con.unregister("rg_err")
                    for row in err_batch:
                        error_examples.append({
                            "archive_name": row[0],
                            "member_name": row[1],
                            "line_number": row[2],
                            "raw_event_id": row[3],
                            "parse_status": row[4],
                            "parse_error": row[5],
                            "error_snippet": "",
                        })

            if scanned != footer_n:
                raise ResumeError(
                    f"Row-group scan count {scanned} != footer num_rows "
                    f"{footer_n} for {path.name}"
                )
    finally:
        con.close()

    if grouped_total != int(expected_footer_total):
        raise ResumeError(
            f"Grouped locator counts sum to {grouped_total} but footer total "
            f"is {expected_footer_total}"
        )
    if ok + err != grouped_total:
        raise ResumeError(
            f"ok+err ({ok}+{err}) != grouped_total {grouped_total}"
        )

    summaries = []
    for key, n in counts.items():
        arch, mem = key.split("::", 1)
        summaries.append({
            "archive_filename": arch,
            "member_name": mem,
            "events_written": n,
        })
    return {
        "member_summaries": summaries,
        "events_per_member": dict(counts),
        "events_ok": ok,
        "parse_errors": err,
        "error_examples": error_examples,
        "grouped_total": grouped_total,
        "footer_total": int(expected_footer_total),
    }


def merge_resume_aggregates(
    preexisting: dict,
    *,
    new_events: int,
    new_events_per_member: dict,
    new_ok: int,
    new_err: int,
    new_error_examples: list,
    error_example_limit: int,
) -> Dict[str, Any]:
    """
    Merge one-pass preexisting aggregates with live counters from newly
    emitted events. Does not re-read any Parquet chunks.
    """
    from collections import OrderedDict

    merged_epm: "OrderedDict[str, int]" = OrderedDict(
        preexisting["events_per_member"]
    )
    for key, n in new_events_per_member.items():
        merged_epm[key] = merged_epm.get(key, 0) + int(n)

    summaries = []
    for key, n in merged_epm.items():
        arch, mem = key.split("::", 1)
        summaries.append({
            "archive_filename": arch,
            "member_name": mem,
            "events_written": n,
        })

    merged_errs = list(preexisting["error_examples"])
    for row in new_error_examples:
        if len(merged_errs) >= error_example_limit:
            break
        merged_errs.append(row)

    total_events = int(preexisting["footer_total"]) + int(new_events)
    events_ok = int(preexisting["events_ok"]) + int(new_ok)
    parse_errors = int(preexisting["parse_errors"]) + int(new_err)
    if events_ok + parse_errors != total_events:
        raise ResumeError(
            f"Merged ok+err ({events_ok}+{parse_errors}) != "
            f"total_events {total_events}"
        )
    if sum(merged_epm.values()) != total_events:
        raise ResumeError(
            f"Merged member counts sum to {sum(merged_epm.values())} but "
            f"total_events is {total_events}"
        )

    return {
        "member_summaries": summaries,
        "events_per_member": dict(merged_epm),
        "events_ok": events_ok,
        "parse_errors": parse_errors,
        "error_examples": merged_errs,
        "total_events": total_events,
    }


def prepare_resume_context(cache_dir: pathlib.Path, manifest) -> Dict[str, Any]:
    """
    Validate existing cache for resume and return a context dict.
    Does not write or delete anything.

    Resume-state JSON is advisory only: chunk-derived checkpoint / indexes /
    event totals always win. A state file with a matching chunk index but
    incorrect event count or checkpoint cannot override chunk truth.
    """
    cache_dir = pathlib.Path(cache_dir)
    leftovers = warn_leftover_temps(cache_dir)
    chunks = discover_finalized_chunks(cache_dir)
    stats = validate_all_chunks(chunks)
    highest_path = chunks[-1][1]
    checkpoint = read_last_row_checkpoint(highest_path)
    validate_checkpoint_in_manifest(checkpoint, manifest)

    state = load_resume_state(cache_dir)
    inferred_legacy = state is None
    state_ignored_fields: List[str] = []
    if state is not None:
        state_idx = state.get("last_committed_chunk_index")
        if state_idx is not None and int(state_idx) > chunks[-1][0]:
            raise ResumeError(
                f"Resume state claims chunk index {state_idx} but highest "
                f"finalized chunk is {chunks[-1][0]}"
            )
        # Chunks win on event count / checkpoint even when indexes match.
        if state.get("combined_events") is not None and int(state["combined_events"]) != int(
            stats["total_rows"]
        ):
            state_ignored_fields.append("combined_events")
        st_ck = state.get("checkpoint") or {}
        for key in ("archive_name", "member_name", "line_number", "raw_event_id", "file_id"):
            if key in st_ck and str(st_ck.get(key)) != str(checkpoint.get(key)):
                state_ignored_fields.append(f"checkpoint.{key}")

    next_file_id = next_file_id_from_checkpoint(checkpoint)

    return {
        "chunks": chunks,
        "stats": stats,
        "checkpoint": checkpoint,
        "next_chunk_index": chunks[-1][0] + 1,
        "next_file_id": next_file_id,
        "preexisting_events": stats["total_rows"],
        "preexisting_chunks": len(chunks),
        "inferred_legacy": inferred_legacy,
        "prior_state": state,
        "state_ignored_fields": state_ignored_fields,
        "leftover_temps": leftovers,
    }
