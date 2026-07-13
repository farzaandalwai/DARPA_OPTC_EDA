"""
DARPA OpTC Streaming Event Parser
===================================
Streams JSON events from .tar archives that contain .json.gz member files.
Archives are NEVER extracted to disk.

Member bodies are streamed line-by-line via tar.extractfile → gzip → TextIOWrapper.
They are NOT fully loaded into RAM.

Usage (module):
    from optc_streaming_parser import stream_from_archives
    for event in stream_from_archives(
        [path_to_tar],
        allowed_members_by_archive={"2019-09-16.tar": {"path/to/member.json.gz"}},
        include_raw_json=False,
        max_events=100000,
    ):
        ...

Scope constraints (EDA 1-3):
    - No attack / benign / MITRE claims.
    - No ground-truth overlays.
    - Raw fields and normalized fields kept separately.
    - Malformed records are counted and yielded with parse_status='json_parse_error'.
"""

from __future__ import annotations

import argparse
import datetime
import gzip
import hashlib
import io
import json
import pathlib
import sys
import tarfile
from typing import Dict, Iterator, Optional, Set

# ── Field key candidates (tried in order; first present key wins) ──────────
_TIMESTAMP_KEYS   = ["timestamp", "time", "ts", "eventTime", "event_time",
                      "time_stamp", "Time", "Timestamp", "@timestamp"]
_HOST_KEYS        = ["hostname", "host", "computer", "computerName",
                      "computer_name", "fqdn", "Hostname", "machine"]
_USER_KEYS        = ["principal", "user", "username", "user_name",
                      "actorID", "actor", "subject_user", "UserName", "uid"]
_PROCESS_KEYS     = ["processName", "process_name", "process", "imageName",
                      "image_name", "exe", "cmdline", "ProcessName", "image"]
_PARENT_PROC_KEYS = ["parentProcessName", "parent_process_name", "parentName",
                      "ppid_name", "parent", "parentImageName", "parent_image"]
_ACTION_KEYS      = ["action", "eventType", "event_type", "type", "act",
                      "operation", "EventType", "Action", "objectType"]
_OBJECT_KEYS      = ["object", "objectName", "object_name", "path",
                      "file_path", "filepath", "resource", "ObjectName",
                      "target", "artifact"]
_DEST_KEYS        = ["dest_ip", "destination", "dstIp", "dst_ip",
                      "remote_addr", "dhost", "dst_host", "destIP",
                      "id.resp_h", "remote_ip"]
_EVENT_ID_KEYS    = ["id", "uuid", "eventId", "event_id", "EventID",
                      "record_id", "seq", "sequence", "uid", "logRecordId"]

# ── Source-type inference: keyword sets ────────────────────────────────────
_GT_KW  = {"ground_truth", "truth", "label", "redteam", "gt_"}
_NET_KW = {"flow", "netflow", "bro", "dns", "http", "conn",
           "network", "pcap", "zeek", "net_"}
_EP_KW  = {"ecar", "endpoint", "sysclient", "process", "file_event",
           "registry", "sysmon", "edr", "host", ".ecar"}

# Slim columns written to normalized cache (no full raw_json)
SLIM_EVENT_COLUMNS = [
    "file_id", "archive_name", "member_name", "line_number", "raw_event_id",
    "parse_status", "parse_error",
    "timestamp_raw", "timestamp_parsed",
    "host_raw", "user_raw", "process_raw", "parent_process_raw",
    "action_raw", "object_raw", "destination_raw", "source_type",
]


def infer_source_type_from_member(member_name: str) -> str:
    """
    Conservative source-type inference from the member path/name only.
    Returns 'endpoint' | 'network' | 'ground_truth' | 'unknown'.
    Does NOT read file contents.
    """
    n = member_name.lower()
    if any(k in n for k in _GT_KW):
        return "ground_truth"
    if any(k in n for k in _NET_KW):
        return "network"
    if any(k in n for k in _EP_KW):
        return "endpoint"
    return "unknown"


def _parse_timestamp(raw_val) -> Optional[datetime.datetime]:
    """
    Convert raw timestamp to a naive UTC datetime.
    Handles: epoch int/float (seconds, milliseconds, nanoseconds), ISO strings.
    Returns None on failure.
    """
    if raw_val is None:
        return None
    try:
        if isinstance(raw_val, (int, float)):
            v = float(raw_val)
            if v > 1e15:     # nanoseconds → seconds
                v /= 1e9
            elif v > 1e12:   # milliseconds → seconds
                v /= 1e3
            return datetime.datetime.utcfromtimestamp(v)
        if isinstance(raw_val, str):
            s = raw_val.strip()
            try:                          # numeric string
                return _parse_timestamp(float(s))
            except ValueError:
                pass
            s = s.replace("Z", "+00:00")
            dt = datetime.datetime.fromisoformat(s)
            return dt.replace(tzinfo=None)   # normalize to naive UTC
    except (ValueError, OSError, OverflowError, TypeError):
        pass
    return None


def _extract_first(d: dict, keys: list) -> tuple:
    """Return (matched_key, value) for the first key present in d, else ('', None)."""
    for k in keys:
        if k in d:
            return k, d[k]
    return "", None


def _stable_id(archive_name: str, member_name: str, line_num: int) -> str:
    """Generate a deterministic evidence ID when no raw event ID is found."""
    data = f"{archive_name}:{member_name}:{line_num}".encode()
    return "gen_" + hashlib.md5(data).hexdigest()[:12]


def normalize_event(
    raw: dict,
    archive_name: str,
    member_name: str,
    line_num: int,
    event_counter: int,
    source_type: str,
    include_raw_json: bool = True,
) -> dict:
    """
    Build a flat normalized event dict from a raw JSON object.
    Provenance and normalized fields are always set.
    Full raw_json is optional (disable for slim Parquet cache).
    """
    _, raw_id = _extract_first(raw, _EVENT_ID_KEYS)
    evidence_id = str(raw_id) if raw_id is not None else _stable_id(
        archive_name, member_name, line_num
    )

    _, ts_raw    = _extract_first(raw, _TIMESTAMP_KEYS)
    _, host_raw  = _extract_first(raw, _HOST_KEYS)
    _, user_raw  = _extract_first(raw, _USER_KEYS)
    _, proc_raw  = _extract_first(raw, _PROCESS_KEYS)
    _, pproc_raw = _extract_first(raw, _PARENT_PROC_KEYS)
    _, act_raw   = _extract_first(raw, _ACTION_KEYS)
    _, obj_raw   = _extract_first(raw, _OBJECT_KEYS)
    _, dest_raw  = _extract_first(raw, _DEST_KEYS)

    ts_parsed = _parse_timestamp(ts_raw)

    out = {
        "file_id"            : event_counter,
        "archive_name"       : archive_name,
        "member_name"        : member_name,
        "line_number"        : line_num,
        "raw_event_id"       : evidence_id,
        "parse_status"       : "ok",
        "parse_error"        : "",
        "timestamp_raw"      : "" if ts_raw is None else str(ts_raw),
        "timestamp_parsed"   : ts_parsed.isoformat() if ts_parsed else "",
        "host_raw"           : "" if host_raw is None else str(host_raw),
        "user_raw"           : "" if user_raw is None else str(user_raw),
        "process_raw"        : "" if proc_raw is None else str(proc_raw),
        "parent_process_raw" : "" if pproc_raw is None else str(pproc_raw),
        "action_raw"         : "" if act_raw is None else str(act_raw),
        "object_raw"         : "" if obj_raw is None else str(obj_raw),
        "destination_raw"    : "" if dest_raw is None else str(dest_raw),
        "source_type"        : source_type,
    }
    if include_raw_json:
        out["raw_json"] = json.dumps(raw, separators=(",", ":"))
    else:
        out["raw_json"] = ""
    return out


def _error_record(
    archive_name: str, member_name: str, line_num: int,
    event_counter: int, raw_snippet: str, error_msg: str,
    source_type: str,
    include_raw_json: bool = True,
) -> dict:
    """Return a record representing a JSON parse failure."""
    blank = ""
    # Bounded snippet for evidence only (never full member)
    snippet = raw_snippet[:300]
    return {
        "file_id"            : event_counter,
        "archive_name"       : archive_name,
        "member_name"        : member_name,
        "line_number"        : line_num,
        "raw_event_id"       : _stable_id(archive_name, member_name, line_num),
        "raw_json"           : snippet if include_raw_json else "",
        "parse_status"       : "json_parse_error",
        "parse_error"        : error_msg[:200],
        "timestamp_raw"      : blank, "timestamp_parsed"   : blank,
        "host_raw"           : blank, "user_raw"           : blank,
        "process_raw"        : blank, "parent_process_raw" : blank,
        "action_raw"         : blank, "object_raw"         : blank,
        "destination_raw"    : blank, "source_type"        : source_type,
        # Always keep a tiny evidence snippet separate from full raw_json
        "error_snippet"      : snippet,
    }


def stream_events(
    archive_path: pathlib.Path,
    max_members: Optional[int] = None,
    max_events: Optional[int] = None,
    max_events_per_member: Optional[int] = None,
    member_name_contains: Optional[str] = None,
    allowed_members: Optional[Set[str]] = None,
    include_raw_json: bool = True,
    quiet: bool = False,
) -> Iterator[dict]:
    """
    Yield normalized event dicts from a single .tar archive.

    Streaming I/O: tar.extractfile → gzip.GzipFile → TextIOWrapper, line by line.
    The compressed member is NOT fully buffered into a BytesIO.

    Parameters
    ----------
    archive_path          : path to the .tar file
    max_members           : stop after this many matching members (None = all);
                            ignored when allowed_members is set (exact set used)
    max_events            : global cap on total events yielded (None = unlimited)
    max_events_per_member : cap per individual member (None = unlimited)
    member_name_contains  : substring filter (legacy); ignored when allowed_members set
    allowed_members       : exact member path allowlist for this archive (manifest mode)
    include_raw_json      : if False, omit full raw_json (slim cache mode)
    quiet                 : suppress progress prints
    """
    archive_path = pathlib.Path(archive_path)
    archive_name = archive_path.name

    if not archive_path.exists():
        print(f"[ERROR] Archive not found: {archive_path}", file=sys.stderr)
        return

    members_seen  = 0
    total_events  = 0
    parse_errors  = 0
    matched_allow = set()
    remaining_allow = set(allowed_members) if allowed_members is not None else None

    try:
        tf = tarfile.open(archive_path, "r:*")
    except Exception as exc:
        print(f"[ERROR] Cannot open archive {archive_path}: {exc}", file=sys.stderr)
        return

    try:
        for member in tf:
            if not member.isfile():
                continue

            # ── Exact allowlist (manifest mode) — no substring matching ──
            if allowed_members is not None:
                if member.name not in allowed_members:
                    continue
            else:
                if member_name_contains and member_name_contains not in member.name:
                    continue

            name_lower = member.name.lower()
            is_jsonl_gz = name_lower.endswith(".json.gz") or name_lower.endswith(".jsonl.gz")
            is_plain    = name_lower.endswith(".json") or name_lower.endswith(".jsonl")
            if not (is_jsonl_gz or is_plain):
                continue

            # Legacy max_members (not used when exact allowlist is active)
            if allowed_members is None:
                if max_members is not None and members_seen >= max_members:
                    if not quiet:
                        print(f"  [PARSER] max_members={max_members} reached; stopping.",
                              file=sys.stderr)
                    break

            members_seen += 1
            if remaining_allow is not None:
                remaining_allow.discard(member.name)
                matched_allow.add(member.name)

            source_type = infer_source_type_from_member(member.name)

            if not quiet:
                print(f"  [member {members_seen:>3}] {member.name}", flush=True)

            fobj = tf.extractfile(member)
            if fobj is None:
                continue

            member_event_count = 0

            try:
                if is_jsonl_gz:
                    # True streaming: do NOT fobj.read() into BytesIO
                    gz = gzip.GzipFile(fileobj=fobj, mode="rb")
                    reader = io.TextIOWrapper(gz, encoding="utf-8", errors="replace")
                else:
                    reader = io.TextIOWrapper(fobj, encoding="utf-8", errors="replace")

                try:
                    for line_num, raw_line in enumerate(reader, 1):
                        stripped = raw_line.strip()
                        if not stripped:
                            continue

                        if (max_events_per_member is not None
                                and member_event_count >= max_events_per_member):
                            if not quiet:
                                print(
                                    f"    [PARSER] max_events_per_member="
                                    f"{max_events_per_member} reached for "
                                    f"{pathlib.Path(member.name).name}; "
                                    "moving to next member.",
                                    file=sys.stderr,
                                )
                            break

                        if max_events is not None and total_events >= max_events:
                            if not quiet:
                                print(f"  [PARSER] max_events={max_events} reached; stopping.",
                                      file=sys.stderr)
                            return

                        try:
                            raw = json.loads(stripped)
                            if not isinstance(raw, dict):
                                parse_errors += 1
                                continue
                        except json.JSONDecodeError as exc:
                            parse_errors += 1
                            member_event_count += 1
                            total_events += 1
                            yield _error_record(
                                archive_name, member.name, line_num,
                                total_events, stripped, str(exc), source_type,
                                include_raw_json=include_raw_json,
                            )
                            continue

                        total_events += 1
                        member_event_count += 1
                        yield normalize_event(
                            raw, archive_name, member.name,
                            line_num, total_events, source_type,
                            include_raw_json=include_raw_json,
                        )
                finally:
                    try:
                        reader.close()
                    except Exception:
                        pass

            except Exception as exc:
                if not quiet:
                    print(f"  [WARN] Cannot decompress {member.name}: {exc}", file=sys.stderr)

            # Early exit when every allowlisted member for this archive is done
            if remaining_allow is not None and not remaining_allow:
                if not quiet:
                    print(f"  [PARSER] all {len(matched_allow)} allowlisted members "
                          f"processed for {archive_name}.", flush=True)
                break

    finally:
        tf.close()

    if not quiet:
        print(
            f"  [PARSER DONE] {archive_name}: "
            f"{members_seen} members scanned, {total_events} events yielded, "
            f"{parse_errors} parse errors",
            flush=True,
        )


def stream_from_archives(
    archive_paths: list,
    max_members: Optional[int] = None,
    max_events: Optional[int] = None,
    max_events_per_member: Optional[int] = None,
    member_name_contains: Optional[str] = None,
    allowed_members_by_archive: Optional[Dict[str, Set[str]]] = None,
    include_raw_json: bool = True,
    quiet: bool = False,
) -> Iterator[dict]:
    """
    Stream events from multiple .tar archives.

    allowed_members_by_archive maps archive filename → exact member path set.
    When provided, only those members are processed (manifest mode).
    """
    total = 0
    for archive_path in archive_paths:
        archive_path = pathlib.Path(archive_path)
        per_archive_cap = None if max_events is None else max_events - total
        if per_archive_cap is not None and per_archive_cap <= 0:
            break

        allowed = None
        if allowed_members_by_archive is not None:
            allowed = allowed_members_by_archive.get(archive_path.name)
            if not allowed:
                if not quiet:
                    print(f"  [PARSER] no allowlisted members for {archive_path.name}; skipping.")
                continue

        for event in stream_events(
            archive_path,
            max_members=max_members if allowed is None else None,
            max_events=per_archive_cap,
            max_events_per_member=max_events_per_member,
            member_name_contains=member_name_contains if allowed is None else None,
            allowed_members=allowed,
            include_raw_json=include_raw_json,
            quiet=quiet,
        ):
            total += 1
            yield event
            if max_events is not None and total >= max_events:
                return


# ── CLI smoke-test ─────────────────────────────────────────────────────────

def _parse_cli_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="DARPA OpTC streaming parser — CLI smoke-test mode.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--archives", nargs="+", required=True,
                   help="One or more .tar archive paths")
    p.add_argument("--max-members", type=int, default=5,
                   help="Max members to scan per archive (default: 5)")
    p.add_argument("--max-events", type=int, default=500,
                   help="Max total events to yield (default: 500)")
    p.add_argument("--max-events-per-member", type=int, default=None,
                   help="Max events per tar member; ensures coverage across members")
    p.add_argument("--member-name-contains", default=None,
                   help="Only process members whose name contains this string")
    p.add_argument("--no-raw-json", action="store_true",
                   help="Omit full raw_json from yielded events")
    p.add_argument("--output-csv", default=None,
                   help="If set, write events to this CSV file")
    return p.parse_args()


def main() -> None:
    args = _parse_cli_args()
    import csv

    archive_paths = [pathlib.Path(a) for a in args.archives]
    events = list(stream_from_archives(
        archive_paths,
        max_members=args.max_members,
        max_events=args.max_events,
        max_events_per_member=args.max_events_per_member,
        member_name_contains=args.member_name_contains,
        include_raw_json=not args.no_raw_json,
        quiet=False,
    ))

    if not events:
        print("[INFO] No events parsed. Check archive paths and member names.")
        return

    print(f"\n[SUMMARY] {len(events)} events parsed.")

    ok_count  = sum(1 for e in events if e["parse_status"] == "ok")
    err_count = len(events) - ok_count
    print(f"  ok: {ok_count}   parse_errors: {err_count}")

    print("\nFirst 3 events (normalized fields):")
    preview_keys = [
        "archive_name", "member_name", "line_number",
        "timestamp_parsed", "host_raw", "action_raw", "source_type", "parse_status",
    ]
    for ev in events[:3]:
        row = {k: ev.get(k, "") for k in preview_keys}
        print("  ", row)

    if args.output_csv:
        out = pathlib.Path(args.output_csv)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", newline="", encoding="utf-8") as f:
            if events:
                writer = csv.DictWriter(f, fieldnames=list(events[0].keys()))
                writer.writeheader()
                writer.writerows(events)
        print(f"\n[SAVED] {out}")


if __name__ == "__main__":
    main()
