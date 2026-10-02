#!/usr/bin/env python3
"""Lossless legacy behavior adapter; periods and literal keys are never inferred.

Join by (period_role, source_node_id): historical PROCESS node IDs can repeat
across periods. Old target IDs are used ONLY to audit context collapse, never
to identify a new entity. Compact links by period, real process, type, action
and exact behavior_key; sum counts and take min/max evidence times. Both
CREATE-family metadata columns are retained when present. Outputs are atomic,
existing destinations are refused, and source/output SHA256s are recorded.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

import pandas as pd
import pyarrow.parquet as pq

try:
    from . import build_period_heterogeneous_graph as graph
except ImportError:
    import build_period_heterogeneous_graph as graph


RELATION_MAPPING = {relation: pair for pair, relation in graph.BEHAVIOR_RELATIONS.items()}
FAMILY_COLUMNS = ("split_structure_id", "reference_full_structure_id", "structure_id")
PROCESS_COLUMNS = ["period_role", "node_id", "node_type", "process_id"]
EDGE_COLUMNS = ["period_role", "source_node_id", "source_node_type", "target_node_id",
                "target_node_type", "relation_type", "behavior_key", "event_count",
                "first_seen_time", "last_seen_time"]
LINK_COLUMNS = ["period_role", "process_id", "behavior_type", "action_raw", "behavior_key",
                "attach_event_count", "first_seen_time", "last_seen_time"]
AUDIT_NAME = "behavior_link_adapter_audit_v1.json"


@dataclass(frozen=True)
class Config:
    process_nodes: Path
    behavior_edges: Path
    output_dir: Path


class AdapterInputError(graph.GraphInputError):
    def __init__(self, message: str, audit: dict):
        super().__init__(message)
        self.audit = audit


def _relation_stats(frame: pd.DataFrame, relation_column: str, count_column: str) -> dict:
    stats = {}
    for (role, relation), group in frame.groupby(["period_role", relation_column], sort=True):
        stats.setdefault(role, {})[relation] = {
            "row_count": len(group), "event_count": sum(map(int, group[count_column])),
        }
    return stats


def convert_frames(processes: pd.DataFrame, edges: pd.DataFrame) -> tuple[dict[str, pd.DataFrame], dict]:
    """Validate and reconcile frames; do not publish files on any mismatch."""
    audit = {"schema_version": "structure_scoped_behavior_adapter_v1", "passed": False,
             "source_process_row_count": len(processes), "source_row_count": len(edges),
             "unmatched_source_process_count": 0, "unmatched_source_row_count": 0,
             "period_mismatches": 0, "structure_mismatches": 0, "errors": [],
             "period_assignment": "Explicit period_role only; timestamps never assign periods",
             "context_identity": ["period_role", "target_node_type", "behavior_key"],
             "key_policy": "Literal behavior_key preserved; old target_node_id excluded",
             "process_join": ["period_role", "source_node_id -> node_id"],
             "relation_mapping": {name: list(pair) for name, pair in RELATION_MAPPING.items()}}

    def fail(message):
        audit["errors"].append(message)
        raise AdapterInputError(message, audit)

    for label, frame, columns in (("PROCESS", processes, PROCESS_COLUMNS), ("behavior", edges, EDGE_COLUMNS)):
        missing = sorted(set(columns) - set(frame.columns))
        if missing:
            fail(f"{label}: missing explicit columns {missing}")
        strings = [column for column in columns if column not in {"event_count", "first_seen_time", "last_seen_time"}]
        try:
            graph._require(frame, strings, label)
        except graph.GraphInputError as exc:
            fail(str(exc))
        if not frame.period_role.isin(graph.PERIOD_ROLES).all():
            fail(f"{label}: unknown period_role; only verified_benign/evaluation allowed")
    if not processes.node_type.eq("PROCESS").all() or not edges.source_node_type.eq("PROCESS").all():
        fail("PROCESS node_type and behavior source_node_type must be exactly PROCESS")
    if processes.duplicated(["period_role", "node_id"]).any():
        fail("Duplicate historical PROCESS (period_role, node_id); join would multiply evidence")
    if processes.duplicated(["period_role", "process_id"]).any():
        fail("Duplicate historical (period_role, process_id); PROCESS identity is ambiguous")
    families = [column for column in FAMILY_COLUMNS if column in processes]
    for column in families:
        try:
            graph._require(processes, [column], "PROCESS metadata")
        except graph.GraphInputError as exc:
            fail(str(exc))
    if "split_structure_id" in edges and "split_structure_id" not in processes:
        fail("Edge split_structure_id cannot be checked without PROCESS split_structure_id")
    unknown = sorted(set(edges.relation_type) - set(RELATION_MAPPING))
    if unknown:
        fail(f"Unknown non-CREATE behavior relation_type: {unknown}")
    expected_types = edges.relation_type.map(lambda name: RELATION_MAPPING[name][0])
    if not edges.target_node_type.equals(expected_types):
        fail("Behavior target_node_type does not match exact legacy relation mapping")
    if not pd.api.types.is_integer_dtype(edges.event_count.dtype) or pd.api.types.is_bool_dtype(edges.event_count.dtype):
        fail("event_count must be positive int64 integer evidence, not inferred weights")
    total = sum(map(int, edges.event_count))
    if (edges.event_count < 1).any() or total >= 2**63:
        fail("event_count must be positive with total below int64 overflow")
    for column in ("first_seen_time", "last_seen_time"):
        if not pd.api.types.is_datetime64_any_dtype(edges[column].dtype) or edges[column].isna().any():
            fail(f"{column}: require explicit non-null timestamp values; no reconstruction")
    if (edges.first_seen_time > edges.last_seen_time).any():
        fail("first_seen_time exceeds last_seen_time")

    # Include period in the join, not timestamps or a first/last heuristic.
    metadata = processes[["period_role", "node_id", "process_id", *families]].rename(
        columns={"node_id": "source_node_id", **{column: "process__" + column for column in families}})
    joined = edges.merge(metadata, on=["period_role", "source_node_id"], how="left", validate="many_to_one", indicator=True)
    missing = joined._merge.eq("left_only")
    known_elsewhere = missing & joined.source_node_id.isin(processes.node_id)
    audit["period_mismatches"] = int(known_elsewhere.sum())
    audit["unmatched_source_row_count"] = int((missing & ~known_elsewhere).sum())
    audit["unmatched_source_process_count"] = len(joined.loc[missing & ~known_elsewhere, ["period_role", "source_node_id"]].drop_duplicates())
    mismatch = pd.Series(False, index=joined.index)
    for column in families:
        if column in edges:
            mismatch |= ~missing & ~joined[column].eq(joined["process__" + column])
    audit["structure_mismatches"] = int(mismatch.sum())
    if missing.any() or mismatch.any():
        fail(f"Source reconciliation failed: unmatched PROCESS={audit['unmatched_source_process_count']}, "
             f"period mismatches={audit['period_mismatches']}, structure mismatches={audit['structure_mismatches']}")

    old_identity_columns = ["period_role", "target_node_id", "target_node_type", "behavior_key"]
    if "split_structure_id" in families:
        old_identity_columns.append("process__split_structure_id")
    old_contexts = joined[old_identity_columns].drop_duplicates()
    if old_contexts.duplicated(["period_role", "target_node_id"]).any():
        fail("One old context node maps to conflicting type/key/CREATE-family identities")
    audit["relation_counts_before"] = _relation_stats(edges, "relation_type", "event_count")
    audit["event_count_total_before"] = total
    links = joined[["period_role", "process_id", "behavior_key", "first_seen_time", "last_seen_time"]].copy()
    links["behavior_type"] = joined.target_node_type
    links["action_raw"] = joined.relation_type.map(lambda name: RELATION_MAPPING[name][1])
    links["attach_event_count"] = joined.event_count.astype("int64")
    keys = ["period_role", "process_id", "behavior_type", "action_raw", "behavior_key"]
    links = links.groupby(keys, as_index=False, sort=True, dropna=False).agg(
        attach_event_count=("attach_event_count", "sum"),
        first_seen_time=("first_seen_time", "min"), last_seen_time=("last_seen_time", "max"))
    if families:
        links = links.merge(processes[["period_role", "process_id", *families]],
                            on=["period_role", "process_id"], validate="many_to_one", how="left")
    links = links[LINK_COLUMNS + families].sort_values(keys, kind="stable").reset_index(drop=True)
    relations = links[["period_role", "attach_event_count"]].copy()
    relations["relation_type"] = [graph.BEHAVIOR_RELATIONS[pair] for pair in zip(links.behavior_type, links.action_raw)]
    audit["relation_counts_after"] = _relation_stats(relations, "relation_type", "attach_event_count")
    audit["event_count_total_after"] = sum(map(int, links.attach_event_count))
    if audit["event_count_total_before"] != audit["event_count_total_after"]:
        fail("Total behavior event_count reconciliation failed")
    for role, counts in audit["relation_counts_before"].items():
        for relation, values in counts.items():
            after = audit["relation_counts_after"].get(role, {}).get(relation)
            if after is None or values["event_count"] != after["event_count"]:
                fail(f"Behavior event_count reconciliation failed for {role}/{relation}")
    outputs = {role: links.loc[links.period_role == role].reset_index(drop=True) for role in graph.PERIOD_ROLES}
    audit["output_row_count_by_period"] = {role: len(frame) for role, frame in outputs.items()}
    audit["duplicate_links_aggregated"] = len(edges) - len(links)
    audit["metadata_columns_preserved"] = families
    audit["context_counts_by_period"] = {}
    for role in graph.PERIOD_ROLES:
        old = old_contexts.loc[old_contexts.period_role == role]
        new_count = len(old[["target_node_type", "behavior_key"]].drop_duplicates())
        audit["context_counts_by_period"][role] = {
            "unique_old_context_node_count": len(old), "unique_new_type_key_count": new_count,
            "old_context_nodes_collapsed_by_sharing": len(old) - new_count,
        }
    for name in ("unique_old_context_node_count", "unique_new_type_key_count", "old_context_nodes_collapsed_by_sharing"):
        audit[name] = sum(period[name] for period in audit["context_counts_by_period"].values())
    audit["passed"] = True
    return outputs, audit


def read_and_convert(cfg: Config) -> tuple[dict[str, pd.DataFrame], dict]:
    inputs = {"process_nodes": cfg.process_nodes, "behavior_edges": cfg.behavior_edges}
    hashes = {name: graph._file_hash(path) for name, path in inputs.items()}
    schemas = {name: pq.ParquetFile(path).schema_arrow for name, path in inputs.items()}
    process_columns = PROCESS_COLUMNS + [column for column in FAMILY_COLUMNS if column in schemas["process_nodes"].names]
    edge_columns = EDGE_COLUMNS + [column for column in FAMILY_COLUMNS if column in schemas["behavior_edges"].names]
    # Select only actual columns so the validation reports missing names clearly.
    processes = pd.read_parquet(cfg.process_nodes, columns=[name for name in process_columns if name in schemas["process_nodes"].names])
    edges = pd.read_parquet(cfg.behavior_edges, columns=[name for name in edge_columns if name in schemas["behavior_edges"].names])
    outputs, audit = convert_frames(processes, edges)
    if hashes != {name: graph._file_hash(path) for name, path in inputs.items()}:
        audit["passed"] = False
        audit["errors"].append("Historical artifacts changed during adaptation")
        raise AdapterInputError("Historical artifacts changed during adaptation", audit)
    audit["input_sha256"] = hashes
    audit["inputs"] = {name: {"path": str(path), "row_count": pq.ParquetFile(path).metadata.num_rows,
                             "columns": schema.names, "column_types": {field.name: str(field.type) for field in schema}}
                       for name, (path, schema) in ((name, (inputs[name], schemas[name])) for name in inputs)}
    audit["source_period_row_counts"] = {role: int(edges.period_role.eq(role).sum()) for role in graph.PERIOD_ROLES}
    audit["source_process_period_row_counts"] = {role: int(processes.period_role.eq(role).sum()) for role in graph.PERIOD_ROLES}
    return outputs, audit


def adapt(cfg: Config) -> dict:
    if os.path.lexists(cfg.output_dir):
        raise graph.GraphInputError(f"Refusing existing adapter output: {cfg.output_dir}")
    outputs, audit = read_and_convert(cfg)
    cfg.output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".behavior_adapter_", dir=cfg.output_dir.parent))
    try:
        for role, frame in outputs.items():
            frame.to_parquet(staging / f"{role}_behavior_links_v1.parquet", index=False)
        audit["output_sha256"] = {path.name: graph._file_hash(path) for path in sorted(staging.iterdir())}
        (staging / AUDIT_NAME).write_text(json.dumps(audit, indent=2, sort_keys=True, allow_nan=False) + "\n")
        if os.path.lexists(cfg.output_dir):
            raise graph.GraphInputError("Adapter output appeared during publication")
        os.rename(staging, cfg.output_dir)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return audit


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--process-nodes", required=True, type=Path)
    parser.add_argument("--behavior-edges", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--audit-only", action="store_true")
    args = vars(parser.parse_args(argv))
    audit_only = args.pop("audit_only")
    cfg = Config(**args)
    try:
        audit = read_and_convert(cfg)[1] if audit_only else adapt(cfg)
    except AdapterInputError as exc:
        print(json.dumps(exc.audit, indent=2, sort_keys=True), file=sys.stderr)
        print(f"STOP: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"STOP: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(audit, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
