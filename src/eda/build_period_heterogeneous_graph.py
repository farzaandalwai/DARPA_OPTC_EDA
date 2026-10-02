#!/usr/bin/env python3
"""Build and audit ONE period's heterogeneous provenance graph (v1).

Inputs must already be period-specific Parquet files; this module does not
split timelines or fit features. EDA10 column defaults are explicit in Config.
The unavailable feature-schema format is not inferred: by default JSON must
contain ``{"feature_columns": ["numeric_column", ...]}``; --feature-list-key
selects another top-level key (or JSON pointer, e.g. /process/features).

Context IDs hash [rule version, period_role, node type, host scope, canonical
value], NEVER a structure ID. FILE/MODULE Windows paths use EDA5's separator-
only normalization (case and dot segments are retained). DESTINATION consumes
EDA10's address[:port][|protocol] key; valid IPs are canonicalized, valid decimal
ports normalized, protocols uppercased. Unresolved literals are retained.
An explicit --host-scope identifies a single-host input, or --host-column scopes
FILE/MODULE nodes by each process's host in multi-host inputs. Without either,
all inputs are asserted to share one host namespace. DESTINATION has no host
scope. These are observable path/endpoint identities, not proof of physical
file identity across renames or versions.

Output contract (schema version period_heterogeneous_graph_v1):
* hetero_process_nodes.parquet: ALL original columns, plus canonical process_id,
  structure_id, period_role, node_id, node_type=PROCESS. Only the explicit feature
  allowlist in the audit is predictive; all other columns remain metadata.
* hetero_entity_nodes.parquet: node_id, node_type, period_role, host_scope,
  canonical_key. No process-family scope and no learned features.
* hetero_graph_edges_forward.parquet: edge_id, source_id, target_id,
  source_type, target_type, relation, relation_id, period_role, event_count.
  Each CREATE input row is retained once; canonical duplicate behavior links
  are compacted by (process, type/action, entity), summing event counts.
  EDA10 create_event_count/attach_event_count columns are used when present;
  absent count columns mean unit row weights, explicitly recorded in the audit.
* hetero_graph_edges_bidirectional.parquet: the same schema, with exact mirrored
  REV__ relations and preserved event_count. IDs are deterministic.
* relation_type_mapping.csv: 10 forward and 10 reverse definitions, including
  unused types; IDs 0..9 forward and 10..19 reverse.
* graph_connectivity_audit.json: connectivity, degree/family sharing, input and
  output hashes, configuration, feature allowlist and CREATE reconciliation.

WCC/degree statistics use unique neighbors, not event multiplicities or reverse
edges. Family counts use structure_id metadata; merged-family groups are WCCs
in the family/context incidence graph. Isolated PROCESS nodes are counted even
when their original CREATE family contains other nodes outside these inputs.

CLI example (paths are placeholders):
  python src/eda/build_period_heterogeneous_graph.py \
    --process-nodes period_process_features.parquet \
    --create-edges period_create_edges.parquet \
    --behavior period_behavior.parquet --feature-schema features.json \
    --period-role verified_benign --output-dir new_graph --host-scope HOST

V1 loads compact tables into memory; bidirectional output is streamed in
batches. Production memory/runtime and connectivity need measurement on real
period artifacts. Existing output paths are refused and publication is atomic.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict, dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

try:
    from .eda_05_entity_dictionary import _normalize_windows_path
except ImportError:  # Script execution follows the existing EDA CLI convention.
    from eda_05_entity_dictionary import _normalize_windows_path


VERSION = "period_heterogeneous_graph_v1"
PERIOD_ROLES = ("verified_benign", "evaluation")
FORWARD_RELATIONS = (
    "PROCESS_CREATE_PROCESS",
    "PROCESS_DESTINATION_MESSAGE",
    "PROCESS_DESTINATION_START",
    "PROCESS_FILE_CREATE",
    "PROCESS_FILE_DELETE",
    "PROCESS_FILE_MODIFY",
    "PROCESS_FILE_READ",
    "PROCESS_FILE_RENAME",
    "PROCESS_FILE_WRITE",
    "PROCESS_MODULE_LOAD",
)
BEHAVIOR_RELATIONS = {
    ("DESTINATION", "MESSAGE"): FORWARD_RELATIONS[1],
    ("DESTINATION", "START"): FORWARD_RELATIONS[2],
    **{("FILE", action): f"PROCESS_FILE_{action}"
       for action in ("CREATE", "DELETE", "MODIFY", "READ", "RENAME", "WRITE")},
    ("MODULE", "LOAD"): FORWARD_RELATIONS[9],
}
RELATION_IDS = {name: i for i, name in enumerate(
    FORWARD_RELATIONS + tuple("REV__" + name for name in FORWARD_RELATIONS)
)}
ENTITY_COLUMNS = ["node_id", "node_type", "period_role", "host_scope", "canonical_key"]
EDGE_COLUMNS = ["edge_id", "source_id", "target_id", "source_type", "target_type",
                "relation", "relation_id", "period_role", "event_count"]
EDGE_SCHEMA = pa.schema([
    pa.field(name, pa.int64() if name in ("relation_id", "event_count") else pa.string())
    for name in EDGE_COLUMNS
])


class GraphInputError(ValueError):
    """An input does not satisfy the explicit period-graph contract."""


@dataclass(frozen=True)
class Config:
    process_nodes: Path
    create_edges: Path
    behavior: Path
    feature_schema: Path
    output_dir: Path
    period_role: str
    feature_list_key: str = "feature_columns"
    process_id_column: str = "process_id"
    structure_id_column: str = "structure_id"
    create_parent_column: str = "parent_process_id"
    create_child_column: str = "child_process_id"
    create_count_column: str = "create_event_count"
    behavior_process_column: str = "process_id"
    behavior_type_column: str = "behavior_type"
    behavior_action_column: str = "action_raw"
    behavior_key_column: str = "behavior_key"
    behavior_count_column: str = "attach_event_count"
    period_column: str = "period_role"
    host_scope: str = ""
    host_column: str | None = None
    top_k: int = 20


def _digest(prefix: str, values: list) -> str:
    payload = json.dumps([VERSION, *values], ensure_ascii=False, separators=(",", ":"))
    return prefix + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_context_key(node_type: str, value: str) -> str:
    """Return a typed deterministic identity value; no family metadata is used."""
    if node_type in ("FILE", "MODULE"):
        return _normalize_windows_path(value)[0]
    if node_type != "DESTINATION":
        raise GraphInputError(f"Unsupported context type: {node_type}")
    endpoint, delimiter, protocol = value.rpartition("|")
    if not delimiter:
        endpoint, protocol = value, ""
    address, port = endpoint, ""
    try:
        address = str(ipaddress.ip_address(endpoint))
    except ValueError:
        # Brackets disambiguate IPv6 endpoints. EDA10's unbracketed form is
        # interpreted as a whole address when valid, avoiding invented ports.
        match = re.fullmatch(r"\[([^]]+)\](?::([0-9]+))?", endpoint)
        if match:
            address, port = match.group(1), match.group(2) or ""
        elif endpoint.count(":") == 1:
            address, port = endpoint.rsplit(":", 1)
        try:
            address = str(ipaddress.ip_address(address))
        except ValueError:
            pass  # Preserve unresolved address literals without alias guessing.
    if port.isdecimal() and 0 <= int(port) <= 65535:
        port = str(int(port))
    # A tuple avoids IPv6/port concatenation collisions.
    return json.dumps([address, port, protocol.upper()], ensure_ascii=False,
                      separators=(",", ":"))


def _require(frame: pd.DataFrame, columns: list[str], label: str) -> None:
    missing = set(columns) - set(frame.columns)
    if missing:
        raise GraphInputError(f"{label}: missing columns {sorted(missing)}; configure column names explicitly")
    for name in columns:
        if frame[name].isna().any() or not frame[name].map(
            lambda value: isinstance(value, str) and bool(value.strip())
        ).all():
            raise GraphInputError(f"{label}: {name} must contain nonempty string values")


def _check_period(frame: pd.DataFrame, cfg: Config, label: str) -> bool:
    columns = {cfg.period_column, "period_role"} & set(frame.columns)
    for name in columns:
        if not frame[name].eq(cfg.period_role).all():
            raise GraphInputError(f"{label}: {name} contains a different or missing period role")
    return bool(columns)


def _counts(frame: pd.DataFrame, column: str, label: str) -> pd.Series:
    if column not in frame:
        return pd.Series(1, index=frame.index, dtype="int64")
    values = pd.to_numeric(frame[column], errors="coerce")
    if (values.isna().any() or (values < 1).any() or
            (values >= 2**63).any() or (values % 1 != 0).any()):
        raise GraphInputError(f"{label}: {column} must contain positive int64 event counts")
    return values.astype("int64")


def _features(path: Path, key: str, processes: pd.DataFrame, cfg: Config) -> list[str]:
    schema = json.loads(path.read_text(encoding="utf-8"))
    try:
        if key.startswith("/"):
            for part in key[1:].split("/"):
                schema = schema[part.replace("~1", "/").replace("~0", "~")]
        else:
            schema = schema[key]
    except (KeyError, TypeError, IndexError) as exc:
        raise GraphInputError(f"Feature schema has no feature list at {key!r}; use --feature-list-key") from exc
    if (not isinstance(schema, list) or not schema or
            not all(isinstance(name, str) and name for name in schema) or
            len(set(schema)) != len(schema)):
        raise GraphInputError("Feature schema must select a nonempty list of unique column names")
    configured_metadata = {cfg.process_id_column, cfg.structure_id_column,
                           cfg.period_column, cfg.host_column}
    for name in schema:
        # IDs stay in output metadata, but never enter the predictive allowlist.
        if (name in configured_metadata or "uuid" in name.lower() or
                re.search(r"(^|[^a-z0-9])(uuid|pid|ppid|tid|id|ids)([^a-z0-9]|$)", name.lower()) or
                "structure" in name.lower() or name in {"period_role", "node_type", "host_scope"}):
            raise GraphInputError(f"Metadata/linkage column cannot be a predictive feature: {name}")
        if name not in processes:
            raise GraphInputError(f"Feature column missing from PROCESS table: {name}")
        values = processes[name]
        if not pd.api.types.is_numeric_dtype(values) or not np.isfinite(values.to_numpy(dtype=float)).all():
            raise GraphInputError(f"Feature {name} must be numeric, finite, and non-null")
    return schema


class _UnionFind:
    def __init__(self, size: int):
        self.parents = np.arange(size, dtype=np.int64)
        self.sizes = np.ones(size, dtype=np.int64)

    def root(self, node: int) -> int:
        while self.parents[node] != node:
            self.parents[node] = self.parents[self.parents[node]]
            node = int(self.parents[node])
        return node

    def join(self, left: int, right: int) -> None:
        left, right = self.root(left), self.root(right)
        if left == right:
            return
        if self.sizes[left] < self.sizes[right]:
            left, right = right, left
        self.parents[right] = left
        self.sizes[left] += self.sizes[right]


def _connectivity(processes: pd.DataFrame, entities: pd.DataFrame,
                  edges: pd.DataFrame, cfg: Config) -> dict:
    ids = list(processes.node_id) + list(entities.node_id)
    index = {node: i for i, node in enumerate(ids)}
    uf = _UnionFind(len(ids))
    degree = np.zeros(len(ids), dtype=np.int64)
    neighbors = edges[["source_id", "target_id"]].drop_duplicates()
    for source, target in neighbors.itertuples(index=False, name=None):
        left, right = index[source], index[target]
        uf.join(left, right)
        degree[left] += 1
        if left != right:
            degree[right] += 1
    roots = [uf.root(i) for i in range(len(ids))]
    sizes = Counter(roots)
    process_counts = Counter(roots[:len(processes)])
    largest = max(sizes, key=lambda root: (sizes[root], process_counts[root], -root)) if sizes else None
    entity_degrees = degree[len(processes):]
    # Distinct incident processes/families, independent of actions/event counts.
    context_edges = edges.loc[edges.target_type != "PROCESS", ["source_id", "target_id"]].drop_duplicates()
    family_for_node = processes.set_index("node_id").structure_id
    context_edges["structure_id"] = context_edges.source_id.map(family_for_node)
    incidence = context_edges[["target_id", "structure_id"]].drop_duplicates()
    family_counts = incidence.groupby("target_id").size()
    shared = family_counts[family_counts > 1]
    family_ids = sorted(processes.structure_id.unique())
    family_index = {family: i for i, family in enumerate(family_ids)}
    family_uf = _UnionFind(len(family_ids))
    for _, group in incidence.groupby("target_id", sort=False):
        values = group.structure_id.to_numpy()
        for family in values[1:]:
            family_uf.join(family_index[values[0]], family_index[family])
    merged_sizes = Counter(family_uf.root(i) for i in range(len(family_ids)))
    merged_groups = sorted((count for count in merged_sizes.values() if count > 1), reverse=True)
    top = {}
    for node_type in ("FILE", "MODULE", "DESTINATION"):
        ranked = entities.loc[entities.node_type == node_type].copy()
        ranked["degree"] = ranked.node_id.map(lambda node: int(degree[index[node]]))
        ranked["create_family_count"] = ranked.node_id.map(family_counts).fillna(0).astype(int)
        top[node_type] = ranked.sort_values(["degree", "node_id"], ascending=[False, True]).head(cfg.top_k).to_dict("records")
    return {
        "weakly_connected_component_count": len(sizes),
        "largest_component_node_count": sizes.get(largest, 0),
        "largest_component_process_count": process_counts.get(largest, 0),
        "percentage_process_nodes_in_largest_component": (
            100 * process_counts.get(largest, 0) / len(processes) if len(processes) else 0.0),
        "singleton_process_count": int((degree[:len(processes)] == 0).sum()),
        "shared_context_entity_count": len(shared),
        "create_families_connected_through_shared_context_count": sum(merged_groups),
        "merged_create_family_group_count": len(merged_groups),
        "merged_create_family_group_sizes": merged_groups,
        "create_families_per_shared_context": {
            "frequency": {str(int(k)): int(v) for k, v in sorted(Counter(shared).items())},
            "median": float(shared.median()) if len(shared) else 0.0,
            "p95": float(shared.quantile(0.95)) if len(shared) else 0.0,
            "maximum": int(shared.max()) if len(shared) else 0,
        },
        "top_high_degree_context_nodes": top,
        "maximum_context_node_degree": int(entity_degrees.max()) if len(entity_degrees) else 0,
        "median_context_node_degree": float(np.median(entity_degrees)) if len(entity_degrees) else 0.0,
        "p95_context_node_degree": float(np.percentile(entity_degrees, 95)) if len(entity_degrees) else 0.0,
        "degree_definition": "Unique incident PROCESS neighbors; no reverse-edge or event-count inflation",
        "family_connection_definition": "Distinct CREATE families in non-singleton family/context incidence components",
        "high_degree_filtering_applied": False,
    }


def build_graph(cfg: Config) -> dict:
    """Validate inputs, construct connectivity, and atomically publish six outputs."""
    if cfg.period_role not in PERIOD_ROLES:
        raise GraphInputError(f"period_role must be one of {PERIOD_ROLES}")
    if cfg.top_k < 1 or (cfg.host_scope and cfg.host_column):
        raise GraphInputError("top_k must be positive; host_scope and host_column are mutually exclusive")
    output = Path(cfg.output_dir)
    if os.path.lexists(output):
        raise GraphInputError(f"Refusing existing output path: {output}")
    input_paths = {name: Path(getattr(cfg, name)) for name in
                   ("process_nodes", "create_edges", "behavior", "feature_schema")}
    for label, path in input_paths.items():
        if not path.is_file():
            raise GraphInputError(f"{label}: input file not found: {path}")
    input_hashes = {name: _file_hash(path) for name, path in input_paths.items()}
    processes = pd.read_parquet(input_paths["process_nodes"])
    creates = pd.read_parquet(input_paths["create_edges"])
    behavior = pd.read_parquet(input_paths["behavior"])
    _require(processes, [cfg.process_id_column, cfg.structure_id_column], "PROCESS table")
    _require(creates, [cfg.create_parent_column, cfg.create_child_column], "CREATE table")
    _require(behavior, [cfg.behavior_process_column, cfg.behavior_type_column,
                        cfg.behavior_action_column, cfg.behavior_key_column], "Behavior table")
    period_checked = {name: _check_period(frame, cfg, name) for name, frame in
                      (("process_nodes", processes), ("create_edges", creates), ("behavior", behavior))}
    features = _features(input_paths["feature_schema"], cfg.feature_list_key, processes, cfg)
    for configured, canonical in ((cfg.process_id_column, "process_id"),
                                  (cfg.structure_id_column, "structure_id")):
        if configured != canonical and canonical in processes and not processes[configured].equals(processes[canonical]):
            raise GraphInputError(f"Conflicting configured and canonical PROCESS column: {canonical}")
        processes[canonical] = processes[configured]
    if processes.process_id.duplicated().any():
        raise GraphInputError("PROCESS table contains duplicate process IDs")
    if "node_id" in processes or "node_type" in processes:
        raise GraphInputError("PROCESS input has reserved node_id/node_type columns; supply the upstream node/feature table")
    if cfg.host_column:
        _require(processes, [cfg.host_column], "PROCESS table")
        host_for_process = processes.set_index("process_id")[cfg.host_column]
    else:
        host_for_process = pd.Series(cfg.host_scope, index=processes.process_id)
    processes["period_role"] = cfg.period_role
    processes["node_type"] = "PROCESS"
    processes["node_id"] = processes.process_id.map(lambda value: _digest("proc_", [cfg.period_role, "PROCESS", value]))
    processes = processes.sort_values("process_id", kind="stable").reset_index(drop=True)
    node_for_process = processes.set_index("process_id").node_id
    structure_for_process = processes.set_index("process_id").structure_id
    process_set = set(processes.process_id)
    for label, values in (("CREATE parent", creates[cfg.create_parent_column]),
                          ("CREATE child", creates[cfg.create_child_column]),
                          ("Behavior process", behavior[cfg.behavior_process_column])):
        unknown = set(values) - process_set
        if unknown:
            raise GraphInputError(f"{label}: unknown PROCESS IDs (possibly another period): {sorted(unknown)[:5]}")
    if creates.duplicated([cfg.create_parent_column, cfg.create_child_column]).any():
        raise GraphInputError("CREATE input must be compact: duplicate parent/child pairs")
    if not creates[cfg.create_parent_column].map(structure_for_process).equals(
            creates[cfg.create_child_column].map(structure_for_process)):
        raise GraphInputError("CREATE edge crosses supplied structure_id metadata")
    create_counts = _counts(creates, cfg.create_count_column, "CREATE table")
    behavior_counts = _counts(behavior, cfg.behavior_count_column, "Behavior table")
    types = behavior[cfg.behavior_type_column].str.strip().str.upper()
    actions = behavior[cfg.behavior_action_column].str.strip().str.upper()
    relations = pd.Series([BEHAVIOR_RELATIONS.get(pair) for pair in zip(types, actions)], index=behavior.index)
    if relations.isna().any():
        unsupported = sorted(set(zip(types[relations.isna()], actions[relations.isna()])))
        raise GraphInputError(f"Unsupported behavior type/action pairs: {unsupported}; no rows silently dropped")
    for family_column in {cfg.structure_id_column, "structure_id"} & set(behavior.columns):
        if not behavior[family_column].equals(behavior[cfg.behavior_process_column].map(structure_for_process)):
            raise GraphInputError(f"Behavior {family_column} disagrees with PROCESS metadata")
    keys = [canonical_context_key(kind, value) for kind, value in zip(types, behavior[cfg.behavior_key_column])]
    hosts = ["" if kind == "DESTINATION" else host_for_process[process]
             for kind, process in zip(types, behavior[cfg.behavior_process_column])]
    entity_ids = [_digest("ctx_", [cfg.period_role, kind, host, key])
                  for kind, host, key in zip(types, hosts, keys)]
    entities = pd.DataFrame({"node_id": entity_ids, "node_type": types.to_list(),
                             "period_role": cfg.period_role, "host_scope": hosts,
                             "canonical_key": keys}, columns=ENTITY_COLUMNS).drop_duplicates()
    if entities.node_id.duplicated().any() or processes.node_id.duplicated().any():
        raise GraphInputError("Deterministic node hash collision")
    entities = entities.sort_values("node_id", kind="stable").reset_index(drop=True)
    create_edges = pd.DataFrame({
        "source_id": creates[cfg.create_parent_column].map(node_for_process),
        "target_id": creates[cfg.create_child_column].map(node_for_process),
        "source_type": "PROCESS", "target_type": "PROCESS",
        "relation": FORWARD_RELATIONS[0], "event_count": create_counts,
    })
    behavior_edges = pd.DataFrame({
        "source_id": behavior[cfg.behavior_process_column].map(node_for_process),
        "target_id": entity_ids, "source_type": "PROCESS", "target_type": types,
        "relation": relations, "event_count": behavior_counts,
    })
    group_columns = ["source_id", "target_id", "source_type", "target_type", "relation"]
    # Python integer totals detect overflow before pandas' int64 aggregation.
    if sum(map(int, behavior_counts)) >= 2**63:
        raise GraphInputError("Behavior total event count exceeds int64")
    behavior_edges = behavior_edges.groupby(group_columns, as_index=False, sort=True).event_count.sum()
    forward = pd.concat([create_edges, behavior_edges], ignore_index=True)
    forward["period_role"] = cfg.period_role
    forward["relation_id"] = forward.relation.map(RELATION_IDS).astype("int64")
    forward["event_count"] = forward.event_count.astype("int64")
    forward["edge_id"] = [_digest("edge_", [cfg.period_role, relation, source, target])
                          for source, target, relation in forward[["source_id", "target_id", "relation"]].itertuples(index=False, name=None)]
    forward = forward[EDGE_COLUMNS].sort_values("edge_id", kind="stable").reset_index(drop=True)
    if forward.edge_id.duplicated().any():
        raise GraphInputError("Deterministic edge hash collision")
    input_topology = sorted(zip(creates[cfg.create_parent_column], creates[cfg.create_child_column]))
    inverse_process = dict(zip(processes.node_id, processes.process_id))
    output_topology = sorted((inverse_process[source], inverse_process[target])
                             for source, target in create_edges[["source_id", "target_id"]].itertuples(index=False, name=None))
    audit = {
        "schema_version": VERSION,
        "period_role": cfg.period_role,
        "configuration": {key: str(value) if isinstance(value, Path) else value for key, value in asdict(cfg).items()},
        "input_sha256": input_hashes,
        "input_period_columns_checked": period_checked,
        "period_isolation_contract": "Caller supplies already period-specific inputs; present role columns are validated; all node/edge IDs include period_role",
        "predictive_process_feature_columns": features,
        "process_metadata_columns": [name for name in processes.columns if name not in features],
        "context_predictive_features": [],
        "context_identity_policy": {
            "FILE_MODULE": "EDA5 separator-only Windows path normalization; host-scoped when configured; no family scope",
            "DESTINATION": "Canonical IP, optional port and uppercase protocol; no host/family scope",
            "ambiguous_ipv6": "A valid unbracketed IPv6 endpoint is treated as address-only; explicit [IPv6]:port required for unambiguous port identity",
            "period_namespace": "Node and edge IDs include period_role",
        },
        "process_node_count": len(processes),
        "file_node_count": int((entities.node_type == "FILE").sum()),
        "module_node_count": int((entities.node_type == "MODULE").sum()),
        "destination_node_count": int((entities.node_type == "DESTINATION").sum()),
        "total_entity_node_count": len(entities),
        "total_graph_node_count": len(processes) + len(entities),
        "create_family_count": int(processes.structure_id.nunique()),
        "create_edge_count": len(create_edges),
        "behavior_relation_edge_counts": {relation: int((forward.relation == relation).sum()) for relation in FORWARD_RELATIONS[1:]},
        "forward_relation_count": 10,
        "bidirectional_relation_count": 20,
        "observed_forward_relation_count": int(forward.relation.nunique()),
        "observed_bidirectional_relation_count": int(forward.relation.nunique()) * 2,
        "forward_edge_count": len(forward),
        "bidirectional_edge_count": 2 * len(forward),
        "reconciliation": {
            "input_process_rows": len(processes), "input_create_rows": len(creates),
            "output_create_rows": len(create_edges), "create_topology_unchanged": input_topology == output_topology,
            "input_create_topology_sha256": _digest("", input_topology),
            "output_create_topology_sha256": _digest("", output_topology),
            "input_create_event_count": sum(map(int, create_counts)),
            "output_create_event_count": sum(map(int, create_edges.event_count)),
            "create_weight_source": cfg.create_count_column if cfg.create_count_column in creates else "unit row weights",
            "input_behavior_rows": len(behavior), "output_behavior_edges": len(behavior_edges),
            "input_behavior_event_count": sum(map(int, behavior_counts)),
            "output_behavior_event_count": sum(map(int, behavior_edges.event_count)),
            "behavior_weight_source": cfg.behavior_count_column if cfg.behavior_count_column in behavior else "unit row weights",
            "cross_family_create_edges": 0, "missing_edge_endpoints": 0,
            "node_hash_collisions": 0, "edge_hash_collisions": 0,
        },
        **_connectivity(processes, entities, forward, cfg),
    }
    # Verify files did not change while constructing the graph.
    if input_hashes != {name: _file_hash(path) for name, path in input_paths.items()}:
        raise GraphInputError("Input files changed during graph construction")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".period_graph_", dir=output.parent))
    try:
        processes.to_parquet(staging / "hetero_process_nodes.parquet", index=False)
        entities.to_parquet(staging / "hetero_entity_nodes.parquet", index=False)
        with pq.ParquetWriter(staging / "hetero_graph_edges_forward.parquet", EDGE_SCHEMA) as fw, \
                pq.ParquetWriter(staging / "hetero_graph_edges_bidirectional.parquet", EDGE_SCHEMA) as bi:
            for start in range(0, len(forward), 50_000):
                batch = forward.iloc[start:start + 50_000]
                table = pa.Table.from_pandas(batch, schema=EDGE_SCHEMA, preserve_index=False)
                fw.write_table(table)
                bi.write_table(table)
                reverse = batch.copy()
                reverse["source_id"], reverse["target_id"] = batch.target_id, batch.source_id
                reverse["source_type"], reverse["target_type"] = batch.target_type, batch.source_type
                reverse["relation"] = "REV__" + batch.relation
                reverse["relation_id"] = reverse.relation.map(RELATION_IDS).astype("int64")
                reverse["edge_id"] = [_digest("edge_", [cfg.period_role, relation, source, target])
                                      for source, target, relation in reverse[["source_id", "target_id", "relation"]].itertuples(index=False, name=None)]
                bi.write_table(pa.Table.from_pandas(reverse, schema=EDGE_SCHEMA, preserve_index=False))
        mapping = []
        for i, relation in enumerate(FORWARD_RELATIONS):
            target_type = "PROCESS" if i == 0 else relation.split("_")[1]
            mapping.append({"relation_id": i, "relation": relation, "source_type": "PROCESS", "target_type": target_type, "reverse_relation_id": i + 10})
            mapping.append({"relation_id": i + 10, "relation": "REV__" + relation, "source_type": target_type, "target_type": "PROCESS", "reverse_relation_id": i})
        pd.DataFrame(mapping).sort_values("relation_id").to_csv(staging / "relation_type_mapping.csv", index=False)
        audit["output_sha256"] = {path.name: _file_hash(path) for path in sorted(staging.iterdir())}
        (staging / "graph_connectivity_audit.json").write_text(json.dumps(audit, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
        if os.path.lexists(output):
            raise GraphInputError(f"Output path appeared during publication: {output}")
        os.rename(staging, output)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return audit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for flag in ("process-nodes", "create-edges", "behavior", "feature-schema", "output-dir"):
        parser.add_argument("--" + flag, required=True, type=Path)
    parser.add_argument("--period-role", required=True, choices=PERIOD_ROLES)
    defaults = Config.__dataclass_fields__
    for name in ("feature_list_key", "process_id_column", "structure_id_column", "create_parent_column",
                 "create_child_column", "create_count_column", "behavior_process_column", "behavior_type_column",
                 "behavior_action_column", "behavior_key_column", "behavior_count_column", "period_column"):
        parser.add_argument("--" + name.replace("_", "-"), default=defaults[name].default)
    hosts = parser.add_mutually_exclusive_group()
    hosts.add_argument("--host-scope", default="")
    hosts.add_argument("--host-column", default=None)
    parser.add_argument("--top-k", type=int, default=20)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        audit = build_graph(Config(**vars(parser.parse_args(argv))))
    except (GraphInputError, OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps({key: audit[key] for key in
                      ("period_role", "process_node_count", "total_entity_node_count", "forward_edge_count",
                       "weakly_connected_component_count", "shared_context_entity_count")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
