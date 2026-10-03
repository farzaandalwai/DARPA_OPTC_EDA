"""Training-first, read-only hub-control experiment on completed hybrid graphs.

Only linkage/identity/count columns are read, never PROCESS features or labels.
Policies are frozen before evaluation is opened. Exclusions and candidate weights
are keyed by (node_type, host_scope, canonical_key), not period-specific node IDs.
Evaluation uses TRAIN statistics even for entities that are rarer/more common in
evaluation; unseen identities stay retained with weight 1. This conservative
transfer tests known training hubs, not an evaluation-refitted threshold rule.

Outputs are small context masks, profiles and audit summaries, NOT new graphs.
All PROCESS nodes and every CREATE edge survive each policy. Undirected unique
neighbors define degree/WCC/exposure; event counts and compact relation rows are
reported separately. Weighted profiles leave topology unchanged and are NOT an
RGCN experiment. Zero weights are possible for universal training entities.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import time

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from scipy.sparse import csr_matrix
from scipy.sparse.csgraph import connected_components

from .build_period_heterogeneous_graph import FORWARD_RELATIONS

VERSION = "training_first_hub_control_v1"
TYPES = ("FILE", "MODULE", "DESTINATION")
KEYS = ["node_type", "host_scope", "canonical_key"]
INPUTS = ("hetero_process_nodes.parquet", "hetero_entity_nodes.parquet",
          "hetero_graph_edges_forward.parquet", "graph_connectivity_audit.json")
PERCENTILES = (99.0, 99.5, 99.9)
FAMILY_BANDS = (0.01, 0.05, 0.10)


class HubAuditError(ValueError):
    """Unsafe/incompatible inputs or outputs; do not mutate source artifacts."""


def digest(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def summary(values):
    a = np.asarray(values, dtype=float)
    if not len(a):
        return {"count": 0, "minimum": None, "mean": None, "median": None,
                "p90": None, "p95": None, "p99": None, "p99_5": None,
                "p99_9": None, "maximum": None}
    return dict(count=len(a), minimum=float(a.min()), mean=float(a.mean()),
                median=float(np.median(a)), p90=float(np.percentile(a, 90)),
                p95=float(np.percentile(a, 95)), p99=float(np.percentile(a, 99)),
                p99_5=float(np.percentile(a, 99.5)),
                p99_9=float(np.percentile(a, 99.9)), maximum=float(a.max()))


def json_write(path, value):
    with Path(path).open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")


def require(frame, names, label):
    if set(names) - set(frame):
        raise HubAuditError(f"{label}: missing explicit columns {sorted(set(names) - set(frame))}")
    if frame[names].isna().any().any():
        raise HubAuditError(f"{label}: missing values")


@dataclass
class Graph:
    role: str
    processes: pd.DataFrame
    entities: pd.DataFrame
    edges: pd.DataFrame
    source: np.ndarray
    target: np.ndarray
    is_create: np.ndarray
    family: np.ndarray
    incidence: pd.DataFrame
    profiles: pd.DataFrame
    relation_profiles: pd.DataFrame
    create_hash: str
    input_inventory: dict


def prepare(processes, entities, edges, role, inventory=None):
    """Validate the completed graph contract and compute unique incidence."""
    require(processes, ["node_id", "process_id", "structure_id", "period_role"], "PROCESS")
    require(entities, ["node_id", *KEYS, "period_role"], "context")
    require(edges, ["source_id", "target_id", "source_type", "target_type",
                    "relation", "period_role"], "forward edges")
    if role not in ("verified_benign", "evaluation") or not len(processes):
        raise HubAuditError("Explicit period and nonempty PROCESS universe required")
    for frame, columns in ((processes, ["node_id", "process_id", "structure_id"]),
                           (entities, ["node_id", "node_type", "canonical_key"])):
        for column in columns:
            if not frame[column].map(lambda value: isinstance(value, str) and bool(value.strip())).all():
                raise HubAuditError(f"Invalid identifier: {column}")
    for label, frame in (("PROCESS", processes), ("context", entities), ("edge", edges)):
        if not frame.period_role.eq(role).all():
            raise HubAuditError(f"{label}: period isolation violated")
    if (processes.node_id.duplicated().any() or processes.process_id.duplicated().any()
            or entities.node_id.duplicated().any() or entities.duplicated(KEYS).any()
            or set(processes.node_id) & set(entities.node_id)):
        raise HubAuditError("Nonunique node/identity keys")
    if not entities.node_type.isin(TYPES).all():
        raise HubAuditError("Unexpected context type")
    if not entities.host_scope.map(lambda value: isinstance(value, str)).all():
        raise HubAuditError("host_scope must be an explicit string namespace")
    if not edges.source_type.eq("PROCESS").all() or not edges.relation.isin(FORWARD_RELATIONS).all():
        raise HubAuditError("Only validated forward PROCESS-source relations are accepted")
    expected_type = edges.relation.map({r: "PROCESS" if r == FORWARD_RELATIONS[0] else r.split("_")[1]
                                        for r in FORWARD_RELATIONS})
    if not expected_type.equals(edges.target_type):
        raise HubAuditError("Relation/target-type mismatch")
    pindex = pd.Index(processes.node_id)
    eindex = pd.Index(entities.node_id)
    source = pindex.get_indexer(edges.source_id)
    is_create = edges.relation.eq("PROCESS_CREATE_PROCESS").to_numpy()
    target = np.empty(len(edges), dtype=np.int64)
    target[is_create] = pindex.get_indexer(edges.loc[is_create, "target_id"])
    target[~is_create] = eindex.get_indexer(edges.loc[~is_create, "target_id"])
    if (source < 0).any() or (target < 0).any():
        raise HubAuditError("Unknown endpoint")
    if not np.array_equal(entities.node_type.to_numpy()[target[~is_create]],
                          edges.loc[~is_create, "target_type"].to_numpy()):
        raise HubAuditError("Entity endpoint type mismatch")
    family, _ = pd.factorize(processes.structure_id, sort=True)
    if not np.array_equal(family[source[is_create]], family[target[is_create]]):
        raise HubAuditError("CREATE edge crosses structure metadata")
    if edges.duplicated(["source_id", "target_id", "relation"]).any():
        raise HubAuditError("Edges must be compact within relation")
    if "event_count" in edges:
        counts = edges.event_count
        if (not pd.api.types.is_integer_dtype(counts) or counts.isna().any()
                or (counts < 1).any() or sum(map(int, counts)) >= 2**63):
            raise HubAuditError("event_count must be positive int64 with safe total")
    links = pd.DataFrame({"process": source[~is_create], "context": target[~is_create],
                          "relation": edges.loc[~is_create, "relation"].to_numpy()})
    links["family"] = family[links.process]
    if "event_count" in edges:
        links["event_count"] = edges.loc[~is_create, "event_count"].to_numpy()
    unique = links[["process", "context", "family"]].drop_duplicates()
    profiles = entities.reset_index(drop=True).copy()
    for name, grouped in (
        ("process_degree", unique.groupby("context").size()),
        ("distinct_family_count", unique.groupby("context").family.nunique()),
        ("compact_edge_count", links.groupby("context").size()),
    ):
        profiles[name] = grouped.reindex(profiles.index, fill_value=0).astype("int64")
    profiles["event_count"] = (links.groupby("context").event_count.sum().reindex(
        profiles.index, fill_value=0).astype("int64") if "event_count" in links else None)
    for metric in ("process_degree", "distinct_family_count"):
        grouped = profiles.groupby("node_type")[metric]
        profiles[f"{metric}_rank_desc_min"] = grouped.rank(method="min", ascending=False).astype(int)
        profiles[f"{metric}_percentile_weak"] = grouped.rank(method="max", pct=True) * 100
    degree = profiles.process_degree.to_numpy()
    families = profiles.distinct_family_count.to_numpy()
    profiles["process_frequency"] = degree / len(processes)
    profiles["distinct_family_frequency"] = families / processes.structure_id.nunique()
    profiles["families_per_process_neighbor"] = np.divide(
        families, degree, out=np.zeros(len(degree), float), where=degree > 0)
    relation_profiles = []
    for relation in FORWARD_RELATIONS[1:]:
        sub = links[links.relation == relation]
        ids = profiles.index[profiles.node_type == relation.split("_")[1]]
        row = profiles.loc[ids, ["node_id", *KEYS]].copy()
        row["relation"] = relation
        row["process_degree"] = sub.groupby("context").process.nunique().reindex(ids, fill_value=0)
        row["distinct_family_count"] = sub.groupby("context").family.nunique().reindex(ids, fill_value=0)
        row["compact_edge_count"] = sub.groupby("context").size().reindex(ids, fill_value=0)
        row["event_count"] = (sub.groupby("context").event_count.sum().reindex(ids, fill_value=0)
                               if "event_count" in sub else None)
        for metric in ("process_degree", "distinct_family_count"):
            row[f"{metric}_rank_desc_min"] = row[metric].rank(method="min", ascending=False).astype(int)
            row[f"{metric}_percentile_weak"] = row[metric].rank(method="max", pct=True) * 100
        relation_profiles.append(row)
    create_records = edges.loc[is_create].sort_values(["source_id", "target_id"])
    create_hash = hashlib.sha256(create_records.to_json(orient="records").encode()).hexdigest()
    return Graph(role, processes, entities, edges, source, target, is_create, family,
                 unique, profiles, pd.concat(relation_profiles, ignore_index=True),
                 create_hash, inventory or {})


def load_graph(folder, role, manifest=None):
    """Read only allowed linkage/identity/count columns; labels never enter RAM."""
    folder = Path(folder)
    inventory = {}
    specs = ({e["name"]: e for e in manifest["publication"][role]["published_files"]
              + manifest["publication"][role]["missing_files"]} if manifest else {})
    for name in INPUTS:
        path = folder / name
        if not path.is_file():
            raise HubAuditError(f"Missing source artifact: {path}")
        item = {"path": str(path.resolve()), "size_bytes": path.stat().st_size, "sha256": digest(path)}
        if specs and (item["sha256"] != specs[name]["sha256"]
                      or item["size_bytes"] != int(specs[name]["size"])):
            raise HubAuditError(f"Source differs from completed run: {path}")
        inventory[name] = item
    audit = json.loads((folder / INPUTS[3]).read_text())
    if audit.get("period_role") != role:
        raise HubAuditError("Source audit period mismatch")
    processes = pd.read_parquet(folder / INPUTS[0], columns=["node_id", "process_id", "structure_id", "period_role"])
    entities = pd.read_parquet(folder / INPUTS[1], columns=["node_id", *KEYS, "period_role"])
    schema = pq.ParquetFile(folder / INPUTS[2]).schema_arrow.names
    columns = ["source_id", "target_id", "source_type", "target_type", "relation", "period_role"]
    if "event_count" in schema:
        columns.append("event_count")
    edges = pd.read_parquet(folder / INPUTS[2], columns=columns)
    if (len(processes) != audit["process_node_count"] or len(entities) != audit["total_entity_node_count"]
            or len(edges) != audit["forward_edge_count"]):
        raise HubAuditError("Input counts disagree with completed graph audit")
    return prepare(processes, entities, edges, role, inventory)


def freeze_policies(train):
    if train.role != "verified_benign":
        raise HubAuditError("Policies must be derived from verified-benign training")
    profiles = train.profiles
    nf = train.processes.structure_id.nunique()
    policies = [{"name": "FULL_SHARED", "category": "A", "metric": None, "cutoffs": {}, "excluded_keys": []}]

    def add(name, category, metric, cutoffs, types=TYPES, derivation=None):
        above = np.zeros(len(profiles), bool)
        for node_type in types:
            above |= (profiles.node_type.eq(node_type) & (profiles[metric] > cutoffs[node_type])).to_numpy()
        policies.append({"name": name, "category": category, "metric": metric, "cutoffs": cutoffs,
                         "comparison": "strictly greater than; cutoff ties retained",
                         "derivation": derivation, "excluded_keys": profiles.loc[above, KEYS].values.tolist()})

    for q in PERCENTILES:
        for metric, prefix, category in (("process_degree", "DEGREE", "B"),
                                          ("distinct_family_count", "FAMILY", "C")):
            cutoffs = {t: float(profiles.loc[profiles.node_type == t, metric].quantile(q / 100))
                       for t in TYPES if (profiles.node_type == t).any()}
            add(f"{prefix}_P{q:g}", category, metric, cutoffs, tuple(cutoffs),
                {"quantile_percent": q, "interpolation": "linear", "scope": "within training node type"})
    for band in FAMILY_BANDS:
        cutoffs = {t: float(nf * band) for t in TYPES}
        add(f"FAMILY_FREQ_GT_{100 * band:g}PCT", "C", "distinct_family_count", cutoffs,
            derivation={"training_family_denominator": int(nf), "frequency": band})
        add(f"MODULE_FAMILY_FREQ_GT_{100 * band:g}PCT", "D", "distinct_family_count",
            {"MODULE": float(nf * band)}, ("MODULE",),
            {"training_family_denominator": int(nf), "frequency": band})
    reference = next(p for p in policies if p["name"] == "FAMILY_FREQ_GT_1PCT")
    keys = {tuple(k) for k in reference["excluded_keys"]}
    excluded = []
    budgets = {}
    boundaries = {}
    for t in TYPES:
        sub = profiles[profiles.node_type == t]
        budget = sum(tuple(k) in keys for k in sub[KEYS].values)
        ranked = sub.sort_values(["process_degree", *KEYS], ascending=[False, True, True, True]).head(budget)
        budgets[t] = budget
        boundaries[t] = int(ranked.process_degree.min()) if budget else None
        excluded.extend(ranked[KEYS].values.tolist())
    policies.append({"name": "DEGREE_MATCHED_FAMILY_1PCT_BUDGET", "category": "B",
                     "metric": "process_degree", "cutoffs": boundaries,
                     "comparison": "Top degree TRAIN identities per type; lexical identity tie-break; exact matched removal budget",
                     "derivation": {"matched_policy": reference["name"], "removed_node_budget_by_type": budgets},
                     "excluded_keys": excluded})
    policies.append({"name": "MODULE_SHARING_OFF_DIAGNOSTIC", "category": "D",
                     "metric": "node_type", "cutoffs": {}, "diagnostic_only": True,
                     "exclude_node_types": ["MODULE"], "excluded_keys": []})
    policies.append({"name": "CREATE_ONLY_DIAGNOSTIC", "category": "A",
                     "metric": "node_type", "cutoffs": {}, "diagnostic_only": True,
                     "exclude_node_types": list(TYPES), "excluded_keys": []})
    for kind in ("degree", "family", "geometric"):
        policies.append({"name": f"WEIGHTED_FULL_{kind.upper()}", "category": "E",
                         "metric": None, "cutoffs": {}, "excluded_keys": [], "weight": kind})
    weights = profiles[KEYS + ["process_degree", "distinct_family_count"]].copy()
    weights["weight_degree"] = np.log((len(train.processes) + 1) / (weights.process_degree + 1)) / np.log(len(train.processes) + 1)
    weights["weight_family"] = np.log((nf + 1) / (weights.distinct_family_count + 1)) / np.log(nf + 1)
    weights["weight_geometric"] = np.sqrt(weights.weight_degree * weights.weight_family)
    return {"schema_version": VERSION, "derived_from_period": train.role,
            "training_process_count": len(train.processes), "training_family_count": int(nf),
            "training_input_inventory": train.input_inventory,
            "identity_columns": KEYS, "unseen_evaluation_identity": "retain; each weight = 1",
            "application": "Frozen TRAIN identity exclusion lists and TRAIN weights; no evaluation re-ranking/refitting. Type-off diagnostics use fixed node-type rules including unseen evaluation identities",
            "weight_formula": "log((TRAIN universe + 1)/(TRAIN frequency + 1))/log(TRAIN universe + 1); geometric=sqrt(degree*family)",
            "policies": policies}, weights


def policy_mask(graph, policy):
    forbidden = {tuple(key) for key in policy["excluded_keys"]}
    types_off = set(policy.get("exclude_node_types", []))
    return np.array([tuple(key) not in forbidden and key[0] not in types_off
                     for key in graph.entities[KEYS].values], dtype=bool)


def joined_weights(graph, weights):
    reference = weights.rename(columns={"process_degree": "training_process_degree",
                                       "distinct_family_count": "training_distinct_family_count"})
    result = graph.entities[["node_id", *KEYS]].merge(reference, on=KEYS, how="left", validate="one_to_one", sort=False)
    result["seen_in_training"] = result.training_process_degree.notna()
    for column in ("weight_degree", "weight_family", "weight_geometric"):
        result[column] = result[column].fillna(1.0)
    return result


def adjacency(graph, retained):
    n = len(graph.processes)
    mask = graph.is_create.copy()
    mask[~graph.is_create] = retained[graph.target[~graph.is_create]]
    s = graph.source[mask]
    t = graph.target[mask].copy()
    t[~graph.is_create[mask]] += n
    # Preserve every compact CREATE row in counts; unique symmetric adjacency
    # for WCC/exposure ignores self loops and duplicate undirected neighbors.
    adj = csr_matrix((np.ones(len(s) * 2, bool), (np.r_[s, t], np.r_[t, s])),
                     shape=(n + len(graph.entities),) * 2, dtype=bool)
    adj.setdiag(False)
    adj.eliminate_zeros()
    return adj, mask


def deterministic_sample(graph, sample_size):
    scores = [hashlib.sha256(f"{VERSION}|{p}".encode()).digest() for p in graph.processes.process_id]
    return np.array(sorted(range(len(scores)), key=lambda i: scores[i])[:sample_size], dtype=int)


def neighborhood_stats(adj, process_count, sample):
    one = np.diff(adj.indptr)[:process_count]
    seed = adj[sample]
    reach = (seed @ adj).maximum(seed).tolil()
    for row, index in enumerate(sample):
        reach[row, index] = False
    reach = reach.tocsr()
    reach.eliminate_zeros()
    return {"definition": "Unique nodes at undirected distance <= radius, excluding self, including CREATE; not relation/event multiplicity",
            "one_hop_all_processes": summary(one),
            "two_hop_sample_size": len(sample),
            "two_hop_sampled_all_node_count": summary(np.diff(reach.indptr)),
            "two_hop_sampled_process_count": summary(np.asarray(reach[:, :process_count].getnnz(axis=1))),
            "two_hop_method": "Deterministic SHA256 process_id sample, exact per seed; sampled quantiles are NOT population quantiles"}


def topology(graph, retained, sample):
    adj, edge_mask = adjacency(graph, retained)
    active = np.r_[np.ones(len(graph.processes), bool), retained]
    _, labels = connected_components(adj[active][:, active], directed=False)
    process_count = len(graph.processes)
    sizes = np.bincount(labels)
    pc = np.bincount(labels[:process_count], minlength=len(sizes))
    largest = max(range(len(sizes)), key=lambda i: (sizes[i], pc[i], -i))
    profiles = graph.profiles.loc[retained]
    shared = graph.incidence[retained[graph.incidence.context]].groupby("context").family.nunique()
    shared_ids = shared[shared > 1].index
    bridged = graph.incidence.loc[graph.incidence.context.isin(shared_ids), "family"].nunique()
    types = {t: int((profiles.node_type == t).sum()) for t in TYPES}
    percent = {t: (100 * types[t] / int((graph.entities.node_type == t).sum())
                    if (graph.entities.node_type == t).any() else None) for t in TYPES}
    behavior = ~graph.is_create
    relation_counts = {r: int((edge_mask & graph.edges.relation.eq(r).to_numpy()).sum()) for r in FORWARD_RELATIONS}
    return {
        "process_count": process_count, "retained_context_counts": types,
        "retained_forward_edge_count": int(edge_mask.sum()),
        "retained_context_edge_count": int((edge_mask & behavior).sum()),
        "retained_context_event_count": (int(graph.edges.loc[edge_mask & behavior, "event_count"].sum())
                                           if "event_count" in graph.edges else None),
        "create_edge_count": int(graph.is_create.sum()), "create_topology_sha256": graph.create_hash,
        "create_topology_unchanged": bool(edge_mask[graph.is_create].all()),
        "weakly_connected_component_count": len(sizes),
        "largest_component_process_count": int(pc[largest]),
        "largest_process_component_count": int(pc.max()),
        "largest_component_process_percent": 100 * float(pc[largest]) / process_count,
        "shared_context_count": int((shared > 1).sum()),
        "retained_distinct_family_context_incidence_count": int(shared.sum()),
        "retained_cross_family_incidence_count": int(shared[shared > 1].sum()),
        "create_families_bridged_by_shared_context": int(bridged),
        "context_degree": summary(profiles.process_degree),
        "retained_context_edges_percent": 100 * int((edge_mask & behavior).sum()) / int(behavior.sum()) if behavior.any() else 100.0,
        "retained_context_nodes_percent_by_type": percent,
        "relation_edge_counts": relation_counts,
        "top_remaining_hubs": {t: profiles.loc[profiles.node_type == t].sort_values(
            ["process_degree", "node_id"], ascending=[False, True]).head(10)[
                ["node_id", *KEYS, "process_degree", "distinct_family_count", "event_count"]].to_dict("records") for t in TYPES},
        "neighborhoods": neighborhood_stats(adj, process_count, sample),
    }


def distribution_report(profiles, grouping):
    result = {}
    for key, sub in profiles.groupby(grouping, sort=True):
        active = sub[sub.process_degree > 0]
        corr = active[["process_degree", "distinct_family_count"]].corr(method="spearman").iloc[0, 1] if len(active) > 1 else np.nan
        bands = []
        for low, high in ((0, 1), (1, 10), (10, 100), (100, 1000), (1000, float("inf"))):
            band = active[(active.process_degree > low) & (active.process_degree <= high)]
            if len(band):
                bands.append({"degree_gt": low, "degree_le": high if np.isfinite(high) else None,
                              "family_count": summary(band.distinct_family_count),
                              "families_per_process_neighbor": summary(band.distinct_family_count / band.process_degree)})
        result[str(key)] = {"universe_context_count": len(sub), "active_context_count": len(active),
                            "degree": summary(sub.process_degree), "family_count": summary(sub.distinct_family_count),
                            "event_count": summary(sub.event_count.dropna()),
                            "degree_family_spearman": float(corr) if np.isfinite(corr) else None,
                            "degree_to_family_bands": bands,
                            "top_by_degree": sub.sort_values(["process_degree", "node_id"], ascending=[False, True]).head(10).to_dict("records"),
                            "top_by_family": sub.sort_values(["distinct_family_count", "node_id"], ascending=[False, True]).head(10).to_dict("records")}
    return result


def weight_exposure(graph, weights, kind):
    w = weights[f"weight_{kind}"].to_numpy()
    unique = graph.incidence
    exposure = np.bincount(unique.process, weights=w[unique.context], minlength=len(graph.processes))
    degree = graph.profiles.process_degree.to_numpy()
    mass = degree * w
    top = np.argsort(-degree, kind="stable")[:max(1, int(np.ceil(len(degree) * 0.01)))]
    return {"training_derived_weight_kind": kind, "weights": summary(w),
            "seen_in_training_context_count": int(weights.seen_in_training.sum()),
            "unseen_context_count": int((~weights.seen_in_training).sum()),
            "weighted_unique_context_neighbor_exposure_per_process": summary(exposure),
            "raw_top_one_percent_context_incidence_mass_share_percent": 100 * float(degree[top].sum()) / degree.sum() if degree.sum() else 0.0,
            "weighted_same_top_one_percent_incidence_mass_share_percent": 100 * float(mass[top].sum()) / mass.sum() if mass.sum() else 0.0,
            "weighted_context_incidence_mass_percent_of_full": 100 * float(mass.sum()) / degree.sum() if degree.sum() else 0.0,
            "interpretation": "Static weighted incidence proxy, NOT learned messages or effective RGCN neighborhood; CREATE weights stay 1; weighted topology equals FULL_SHARED"}


def analyze_period(graph, policies, weights, output, sample_size):
    sample = deterministic_sample(graph, sample_size)
    mask_table = graph.entities[["node_id", *KEYS]].copy()
    variants = []
    full = None
    for policy in policies["policies"]:
        print(f"{graph.role}: {policy['name']}", flush=True)
        retained = policy_mask(graph, policy)
        mask_table[policy["name"]] = retained
        if policy.get("weight"):
            metrics = dict(full)
            metrics["weight_exposure"] = weight_exposure(graph, weights, policy["weight"])
        else:
            metrics = topology(graph, retained, sample)
        if policy["name"] == "FULL_SHARED":
            full = metrics
        variants.append({"policy": policy["name"], "category": policy["category"], **metrics})
    graph.profiles.to_parquet(output / f"{graph.role}_context_profiles.parquet", index=False)
    graph.relation_profiles.to_parquet(output / f"{graph.role}_relation_context_profiles.parquet", index=False)
    mask_table.to_parquet(output / f"{graph.role}_context_masks.parquet", index=False)
    weights.to_parquet(output / f"{graph.role}_weight_candidates.parquet", index=False)
    json_write(output / f"{graph.role}_distributions.json", {
        "node_type": distribution_report(graph.profiles, "node_type"),
        "relation": distribution_report(graph.relation_profiles, "relation"),
        "relation_universe": "All entities of the relation's node type; unused entities have degree/family count zero"})
    json_write(output / f"{graph.role}_variants.json", variants)
    return variants


def run_audit(train_dir, evaluation_dir, output_dir, manifest_path=None, sample_size=64):
    started = time.monotonic()
    audit_source_hash = digest(Path(__file__))
    train_dir, evaluation_dir, output = map(Path, (train_dir, evaluation_dir, output_dir))
    if not 1 <= sample_size <= 128:
        raise HubAuditError("sample_size must be 1..128; prevents quadratic neighborhood expansion")
    for source in (train_dir.resolve(), evaluation_dir.resolve()):
        if source == output.resolve() or source in output.resolve().parents or output.resolve() in source.parents:
            raise HubAuditError("Output must be separate from both source graph trees")
    if output.exists() or output.is_symlink():
        raise HubAuditError("Refusing existing output directory")
    manifest = json.loads(Path(manifest_path).read_text()) if manifest_path else None
    train = load_graph(train_dir, "verified_benign", manifest)
    frozen, weight_reference = freeze_policies(train)
    output.mkdir(parents=True, exist_ok=False)
    json_write(output / "frozen_training_policies.json", frozen)
    weight_reference.to_parquet(output / "frozen_training_weights.parquet", index=False)
    policy_hash = digest(output / "frozen_training_policies.json")
    weight_hash = digest(output / "frozen_training_weights.parquet")
    train_variants = analyze_period(train, frozen, joined_weights(train, weight_reference), output, sample_size)
    # Evaluation is not opened until TRAIN profiles, thresholds, masks and
    # weight references have been finalized. No ground-truth paths are accepted.
    evaluation = load_graph(evaluation_dir, "evaluation", manifest)
    eval_variants = analyze_period(evaluation, frozen, joined_weights(evaluation, weight_reference), output, sample_size)
    inventories = {g.role: g.input_inventory for g in (train, evaluation)}
    for inventory in inventories.values():
        for info in inventory.values():
            if digest(info["path"]) != info["sha256"]:
                raise HubAuditError("Source changed during audit; results must not be treated as complete")
    if policy_hash != digest(output / "frozen_training_policies.json") or weight_hash != digest(output / "frozen_training_weights.parquet"):
        raise HubAuditError("Frozen training policy/weights changed")
    if audit_source_hash != digest(Path(__file__)):
        raise HubAuditError("Audit source changed during execution; rerun with fixed code")
    report = {"schema_version": VERSION, "status": "COMPLETE", "timestamp_utc": datetime.now(timezone.utc).isoformat(),
              "input_inventory": inventories, "frozen_policy_sha256": policy_hash,
              "frozen_weights_sha256": weight_hash, "evaluation_ground_truth_read": False,
              "model_training_performed": False, "source_graphs_modified": False,
              "elapsed_seconds": time.monotonic() - started, "two_hop_sample_size": sample_size,
              "audit_source_sha256": audit_source_hash,
              "policy_selection": "No automatic winner; training-only tradeoff comparison; evaluation is topology reporting only",
              "create_topology_unchanged_all_variants": all(v["create_topology_unchanged"] for v in train_variants + eval_variants),
              "process_counts_unchanged_all_variants": all(v["process_count"] == len(g.processes) for g, vs in ((train, train_variants), (evaluation, eval_variants)) for v in vs),
              "variants": {"verified_benign": train_variants, "evaluation": eval_variants}}
    try:
        report["git_head"] = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except subprocess.CalledProcessError:
        report["git_head"] = None
    json_write(output / "hub_control_audit.json", report)
    rows = []
    for role, variants in report["variants"].items():
        for v in variants:
            rows.append({"period_role": role, "policy": v["policy"], "process_count": v["process_count"],
                         "forward_edges": v["retained_forward_edge_count"], "context_edges_retained_pct": v["retained_context_edges_percent"],
                         "wcc": v["weakly_connected_component_count"], "largest_process_count": v["largest_component_process_count"],
                         "largest_process_pct": v["largest_component_process_percent"],
                         "bridged_families": v["create_families_bridged_by_shared_context"],
                         "context_max_degree": v["context_degree"]["maximum"], "context_p95_degree": v["context_degree"]["p95"],
                         "context_p99_degree": v["context_degree"]["p99"],
                         **{f"retained_{t.lower()}_nodes": v["retained_context_counts"][t] for t in TYPES},
                         **{f"retained_{t.lower()}_pct": v["retained_context_nodes_percent_by_type"][t] for t in TYPES}})
    pd.DataFrame(rows).to_csv(output / "variant_comparison.csv", index=False)
    json_write(output / "audit_output_manifest.json", {p.name: {"size_bytes": p.stat().st_size, "sha256": digest(p)} for p in sorted(output.iterdir())})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train-dir", type=Path, required=True)
    parser.add_argument("--evaluation-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--real-run-manifest", type=Path)
    parser.add_argument("--two-hop-sample-size", type=int, default=64)
    args = parser.parse_args()
    report = run_audit(args.train_dir, args.evaluation_dir, args.output_dir, args.real_run_manifest, args.two_hop_sample_size)
    print(f"{report['status']}: topology audit only; sources unchanged; no labels/models")


if __name__ == "__main__":
    main()
