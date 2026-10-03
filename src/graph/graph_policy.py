"""Frozen TRAIN-only context policies for the period heterogeneous graph.

The evidence graph is never rewritten. A view annotates streamed edge batches
with keep_edge / edge_weight; callers must honor keep_edge independently of
weight (a universal TRAIN context can have weight zero without being deleted).
Identity transfer uses the exact (node_type, host_scope, canonical_key) tuple.
Evaluation must load a serialized bundle, never fit one. Unseen contexts are
retained with weight 1, with no suspicious/malicious interpretation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from src.eda import audit_hybrid_graph_hubs as hub
from src.eda.build_period_heterogeneous_graph import (
    EDGE_COLUMNS, FORWARD_RELATIONS, RELATION_IDS, _digest,
)

SCHEMA_VERSION = "frozen_context_policy_bundle_v1"
POLICY_VERSION = "hybrid_context_policy_v1"
POLICY_NAMES = ("FULL_SHARED", "MODULE_FAMILY_FREQ_1PCT",
                "ALL_TYPE_FAMILY_FREQ_5PCT", "DEGREE_WEIGHTED_FULL")
STAT_COLUMNS = [*hub.KEYS, "training_process_degree", "training_distinct_family_count"]
STAT_FILE = "context_statistics.parquet"
WEIGHT_FORMULA = "log((N_process_train + 1)/(degree_train + 1))/log(N_process_train + 1)"


class PolicyError(ValueError):
    """Reject incompatible periods, changed bundles, or invalid edge contracts."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def process_signature(graph):
    """Bind the TRAIN universe including family metadata; never inspect features."""
    columns = ["node_id", "process_id", "structure_id", "period_role"]
    records = graph.processes[columns].sort_values("node_id").values.tolist()
    return hashlib.sha256(canonical(records).encode()).hexdigest()


def source_identity(inventory):
    """Bind bytes, not machine-specific paths: bundles can move to Colab."""
    return {name: {"size_bytes": item["size_bytes"], "sha256": item["sha256"]}
            for name, item in inventory.items()}


def definitions(n_process, n_family):
    """No user/evaluation-derived tunables: the audited four-policy contract."""
    policies = {}
    for name in POLICY_NAMES:
        percentage = 1 if name == "MODULE_FAMILY_FREQ_1PCT" else 5
        filtered_types = (("MODULE",) if name == "MODULE_FAMILY_FREQ_1PCT" else
                          hub.TYPES if name == "ALL_TYPE_FAMILY_FREQ_5PCT" else ())
        policies[name] = {
            "name": name, "policy_version": POLICY_VERSION,
            "statistic": ("training_distinct_family_count" if filtered_types else
                          "training_process_degree" if name == "DEGREE_WEIGHTED_FULL" else None),
            "threshold_definition": ("TRAIN family_count * 100 > TRAIN family_population * percent; ties retained"
                                     if filtered_types else None),
            "family_frequency_percent": percentage if filtered_types else None,
            "per_node_type_thresholds": {
                t: n_family * (percentage / 100) if t in filtered_types else None
                for t in hub.TYPES},
            "weight_formula": WEIGHT_FORMULA if name == "DEGREE_WEIGHTED_FULL" else "1 for retained, 0 for excluded",
            "weight_parameters": {"N_process_train": n_process} if name == "DEGREE_WEIGHTED_FULL" else {},
            "create_edge_rule": "retain, weight 1 in both directions",
        }
    return policies


def statistics_rows(graph):
    return tuple(sorted((str(t), str(h), str(k), int(d), int(f)) for t, h, k, d, f in
                        graph.profiles[hub.KEYS + ["process_degree", "distinct_family_count"]].itertuples(index=False, name=None)))


def check_period(graph):
    if graph.role not in ("verified_benign", "evaluation"):
        raise PolicyError("Only separate explicit train/evaluation periods are accepted")
    for frame in (graph.processes, graph.entities, graph.edges):
        if "period_role" not in frame or not frame.period_role.eq(graph.role).all():
            raise PolicyError("Period isolation violated")


@dataclass(frozen=True)
class FrozenPolicies:
    """Immutable JSON header + immutable TRAIN statistics, not evaluation state."""

    header_json: str
    rows: tuple
    loaded_from_disk: bool = field(default=False, repr=False, compare=False)
    fingerprint: str = field(init=False)

    def __post_init__(self):
        meta = json.loads(self.header_json)
        n, nf = meta["training_process_count"], meta["training_family_count"]
        if (type(n) is not int or type(nf) is not int or not 1 <= nf <= n
                or meta["schema_version"] != SCHEMA_VERSION
                or meta["derived_from_period"] != "verified_benign"
                or meta["identity_columns"] != hub.KEYS
                or meta["unseen_entity_rule"] != {"keep_context": True, "edge_weight": 1.0}
                or meta["policies"] != definitions(n, nf)):
            raise PolicyError("Invalid frozen TRAIN population/definitions/version")
        if not isinstance(self.rows, tuple) or any(not isinstance(r, tuple) or len(r) != 5 for r in self.rows):
            raise PolicyError("TRAIN statistics must be immutable rows")
        keys = set()
        counts = dict.fromkeys(hub.TYPES, 0)
        for t, h, k, d, f in self.rows:
            if (t not in hub.TYPES or not isinstance(h, str) or not isinstance(k, str) or not k.strip()
                    or type(d) is not int or type(f) is not int
                    or not 0 <= f <= min(d, nf) or not 0 <= d <= n or (d == 0) != (f == 0)
                    or (t, h, k) in keys):
                raise PolicyError("Invalid/duplicate TRAIN identity or degree/family statistic")
            keys.add((t, h, k))
            counts[t] += 1
        if (counts != meta["training_context_counts"] or len(self.rows) != meta["training_context_count"]
                or tuple(sorted(self.rows)) != self.rows):
            raise PolicyError("TRAIN statistics/population/order mismatch")
        payload = canonical({"metadata": meta, "statistics": self.rows}).encode()
        object.__setattr__(self, "fingerprint", hashlib.sha256(payload).hexdigest())

    @property
    def metadata(self):
        return json.loads(self.header_json)  # Defensive copy, not mutable fit state.

    def statistics(self):
        table = pd.DataFrame(self.rows, columns=STAT_COLUMNS).astype(
            {"training_process_degree": "int64", "training_distinct_family_count": "int64"})
        n = self.metadata["training_process_count"]
        table["degree_weight"] = np.log((n + 1) / (table.training_process_degree.astype(float) + 1)) / np.log(n + 1)
        return table

    def save(self, folder):
        """Fresh sidecar directory only; source trees are guarded by the runner."""
        folder = Path(folder)
        if folder.exists() or folder.is_symlink():
            raise PolicyError("Refusing existing policy output")
        folder.mkdir(parents=True, exist_ok=False)
        self.statistics().to_parquet(folder / STAT_FILE, index=False)
        document = {"metadata": self.metadata, "fingerprint": self.fingerprint,
                    "statistics_file": STAT_FILE,
                    "statistics_sha256": hub.digest(folder / STAT_FILE)}
        hub.json_write(folder / "policy_bundle.json", document)

    @classmethod
    def load(cls, folder):
        folder = Path(folder)
        try:
            doc = json.loads((folder / "policy_bundle.json").read_text())
            if (doc["statistics_file"] != STAT_FILE or
                    hub.digest(folder / STAT_FILE) != doc["statistics_sha256"]):
                raise PolicyError("Frozen statistics filename/hash mismatch")
            table = pd.read_parquet(folder / STAT_FILE, columns=STAT_COLUMNS + ["degree_weight"])
            for column in STAT_COLUMNS[-2:]:
                if not pd.api.types.is_integer_dtype(table[column]):
                    raise PolicyError("Frozen counts must be integers")
            rows = tuple(tuple(r) for r in table[STAT_COLUMNS].itertuples(index=False, name=None))
            bundle = cls(canonical(doc["metadata"]), rows, loaded_from_disk=True)
            if bundle.fingerprint != doc["fingerprint"]:
                raise PolicyError("Frozen policy fingerprint mismatch")
            if not np.array_equal(table.degree_weight.to_numpy(), bundle.statistics().degree_weight.to_numpy()):
                raise PolicyError("Frozen weight/formula mismatch")
            return bundle
        except (KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
            raise PolicyError(f"Invalid policy bundle: {exc}") from exc

    def view(self, graph, name):
        check_period(graph)
        if name not in POLICY_NAMES:
            raise PolicyError("Unknown policy name")
        if graph.role == "evaluation" and not self.loaded_from_disk:
            raise PolicyError("Evaluation must load the serialized TRAIN bundle")
        meta = self.metadata
        if graph.role == "verified_benign":
            if (process_signature(graph) != meta["training_process_signature"]
                    or graph.create_hash != meta["training_create_sha256"]
                    or statistics_rows(graph) != self.rows
                    or source_identity(graph.input_inventory) != source_identity(meta["training_source_inventory"])):
                raise PolicyError("TRAIN graph differs from the frozen fit")
        return PolicyView(graph, self, name)


def freeze_training(graph):
    """Fit only a validated verified-benign Graph; no evaluation argument exists."""
    check_period(graph)
    if graph.role != "verified_benign":
        raise PolicyError("Policies must originate from verified-benign training only")
    n, nf = len(graph.processes), int(graph.processes.structure_id.nunique())
    metadata = {
        "schema_version": SCHEMA_VERSION, "policy_version": POLICY_VERSION,
        "derived_from_period": graph.role, "training_process_count": n,
        "training_family_count": nf, "training_context_count": len(graph.entities),
        "training_context_counts": {t: int(graph.entities.node_type.eq(t).sum()) for t in hub.TYPES},
        "training_forward_edge_count": len(graph.edges),
        "training_create_edge_count": int(graph.is_create.sum()),
        "training_process_signature": process_signature(graph), "training_create_sha256": graph.create_hash,
        "training_source_inventory": graph.input_inventory, "identity_columns": hub.KEYS,
        "unseen_entity_rule": {"keep_context": True, "edge_weight": 1.0},
        "evaluation_contract": "Exact TRAIN identities/statistics; no evaluation refitting or labels",
        "raw_topology_contract": "Full evidence remains unchanged; keep_edge is independent of edge_weight",
        "policies": definitions(n, nf),
    }
    return FrozenPolicies(canonical(metadata), statistics_rows(graph))


class PolicyView:
    """Period-specific lightweight context decisions + streamed edge annotation.

    All PROCESS nodes (including isolated ones) are retained. Consumers use the
    original PROCESS table and this view, not a reconstructed node universe.
    """

    def __init__(self, graph, bundle, name):
        self.graph, self.bundle, self.name = graph, bundle, name
        table = graph.entities[["node_id", *hub.KEYS, "period_role"]].merge(
            bundle.statistics(), how="left", on=hub.KEYS, validate="one_to_one", sort=False)
        seen = table.training_process_degree.notna().to_numpy()
        keep = np.ones(len(table), bool)
        if name in ("MODULE_FAMILY_FREQ_1PCT", "ALL_TYPE_FAMILY_FREQ_5PCT"):
            percentage = 1 if name == "MODULE_FAMILY_FREQ_1PCT" else 5
            controlled = table.node_type.eq("MODULE").to_numpy() if percentage == 1 else np.ones(len(table), bool)
            # Integer arithmetic makes strictly-greater/tie handling explicit.
            families = table.training_distinct_family_count.fillna(0).to_numpy(dtype=np.int64)
            keep &= ~(seen & controlled & (families * 100 > bundle.metadata["training_family_count"] * percentage))
        weight = table.degree_weight.fillna(1.0).to_numpy() if name == "DEGREE_WEIGHTED_FULL" else keep.astype(float)
        self._decisions = table.assign(seen_in_training=seen, keep_context=keep, edge_weight=weight,
                                       policy_name=name, policy_version=POLICY_VERSION,
                                       policy_fingerprint=bundle.fingerprint)
        self._process_index = pd.Index(graph.processes.node_id)
        self._context_index = pd.Index(table.node_id)
        self._context_types = table.node_type.to_numpy()
        self._keep = keep
        self._weight = weight
        self._families = graph.processes.structure_id.to_numpy()

    @property
    def contexts(self):
        return self._decisions.copy(deep=True)

    @property
    def process_keep(self):
        return np.ones(len(self._process_index), bool)

    @property
    def context_keep(self):
        return self._keep.copy()

    def annotate_edges(self, frame):
        """Allowlisted raw edges plus decisions, for either forward or REV__ rows."""
        hub.require(frame, EDGE_COLUMNS, "policy edges")
        if not frame.period_role.eq(self.graph.role).all():
            raise PolicyError("Edge batch period isolation violated")
        if (not frame.relation.isin(RELATION_IDS).all() or
                not pd.api.types.is_integer_dtype(frame.relation_id) or
                not frame.relation_id.equals(frame.relation.map(RELATION_IDS).astype(frame.relation_id.dtype))):
            raise PolicyError("Unknown/mismatched relation ID")
        if (not pd.api.types.is_integer_dtype(frame.event_count) or frame.event_count.lt(1).any()
                or not frame.edge_id.map(lambda v: isinstance(v, str) and bool(v.strip())).all()):
            raise PolicyError("Invalid edge identifier/event count")
        reverse = frame.relation.str.startswith("REV__").to_numpy()
        base = frame.relation.str.removeprefix("REV__")
        create = base.eq(FORWARD_RELATIONS[0]).to_numpy()
        expected_type = base.map({r: "PROCESS" if i == 0 else r.split("_")[1]
                                  for i, r in enumerate(FORWARD_RELATIONS)}).to_numpy()
        if (not np.array_equal(frame.source_type.to_numpy(), np.where(reverse, expected_type, "PROCESS")) or
                not np.array_equal(frame.target_type.to_numpy(), np.where(reverse, "PROCESS", expected_type))):
            raise PolicyError("Relation endpoint type mismatch")
        process_ids = np.where(reverse, frame.target_id, frame.source_id)
        other_ids = np.where(reverse, frame.source_id, frame.target_id)
        process_index = self._process_index.get_indexer(process_ids)
        if (process_index < 0).any():
            raise PolicyError("Unknown PROCESS endpoint")
        create_target = self._process_index.get_indexer(other_ids[create])
        context_index = self._context_index.get_indexer(other_ids[~create])
        if (create_target < 0).any() or (context_index < 0).any():
            raise PolicyError("Unknown target/context endpoint")
        if not np.array_equal(self._families[process_index[create]], self._families[create_target]):
            raise PolicyError("CREATE crosses frozen structure metadata")
        if not np.array_equal(self._context_types[context_index], expected_type[~create]):
            raise PolicyError("Context identity/type mismatch")
        keep, weight = np.ones(len(frame), bool), np.ones(len(frame), float)
        keep[~create], weight[~create] = self._keep[context_index], self._weight[context_index]
        return frame[EDGE_COLUMNS].copy().assign(
            keep_edge=keep, edge_weight=weight, policy_name=self.name,
            policy_version=POLICY_VERSION, policy_fingerprint=self.bundle.fingerprint)

    def iter_edge_batches(self, path, batch_size=50000):
        """Do not materialize duplicate edge Parquets or read label columns."""
        if not 1 <= batch_size <= 1000000:
            raise PolicyError("batch_size must be 1..1000000")
        parquet = pq.ParquetFile(path)
        if set(EDGE_COLUMNS) - set(parquet.schema_arrow.names):
            raise PolicyError("Incomplete edge Parquet contract")
        for batch in parquet.iter_batches(batch_size=batch_size, columns=EDGE_COLUMNS):
            yield self.annotate_edges(batch.to_pandas())

    def mirror_forward(self, frame):
        """Use the original builder's deterministic REV__ IDs; no graph rebuild."""
        forward = self.annotate_edges(frame)
        if not forward.relation.isin(FORWARD_RELATIONS).all():
            raise PolicyError("mirror_forward accepts forward rows only")
        reverse = forward[EDGE_COLUMNS].copy()
        reverse[["source_id", "target_id"]] = forward[["target_id", "source_id"]].to_numpy()
        reverse[["source_type", "target_type"]] = forward[["target_type", "source_type"]].to_numpy()
        reverse["relation"] = "REV__" + forward.relation
        reverse["relation_id"] = reverse.relation.map(RELATION_IDS).astype("int64")
        reverse["edge_id"] = [_digest("edge_", [role, rel, s, t]) for role, rel, s, t in
                              reverse[["period_role", "relation", "source_id", "target_id"]].itertuples(index=False, name=None)]
        annotated = self.annotate_edges(reverse)
        if (not np.array_equal(forward.keep_edge, annotated.keep_edge) or
                not np.array_equal(forward.edge_weight, annotated.edge_weight)):
            raise PolicyError("Forward/reverse policy parity failed")
        return annotated
