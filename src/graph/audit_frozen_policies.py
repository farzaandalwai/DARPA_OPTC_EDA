"""Reconcile frozen policy views with a completed hub audit; never build graphs.

Writes one compact context-decision table per period (four mask/weight columns),
a frozen TRAIN bundle and a metadata-only verification report. Edge decisions
are streamed for validation, not saved as duplicate graph artifacts.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from src.eda import audit_hybrid_graph_hubs as hub
from src.eda.build_period_heterogeneous_graph import FORWARD_RELATIONS, RELATION_IDS
from .graph_policy import FrozenPolicies, POLICY_NAMES, PolicyError, freeze_training

PREVIOUS_NAMES = dict(zip(POLICY_NAMES, ("FULL_SHARED", "MODULE_FAMILY_FREQ_GT_1PCT",
                                       "FAMILY_FREQ_GT_5PCT", "WEIGHTED_FULL_DEGREE")))
SOURCE_FILES = (*hub.INPUTS, "hetero_graph_edges_bidirectional.parquet", "relation_type_mapping.csv")


def guard_output(output, *sources):
    output = Path(output).resolve()
    for source in sources:
        source = Path(source).resolve()
        if output == source or source in output.parents or output in source.parents:
            raise PolicyError("Output must be separate from every source/audit tree")
    if output.exists():
        raise PolicyError("Refusing existing output directory")


def snapshot(folder, role, manifest):
    expected = {s["name"]: s for s in manifest["publication"][role]["published_files"]
                + manifest["publication"][role]["missing_files"]}
    result = {}
    for name in SOURCE_FILES:
        path = Path(folder) / name
        item = {"path": str(path.resolve()), "size_bytes": path.stat().st_size,
                "sha256": hub.digest(path)}
        if item["size_bytes"] != int(expected[name]["size"]) or item["sha256"] != expected[name]["sha256"]:
            raise PolicyError(f"Source no longer matches the completed run: {path}")
        if path.suffix == ".parquet":
            item["row_count"] = pq.ParquetFile(path).metadata.num_rows
        result[name] = item
    mapping = pd.read_csv(Path(folder) / "relation_type_mapping.csv")
    if dict(zip(mapping.relation, mapping.relation_id)) != RELATION_IDS:
        raise PolicyError("Source relation mapping differs from builder contract")
    return result


def reconcile(actual, expected, location="metrics"):
    """Check every existing summary field, not just a hand-picked edge count."""
    if isinstance(expected, dict):
        for key, value in expected.items():
            if key not in ("policy", "category", "top_remaining_hubs"):
                if key not in actual:
                    raise PolicyError(f"Reconciliation missing field: {location}.{key}")
                reconcile(actual[key], value, f"{location}.{key}")
    elif isinstance(expected, float):
        if actual is None or not np.isclose(actual, expected, rtol=1e-12, atol=1e-12):
            raise PolicyError(f"Reconciliation mismatch: {location}: {actual} != {expected}")
    elif actual != expected:
        raise PolicyError(f"Reconciliation mismatch: {location}: {actual} != {expected}")


def stream_verify(view, path):
    """Check actual bidirectional bytes with all 20 relations, events and weights."""
    totals = {r: {"rows": 0, "retained_rows": 0, "retained_events": 0, "weight_sum": 0.0}
              for r in RELATION_IDS}
    for batch in view.iter_edge_batches(path, batch_size=100000):
        for relation, sub in batch.groupby("relation", sort=False):
            kept = sub[sub.keep_edge]
            row = totals[relation]
            row["rows"] += len(sub)
            row["retained_rows"] += len(kept)
            row["retained_events"] += int(kept.event_count.sum())
            row["weight_sum"] += float(kept.edge_weight.sum())
    g = view.graph
    keep = g.is_create.copy()
    keep[~g.is_create] = view.context_keep[g.target[~g.is_create]]
    weights = np.ones(len(g.edges), float)
    weights[~g.is_create] = view.contexts.edge_weight.to_numpy()[g.target[~g.is_create]]
    for relation in FORWARD_RELATIONS:
        selected = g.edges.relation.eq(relation).to_numpy()
        wanted = {"rows": int(selected.sum()), "retained_rows": int((selected & keep).sum()),
                  "retained_events": int(g.edges.loc[selected & keep, "event_count"].sum()),
                  "weight_sum": float(weights[selected & keep].sum())}
        reconcile(totals[relation], wanted, relation)
        reconcile(totals["REV__" + relation], wanted, "REV__" + relation)
    return {"forward_rows": sum(totals[r]["rows"] for r in FORWARD_RELATIONS),
            "retained_forward_rows": int(keep.sum()), "retained_bidirectional_rows": 2 * int(keep.sum()),
            "all_20_relation_counts_events_weights_reconciled": True,
            "create_rows_retained_both_directions": 2 * int(g.is_create.sum()),
            "per_relation": totals}


def run(train_dir, evaluation_dir, output_dir, manifest_path, previous_audit_path):
    guard_output(output_dir, train_dir, evaluation_dir, Path(previous_audit_path).parent)
    output = Path(output_dir)
    manifest = json.loads(Path(manifest_path).read_text())
    previous = json.loads(Path(previous_audit_path).read_text())
    if previous["status"] != "COMPLETE" or not 1 <= previous["two_hop_sample_size"] <= 128:
        raise PolicyError("Require a completed hub audit with the original sample size")
    audit_hash = hub.digest(previous_audit_path)
    source_hashes = {str(Path(__file__).resolve()): hub.digest(__file__),
                     str(Path(__file__).with_name("graph_policy.py").resolve()): hub.digest(Path(__file__).with_name("graph_policy.py"))}
    before_train = snapshot(train_dir, "verified_benign", manifest)
    train = hub.load_graph(train_dir, "verified_benign", manifest)
    # Every statistical/parameter operation is completed before evaluation opens.
    fitted = freeze_training(train)
    output.mkdir(parents=True, exist_ok=False)
    fitted.save(output / "frozen_policy")
    frozen = FrozenPolicies.load(output / "frozen_policy")
    if fitted.fingerprint != frozen.fingerprint:
        raise PolicyError("Serialization changed the TRAIN policy")
    bundle_files = {p: hub.digest(p) for p in (output / "frozen_policy").iterdir()}
    period_reports, inventories = {}, {"verified_benign": before_train}
    for role, folder in (("verified_benign", train_dir), ("evaluation", evaluation_dir)):
        print(f"{role}: load frozen policy; topology/stream reconciliation", flush=True)
        if role == "verified_benign":
            graph = train
        else:
            inventories[role] = snapshot(folder, role, manifest)
            graph = hub.load_graph(folder, role, manifest)
        # The four consumed files must be the same source identities as the old
        # 19-policy audit. Extra bidirectional/mapping files are verified above.
        for name in hub.INPUTS:
            if graph.input_inventory[name]["sha256"] != previous["input_inventory"][role][name]["sha256"]:
                raise PolicyError("Previous audit used different graph bytes")
        sample = hub.deterministic_sample(graph, previous["two_hop_sample_size"])
        decisions = graph.entities[["node_id", *hub.KEYS, "period_role"]].copy()
        results, full = {}, None
        for name in POLICY_NAMES:
            print(f"{role}: {name}", flush=True)
            view = frozen.view(graph, name)
            contexts = view.contexts
            decisions[f"{name}__keep_context"] = contexts.keep_context.to_numpy()
            decisions[f"{name}__edge_weight"] = contexts.edge_weight.to_numpy()
            decisions["seen_in_training"] = contexts.seen_in_training.to_numpy()
            metrics = hub.topology(graph, view.context_keep, sample) if name != "DEGREE_WEIGHTED_FULL" else dict(full)
            if name == "FULL_SHARED":
                full = metrics
            if name == "DEGREE_WEIGHTED_FULL":
                metrics["weight_exposure"] = hub.weight_exposure(
                    graph, contexts.rename(columns={"edge_weight": "weight_degree"}), "degree")
            old = next(v for v in previous["variants"][role] if v["policy"] == PREVIOUS_NAMES[name])
            reconcile(metrics, old, f"{role}.{name}")
            if not view.process_keep.all() or not metrics["create_topology_unchanged"]:
                raise PolicyError("PROCESS/CREATE preservation failure")
            stream = stream_verify(view, Path(folder) / "hetero_graph_edges_bidirectional.parquet")
            if stream["retained_forward_rows"] != metrics["retained_forward_edge_count"]:
                raise PolicyError("Stream versus topology edge count mismatch")
            results[name] = {"previous_audit_policy": PREVIOUS_NAMES[name], "reconciled": True,
                             "metrics": {k: v for k, v in metrics.items() if k != "top_remaining_hubs"},
                             "bidirectional_stream_verification": stream}
        decisions["policy_version"] = frozen.metadata["policy_version"]
        decisions["policy_fingerprint"] = frozen.fingerprint
        decisions.to_parquet(output / f"{role}_context_decisions.parquet", index=False)
        period_reports[role] = {"policies": results, "unseen_context_count": int((~decisions.seen_in_training).sum())}
    for role, folder in (("verified_benign", train_dir), ("evaluation", evaluation_dir)):
        if snapshot(folder, role, manifest) != inventories[role]:
            raise PolicyError("Full source graph changed during validation")
    if (hub.digest(previous_audit_path) != audit_hash or
            any(hub.digest(p) != sha for p, sha in bundle_files.items()) or
            any(hub.digest(p) != sha for p, sha in source_hashes.items())):
        raise PolicyError("Audit, frozen bundle, or policy source changed during execution")
    report = {
        "schema_version": "frozen_policy_reconciliation_v1", "status": "COMPLETE",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "policy_source_sha256": source_hashes, "frozen_policy_fingerprint": frozen.fingerprint,
        "frozen_policy_metadata": frozen.metadata, "source_inventory": inventories,
        "previous_audit_sha256": audit_hash, "periods": period_reports,
        "all_12_source_files_byte_identical": True, "all_four_policies_reconciled_both_periods": True,
        "evaluation_ground_truth_read": False, "model_training_performed": False,
        "graph_files_written": False,
        "output_inventory": {str(p.relative_to(output)): {"size_bytes": p.stat().st_size, "sha256": hub.digest(p)}
                             for p in sorted(output.rglob("*")) if p.is_file()},
        "notes": ["Validation used local completed authentic snapshots; no new Drive/Colab run.",
                  "Weighted incidence is a static proxy, not detection performance.",
                  "PROCESS and CREATE retained; zero weight does not delete raw topology."]}
    hub.json_write(output / "policy_reconciliation.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train-dir", type=Path, required=True)
    parser.add_argument("--evaluation-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--real-run-manifest", type=Path, required=True)
    parser.add_argument("--previous-hub-audit", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.train_dir, args.evaluation_dir, args.output_dir, args.real_run_manifest, args.previous_hub_audit)
    print(f"{report['status']}: four frozen views reconciled; no graphs/models rebuilt")


if __name__ == "__main__":
    main()
