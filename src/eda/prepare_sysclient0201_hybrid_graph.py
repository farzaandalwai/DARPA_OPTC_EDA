#!/usr/bin/env python3
"""Audit real SysClient0201 contracts and drive the existing period graph builder.

The Colab notebook is only a runner. This module owns schema inspection,
compatibility checks, temporary inputs, graph invocation, and comparison.
Known Drive filenames are explicit; absent semantics are never inferred.
In particular, period_process_activity_raw_v1 is NOT assumed to contain
behavior keys. The actual 2026-10-01 file is a process aggregate without them.
Use --behavior-table and column options only for an inspected, explicitly
period-assigned behavior artifact. Never substitute full-timeline compaction.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import sys

import pandas as pd
import pyarrow.parquet as pq

try:
    from . import build_period_heterogeneous_graph as graph
except ImportError:
    import build_period_heterogeneous_graph as graph


FEATURE_GROUP = "eda_10_sysclient0201_period_features_v1"
SPLIT_GROUP = "eda_10_sysclient0201_leakage_safe_split_v1"
OLD_GRAPH_GROUP = "eda_10_sysclient0201_rgcn_graph_v1"
OUTPUT_NAMES = {
    role: f"eda_10_sysclient0201_hybrid_graph_{role}_v1"
    for role in graph.PERIOD_ROLES
}
AUDIT_NAME = "compatibility_audit.json"
MANIFEST_NAME = "prepared_inputs.json"


@dataclass(frozen=True)
class Inputs:
    data_root: Path
    work_dir: Path
    behavior_table: Path | None = None
    process_id_column: str = "process_id"
    structure_id_column: str = "reference_full_structure_id"
    behavior_process_column: str = "process_id"
    behavior_type_column: str = "behavior_type"
    behavior_action_column: str = "action_raw"
    behavior_key_column: str = "behavior_key"
    behavior_count_column: str = "attach_event_count"
    period_column: str = "period_role"


def paths_for(cfg: Inputs) -> dict[str, Path]:
    features = cfg.data_root / FEATURE_GROUP
    split = cfg.data_root / SPLIT_GROUP
    return {
        "train_features": features / "train_process_features_raw_v1.parquet",
        "evaluation_features": features / "evaluation_process_features_raw_v1.parquet",
        "train_create": features / "train_process_create_edges_v1.parquet",
        "evaluation_create": features / "evaluation_process_create_edges_v1.parquet",
        "candidate_features": features / "period_process_feature_columns_v1.json",
        "behavior": cfg.behavior_table or split / "period_process_activity_raw_v1.parquet",
        "period_process_nodes": split / "period_process_nodes_v1.parquet",
        "period_create_edges": split / "period_create_edges_v1.parquet",
        "split_summary": split / "period_split_summary_v1.csv",
        "boundaries": split / "period_boundaries_v1.json",
        "feature_policy": cfg.data_root / OLD_GRAPH_GROUP / "rgcn_model_feature_policy_v1.json",
        "previous_graph_summary": cfg.data_root / OLD_GRAPH_GROUP / "rgcn_graph_summary_v1.csv",
    }


def _safe_work_dir(cfg: Inputs) -> None:
    work = cfg.work_dir.resolve()
    root = cfg.data_root.resolve()
    if work == root or root in work.parents or any(part == "drive" for part in work.parts):
        raise graph.GraphInputError("Temporary inputs/audit must be local; work_dir cannot be on Drive or inside source artifacts")
    cfg.work_dir.mkdir(parents=True, exist_ok=True)


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def inspect_file(path: Path) -> dict:
    result = {"path": str(path), "exists": path.is_file()}
    if not path.is_file():
        return result
    result["sha256"] = graph._file_hash(path)
    if path.suffix == ".parquet":
        parquet = pq.ParquetFile(path)
        result.update(row_count=parquet.metadata.num_rows, columns=parquet.schema_arrow.names,
                      column_types={field.name: str(field.type) for field in parquet.schema_arrow})
        if "period_role" in result["columns"]:
            roles = pd.read_parquet(path, columns=["period_role"]).period_role
            result["period_roles"] = sorted(str(value) for value in roles.dropna().unique())
            result["period_role_counts"] = {str(key): int(value) for key, value in roles.value_counts(dropna=False).items()}
            result["null_period_role_count"] = int(roles.isna().sum())
    elif path.suffix == ".json":
        value = json.loads(path.read_text(encoding="utf-8"))
        result["json_keys"] = list(value) if isinstance(value, dict) else None
    elif path.suffix == ".csv":
        frame = pd.read_csv(path)
        result.update(row_count=len(frame), columns=list(frame.columns))
    return result


def _builder_config(cfg: Inputs, role: str, process_path: Path,
                    create_path: Path, behavior_path: Path, policy_path: Path) -> graph.Config:
    return graph.Config(
        process_nodes=process_path, create_edges=create_path, behavior=behavior_path,
        feature_schema=policy_path, feature_list_key="process_features",
        output_dir=cfg.data_root / OUTPUT_NAMES[role], period_role=role,
        process_id_column=cfg.process_id_column, structure_id_column=cfg.structure_id_column,
        behavior_process_column=cfg.behavior_process_column,
        behavior_type_column=cfg.behavior_type_column, behavior_action_column=cfg.behavior_action_column,
        behavior_key_column=cfg.behavior_key_column, behavior_count_column=cfg.behavior_count_column,
        period_column=cfg.period_column, host_scope="sysclient0201", top_k=10,
    )


def audit_inputs(cfg: Inputs) -> dict:
    """Inspect all listed artifacts before deciding whether graph inputs exist."""
    _safe_work_dir(cfg)
    paths = paths_for(cfg)
    report = {"audit_passed": False, "final_70_feature_policy_passed": False,
              "files": {}, "errors": [], "period_checks": {},
              "behavior_is_explicitly_period_assigned": False,
              "behavior_has_context_columns": False,
              "column_mapping": {key: value for key, value in asdict(cfg).items() if key.endswith("column")},
              "family_metadata_policy": "structure_id comes from reference_full_structure_id by default; split_structure_id is preserved as metadata",
              "temporary_inputs_location": str(cfg.work_dir),
              "output_paths": {role: str(cfg.data_root / name) for role, name in OUTPUT_NAMES.items()}}
    for name, path in paths.items():
        try:
            report["files"][name] = inspect_file(path)
        except Exception as exc:
            report["files"][name] = {"path": str(path), "exists": path.is_file(), "error": str(exc)}
            if name != "previous_graph_summary":
                report["errors"].append(f"Cannot inspect {name}: {exc}")
    required = set(paths) - {"previous_graph_summary"}
    for name in sorted(required):
        if not report["files"][name].get("exists"):
            report["errors"].append(f"Missing required artifact {name}: {paths[name]}")
    try:
        policy = json.loads(paths["feature_policy"].read_text(encoding="utf-8"))
        candidates = json.loads(paths["candidate_features"].read_text(encoding="utf-8"))
        columns = policy["process_features"]
        if (policy.get("process_feature_count") != 70 or not isinstance(columns, list)
                or len(columns) != 70 or len(set(columns)) != 70):
            raise graph.GraphInputError("Established policy must contain exactly 70 unique process_features")
        if (policy.get("dropped_zero_variance_features") != ["event__DESTINATION__OPEN"]
                or "event__DESTINATION__OPEN" in columns):
            raise graph.GraphInputError("Policy does not match the established DESTINATION OPEN exclusion")
        if candidates.get("feature_count") != 71 or candidates.get("feature_columns") is None:
            raise graph.GraphInputError("Candidate schema must explicitly declare 71 feature_columns")
        if [name for name in candidates["feature_columns"] if name != "event__DESTINATION__OPEN"] != columns:
            raise graph.GraphInputError("Final feature order does not reconcile with the 71-feature candidate schema")
        if policy.get("forward_relations") != list(graph.FORWARD_RELATIONS):
            raise graph.GraphInputError("Established forward relations differ from the current builder")
        report["exact_feature_columns"] = columns
        report["feature_policy_key"] = "process_features"
        report["feature_policy_checks"] = {}
        process_frames = {}
        for role, prefix in (("verified_benign", "train"), ("evaluation", "evaluation")):
            frame = pd.read_parquet(paths[prefix + "_features"])
            graph._require(frame, [cfg.process_id_column, cfg.structure_id_column, "split_structure_id"], role + " PROCESS")
            if cfg.period_column not in frame or not frame[cfg.period_column].eq(role).all():
                raise graph.GraphInputError(f"{role} PROCESS table needs explicit matching period assignment")
            if frame[cfg.process_id_column].duplicated().any():
                raise graph.GraphInputError(f"{role}: duplicate PROCESS IDs")
            if {"node_id", "node_type"} & set(frame.columns):
                raise graph.GraphInputError(f"{role}: reserved builder output columns in PROCESS input")
            if "structure_id" in frame and not frame["structure_id"].equals(frame[cfg.structure_id_column]):
                raise graph.GraphInputError(f"{role}: canonical structure_id conflicts with configured family column")
            builder = _builder_config(cfg, role, paths[prefix + "_features"], paths[prefix + "_create"], paths["behavior"], paths["feature_policy"])
            graph._features(paths["feature_policy"], "process_features", frame, builder)
            process_frames[role] = frame
            report["feature_policy_checks"][role] = {"passed": True, "process_rows": len(frame), "feature_count": 70}
        report["final_70_feature_policy_passed"] = True
    except Exception as exc:
        report["errors"].append(f"Feature compatibility: {exc}")
        process_frames = {}
    try:
        boundaries = json.loads(paths["boundaries"].read_text(encoding="utf-8"))
        if boundaries.get("boundary_policy") != "[start, end)":
            raise graph.GraphInputError("Boundary metadata must explicitly specify [start, end)")
        intervals = [(pd.Timestamp(boundaries[role]["start"]), pd.Timestamp(boundaries[role]["end_exclusive"]))
                     for role in graph.PERIOD_ROLES]
        if any(start >= end for start, end in intervals) or intervals[0][1] != intervals[1][0]:
            raise graph.GraphInputError("Period boundaries are not ordered and contiguous")
        report["period_boundaries"] = {role: boundaries[role] for role in graph.PERIOD_ROLES}
    except Exception as exc:
        report["errors"].append(f"Period boundary provenance: {exc}")
    try:
        # The role column alone establishes safe partitioning, not behavioral
        # sufficiency. Process aggregates without entity keys are a hard stop.
        activity = pd.read_parquet(paths["behavior"])
        if cfg.period_column not in activity:
            raise graph.GraphInputError("Behavior input has no explicit period column; timestamp partitioning is forbidden")
        roles = activity[cfg.period_column]
        if roles.isna().any() or not roles.isin(graph.PERIOD_ROLES).all():
            raise graph.GraphInputError("Behavior input has unassigned/unknown period roles")
        report["behavior_is_explicitly_period_assigned"] = True
        needed = [cfg.behavior_process_column, cfg.behavior_type_column,
                  cfg.behavior_action_column, cfg.behavior_key_column, cfg.behavior_count_column]
        missing = sorted(set(needed) - set(activity.columns))
        report["behavior_missing_columns"] = missing
        report["behavior_has_context_columns"] = not missing
        if missing:
            raise graph.GraphInputError(
                f"Explicitly assigned activity table lacks behavior/context columns {missing}; "
                "per-process actor counts cannot reconstruct FILE/MODULE/DESTINATION links. "
                "Supply an inspected period-assigned behavior table; do not use full-timeline compact behavior.")
        graph._require(activity, needed[:-1], "Behavior table")
        graph._counts(activity, cfg.behavior_count_column, "Behavior table")
        pairs = set(zip(activity[cfg.behavior_type_column].str.strip().str.upper(),
                        activity[cfg.behavior_action_column].str.strip().str.upper()))
        unsupported = pairs - set(graph.BEHAVIOR_RELATIONS)
        if unsupported:
            raise graph.GraphInputError(f"Unsupported behavior pairs: {sorted(unsupported)}; no filtering is authorized")
        report["behavior_type_action_pairs"] = sorted([list(pair) for pair in pairs])
    except Exception as exc:
        report["errors"].append(f"Behavior compatibility: {exc}")
        activity = None
    try:
        period_nodes = pd.read_parquet(paths["period_process_nodes"])
        period_creates = pd.read_parquet(paths["period_create_edges"])
        for label, frame in (("period_process_nodes", period_nodes), ("period_create_edges", period_creates)):
            if cfg.period_column not in frame or not frame[cfg.period_column].isin(graph.PERIOD_ROLES).all():
                raise graph.GraphInputError(f"{label}: invalid or absent period assignments")
        for role, prefix in (("verified_benign", "train"), ("evaluation", "evaluation")):
            if role not in process_frames:
                continue
            processes = process_frames[role]
            ids = set(processes[cfg.process_id_column])
            metadata = period_nodes.loc[period_nodes[cfg.period_column] == role]
            graph._require(metadata, [cfg.process_id_column, cfg.structure_id_column, "split_structure_id"], role + " split nodes")
            if metadata[cfg.process_id_column].duplicated().any() or set(metadata[cfg.process_id_column]) != ids:
                raise graph.GraphInputError(f"{role}: feature and split PROCESS universes disagree")
            for column in (cfg.structure_id_column, "split_structure_id"):
                source = metadata.set_index(cfg.process_id_column)[column]
                if not processes[column].equals(processes[cfg.process_id_column].map(source)):
                    raise graph.GraphInputError(f"{role}: {column} differs between feature and split nodes")
            creates = pd.read_parquet(paths[prefix + "_create"])
            graph._require(creates, ["parent_process_id", "child_process_id"], role + " CREATE")
            if "create_event_count" not in creates:
                raise graph.GraphInputError(f"{role}: missing explicit CREATE event counts")
            if cfg.period_column not in creates or not creates[cfg.period_column].eq(role).all():
                raise graph.GraphInputError(f"{role}: CREATE rows lack matching explicit period assignment")
            if creates.duplicated(["parent_process_id", "child_process_id"]).any():
                raise graph.GraphInputError(f"{role}: duplicate CREATE pairs")
            if not set(creates.parent_process_id).union(creates.child_process_id) <= ids:
                raise graph.GraphInputError(f"{role}: CREATE endpoint not found in PROCESS table")
            if "relation_type" in creates and not creates.relation_type.eq("PROCESS_CREATE_PROCESS").all():
                raise graph.GraphInputError(f"{role}: unexpected CREATE relation_type")
            reference = period_creates.loc[period_creates[cfg.period_column] == role]
            cols = ["parent_process_id", "child_process_id", "create_event_count"]
            graph._counts(creates, "create_event_count", role + " CREATE")
            if not creates.sort_values(cols)[cols].reset_index(drop=True).equals(reference.sort_values(cols)[cols].reset_index(drop=True)):
                raise graph.GraphInputError(f"{role}: feature CREATE table differs from split topology/counts")
            families = processes.set_index(cfg.process_id_column)[cfg.structure_id_column]
            if not creates.parent_process_id.map(families).equals(creates.child_process_id.map(families)):
                raise graph.GraphInputError(f"{role}: CREATE crosses reference CREATE-family metadata")
            if activity is not None:
                partition = activity.loc[activity[cfg.period_column] == role]
                if not set(partition[cfg.behavior_process_column]) <= ids:
                    raise graph.GraphInputError(f"{role}: behavior references a missing PROCESS ID")
                graph._check_period(partition, _builder_config(cfg, role, paths[prefix + "_features"], paths[prefix + "_create"], paths["behavior"], paths["feature_policy"]), "Behavior")
                for column in {cfg.structure_id_column, "structure_id"} & set(partition.columns):
                    if not partition[column].equals(partition[cfg.behavior_process_column].map(families)):
                        raise graph.GraphInputError(f"{role}: behavior {column} conflicts with PROCESS family metadata")
            report["period_checks"][role] = {"passed": True, "process_rows": len(processes), "create_rows": len(creates)}
    except Exception as exc:
        report["errors"].append(f"Split/topology compatibility: {exc}")
    for name, info in report["files"].items():
        if "sha256" in info and graph._file_hash(paths[name]) != info["sha256"]:
            report["errors"].append(f"Artifact changed during audit: {name}")
    report["audit_passed"] = not report["errors"]
    _write_json(cfg.work_dir / AUDIT_NAME, report)
    return report


def prepare_inputs(cfg: Inputs) -> dict:
    """Only after a fresh passing audit, materialize behavior roles locally."""
    report = audit_inputs(cfg)
    if not report["audit_passed"]:
        raise graph.GraphInputError("Compatibility audit failed; no graph inputs prepared: " + "; ".join(report["errors"]))
    paths = paths_for(cfg)
    activity = pd.read_parquet(paths["behavior"])
    manifest = {"audit_sha256": graph._file_hash(cfg.work_dir / AUDIT_NAME),
                "source_sha256": {name: info["sha256"] for name, info in report["files"].items() if "sha256" in info},
                "graphs": {}, "configuration": {k: str(v) if isinstance(v, Path) else v for k, v in asdict(cfg).items()}}
    for role, prefix in (("verified_benign", "train"), ("evaluation", "evaluation")):
        destination = cfg.work_dir / f"{role}_behavior.parquet"
        if destination.exists():
            raise graph.GraphInputError(f"Refusing existing prepared file: {destination}")
        partition = activity.loc[activity[cfg.period_column] == role].copy()
        # Full EDA10 structure_id stays attached to PROCESS nodes; activity's
        # split_structure_id, if present, remains separate reference metadata.
        partition.to_parquet(destination, index=False)
        builder = _builder_config(cfg, role, paths[prefix + "_features"], paths[prefix + "_create"], destination, paths["feature_policy"])
        manifest["graphs"][role] = {"builder_configuration": {k: str(v) if isinstance(v, Path) else v for k, v in asdict(builder).items()},
                                   "prepared_behavior_sha256": graph._file_hash(destination)}
    if manifest["source_sha256"]["behavior"] != graph._file_hash(paths["behavior"]):
        raise graph.GraphInputError("Drive behavior source changed during partitioning")
    _write_json(cfg.work_dir / MANIFEST_NAME, manifest)
    return manifest


def build_both(cfg: Inputs) -> dict:
    manifest = json.loads((cfg.work_dir / MANIFEST_NAME).read_text(encoding="utf-8"))
    current_configuration = {k: str(v) if isinstance(v, Path) else v for k, v in asdict(cfg).items()}
    if manifest["configuration"] != current_configuration:
        raise graph.GraphInputError("Runner configuration changed after preparation")
    if not json.loads((cfg.work_dir / AUDIT_NAME).read_text(encoding="utf-8"))["audit_passed"]:
        raise graph.GraphInputError("Compatibility audit did not pass")
    if manifest["audit_sha256"] != graph._file_hash(cfg.work_dir / AUDIT_NAME):
        raise graph.GraphInputError("Compatibility audit changed after preparation")
    paths = paths_for(cfg)
    for name, digest in manifest["source_sha256"].items():
        if graph._file_hash(paths[name]) != digest:
            raise graph.GraphInputError(f"Drive artifact changed after audit: {name}")
    for role in graph.PERIOD_ROLES:
        entry = manifest["graphs"][role]
        settings = entry["builder_configuration"]
        if Path(settings["output_dir"]).exists():
            raise graph.GraphInputError(f"Output already exists; refusing overwrite: {settings['output_dir']}")
        if graph._file_hash(Path(settings["behavior"])) != entry["prepared_behavior_sha256"]:
            raise graph.GraphInputError(f"Prepared {role} behavior changed")
    results = {}
    for role in graph.PERIOD_ROLES:
        settings = manifest["graphs"][role]["builder_configuration"]
        for name in ("process_nodes", "create_edges", "behavior", "feature_schema", "output_dir"):
            settings[name] = Path(settings[name])
        # One builder call per role; no shared graph state or feature fitting.
        try:
            results[role] = graph.build_graph(graph.Config(**settings))
            _write_json(cfg.work_dir / "execution_status.json", {"completed_periods": list(results), "errors": []})
        except Exception as exc:
            _write_json(cfg.work_dir / "execution_status.json", {"completed_periods": list(results), "errors": [str(exc)]})
            raise
    return results


def print_comparison(cfg: Inputs) -> None:
    metrics = ["process_node_count", "file_node_count", "module_node_count", "destination_node_count",
               "forward_edge_count", "create_edge_count", "weakly_connected_component_count",
               "largest_component_process_count", "percentage_process_nodes_in_largest_component",
               "shared_context_entity_count", "create_families_connected_through_shared_context_count",
               "maximum_context_node_degree", "p95_context_node_degree"]
    rows = []
    status_path = cfg.work_dir / "execution_status.json"
    completed = json.loads(status_path.read_text())["completed_periods"] if status_path.is_file() else []
    for role in graph.PERIOD_ROLES:
        path = cfg.data_root / OUTPUT_NAMES[role] / "graph_connectivity_audit.json"
        if role not in completed or not path.is_file():
            print(role + ": graph not completed")
            continue
        audit = json.loads(path.read_text(encoding="utf-8"))
        rows.append({"period_role": role, **{metric: audit[metric] for metric in metrics}})
        top = [node for nodes in audit["top_high_degree_context_nodes"].values() for node in nodes]
        top = sorted(top, key=lambda node: (-node["degree"], node["node_id"]))[:10]
        print(f"{role}: top 10 context entities")
        print(pd.DataFrame(top)[["node_type", "canonical_key", "degree", "create_family_count"]].to_string(index=False) if top else "none")
    if rows:
        print(pd.DataFrame(rows).set_index("period_role").T.to_string())
    previous = paths_for(cfg)["previous_graph_summary"]
    if previous.is_file():
        try:
            old = pd.read_csv(previous)
        except (OSError, ValueError) as exc:
            print(f"Previous graph summary unreadable: {exc}")
            return
        print("Previous structure-scoped graph summary (only stored metrics; WCCs were not reported):")
        print(old.to_string(index=False))
        comparisons = []
        mapping = {key: key for key in metrics[:4]}
        mapping["forward_edge_count"] = "forward_compact_edge_rows"
        if "period_role" in old and not old.period_role.duplicated().any():
            for row in rows:
                match = old.loc[old.period_role == row["period_role"]]
                if len(match) != 1:
                    continue
                for metric, source in mapping.items():
                    if source in old and pd.notna(match.iloc[0][source]):
                        prior = int(match.iloc[0][source])
                        comparisons.append({"period": row["period_role"], "metric": metric,
                                            "old": prior, "hybrid": row[metric], "delta": row[metric] - prior})
        if comparisons:
            print("Comparable stored counts (hybrid minus old):")
            print(pd.DataFrame(comparisons).to_string(index=False))
        print("Old WCC concentration, context degrees and family sharing: unavailable; no inferred comparison")
    else:
        print("Previous graph summary unavailable")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("audit", "prepare", "build", "compare"))
    parser.add_argument("--data-root", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--behavior-table", type=Path)
    for name in Inputs.__dataclass_fields__:
        if name.endswith("column"):
            parser.add_argument("--" + name.replace("_", "-"), default=Inputs.__dataclass_fields__[name].default)
    args = vars(parser.parse_args(argv))
    phase = args.pop("phase")
    cfg = Inputs(**args)
    try:
        if phase == "audit":
            report = audit_inputs(cfg)
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0 if report["audit_passed"] else 2
        if phase == "prepare":
            prepare_inputs(cfg)
        elif phase == "build":
            build_both(cfg)
        else:
            print_comparison(cfg)
    except (graph.GraphInputError, OSError, ValueError, KeyError) as exc:
        print(f"STOP: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
