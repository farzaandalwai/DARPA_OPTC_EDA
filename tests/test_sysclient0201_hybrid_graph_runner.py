"""Real-artifact-shaped contracts; these small fixtures are not dataset results."""

from dataclasses import replace
import json
from pathlib import Path
import sys

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.eda import prepare_sysclient0201_hybrid_graph as runner


@pytest.fixture
def cfg(tmp_path):
    config = runner.Inputs(tmp_path / "artifacts", tmp_path / "local")
    paths = runner.paths_for(config)
    for path in paths.values():
        path.parent.mkdir(parents=True, exist_ok=True)
    features = [f"event__FILE__READ_{index}" for index in range(70)]
    paths["feature_policy"].write_text(json.dumps({
        "process_feature_count": 70, "process_features": features,
        "dropped_zero_variance_features": ["event__DESTINATION__OPEN"],
        "forward_relations": list(runner.graph.FORWARD_RELATIONS),
    }))
    paths["candidate_features"].write_text(json.dumps({
        "feature_count": 71, "feature_columns": features + ["event__DESTINATION__OPEN"],
    }))
    paths["boundaries"].write_text(json.dumps({
        "boundary_policy": "[start, end)",
        "verified_benign": {"start": "2019-09-16T00:00:00Z", "end_exclusive": "2019-09-23T00:00:00Z"},
        "evaluation": {"start": "2019-09-23T00:00:00Z", "end_exclusive": "2019-09-25T00:00:00Z"},
    }))
    nodes, creates, behavior = [], [], []
    for role, prefix in (("verified_benign", "train"), ("evaluation", "evaluation")):
        frame = pd.DataFrame({
            "process_id": ["a", "b", "c"], "period_role": [role] * 3,
            "reference_full_structure_id": ["full_a", "full_a", "full_c"],
            "split_structure_id": [role + "_a", role + "_a", role + "_c"],
            **{name: [1, 2, 3] for name in features}, "event__DESTINATION__OPEN": [0, 0, 0],
        })
        frame.to_parquet(paths[prefix + "_features"], index=False)
        nodes.append(frame[["process_id", "period_role", "reference_full_structure_id", "split_structure_id"]])
        create = pd.DataFrame({
            "parent_process_id": ["a"], "child_process_id": ["b"],
            "create_event_count": [2], "period_role": [role], "relation_type": ["PROCESS_CREATE_PROCESS"],
        })
        create.to_parquet(paths[prefix + "_create"], index=False)
        creates.append(create.drop(columns="relation_type"))
        behavior.append(pd.DataFrame({
            "process_id": ["b", "c"], "period_role": [role] * 2,
            "behavior_type": ["FILE"] * 2, "action_raw": ["READ"] * 2,
            "behavior_key": ["C:/shared.txt"] * 2, "attach_event_count": [3, 4],
        }))
    pd.concat(nodes, ignore_index=True).to_parquet(paths["period_process_nodes"], index=False)
    pd.concat(creates, ignore_index=True).to_parquet(paths["period_create_edges"], index=False)
    pd.concat(behavior, ignore_index=True).to_parquet(paths["behavior"], index=False)
    pd.DataFrame({"period_role": list(runner.graph.PERIOD_ROLES)}).to_csv(paths["split_summary"], index=False)
    pd.DataFrame({"period_role": list(runner.graph.PERIOD_ROLES), "process_node_count": [3, 3]}).to_csv(paths["previous_graph_summary"], index=False)
    return config


def change(cfg, name, transform):
    path = runner.paths_for(cfg)[name]
    transform(pd.read_parquet(path)).to_parquet(path, index=False)


def test_real_shaped_activity_aggregate_stops_without_creating_graphs(cfg):
    path = runner.paths_for(cfg)["behavior"]
    pd.DataFrame({"period_role": list(runner.graph.PERIOD_ROLES), "process_id": ["b", "c"],
                  "actor_event_count": [4, 5], "first_actor_event_time": ["2019-01-01"] * 2,
                  "last_actor_event_time": ["2019-10-01"] * 2}).to_parquet(path, index=False)
    before = runner.graph._file_hash(path)
    report = runner.audit_inputs(cfg)
    assert not report["audit_passed"]
    assert report["final_70_feature_policy_passed"]
    assert report["behavior_is_explicitly_period_assigned"]
    assert report["behavior_missing_columns"] == ["action_raw", "attach_event_count", "behavior_key", "behavior_type"]
    with pytest.raises(runner.graph.GraphInputError, match="Compatibility audit failed"):
        runner.prepare_inputs(cfg)
    assert runner.graph._file_hash(path) == before
    assert not list(cfg.work_dir.glob("*behavior.parquet"))
    assert not any((cfg.data_root / name).exists() for name in runner.OUTPUT_NAMES.values())


def test_successful_partition_build_and_comparison_are_period_isolated(cfg, capsys):
    paths = runner.paths_for(cfg)
    original_hashes = {name: runner.graph._file_hash(path) for name, path in paths.items()}
    report = runner.audit_inputs(cfg)
    assert report["audit_passed"], report["errors"]
    assert report["files"]["behavior"]["row_count"] == 4
    manifest = runner.prepare_inputs(cfg)
    for role, entry in manifest["graphs"].items():
        partition = pd.read_parquet(entry["builder_configuration"]["behavior"])
        assert partition.period_role.eq(role).all()
        assert Path(entry["builder_configuration"]["behavior"]).parent == cfg.work_dir
    results = runner.build_both(cfg)
    assert set(results) == set(runner.graph.PERIOD_ROLES)
    all_ids = []
    for role, result in results.items():
        assert result["process_node_count"] == 3
        assert result["forward_edge_count"] == 3
        assert result["create_edge_count"] == 1
        assert result["shared_context_entity_count"] == 1
        assert result["weakly_connected_component_count"] == 1
        assert result["largest_component_process_count"] == 3
        directory = cfg.data_root / runner.OUTPUT_NAMES[role]
        nodes = pd.read_parquet(directory / "hetero_process_nodes.parquet")
        assert nodes.structure_id.equals(nodes.reference_full_structure_id)
        assert "split_structure_id" in nodes
        entities = pd.read_parquet(directory / "hetero_entity_nodes.parquet")
        all_ids.append(set(nodes.node_id) | set(entities.node_id))
    assert not all_ids[0] & all_ids[1]
    assert original_hashes == {name: runner.graph._file_hash(path) for name, path in paths.items()}
    runner.print_comparison(cfg)
    output = capsys.readouterr().out
    assert "top 10 context entities" in output and "C:\\shared.txt" in output
    assert "Previous structure-scoped" in output
    with pytest.raises(runner.graph.GraphInputError, match="Output already exists"):
        runner.build_both(cfg)


@pytest.mark.parametrize("name,transform,error", [
    ("behavior", lambda frame: frame.drop(columns="period_role"), "no explicit period column"),
    ("behavior", lambda frame: frame.assign(period_role="unassigned"), "unassigned/unknown"),
    ("behavior", lambda frame: frame.assign(process_id="missing"), "missing PROCESS"),
    ("behavior", lambda frame: frame.assign(structure_id="wrong"), "conflicts with PROCESS family"),
    ("behavior", lambda frame: frame.assign(action_raw="OPEN"), "Unsupported behavior"),
    ("behavior", lambda frame: frame.assign(attach_event_count=0), "positive int64"),
    ("train_features", lambda frame: frame.drop(columns="event__FILE__READ_0"), "Feature column missing"),
    ("train_features", lambda frame: frame.assign(event__FILE__READ_0=float("nan")), "numeric, finite"),
    ("train_create", lambda frame: frame.assign(child_process_id="c"), "differs from split topology"),
    ("train_create", lambda frame: frame.drop(columns="create_event_count"), "explicit CREATE event counts"),
])
def test_incompatible_inputs_fail_closed(cfg, name, transform, error):
    change(cfg, name, transform)
    report = runner.audit_inputs(cfg)
    assert not report["audit_passed"]
    assert any(error in message for message in report["errors"]), report["errors"]
    with pytest.raises(runner.graph.GraphInputError):
        runner.prepare_inputs(cfg)


def test_missing_required_file_and_optional_old_summary(cfg):
    paths = runner.paths_for(cfg)
    paths["previous_graph_summary"].unlink()
    assert runner.audit_inputs(cfg)["audit_passed"]
    paths["previous_graph_summary"].write_text("")
    assert runner.audit_inputs(cfg)["audit_passed"]
    paths["train_features"].unlink()
    report = runner.audit_inputs(cfg)
    assert not report["audit_passed"]
    assert any("Missing required artifact train_features" in error for error in report["errors"])


def test_hash_and_configuration_guards(cfg):
    runner.prepare_inputs(cfg)
    with pytest.raises(runner.graph.GraphInputError, match="configuration changed"):
        runner.build_both(replace(cfg, structure_id_column="split_structure_id"))
    change(cfg, "behavior", lambda frame: frame.assign(attach_event_count=5))
    with pytest.raises(runner.graph.GraphInputError, match="artifact changed after audit"):
        runner.build_both(cfg)


def test_local_work_directory_guard(cfg):
    with pytest.raises(runner.graph.GraphInputError, match="must be local"):
        runner.audit_inputs(replace(cfg, work_dir=cfg.data_root / "temporary"))


def test_comparison_does_not_claim_an_unexecuted_graph(cfg, capsys):
    runner.print_comparison(cfg)
    assert capsys.readouterr().out.count("graph not completed") == 2


def test_notebook_startup_order_thin_runner_and_no_saved_outputs():
    path = Path(__file__).resolve().parents[1] / "colab/run_sysclient0201_hybrid_graph.ipynb"
    notebook = json.loads(path.read_text())
    assert notebook["nbformat"] == 4
    cells = notebook["cells"]
    sources = ["".join(cell["source"]) for cell in cells]
    assert all(cell["cell_type"] == "code" for cell in cells[:4])
    assert "drive.mount" in sources[0]
    assert "clone" in sources[1] and "fetch" in sources[1] and "pull" in sources[1]
    assert "eda08" in sources[1] and "/content/DARPA_OPTC_EDA" in sources[1]
    assert "HEAD" in sources[2] and "branch" in sources[2]
    assert "ismount" in sources[3] and "MyDrive" in sources[3]
    assert "prepare_sysclient0201_hybrid_graph.py" in "".join(sources)
    assert "legacy-audit" in "".join(sources) and "legacy-adapt" in "".join(sources)
    assert "exact_behavior_key_v1" in "".join(sources) and "split_structure_id" in "".join(sources)
    for cell in cells:
        if cell["cell_type"] == "code":
            assert cell["outputs"] == [] and cell["execution_count"] is None
            compile("".join(cell["source"]), str(path), "exec")


@pytest.fixture
def legacy_cfg(cfg):
    config = replace(cfg, legacy_inputs=True, behavior_links_dir=cfg.work_dir / "adapted_behavior",
                     context_key_policy="exact_behavior_key_v1", structure_id_column="split_structure_id")
    paths = runner.paths_for(config)
    nodes, edges, creates = [], [], []
    for role, prefix in (("verified_benign", "train"), ("evaluation", "evaluation")):
        frame = pd.read_parquet(paths[prefix + "_features"]).drop(columns="event__DESTINATION__OPEN")
        frame["node_id"] = "old_" + frame.process_id
        frame["node_type"] = "PROCESS"
        nodes.append(frame)
        raw = pd.read_parquet(cfg.data_root / runner.SPLIT_GROUP / "period_process_activity_raw_v1.parquet")
        raw = raw.loc[raw.period_role == role]
        lookup = frame.set_index("process_id").split_structure_id
        edges.append(pd.DataFrame({
            "period_role": raw.period_role, "split_structure_id": raw.process_id.map(lookup),
            "source_node_id": "old_" + raw.process_id, "source_node_type": "PROCESS",
            "target_node_id": role + "_context_" + raw.process_id, "target_node_type": raw.behavior_type,
            "relation_type": "PROCESS_FILE_READ", "behavior_key": raw.behavior_key,
            "event_count": raw.attach_event_count, "first_seen_time": pd.Timestamp("2019-01-01"),
            "last_seen_time": pd.Timestamp("2020-01-01"),
        }))
        create = pd.read_parquet(paths[prefix + "_create"])
        creates.append(pd.DataFrame({
            "period_role": create.period_role, "split_structure_id": create.parent_process_id.map(lookup),
            "source_node_id": "old_" + create.parent_process_id, "source_node_type": "PROCESS",
            "target_node_id": "old_" + create.child_process_id, "target_node_type": "PROCESS",
            "relation_type": create.relation_type, "event_count": create.create_event_count,
        }))
    for name, frames in (("legacy_process_nodes", nodes), ("legacy_behavior_edges", edges), ("legacy_create_edges", creates)):
        pd.concat(frames, ignore_index=True).to_parquet(paths[name], index=False)
    return config


def test_controlled_legacy_pipeline_feeds_exact_adapted_files(legacy_cfg):
    cfg = legacy_cfg
    assert runner.audit_legacy_inputs(cfg)["passed"]
    proof = runner.adapt_legacy_inputs(cfg)
    assert proof["event_count_total_before"] == proof["event_count_total_after"] == 14
    report = runner.audit_inputs(cfg)
    assert report["audit_passed"], report["errors"]
    manifest = runner.prepare_inputs(cfg)
    for role, entry in manifest["graphs"].items():
        assert Path(entry["builder_configuration"]["behavior"]) == cfg.behavior_links_dir / f"{role}_behavior_links_v1.parquet"
    results = runner.build_both(cfg)
    assert all(result["create_family_count"] == 2 for result in results.values())
    assert all(result["context_identity_policy"]["key_policy"] == "exact_behavior_key_v1" for result in results.values())
    baseline = runner.legacy_connectivity(cfg)
    assert all(period["weakly_connected_component_count"] == 2 for period in baseline["periods"].values())
    assert all(period["shared_context_entity_count"] == 0 for period in baseline["periods"].values())
    assert all(period["largest_component_process_count"] == 2 for period in baseline["periods"].values())


@pytest.mark.parametrize("name,transform", [
    ("train_features", lambda frame: frame.assign(event__FILE__READ_0=99)),
    ("train_create", lambda frame: frame.assign(create_event_count=99)),
    ("legacy_behavior_edges", lambda frame: frame.assign(split_structure_id="wrong")),
])
def test_controlled_experiment_mismatches_stop_before_adaptation(legacy_cfg, name, transform):
    change(legacy_cfg, name, transform)
    assert not runner.audit_legacy_inputs(legacy_cfg)["passed"]
    with pytest.raises(runner.graph.GraphInputError, match="Historical/control audit failed"):
        runner.adapt_legacy_inputs(legacy_cfg)
    assert not legacy_cfg.behavior_links_dir.exists()


def test_adapted_links_cannot_be_modified_after_reconciliation(legacy_cfg):
    runner.adapt_legacy_inputs(legacy_cfg)
    change(legacy_cfg, "verified_benign_behavior", lambda frame: frame.assign(attach_event_count=999))
    report = runner.audit_inputs(legacy_cfg)
    assert not report["audit_passed"]
    assert any("Adapted links changed" in error for error in report["errors"])
