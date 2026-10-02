"""Synthetic period contracts and connectivity tests; no external schema assumed."""

from dataclasses import replace
import json
import pathlib
import sys

import pandas as pd
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src" / "eda"))
import build_period_heterogeneous_graph as graph


def inputs(root, role="verified_benign", processes=None, creates=None, behavior=None, features=None):
    root.mkdir(parents=True)
    if processes is None:
        processes = pd.DataFrame({
            "process_id": ["a", "b", "c"], "structure_id": ["family_a", "family_a", "family_b"],
            "period_role": [role] * 3, "event_count": [4, 2, 7],
            "process_instance_uuid": ["uuid_a", "uuid_b", "uuid_c"], "pid_raw": [10, 11, 12],
        })
    if creates is None:
        creates = pd.DataFrame({"parent_process_id": ["a"], "child_process_id": ["b"],
                                "create_event_count": [3], "period_role": [role]})
    if behavior is None:
        behavior = pd.DataFrame({
            "process_id": ["b", "c"], "structure_id": ["family_a", "family_b"],
            "behavior_type": ["FILE", "FILE"], "action_raw": ["READ", "READ"],
            "behavior_key": [r"C:\x.dll", "C:/x.dll"], "attach_event_count": [5, 6],
            "period_role": [role, role],
        })
    for name, frame in (("processes", processes), ("creates", creates), ("behavior", behavior)):
        frame.to_parquet(root / f"{name}.parquet", index=False)
    (root / "features.json").write_text(json.dumps(features or {"feature_columns": ["event_count"]}))
    return graph.Config(root / "processes.parquet", root / "creates.parquet",
                        root / "behavior.parquet", root / "features.json", root / "output", role)


def load(cfg, name):
    return pd.read_parquet(cfg.output_dir / f"{name}.parquet")


def change_table(cfg, name, mutate):
    path = getattr(cfg, name)
    mutate(pd.read_parquet(path)).to_parquet(path, index=False)


def test_cross_family_file_sharing_preserves_metadata_create_topology_and_audit(tmp_path):
    cfg = inputs(tmp_path / "inputs")
    original_processes = pd.read_parquet(cfg.process_nodes)
    audit = graph.build_graph(cfg)
    processes = load(cfg, "hetero_process_nodes")
    pd.testing.assert_frame_equal(processes[original_processes.columns], original_processes)
    entities = load(cfg, "hetero_entity_nodes")
    assert len(entities) == 1 and entities.iloc[0].node_type == "FILE"
    assert "structure_id" not in entities and "split_structure_id" not in entities
    edges = load(cfg, "hetero_graph_edges_forward")
    create = edges[edges.relation == "PROCESS_CREATE_PROCESS"]
    ids = processes.set_index("node_id").process_id
    assert [(ids[row.source_id], ids[row.target_id], row.event_count) for row in create.itertuples()] == [("a", "b", 3)]
    assert audit["reconciliation"]["create_topology_unchanged"] is True
    assert audit["reconciliation"]["input_create_topology_sha256"] == audit["reconciliation"]["output_create_topology_sha256"]
    assert audit["shared_context_entity_count"] == 1
    assert audit["create_families_connected_through_shared_context_count"] == 2
    assert audit["create_families_per_shared_context"]["frequency"] == {"2": 1}
    assert audit["weakly_connected_component_count"] == 1
    assert audit["largest_component_node_count"] == 4
    assert audit["largest_component_process_count"] == 3
    assert audit["percentage_process_nodes_in_largest_component"] == 100
    assert audit["maximum_context_node_degree"] == 2
    assert audit["median_context_node_degree"] == 2
    assert audit["p95_context_node_degree"] == 2
    assert audit["singleton_process_count"] == 0
    assert audit["top_high_degree_context_nodes"]["FILE"][0]["create_family_count"] == 2
    assert audit["predictive_process_feature_columns"] == ["event_count"]
    assert {"pid_raw", "process_instance_uuid", "structure_id"} <= set(audit["process_metadata_columns"])


def test_periods_have_disjoint_ids_and_no_edges_between_them(tmp_path):
    configs = [inputs(tmp_path / role, role) for role in graph.PERIOD_ROLES]
    for cfg in configs:
        graph.build_graph(cfg)
    node_sets = []
    for cfg in configs:
        nodes = set(load(cfg, "hetero_process_nodes").node_id) | set(load(cfg, "hetero_entity_nodes").node_id)
        edges = load(cfg, "hetero_graph_edges_bidirectional")
        assert set(edges.source_id) | set(edges.target_id) <= nodes
        assert set(edges.period_role) == {cfg.period_role}
        node_sets.append(nodes)
    assert node_sets[0].isdisjoint(node_sets[1])


def test_deterministic_outputs_after_reordering_input_rows(tmp_path):
    cfg = inputs(tmp_path / "inputs")
    graph.build_graph(cfg)
    for name in ("process_nodes", "create_edges", "behavior"):
        change_table(cfg, name, lambda frame: frame.iloc[::-1].reset_index(drop=True))
    other = replace(cfg, output_dir=tmp_path / "again")
    graph.build_graph(other)
    for name in ("hetero_process_nodes", "hetero_entity_nodes", "hetero_graph_edges_forward", "hetero_graph_edges_bidirectional"):
        pd.testing.assert_frame_equal(load(cfg, name), load(other, name))


def test_file_module_same_path_are_distinct(tmp_path):
    cfg = inputs(tmp_path / "inputs")
    change_table(cfg, "behavior", lambda frame: frame.assign(behavior_type=["FILE", "MODULE"], action_raw=["READ", "LOAD"]))
    graph.build_graph(cfg)
    entities = load(cfg, "hetero_entity_nodes")
    assert set(entities.node_type) == {"FILE", "MODULE"}
    assert entities.canonical_key.nunique() == 1
    assert entities.node_id.nunique() == 2


@pytest.mark.parametrize("left,right,equal", [
    ("192.0.2.1:0443|tcp", "192.0.2.1:443|TCP", True),
    ("192.0.2.1:443|TCP", "192.0.2.1:80|TCP", False),
    ("192.0.2.1:443|TCP", "192.0.2.1:443|UDP", False),
    ("192.0.2.1", "192.0.2.1:443", False),
    ("[2001:0db8::1]:443|tcp", "[2001:db8::1]:0443|TCP", True),
    ("2001:0db8::1|TCP", "2001:db8::1|TCP", True),
    ("unresolved:80|tcp", "unresolved:080|TCP", True),
])
def test_destination_identity(tmp_path, left, right, equal):
    cfg = inputs(tmp_path / "inputs")
    change_table(cfg, "behavior", lambda frame: frame.assign(
        behavior_type="DESTINATION", action_raw="MESSAGE", behavior_key=[left, right]))
    graph.build_graph(cfg)
    assert len(load(cfg, "hetero_entity_nodes")) == (1 if equal else 2)


def test_reverse_relations_exactly_mirror_forward_and_all_ten_supported(tmp_path):
    rows = [{"process_id": "a", "behavior_type": kind, "action_raw": action,
             "behavior_key": "192.0.2.1:443|TCP" if kind == "DESTINATION" else r"C:\x.dll",
             "attach_event_count": 2} for kind, action in graph.BEHAVIOR_RELATIONS]
    cfg = inputs(tmp_path / "inputs", behavior=pd.DataFrame(rows))
    audit = graph.build_graph(cfg)
    forward = load(cfg, "hetero_graph_edges_forward")
    bi = load(cfg, "hetero_graph_edges_bidirectional")
    assert set(forward.relation) == set(graph.FORWARD_RELATIONS)
    assert audit["forward_relation_count"] == audit["observed_forward_relation_count"] == 10
    assert audit["bidirectional_relation_count"] == audit["observed_bidirectional_relation_count"] == 20
    assert len(bi) == 2 * len(forward)
    assert bi.edge_id.is_unique
    for row in forward.itertuples():
        matches = bi[(bi.relation == "REV__" + row.relation) &
                     (bi.source_id == row.target_id) & (bi.target_id == row.source_id)]
        assert len(matches) == 1
        mirror = matches.iloc[0]
        assert mirror.source_type == row.target_type
        assert mirror.target_type == row.source_type
        assert mirror.event_count == row.event_count and mirror.period_role == row.period_role
        assert mirror.relation_id == row.relation_id + 10
    mapping = pd.read_csv(cfg.output_dir / "relation_type_mapping.csv")
    assert list(mapping.relation_id) == list(range(20))
    assert all(mapping.set_index("relation_id").reverse_relation_id[other] == i
               for i, other in zip(mapping.relation_id, mapping.reverse_relation_id))


@pytest.mark.parametrize("feature", ["process_id", "structure_id", "split_structure_id", "uuid", "processUUID", "pid", "pid_raw", "process_instance_uuid", "actor_id_raw", "object_id_raw"])
def test_linkage_metadata_rejected_as_features(tmp_path, feature):
    cfg = inputs(tmp_path / "inputs", features={"feature_columns": [feature]})
    with pytest.raises(graph.GraphInputError, match="Metadata/linkage"):
        graph.build_graph(cfg)
    assert not cfg.output_dir.exists()


@pytest.mark.parametrize("table", ["process_nodes", "create_edges", "behavior"])
def test_mixed_period_inputs_rejected(tmp_path, table):
    cfg = inputs(tmp_path / "inputs")
    change_table(cfg, table, lambda frame: frame.assign(period_role="evaluation"))
    with pytest.raises(graph.GraphInputError, match="period role"):
        graph.build_graph(cfg)


@pytest.mark.parametrize("table,column", [("create_edges", "child_process_id"), ("behavior", "process_id")])
def test_unknown_or_other_period_process_rejected(tmp_path, table, column):
    cfg = inputs(tmp_path / "inputs")
    change_table(cfg, table, lambda frame: frame.assign(**{column: "other_period_process"}))
    with pytest.raises(graph.GraphInputError, match="unknown PROCESS"):
        graph.build_graph(cfg)


def test_empty_graph_has_typed_outputs_and_complete_relation_registry(tmp_path):
    processes = pd.DataFrame({"process_id": pd.Series(dtype=str), "structure_id": pd.Series(dtype=str),
                              "event_count": pd.Series(dtype="int64")})
    creates = pd.DataFrame(columns=["parent_process_id", "child_process_id"])
    behavior = pd.DataFrame(columns=["process_id", "behavior_type", "action_raw", "behavior_key"])
    cfg = inputs(tmp_path / "inputs", processes=processes, creates=creates, behavior=behavior)
    audit = graph.build_graph(cfg)
    assert audit["weakly_connected_component_count"] == 0
    assert audit["percentage_process_nodes_in_largest_component"] == 0
    assert len(load(cfg, "hetero_graph_edges_bidirectional")) == 0
    assert list(load(cfg, "hetero_graph_edges_forward").columns) == graph.EDGE_COLUMNS
    assert len(pd.read_csv(cfg.output_dir / "relation_type_mapping.csv")) == 20


def test_isolated_processes_no_context(tmp_path):
    cfg = inputs(tmp_path / "inputs", behavior=pd.DataFrame(columns=["process_id", "behavior_type", "action_raw", "behavior_key"]))
    audit = graph.build_graph(cfg)
    assert audit["weakly_connected_component_count"] == 2
    assert audit["largest_component_process_count"] == 2
    assert audit["singleton_process_count"] == 1
    assert audit["shared_context_entity_count"] == 0


def test_repeated_actions_do_not_inflate_neighbor_degree_and_counts_reconcile(tmp_path):
    cfg = inputs(tmp_path / "inputs")
    change_table(cfg, "behavior", lambda frame: pd.concat([frame, frame, frame.assign(action_raw="WRITE")], ignore_index=True))
    audit = graph.build_graph(cfg)
    assert audit["reconciliation"]["input_behavior_rows"] == 6
    assert audit["reconciliation"]["output_behavior_edges"] == 4
    assert audit["reconciliation"]["input_behavior_event_count"] == audit["reconciliation"]["output_behavior_event_count"] == 33
    assert audit["maximum_context_node_degree"] == 2


def test_high_degree_entities_retained(tmp_path):
    processes = pd.DataFrame({"process_id": [f"p{i}" for i in range(100)],
                              "structure_id": [f"s{i}" for i in range(100)], "event_count": 1})
    creates = pd.DataFrame(columns=["parent_process_id", "child_process_id"])
    behavior = pd.DataFrame({"process_id": processes.process_id, "behavior_type": "MODULE",
                             "action_raw": "LOAD", "behavior_key": r"C:\common.dll"})
    cfg = inputs(tmp_path / "inputs", processes=processes, creates=creates, behavior=behavior)
    audit = graph.build_graph(cfg)
    assert audit["maximum_context_node_degree"] == 100
    assert audit["module_node_count"] == 1 and audit["forward_edge_count"] == 100
    assert audit["create_families_connected_through_shared_context_count"] == 100
    assert audit["high_degree_filtering_applied"] is False


def test_multihost_file_namespace_and_destination_sharing(tmp_path):
    cfg = inputs(tmp_path / "inputs")
    change_table(cfg, "process_nodes", lambda frame: frame.assign(host=["h1", "h1", "h2"]))
    cfg = replace(cfg, host_column="host")
    graph.build_graph(cfg)
    assert len(load(cfg, "hetero_entity_nodes")) == 2
    change_table(cfg, "behavior", lambda frame: frame.assign(behavior_type="DESTINATION", action_raw="START", behavior_key="192.0.2.1:443|TCP"))
    cfg = replace(cfg, output_dir=tmp_path / "dest")
    graph.build_graph(cfg)
    assert len(load(cfg, "hetero_entity_nodes")) == 1


def test_configurable_columns_and_feature_json_pointer(tmp_path):
    cfg = inputs(tmp_path / "inputs", features={"process": {"features": ["event_count"]}})
    change_table(cfg, "process_nodes", lambda frame: frame.rename(columns={"process_id": "proc", "structure_id": "family"}))
    change_table(cfg, "create_edges", lambda frame: frame.rename(columns={"parent_process_id": "parent", "child_process_id": "child"}))
    change_table(cfg, "behavior", lambda frame: frame.rename(columns={"process_id": "actor", "structure_id": "family", "behavior_type": "kind", "action_raw": "action", "behavior_key": "key"}))
    cfg = replace(cfg, process_id_column="proc", structure_id_column="family", create_parent_column="parent",
                  create_child_column="child", behavior_process_column="actor", behavior_type_column="kind",
                  behavior_action_column="action", behavior_key_column="key", feature_list_key="/process/features")
    graph.build_graph(cfg)
    nodes = load(cfg, "hetero_process_nodes")
    assert nodes.proc.equals(nodes.process_id) and nodes.family.equals(nodes.structure_id)


@pytest.mark.parametrize("failure", ["duplicate_process", "duplicate_create", "cross_family_create", "wrong_behavior_family", "missing_column", "blank_key", "unsupported_action", "invalid_count", "non_numeric_feature", "bad_schema"])
def test_invalid_input_fails_without_output(tmp_path, failure):
    cfg = inputs(tmp_path / "inputs")
    if failure == "duplicate_process":
        change_table(cfg, "process_nodes", lambda f: pd.concat([f, f], ignore_index=True))
    elif failure == "duplicate_create":
        change_table(cfg, "create_edges", lambda f: pd.concat([f, f], ignore_index=True))
    elif failure == "cross_family_create":
        change_table(cfg, "create_edges", lambda f: f.assign(child_process_id="c"))
    elif failure == "wrong_behavior_family":
        change_table(cfg, "behavior", lambda f: f.assign(structure_id="wrong"))
    elif failure == "missing_column":
        change_table(cfg, "behavior", lambda f: f.drop(columns="behavior_key"))
    elif failure == "blank_key":
        change_table(cfg, "behavior", lambda f: f.assign(behavior_key=" "))
    elif failure == "unsupported_action":
        change_table(cfg, "behavior", lambda f: f.assign(action_raw="OPEN"))
    elif failure == "invalid_count":
        change_table(cfg, "behavior", lambda f: f.assign(attach_event_count=-1))
    elif failure == "non_numeric_feature":
        change_table(cfg, "process_nodes", lambda f: f.assign(event_count="text"))
    elif failure == "bad_schema":
        cfg.feature_schema.write_text('{"unknown": ["event_count"]}')
    with pytest.raises(graph.GraphInputError):
        graph.build_graph(cfg)
    assert not cfg.output_dir.exists()


def test_publication_refuses_existing_output_and_audit_hashes_outputs(tmp_path):
    cfg = inputs(tmp_path / "inputs")
    audit = graph.build_graph(cfg)
    assert {p.name for p in cfg.output_dir.iterdir()} == {
        "hetero_process_nodes.parquet", "hetero_entity_nodes.parquet", "hetero_graph_edges_forward.parquet",
        "hetero_graph_edges_bidirectional.parquet", "relation_type_mapping.csv", "graph_connectivity_audit.json"}
    assert json.loads((cfg.output_dir / "graph_connectivity_audit.json").read_text()) == audit
    for name, digest in audit["output_sha256"].items():
        assert graph._file_hash(cfg.output_dir / name) == digest
    with pytest.raises(graph.GraphInputError, match="existing output"):
        graph.build_graph(cfg)


def test_cli_builds_graph(tmp_path):
    cfg = inputs(tmp_path / "inputs")
    assert graph.main(["--process-nodes", str(cfg.process_nodes), "--create-edges", str(cfg.create_edges),
                       "--behavior", str(cfg.behavior), "--feature-schema", str(cfg.feature_schema),
                       "--output-dir", str(cfg.output_dir), "--period-role", cfg.period_role]) == 0


def test_family_names_and_split_metadata_do_not_affect_context_identity(tmp_path):
    cfg = inputs(tmp_path / "inputs")
    change_table(cfg, "process_nodes", lambda f: f.assign(split_structure_id=["split_a", "split_a", "split_b"]))
    graph.build_graph(cfg)
    change_table(cfg, "process_nodes", lambda f: f.assign(structure_id=["new_a", "new_a", "new_b"]))
    change_table(cfg, "behavior", lambda f: f.assign(structure_id=["new_a", "new_b"]))
    other = replace(cfg, output_dir=tmp_path / "again")
    graph.build_graph(other)
    pd.testing.assert_frame_equal(load(cfg, "hetero_entity_nodes"), load(other, "hetero_entity_nodes"))
    assert list(load(other, "hetero_process_nodes").split_structure_id) == ["split_a", "split_a", "split_b"]


def test_transitive_family_connections_and_degree_quantiles(tmp_path):
    processes = pd.DataFrame({"process_id": ["a", "b", "c", "d"],
                              "structure_id": ["A", "B", "C", "D"], "event_count": 1})
    creates = pd.DataFrame(columns=["parent_process_id", "child_process_id"])
    behavior = pd.DataFrame({"process_id": ["a", "b", "b", "c", "d"],
                             "behavior_type": "FILE", "action_raw": "READ",
                             "behavior_key": ["x", "x", "y", "y", "z"]})
    cfg = inputs(tmp_path / "inputs", processes=processes, creates=creates, behavior=behavior)
    audit = graph.build_graph(cfg)
    assert audit["weakly_connected_component_count"] == 2
    assert audit["largest_component_node_count"] == 5
    assert audit["largest_component_process_count"] == 3
    assert audit["percentage_process_nodes_in_largest_component"] == 75
    assert audit["shared_context_entity_count"] == 2
    assert audit["create_families_connected_through_shared_context_count"] == 3
    assert audit["merged_create_family_group_sizes"] == [3]
    assert audit["create_families_per_shared_context"]["frequency"] == {"2": 2}
    assert audit["median_context_node_degree"] == audit["p95_context_node_degree"] == 2


def test_publishing_failure_cleans_staging_without_touching_inputs(tmp_path, monkeypatch):
    cfg = inputs(tmp_path / "inputs")
    original = graph._file_hash(cfg.process_nodes)
    monkeypatch.setattr(pd.DataFrame, "to_parquet", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError, match="disk full"):
        graph.build_graph(cfg)
    assert not cfg.output_dir.exists()
    assert not list(cfg.output_dir.parent.glob(".period_graph_*"))
    assert graph._file_hash(cfg.process_nodes) == original
