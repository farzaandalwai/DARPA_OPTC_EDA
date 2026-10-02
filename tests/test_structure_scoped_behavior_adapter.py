"""Legacy-key controlled experiment contracts, with synthetic evidence only."""

from dataclasses import replace
import json
from pathlib import Path
import sys

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.eda import adapt_structure_scoped_behavior_links as adapter
from src.eda import build_period_heterogeneous_graph as graph


def frames():
    processes, edges = [], []
    for role in graph.PERIOD_ROLES:
        for name in ("a", "b"):
            processes.append({"period_role": role, "node_id": "legacy_" + name,
                              "node_type": "PROCESS", "process_id": "real_" + name,
                              "split_structure_id": role + "_family_" + name,
                              "reference_full_structure_id": "full_" + name})
        for name, kind, action, key in (("a", "FILE", "READ", "C:/same.txt"),
                                        ("b", "FILE", "READ", "C:/same.txt"),
                                        ("a", "MODULE", "LOAD", "C:/same.txt"),
                                        ("a", "DESTINATION", "START", "192.0.2.1:0080|tcp")):
            edges.append({"period_role": role, "split_structure_id": role + "_family_" + name,
                          "source_node_id": "legacy_" + name, "source_node_type": "PROCESS",
                          "target_node_id": role + "_" + kind + "_" + name, "target_node_type": kind,
                          "relation_type": f"PROCESS_{kind}_{action}", "behavior_key": key, "event_count": 3,
                          "first_seen_time": pd.Timestamp("2010-01-01"), "last_seen_time": pd.Timestamp("2030-01-01")})
    return pd.DataFrame(processes), pd.DataFrame(edges)


def graph_from_links(tmp_path, role, processes, links):
    root = tmp_path / role
    root.mkdir()
    nodes = processes.loc[processes.period_role == role].drop(columns=["node_id", "node_type"]).copy()
    nodes["event_total"] = 12
    nodes.to_parquet(root / "nodes.parquet", index=False)
    links.to_parquet(root / "links.parquet", index=False)
    pd.DataFrame({"parent_process_id": pd.Series(dtype="str"), "child_process_id": pd.Series(dtype="str"),
                  "create_event_count": pd.Series(dtype="int64"), "period_role": pd.Series(dtype="str")}).to_parquet(root / "create.parquet", index=False)
    (root / "features.json").write_text(json.dumps({"feature_columns": ["event_total"]}))
    config = graph.Config(root / "nodes.parquet", root / "create.parquet", root / "links.parquet",
                          root / "features.json", root / "graph", role,
                          structure_id_column="split_structure_id", context_key_policy="exact_behavior_key_v1")
    return config, graph.build_graph(config)


def test_shared_context_preserves_real_process_family_type_period_and_literal_key(tmp_path):
    processes, edges = frames()
    outputs, audit = adapter.convert_frames(processes, edges)
    assert audit["passed"] and audit["unique_old_context_node_count"] == 8
    assert audit["unique_new_type_key_count"] == 6
    assert audit["old_context_nodes_collapsed_by_sharing"] == 2
    assert audit["period_mismatches"] == audit["structure_mismatches"] == audit["unmatched_source_process_count"] == 0
    ids = []
    for role, links in outputs.items():
        assert set(links.process_id) == {"real_a", "real_b"}
        expected = processes.loc[processes.period_role == role].set_index("process_id")
        for column in adapter.FAMILY_COLUMNS[:2]:
            assert links[column].equals(links.process_id.map(expected[column]))
        assert not {"source_node_id", "target_node_id"} & set(links.columns)
        config, result = graph_from_links(tmp_path, role, processes, links)
        entities = pd.read_parquet(config.output_dir / "hetero_entity_nodes.parquet")
        assert result["file_node_count"] == result["module_node_count"] == result["destination_node_count"] == 1
        assert result["shared_context_entity_count"] == 1
        assert result["create_families_connected_through_shared_context_count"] == 2
        assert set(entities.canonical_key) == {"C:/same.txt", "192.0.2.1:0080|tcp"}
        assert entities.host_scope.eq("").all()
        nodes = pd.read_parquet(config.output_dir / "hetero_process_nodes.parquet")
        assert nodes.structure_id.equals(nodes.split_structure_id)
        assert "reference_full_structure_id" in nodes
        ids.append(set(entities.node_id))
    assert ids[0].isdisjoint(ids[1])


@pytest.mark.parametrize("relation,pair", list(adapter.RELATION_MAPPING.items()))
def test_exact_nine_relation_mapping(relation, pair):
    processes, edges = frames()
    edges = edges.iloc[:1].copy()
    edges["relation_type"] = relation
    edges["target_node_type"] = pair[0]
    output, audit = adapter.convert_frames(processes, edges)
    row = output["verified_benign"].iloc[0]
    assert (row.behavior_type, row.action_raw) == pair
    assert len(adapter.RELATION_MAPPING) == 9
    assert set(adapter.RELATION_MAPPING) == set(graph.FORWARD_RELATIONS[1:])
    assert audit["relation_counts_after"]["verified_benign"][relation]["event_count"] == 3


def test_duplicate_evidence_sums_counts_and_reconciles_time_extents_deterministically():
    processes, edges = frames()
    duplicate = edges.iloc[:1].copy()
    duplicate.target_node_id = "a_second_old_context"
    duplicate.event_count = 7
    duplicate.first_seen_time = pd.Timestamp("2009-01-01")
    duplicate.last_seen_time = pd.Timestamp("2031-01-01")
    edges = pd.concat([edges, duplicate], ignore_index=True)
    outputs, audit = adapter.convert_frames(processes, edges)
    row = outputs["verified_benign"].query("process_id == 'real_a' and behavior_type == 'FILE'").iloc[0]
    assert row.attach_event_count == 10
    assert row.first_seen_time == pd.Timestamp("2009-01-01") and row.last_seen_time == pd.Timestamp("2031-01-01")
    assert audit["event_count_total_before"] == audit["event_count_total_after"] == 31
    assert audit["duplicate_links_aggregated"] == 1
    shuffled, _ = adapter.convert_frames(processes.sample(frac=1, random_state=4), edges.sample(frac=1, random_state=7))
    for role in outputs:
        pd.testing.assert_frame_equal(outputs[role], shuffled[role])


def test_timestamps_do_not_assign_periods():
    processes, edges = frames()
    outputs, _ = adapter.convert_frames(processes, edges)
    # Both roles intentionally have the exact same times, outside either real
    # period. These are evidence summaries, never a temporal membership rule.
    assert all(len(output) == 4 for output in outputs.values())
    assert all(output.period_role.eq(role).all() for role, output in outputs.items())


@pytest.mark.parametrize("mutation,error", [
    (lambda frame: frame.drop(columns="period_role"), "missing explicit columns"),
    (lambda frame: frame.assign(period_role="train"), "unknown period_role"),
    (lambda frame: frame.assign(source_node_type="FILE"), "exactly PROCESS"),
    (lambda frame: frame.assign(target_node_type="SHELL"), "target_node_type"),
    (lambda frame: frame.assign(relation_type="PROCESS_FILE_OPEN"), "Unknown non-CREATE"),
    (lambda frame: frame.assign(relation_type="PROCESS_CREATE_PROCESS"), "Unknown non-CREATE"),
    (lambda frame: frame.assign(source_node_id="unmatched"), "unmatched PROCESS=2"),
    (lambda frame: frame.assign(split_structure_id="wrong"), "structure mismatches=8"),
    (lambda frame: frame.assign(behavior_key=""), "nonempty string"),
    (lambda frame: frame.assign(behavior_key=None), "nonempty string"),
    (lambda frame: frame.drop(columns="event_count"), "missing explicit columns"),
    (lambda frame: frame.assign(event_count=0), "positive"),
    (lambda frame: frame.assign(event_count=1.5), "integer evidence"),
    (lambda frame: frame.assign(event_count=True), "integer evidence"),
    (lambda frame: frame.assign(first_seen_time=pd.NaT), "non-null timestamp"),
    (lambda frame: frame.assign(last_seen_time=pd.Timestamp("2000-01-01")), "exceeds"),
])
def test_invalid_evidence_fails_clearly(mutation, error):
    processes, edges = frames()
    with pytest.raises(adapter.AdapterInputError, match=error) as exc:
        adapter.convert_frames(processes, mutation(edges))
    assert not exc.value.audit["passed"]


def test_process_join_period_mismatch_and_duplicate_nodes_fail():
    processes, edges = frames()
    processes = processes.loc[processes.period_role == "verified_benign"]
    with pytest.raises(adapter.AdapterInputError, match="period mismatches=4") as exc:
        adapter.convert_frames(processes, edges)
    assert exc.value.audit["period_mismatches"] == 4
    with pytest.raises(adapter.AdapterInputError, match="multiply evidence"):
        adapter.convert_frames(pd.concat([processes, processes]), edges.iloc[:4])


def test_conflicting_old_context_identity_and_overflow_fail():
    processes, edges = frames()
    edges.loc[1, "target_node_id"] = edges.loc[0, "target_node_id"]
    with pytest.raises(adapter.AdapterInputError, match="conflicting"):
        adapter.convert_frames(processes, edges)
    _, edges = frames()
    edges.event_count = 2**62
    with pytest.raises(adapter.AdapterInputError, match="overflow"):
        adapter.convert_frames(processes, edges)


def test_atomic_outputs_hashes_overwrite_refusal_and_audit_only(tmp_path, monkeypatch):
    processes, edges = frames()
    processes.to_parquet(tmp_path / "nodes.parquet", index=False)
    edges.to_parquet(tmp_path / "edges.parquet", index=False)
    cfg = adapter.Config(tmp_path / "nodes.parquet", tmp_path / "edges.parquet", tmp_path / "adapted")
    assert adapter.main(["--process-nodes", str(cfg.process_nodes), "--behavior-edges", str(cfg.behavior_edges),
                         "--output-dir", str(cfg.output_dir), "--audit-only"]) == 0
    assert not cfg.output_dir.exists()
    audit = adapter.adapt(cfg)
    for role in graph.PERIOD_ROLES:
        path = cfg.output_dir / f"{role}_behavior_links_v1.parquet"
        assert audit["output_sha256"][path.name] == graph._file_hash(path)
    assert audit["input_sha256"]["process_nodes"] == graph._file_hash(cfg.process_nodes)
    assert json.loads((cfg.output_dir / adapter.AUDIT_NAME).read_text()) == audit
    with pytest.raises(graph.GraphInputError, match="Refusing existing"):
        adapter.adapt(cfg)
    _, invalid = frames()
    invalid.relation_type = "unknown"
    invalid.to_parquet(cfg.behavior_edges, index=False)
    with pytest.raises(adapter.AdapterInputError):
        adapter.adapt(replace(cfg, output_dir=tmp_path / "must_not_exist"))
    assert not (tmp_path / "must_not_exist").exists()
    edges.to_parquet(cfg.behavior_edges, index=False)
    original_hash = graph._file_hash
    calls = 0

    def changed_source(path):
        nonlocal calls
        calls += 1
        return "changed" if calls == 3 else original_hash(path)

    monkeypatch.setattr(graph, "_file_hash", changed_source)
    with pytest.raises(adapter.AdapterInputError, match="changed during adaptation") as exc:
        adapter.adapt(replace(cfg, output_dir=tmp_path / "changed_source_must_not_publish"))
    assert not exc.value.audit["passed"]
    assert not (tmp_path / "changed_source_must_not_publish").exists()


def test_legacy_exact_identity_does_not_canonicalize_or_add_host_scope(tmp_path):
    processes, edges = frames()
    extra = edges.iloc[:1].copy()
    extra.behavior_key = "C:\\same.txt"
    extra.target_node_id = "another_raw_spelling"
    outputs, _ = adapter.convert_frames(processes, pd.concat([edges, extra], ignore_index=True))
    cfg, audit = graph_from_links(tmp_path, "verified_benign", processes, outputs["verified_benign"])
    assert audit["file_node_count"] == 2  # Slash variants deliberately stay distinct.
    for invalid in (replace(cfg, host_scope="host"), replace(cfg, context_key_policy="unknown")):
        with pytest.raises(graph.GraphInputError):
            graph.build_graph(invalid)
