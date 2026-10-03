"""Exact synthetic hub controls, leakage boundaries and immutable-source tests."""
import json
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pandas as pd
import pytest

from src.eda import audit_hybrid_graph_hubs as hub


def fixture(role="verified_benign", module_key="common.dll", count=True):
    p = pd.DataFrame({"node_id": ["p0", "p1", "p2", "p3"],
                      "process_id": ["a", "b", "c", "d"],
                      "structure_id": ["f0", "f0", "f1", "f2"], "period_role": role})
    e = pd.DataFrame({"node_id": ["m", "f", "d"], "node_type": ["MODULE", "FILE", "DESTINATION"],
                      "canonical_key": [module_key, "x", "addr"], "host_scope": "", "period_role": role})
    rows = [("p0", "p1", "PROCESS", "PROCESS_CREATE_PROCESS"),
            ("p0", "m", "MODULE", "PROCESS_MODULE_LOAD"),
            ("p2", "m", "MODULE", "PROCESS_MODULE_LOAD"),
            ("p3", "m", "MODULE", "PROCESS_MODULE_LOAD"),
            ("p0", "f", "FILE", "PROCESS_FILE_READ"),
            ("p0", "f", "FILE", "PROCESS_FILE_WRITE"),
            ("p1", "f", "FILE", "PROCESS_FILE_READ"),
            ("p2", "d", "DESTINATION", "PROCESS_DESTINATION_MESSAGE")]
    edges = pd.DataFrame(rows, columns=["source_id", "target_id", "target_type", "relation"])
    edges["source_type"] = "PROCESS"
    edges["period_role"] = role
    if count:
        edges["event_count"] = [2, 9, 3, 1, 5, 6, 7, 11]
    return p, e, edges


def graph(role="verified_benign", **kwargs):
    return hub.prepare(*fixture(role, **kwargs), role)


def test_profile_counts_unique_processes_families_and_events_not_relations():
    g = graph()
    file = g.profiles.set_index("node_id").loc["f"]
    assert (file.process_degree, file.distinct_family_count, file.event_count, file.compact_edge_count) == (2, 1, 18, 3)
    module = g.profiles.set_index("node_id").loc["m"]
    assert (module.process_degree, module.distinct_family_count) == (3, 3)
    assert file.process_degree_percentile_weak == 100
    assert file.process_degree_rank_desc_min == 1
    read = g.relation_profiles[g.relation_profiles.relation == "PROCESS_FILE_READ"]
    assert read.iloc[0].process_degree == 2 and read.iloc[0].event_count == 12


def test_family_frequency_distinguishes_within_family_degree():
    g = graph()
    frozen, _ = hub.freeze_policies(g)
    policy = next(p for p in frozen["policies"] if p["name"] == "FAMILY_FREQ_GT_10PCT")
    assert policy["cutoffs"]["FILE"] == pytest.approx(0.3)
    assert g.profiles.set_index("node_id").loc["f"].families_per_process_neighbor == 0.5


def test_create_and_process_universe_survive_context_filter():
    g = graph()
    baseline = hub.topology(g, np.ones(3, bool), np.arange(4))
    filtered = hub.topology(g, np.array([False, True, True]), np.arange(4))
    assert baseline["weakly_connected_component_count"] == 1
    assert baseline["largest_component_process_count"] == 4
    assert baseline["create_families_bridged_by_shared_context"] == 3
    assert filtered["weakly_connected_component_count"] == 3
    assert filtered["largest_component_process_count"] == 2
    assert filtered["create_families_bridged_by_shared_context"] == 0
    assert filtered["retained_forward_edge_count"] == 5
    assert filtered["create_topology_sha256"] == baseline["create_topology_sha256"]
    assert filtered["create_topology_unchanged"] and filtered["process_count"] == 4
    assert filtered["retained_context_edges_percent"] == pytest.approx(100 * 4 / 7)


def test_all_contexts_removed_preserves_isolated_processes_and_create():
    g = graph()
    out = hub.topology(g, np.zeros(3, bool), np.arange(4))
    assert out["weakly_connected_component_count"] == 3
    assert out["context_degree"]["count"] == 0
    assert out["retained_forward_edge_count"] == 1
    assert out["create_edge_count"] == 1


def test_neighborhood_exact_against_breadth_first_search():
    g = graph()
    adj, _ = hub.adjacency(g, np.ones(3, bool))
    measured = hub.neighborhood_stats(adj, 4, np.arange(4))
    counts, process_counts = [], []
    for seed in range(4):
        visited = set(adj[seed].indices)
        for neighbor in list(visited):
            visited.update(adj[neighbor].indices)
        visited.discard(seed)
        counts.append(len(visited))
        process_counts.append(len(visited & set(range(4))))
    assert measured["two_hop_sampled_all_node_count"] == hub.summary(counts)
    assert measured["two_hop_sampled_process_count"] == hub.summary(process_counts)


def test_frozen_identity_exclusions_not_evaluation_refitted():
    train = graph()
    frozen, weights = hub.freeze_policies(train)
    policy = next(p for p in frozen["policies"] if p["name"] == "MODULE_FAMILY_FREQ_GT_10PCT")
    evaluation = graph("evaluation")
    # Change evaluation node IDs / period only: membership transfers by identity.
    assert hub.policy_mask(evaluation, policy).tolist() == [False, True, True]
    unseen = graph("evaluation", module_key="unseen.dll")
    assert hub.policy_mask(unseen, policy).all()
    joined = hub.joined_weights(unseen, weights)
    assert joined.iloc[0].weight_degree == 1 and not joined.iloc[0].seen_in_training
    assert frozen["training_process_count"] == 4
    assert frozen["training_family_count"] == 3


def test_weight_formula_and_universal_context():
    train = graph()
    _, weights = hub.freeze_policies(train)
    module = weights[weights.node_type == "MODULE"].iloc[0]
    assert module.weight_family == 0
    assert module.weight_degree == pytest.approx(np.log(5 / 4) / np.log(5))
    assert module.weight_geometric == 0
    assert weights[["weight_family", "weight_degree", "weight_geometric"]].ge(0).all().all()
    assert weights[["weight_family", "weight_degree", "weight_geometric"]].le(1).all().all()


def test_no_evaluation_policy_derivation():
    with pytest.raises(hub.HubAuditError, match="training"):
        hub.freeze_policies(graph("evaluation"))


def test_cutoff_ties_retained_and_rank_ties_explicit():
    p, e, edges = fixture()
    e2 = e.iloc[[1]].copy()
    e2["node_id"] = "f2"
    e2["canonical_key"] = "x2"
    edge2 = edges[edges.target_id == "f"].copy()
    edge2["target_id"] = "f2"
    g = hub.prepare(p, pd.concat([e, e2], ignore_index=True), pd.concat([edges, edge2], ignore_index=True), "verified_benign")
    policies, _ = hub.freeze_policies(g)
    degree = next(x for x in policies["policies"] if x["name"] == "DEGREE_P99")
    assert degree["cutoffs"]["FILE"] == 2
    assert hub.policy_mask(g, degree).all()
    files = g.profiles[g.profiles.node_type == "FILE"]
    assert files.process_degree_rank_desc_min.eq(1).all()
    assert files.process_degree_percentile_weak.eq(100).all()


@pytest.mark.parametrize("change,match", [
    (lambda p,e,x: x.__setitem__("period_role", "evaluation"), "isolation"),
    (lambda p,e,x: x.loc.__setitem__((0,"target_id"), "unknown"), "endpoint"),
    (lambda p,e,x: p.loc.__setitem__((1,"structure_id"), "f1"), "crosses"),
    (lambda p,e,x: x.loc.__setitem__((1,"relation"), "REV__PROCESS_MODULE_LOAD"), "forward"),
    (lambda p,e,x: x.loc.__setitem__((1,"target_type"), "FILE"), "type"),
    (lambda p,e,x: x.loc.__setitem__((1,"event_count"), 0), "event_count"),
    (lambda p,e,x: p.loc.__setitem__((0,"structure_id"), ""), "identifier"),
    (lambda p,e,x: e.loc.__setitem__((0,"node_type"), "HOST"), "context type"),
])
def test_rejects_bad_inputs(change, match):
    p, e, edges = fixture()
    change(p, e, edges)
    with pytest.raises(hub.HubAuditError, match=match):
        hub.prepare(p, e, edges, "verified_benign")


def test_duplicate_compact_edges_rejected():
    p,e,x = fixture()
    with pytest.raises(hub.HubAuditError, match="compact"):
        hub.prepare(p,e,pd.concat([x,x.iloc[[0]]],ignore_index=True),"verified_benign")


def test_event_count_absence_is_explicit_not_invented():
    g = graph(count=False)
    assert g.profiles.event_count.isna().all()
    report = hub.distribution_report(g.profiles, "node_type")
    assert report["MODULE"]["event_count"]["count"] == 0


def write_graph(root, role):
    root.mkdir()
    p,e,x = fixture(role)
    p["evaluation_ground_truth"] = ["DO_NOT_READ"] * 4
    for name, frame in zip(hub.INPUTS[:3], (p,e,x)):
        frame.to_parquet(root / name, index=False)
    (root / hub.INPUTS[3]).write_text(json.dumps({"period_role": role, "process_node_count": len(p),
        "total_entity_node_count": len(e), "forward_edge_count": len(x)}))


def test_end_to_end_frozen_before_evaluation_no_source_mutation_no_graph_copies(tmp_path):
    train, evaluation, out = [tmp_path / s for s in ("train", "evaluation", "out")]
    write_graph(train, "verified_benign")
    write_graph(evaluation, "evaluation")
    before = {p: hub.digest(p) for root in (train, evaluation) for p in root.iterdir()}
    original = hub.load_graph
    calls = []
    def guarded_load(folder, role, manifest):
        if role == "evaluation":
            assert (out / "frozen_training_policies.json").is_file()
            assert (out / "verified_benign_variants.json").is_file()
        calls.append(role)
        return original(folder, role, manifest)
    with patch.object(hub, "load_graph", guarded_load), patch.object(pd, "read_parquet", wraps=pd.read_parquet) as read:
        report = hub.run_audit(train,evaluation,out,sample_size=4)
        for call in read.call_args_list:
            assert "evaluation_ground_truth" not in call.kwargs["columns"]
    assert calls == ["verified_benign", "evaluation"]
    assert report["status"] == "COMPLETE" and report["create_topology_unchanged_all_variants"]
    assert report["process_counts_unchanged_all_variants"]
    assert not report["evaluation_ground_truth_read"] and not report["model_training_performed"]
    assert before == {p: hub.digest(p) for p in before}
    assert not any(p.name.startswith("hetero_graph") for p in out.iterdir())
    assert len(report["variants"]["verified_benign"]) == 19
    full = report["variants"]["verified_benign"][0]
    for v in report["variants"]["verified_benign"]:
        if v["category"] == "E":
            assert v["largest_component_process_count"] == full["largest_component_process_count"]
            assert v["retained_forward_edge_count"] == full["retained_forward_edge_count"]
    with pytest.raises(hub.HubAuditError, match="existing"):
        hub.run_audit(train,evaluation,out)


@pytest.mark.parametrize("sample_size", [0,129])
def test_sample_memory_limit(tmp_path,sample_size):
    with pytest.raises(hub.HubAuditError, match="sample_size"):
        hub.run_audit(tmp_path/"train",tmp_path/"eval",tmp_path/"out",sample_size=sample_size)


def test_output_cannot_be_inside_source(tmp_path):
    with pytest.raises(hub.HubAuditError, match="separate"):
        hub.run_audit(tmp_path/"train",tmp_path/"eval",tmp_path/"train"/"out")


def test_manifest_hash_mismatch_fails_before_output(tmp_path):
    train, evaluation, out = [tmp_path / s for s in ("train", "evaluation", "out")]
    write_graph(train, "verified_benign")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"publication": {"verified_benign": {"published_files": [
        {"name": name, "sha256": "wrong", "size": 1} for name in hub.INPUTS], "missing_files": []}}}))
    with pytest.raises(hub.HubAuditError, match="differs"):
        hub.run_audit(train, evaluation, out, manifest)
    assert not out.exists()


def test_diagnostic_type_rules_include_unseen_evaluation_modules():
    frozen, _ = hub.freeze_policies(graph())
    eval_graph = graph("evaluation", module_key="unseen.dll")
    module_off = next(p for p in frozen["policies"] if p["name"] == "MODULE_SHARING_OFF_DIAGNOSTIC")
    create_only = next(p for p in frozen["policies"] if p["name"] == "CREATE_ONLY_DIAGNOSTIC")
    assert hub.policy_mask(eval_graph, module_off).tolist() == [False, True, True]
    assert not hub.policy_mask(eval_graph, create_only).any()


def test_matched_degree_policy_removes_same_number_by_type_as_family_policy():
    g = graph()
    frozen, _ = hub.freeze_policies(g)
    family = next(p for p in frozen["policies"] if p["name"] == "FAMILY_FREQ_GT_1PCT")
    degree = next(p for p in frozen["policies"] if p["name"] == "DEGREE_MATCHED_FAMILY_1PCT_BUDGET")
    for t in hub.TYPES:
        in_type = g.entities.node_type.eq(t).to_numpy()
        assert (~hub.policy_mask(g, family) & in_type).sum() == (~hub.policy_mask(g, degree) & in_type).sum()
    assert degree["derivation"]["matched_policy"] == family["name"]
