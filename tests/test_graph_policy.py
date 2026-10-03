"""TRAIN freeze, exact identity transfer, immutable evidence and loader parity."""
from dataclasses import FrozenInstanceError
import json

import numpy as np
import pandas as pd
import pytest

from src.eda import audit_hybrid_graph_hubs as hub
from src.eda.build_period_heterogeneous_graph import EDGE_COLUMNS, RELATION_IDS, _digest
from src.graph import graph_policy as policy
from src.graph import audit_frozen_policies as runner


def fixture(role="verified_benign", module_key="common", host_scope="host"):
    p = pd.DataFrame({"node_id": ["p0", "p1", "p2", "p3"], "process_id": ["a", "b", "c", "d"],
                      "structure_id": ["f0", "f0", "f1", "f2"], "period_role": role})
    e = pd.DataFrame({"node_id": ["m", "f", "d"], "node_type": ["MODULE", "FILE", "DESTINATION"],
                      "host_scope": host_scope, "canonical_key": [module_key, "file", "address"], "period_role": role})
    x = pd.DataFrame([
        ("p0", "p1", "PROCESS", "PROCESS_CREATE_PROCESS", 2),
        ("p0", "m", "MODULE", "PROCESS_MODULE_LOAD", 9),
        ("p2", "m", "MODULE", "PROCESS_MODULE_LOAD", 3),
        ("p3", "m", "MODULE", "PROCESS_MODULE_LOAD", 1),
        ("p0", "f", "FILE", "PROCESS_FILE_READ", 5),
        ("p0", "f", "FILE", "PROCESS_FILE_WRITE", 6),
        ("p1", "f", "FILE", "PROCESS_FILE_READ", 7),
        ("p2", "d", "DESTINATION", "PROCESS_DESTINATION_MESSAGE", 11),
    ], columns=["source_id", "target_id", "target_type", "relation", "event_count"])
    x["source_type"], x["period_role"] = "PROCESS", role
    x["relation_id"] = x.relation.map(RELATION_IDS).astype("int64")
    x["edge_id"] = [_digest("edge_", [role, r, s, t]) for r, s, t in
                    x[["relation", "source_id", "target_id"]].itertuples(index=False, name=None)]
    return hub.prepare(p, e, x[EDGE_COLUMNS], role)


def saved(tmp_path, train=None):
    bundle = policy.freeze_training(train or fixture())
    bundle.save(tmp_path / "bundle")
    return policy.FrozenPolicies.load(tmp_path / "bundle")


def test_exact_train_definitions_and_unique_statistics():
    train = fixture()
    bundle = policy.freeze_training(train)
    meta = bundle.metadata
    assert (meta["training_process_count"], meta["training_family_count"]) == (4, 3)
    assert meta["policies"]["MODULE_FAMILY_FREQ_1PCT"]["per_node_type_thresholds"] == {
        "MODULE": .03, "FILE": None, "DESTINATION": None}
    assert meta["policies"]["ALL_TYPE_FAMILY_FREQ_5PCT"]["per_node_type_thresholds"] == dict.fromkeys(hub.TYPES, 3 * .05)
    row = bundle.statistics().set_index("canonical_key").loc["file"]
    assert (row.training_process_degree, row.training_distinct_family_count) == (2, 1)
    assert row.degree_weight == np.log(5/3) / np.log(5)  # not event/relation multiplicity


@pytest.mark.parametrize("name,mask,count", [
    ("FULL_SHARED", [True, True, True], 8),
    ("MODULE_FAMILY_FREQ_1PCT", [False, True, True], 5),
    ("ALL_TYPE_FAMILY_FREQ_5PCT", [False, False, False], 1),
    ("DEGREE_WEIGHTED_FULL", [True, True, True], 8),
])
def test_masks_process_create_and_raw_graph_preserved(name, mask, count):
    graph = fixture()
    before = graph.edges.copy(deep=True)
    view = policy.freeze_training(graph).view(graph, name)
    assert view.context_keep.tolist() == mask and view.process_keep.all()
    annotated = view.annotate_edges(graph.edges)
    assert annotated.keep_edge.sum() == count
    assert annotated.iloc[0].keep_edge and annotated.iloc[0].edge_weight == 1
    pd.testing.assert_frame_equal(before, graph.edges)
    pd.testing.assert_frame_equal(annotated[EDGE_COLUMNS], before)


def test_serialization_reproducibility_and_defensive_copies(tmp_path):
    original = policy.freeze_training(fixture())
    restored = saved(tmp_path)
    assert original == restored and original.fingerprint == restored.fingerprint
    pd.testing.assert_frame_equal(original.statistics(), restored.statistics())
    mutable = restored.metadata
    mutable["training_family_count"] = 9000
    mutable["policies"]["FULL_SHARED"]["name"] = "bad"
    frame = restored.statistics()
    frame.iloc[0, -1] = -10
    assert restored.metadata["training_family_count"] == 3
    assert restored.statistics().degree_weight.between(0, 1).all()
    with pytest.raises(FrozenInstanceError):
        restored.header_json = "{}"
    view = restored.view(fixture(), "FULL_SHARED")
    copy = view.contexts
    copy["keep_context"] = False
    assert view.context_keep.all()


def test_frozen_train_bundle_portable_paths_but_not_changed_bytes(tmp_path):
    graph = fixture()
    graph.input_inventory = {"graph.parquet": {"path": "/local/graph.parquet", "size_bytes": 100, "sha256": "a" * 64}}
    bundle = saved(tmp_path, graph)
    graph.input_inventory["graph.parquet"]["path"] = "/content/drive/graph.parquet"
    assert bundle.view(graph, "FULL_SHARED").context_keep.all()
    graph.input_inventory["graph.parquet"]["sha256"] = "b" * 64
    with pytest.raises(policy.PolicyError, match="differs"):
        bundle.view(graph, "FULL_SHARED")


def test_evaluation_must_load_cannot_fit_or_tune(tmp_path):
    eval_graph = fixture("evaluation")
    with pytest.raises(policy.PolicyError, match="training"):
        policy.freeze_training(eval_graph)
    with pytest.raises(policy.PolicyError, match="load"):
        policy.freeze_training(fixture()).view(eval_graph, "FULL_SHARED")
    restored = saved(tmp_path)
    fingerprint = restored.fingerprint
    # Make a known TRAIN MODULE low-degree / within one evaluation family.
    x = eval_graph.edges[~eval_graph.edges.source_id.isin(["p2", "p3"]) | eval_graph.edges.target_id.ne("m")]
    evaluation = hub.prepare(eval_graph.processes, eval_graph.entities, x, "evaluation")
    assert evaluation.profiles.iloc[0].distinct_family_count == 1
    view = restored.view(evaluation, "MODULE_FAMILY_FREQ_1PCT")
    assert not view.context_keep[0]  # still excluded from TRAIN statistic, not eval rank
    assert restored.fingerprint == fingerprint
    expected = np.log(5/4) / np.log(5)
    assert restored.view(evaluation, "DEGREE_WEIGHTED_FULL").contexts.iloc[0].edge_weight == expected


@pytest.mark.parametrize("name", policy.POLICY_NAMES)
def test_unseen_entities_retained_neutral_weight_no_labels(tmp_path, name):
    restored = saved(tmp_path)
    evaluation = fixture("evaluation", module_key="unseen")
    evaluation.processes["attack_label"] = "DO_NOT_READ"
    view = restored.view(evaluation, name)
    module = view.contexts.iloc[0]
    assert module.keep_context and module.edge_weight == 1 and not module.seen_in_training
    assert "attack_label" not in view.contexts
    evaluation.edges["attack_label"] = "DO_NOT_READ"
    assert "attack_label" not in view.annotate_edges(evaluation.edges)


def test_identity_namespace_type_host_key_not_node_id(tmp_path):
    restored = saved(tmp_path)
    other_host = fixture("evaluation", host_scope="other")
    assert restored.view(other_host, "ALL_TYPE_FAMILY_FREQ_5PCT").context_keep.all()
    graph = fixture("evaluation")
    graph.entities.loc[0, "canonical_key"] = "file"  # FILE name under MODULE type is unseen
    assert restored.view(graph, "MODULE_FAMILY_FREQ_1PCT").context_keep[0]


@pytest.mark.parametrize("name", policy.POLICY_NAMES)
def test_reverse_parity_exact_builder_ids_events_and_weights(name):
    graph = fixture()
    view = policy.freeze_training(graph).view(graph, name)
    forward, reverse = view.annotate_edges(graph.edges), view.mirror_forward(graph.edges)
    assert forward.keep_edge.tolist() == reverse.keep_edge.tolist()
    assert np.array_equal(forward.edge_weight, reverse.edge_weight)
    assert np.array_equal(forward.event_count, reverse.event_count)
    assert np.array_equal(reverse.relation_id, forward.relation_id + 10)
    assert np.array_equal(reverse.source_id, forward.target_id)
    for row in reverse.itertuples():
        assert row.edge_id == _digest("edge_", [graph.role, row.relation, row.source_id, row.target_id])
    with pytest.raises(policy.PolicyError, match="forward"):
        view.mirror_forward(reverse)


def test_weight_zero_does_not_delete_raw_topology():
    g = fixture()
    universal = pd.concat([g.edges, g.edges.iloc[[1]].assign(source_id="p1", edge_id="extra")], ignore_index=True)
    graph = hub.prepare(g.processes, g.entities, universal, g.role)
    view = policy.freeze_training(graph).view(graph, "DEGREE_WEIGHTED_FULL")
    assert view.contexts.iloc[0].edge_weight == 0
    assert view.context_keep.all() and view.annotate_edges(graph.edges).keep_edge.all()


def test_strict_family_cutoff_ties_kept():
    n = 100
    processes = pd.DataFrame({"node_id": [f"p{i}" for i in range(n)], "process_id": [f"x{i}" for i in range(n)],
                              "structure_id": [f"f{i}" for i in range(n)], "period_role": "verified_benign"})
    entities = fixture().entities.iloc[[0]].copy()
    edges = fixture().edges.iloc[[1]].copy()
    graph = hub.prepare(processes, entities, edges, "verified_benign")
    view = policy.freeze_training(graph).view(graph, "MODULE_FAMILY_FREQ_1PCT")
    assert view.context_keep.all()  # exactly one family = exactly 1%, not >1%


def test_context_free_train_serializes_and_retains_unseen_eval_contexts(tmp_path):
    original = fixture()
    graph = hub.prepare(original.processes, original.entities.iloc[:0], original.edges.iloc[:1], original.role)
    restored = saved(tmp_path, graph)
    assert restored.metadata["training_context_count"] == 0
    assert restored.view(graph, "FULL_SHARED").annotate_edges(graph.edges).keep_edge.all()
    evaluation = restored.view(fixture("evaluation"), "ALL_TYPE_FAMILY_FREQ_5PCT")
    assert evaluation.context_keep.all() and not evaluation.contexts.seen_in_training.any()


@pytest.mark.parametrize("column,value,match", [
    ("period_role", "evaluation", "isolation"), ("target_id", "bad", "endpoint"),
    ("relation_id", 19, "relation"), ("target_type", "FILE", "type"),
    ("event_count", 0, "count"), ("edge_id", "", "identifier"),
])
def test_loader_rejects_invalid_batch(column, value, match):
    graph = fixture()
    view = policy.freeze_training(graph).view(graph, "FULL_SHARED")
    invalid = graph.edges.copy()
    invalid.loc[0, column] = value
    with pytest.raises(ValueError, match=match):
        view.annotate_edges(invalid)


def test_cross_period_fit_and_changed_training_metadata_rejected():
    graph = fixture()
    bundle = policy.freeze_training(graph)
    graph.processes.loc[2, "period_role"] = "evaluation"
    with pytest.raises(policy.PolicyError, match="isolation"):
        policy.freeze_training(graph)
    graph.processes.loc[2, "period_role"] = graph.role
    graph.processes.loc[2, "structure_id"] = "different"
    with pytest.raises(policy.PolicyError, match="differs"):
        bundle.view(graph, "FULL_SHARED")


@pytest.mark.parametrize("what", ["threshold", "fingerprint", "statistics_hash", "path", "counts"])
def test_corrupt_or_changed_frozen_bundle_rejected(tmp_path, what):
    bundle = saved(tmp_path)
    path = tmp_path / "bundle" / "policy_bundle.json"
    doc = json.loads(path.read_text())
    if what == "threshold":
        doc["metadata"]["policies"]["MODULE_FAMILY_FREQ_1PCT"]["family_frequency_percent"] = 20
    elif what == "fingerprint":
        doc["fingerprint"] = "bad"
    elif what == "statistics_hash":
        doc["statistics_sha256"] = "bad"
    elif what == "path":
        doc["statistics_file"] = "../another.parquet"
    else:
        doc["metadata"]["training_context_count"] = 9999
    path.write_text(json.dumps(doc))
    with pytest.raises(policy.PolicyError):
        policy.FrozenPolicies.load(tmp_path / "bundle")
    assert bundle.fingerprint  # existing in-memory snapshot remains immutable


def test_existing_output_refused_and_fresh_stream_no_graph_copies(tmp_path):
    graph = fixture()
    view = policy.freeze_training(graph).view(graph, "DEGREE_WEIGHTED_FULL")
    raw = pd.concat([graph.edges, view.mirror_forward(graph.edges)[EDGE_COLUMNS]], ignore_index=True)
    path = tmp_path / "edges.parquet"
    raw.to_parquet(path, index=False)
    before = hub.digest(path)
    batches = list(view.iter_edge_batches(path, 3))
    assert sum(len(b) for b in batches) == 16
    checked = runner.stream_verify(view, path)
    assert checked["retained_bidirectional_rows"] == 16
    assert checked["all_20_relation_counts_events_weights_reconciled"]
    assert hub.digest(path) == before
    bundle = saved(tmp_path)
    with pytest.raises(policy.PolicyError, match="existing"):
        bundle.save(tmp_path / "bundle")
    with pytest.raises(policy.PolicyError, match="batch_size"):
        list(view.iter_edge_batches(path, 0))


@pytest.mark.parametrize("mode", ["inside", "same", "ancestor", "exists"])
def test_runner_source_output_guards(tmp_path, mode):
    source = tmp_path / "source"
    source.mkdir()
    choices = {"inside": source / "out", "same": source, "ancestor": tmp_path, "exists": tmp_path / "exists"}
    if mode == "exists":
        choices[mode].mkdir()
    with pytest.raises(policy.PolicyError):
        runner.guard_output(choices[mode], source)


def test_count_reconciliation_fail_closed():
    with pytest.raises(policy.PolicyError, match="mismatch"):
        runner.reconcile({"process_count": 4}, {"process_count": 5})
    with pytest.raises(policy.PolicyError, match="missing"):
        runner.reconcile({}, {"create_edge_count": 1})


def test_all_policies_reconcile_prior_audit_logic(tmp_path):
    train = fixture()
    frozen, old_weights = hub.freeze_policies(train)
    bundle = saved(tmp_path, train)
    for graph in (train, fixture("evaluation", module_key="unseen")):
        for name in policy.POLICY_NAMES:
            old_name = runner.PREVIOUS_NAMES[name]
            old = next(p for p in frozen["policies"] if p["name"] == old_name)
            view = bundle.view(graph, name)
            assert np.array_equal(view.context_keep, hub.policy_mask(graph, old))
            if name == "DEGREE_WEIGHTED_FULL":
                assert np.array_equal(view.contexts.edge_weight, hub.joined_weights(graph, old_weights).weight_degree)


def write_contract(root, role):
    root.mkdir()
    graph = fixture(role, module_key="unseen" if role == "evaluation" else "common")
    process = graph.processes.assign(attack_label="DO_NOT_READ", feature_column=123)
    process.to_parquet(root / hub.INPUTS[0], index=False)
    graph.entities.to_parquet(root / hub.INPUTS[1], index=False)
    graph.edges.to_parquet(root / hub.INPUTS[2], index=False)
    reverse = policy.freeze_training(fixture()).view(fixture(), "FULL_SHARED").mirror_forward(fixture().edges)
    # Build the exact evaluation mirror via the original builder formula, not
    # an evaluation fit. Endpoint topology is identical in this fixture.
    reverse = reverse[EDGE_COLUMNS].assign(period_role=role)
    reverse["edge_id"] = [_digest("edge_", [role, r, s, t]) for r, s, t in
                          reverse[["relation", "source_id", "target_id"]].itertuples(index=False, name=None)]
    pd.concat([graph.edges, reverse], ignore_index=True).to_parquet(root / "hetero_graph_edges_bidirectional.parquet", index=False)
    pd.DataFrame({"relation": list(RELATION_IDS), "relation_id": list(RELATION_IDS.values())}).to_csv(root / "relation_type_mapping.csv", index=False)
    (root / hub.INPUTS[3]).write_text(json.dumps({"period_role": role, "process_node_count": 4,
                                                "total_entity_node_count": 3, "forward_edge_count": 8}))
    return {"published_files": [{"name": name, "size": (root / name).stat().st_size,
                                  "sha256": hub.digest(root / name)} for name in runner.SOURCE_FILES], "missing_files": []}


def test_end_to_end_freezes_before_eval_reads_no_labels_no_graph_writes(tmp_path, monkeypatch):
    train, evaluation, output, evidence = [tmp_path / p for p in ("train", "evaluation", "output", "evidence")]
    evidence.mkdir()
    manifest = {"publication": {"verified_benign": write_contract(train, "verified_benign"),
                                "evaluation": write_contract(evaluation, "evaluation")}}
    manifest_path = evidence / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    gtrain = hub.load_graph(train, "verified_benign", manifest)
    frozen, weights = hub.freeze_policies(gtrain)
    old_report = {"status": "COMPLETE", "two_hop_sample_size": 4, "input_inventory": {}, "variants": {}}
    for role, folder in (("verified_benign", train), ("evaluation", evaluation)):
        g = hub.load_graph(folder, role, manifest)
        old_report["input_inventory"][role] = g.input_inventory
        old_report["variants"][role] = []
        for old_name in runner.PREVIOUS_NAMES.values():
            old_policy = next(p for p in frozen["policies"] if p["name"] == old_name)
            metrics = hub.topology(g, hub.policy_mask(g, old_policy), hub.deterministic_sample(g, 4))
            if old_name == "WEIGHTED_FULL_DEGREE":
                metrics["weight_exposure"] = hub.weight_exposure(g, hub.joined_weights(g, weights), "degree")
            old_report["variants"][role].append({"policy": old_name, **metrics})
    old_path = evidence / "hub.json"
    old_path.write_text(json.dumps(old_report))
    original = hub.load_graph
    calls = []
    def guarded_load(folder, role, manifest):
        if role == "evaluation":
            assert (output / "frozen_policy" / "policy_bundle.json").exists()
            policy.FrozenPolicies.load(output / "frozen_policy")
        g = original(folder, role, manifest)
        assert "attack_label" not in g.processes and "feature_column" not in g.processes
        calls.append(role)
        return g
    monkeypatch.setattr(hub, "load_graph", guarded_load)
    before = {p: hub.digest(p) for root in (train, evaluation) for p in root.iterdir()}
    report = runner.run(train, evaluation, output, manifest_path, old_path)
    assert calls == ["verified_benign", "evaluation"]
    assert report["status"] == "COMPLETE" and report["all_12_source_files_byte_identical"]
    assert report["all_four_policies_reconciled_both_periods"]
    assert not report["evaluation_ground_truth_read"] and not report["graph_files_written"]
    assert all(hub.digest(p) == sha for p, sha in before.items())
    assert {p.name for p in output.rglob("*.parquet")} == {
        "context_statistics.parquet", "verified_benign_context_decisions.parquet", "evaluation_context_decisions.parquet"}
