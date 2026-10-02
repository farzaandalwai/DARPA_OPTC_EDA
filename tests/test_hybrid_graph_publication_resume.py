"""Synthetic publication safety tests; no graph construction or dataset claims."""

from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.eda import resume_sysclient0201_hybrid_graph_publication as publication


@pytest.fixture
def run(tmp_path):
    complete, drive = tmp_path / "complete", tmp_path / "drive"
    manifest = {"both_hybrid_graphs_completed": True, "compatibility_audit_passed": True,
                "hybrid_graphs": {}, "publication": {}}
    for role in publication.ROLES:
        folder = complete / publication.OUTPUT_NAMES[role]
        folder.mkdir(parents=True)
        audit = {key: 1 for key in publication.METRICS}
        audit.update(total_entity_node_count=1, bidirectional_relation_count=20,
                     period_role=role, output_sha256={})
        for name, count in publication.FILES.items():
            if name.endswith(".parquet"):
                pd.DataFrame({"period_role": [role], "value": [1]}).to_parquet(folder / name, index=False)
            elif name.endswith(".csv"):
                pd.DataFrame({"relation_id": range(20)}).to_csv(folder / name, index=False)
            else:
                continue
            audit["output_sha256"][name] = publication.digest(folder / name)
        (folder / "graph_connectivity_audit.json").write_text(json.dumps(audit))
        manifest["hybrid_graphs"][role] = audit
        manifest["publication"][role] = {"published_files": [
            {"name": name, "size": str((folder / name).stat().st_size),
             "sha256": publication.digest(folder / name)} for name in publication.FILES],
            "missing_files": []}
        shutil.copytree(folder, drive / publication.OUTPUT_NAMES[role])
        (drive / publication.OUTPUT_NAMES[role] / "publication_status.json").write_text("historical marker")
    return complete, drive, manifest


def call(run, **kwargs):
    complete, drive, manifest = run
    return publication.resume(drive, manifest, checkout={"git_head": "synthetic"}, **kwargs)


def snapshots(root):
    return {str(p.relative_to(root)): (p.read_bytes(), p.stat().st_mtime_ns)
            for p in root.rglob("*") if p.is_file()}


def missing(run, role="verified_benign", name="hetero_graph_edges_forward.parquet"):
    _, drive, _ = run
    path = drive / publication.OUTPUT_NAMES[role] / name
    path.unlink()
    return path


def test_complete_is_read_only_even_without_recovery_sources(run):
    before = snapshots(run[1])
    report = call(run)
    assert report["overall_status"] == "COMPLETE"
    assert len(report["already_valid_files"]) == 12
    assert not report["restored_files"]
    assert not report["graph_rebuild_attempted"]
    assert before == snapshots(run[1])


def test_copy_only_missing_training_edges_and_idempotent(run):
    paths = [missing(run, name=name) for name in
             ("hetero_graph_edges_forward.parquet", "hetero_graph_edges_bidirectional.parquet")]
    before = snapshots(run[1])
    report = call(run, completed_root=run[0])
    assert report["overall_status"] == "COMPLETE"
    assert len(report["restored_files"]) == 2
    for path in paths:
        assert path.read_bytes() == (run[0] / path.parent.name / path.name).read_bytes()
    assert all(snapshots(run[1])[key] == value for key, value in before.items())
    after = snapshots(run[1])
    assert call(run, completed_root=run[0])["overall_status"] == "COMPLETE"
    assert snapshots(run[1]) == after


@pytest.mark.parametrize("role", publication.ROLES)
def test_any_existing_mismatch_prevents_all_writes(run, role):
    missing(run)
    corrupt = run[1] / publication.OUTPUT_NAMES[role] / "hetero_entity_nodes.parquet"
    corrupt.write_bytes(b"truncated")
    before = snapshots(run[1])
    report = call(run, completed_root=run[0])
    assert report["overall_status"] == "INCOMPLETE"
    assert "existing artifact mismatch" in report["errors"][0]
    assert not report["temporary_files"]
    assert snapshots(run[1]) == before


def test_same_size_hash_mismatch_is_not_overwritten(run):
    path = run[1] / publication.OUTPUT_NAMES["evaluation"] / "relation_type_mapping.csv"
    original = path.read_bytes()
    path.write_bytes(original.replace(b"0", b"1", 1))
    report = call(run)
    file = report["periods"]["evaluation"]["files"][path.name]
    assert file["size_bytes"] == len(original)
    assert file["status"] == "MISMATCH"
    assert "sha256 differs from completed run" in file["errors"]
    assert path.read_bytes() != original


def test_non_object_audit_stops_with_full_inventory(run):
    path = run[1] / publication.OUTPUT_NAMES["evaluation"] / "graph_connectivity_audit.json"
    path.write_text("[]")
    before = snapshots(run[1])
    report = call(run, completed_root=run[0])
    assert report["overall_status"] == "INCOMPLETE"
    assert "JSON object" in report["errors"][0]
    assert len(report["periods"]["verified_benign"]["files"]) == 6
    assert snapshots(run[1]) == before


def test_existing_report_refused_before_any_graph_write(run, tmp_path, monkeypatch):
    path = missing(run)
    report_path = tmp_path / "report.json"
    report_path.write_bytes(b"valid historical report")
    monkeypatch.setattr(sys, "argv", ["resume", "--data-root", str(run[1]),
                                    "--completed-root", str(run[0]), "--report", str(report_path)])
    with pytest.raises(FileExistsError):
        publication.main()
    assert not path.exists()
    assert report_path.read_bytes() == b"valid historical report"


def test_unrecoverable_missing_bytes_stops_no_rebuild(run):
    missing(run)
    before = snapshots(run[1])
    report = call(run)
    assert report["overall_status"] == "INCOMPLETE"
    assert "NO rebuild" in report["errors"][0]
    assert snapshots(run[1]) == before


def test_all_missing_sources_preflight_before_first_write(run):
    first = missing(run)
    second = missing(run, name="hetero_graph_edges_bidirectional.parquet")
    (run[0] / second.parent.name / second.name).unlink()
    before = snapshots(run[1])
    report = call(run, completed_root=run[0])
    assert report["overall_status"] == "INCOMPLETE"
    assert not first.exists() and not second.exists()
    assert snapshots(run[1]) == before


def test_bad_completed_source_stops_instead_of_falling_back(run):
    path = missing(run)
    (run[0] / path.parent.name / path.name).write_bytes(b"bad source")
    report = call(run, completed_root=run[0])
    assert "completed source mismatch" in report["errors"][0]
    assert not path.exists()


def test_lossless_parts_restore_real_file_bytes(run, tmp_path):
    path = missing(run)
    parts = tmp_path / "parts"
    transport = publication.pack_sources(run[2], run[0], parts, ["verified_benign/" + path.name], chunk_bytes=31)
    report = call(run, parts_root=parts, transport=transport)
    assert report["overall_status"] == "COMPLETE"
    assert path.read_bytes() == (run[0] / path.parent.name / path.name).read_bytes()


@pytest.mark.parametrize("problem", ["missing", "hash", "order", "path", "full_hash", "commit"])
def test_bad_parts_stop_before_destination_writes(run, tmp_path, problem):
    path = missing(run)
    parts = tmp_path / "parts"
    transport = publication.pack_sources(run[2], run[0], parts, ["verified_benign/" + path.name], chunk_bytes=100)
    entry = transport["files"]["verified_benign/" + path.name]
    part = entry["parts"][0]
    if problem == "missing":
        (parts / part["name"]).unlink()
    elif problem == "hash":
        (parts / part["name"]).write_bytes(b"x" * part["size_bytes"])
    elif problem == "order":
        part["index"] = 42
    elif problem == "path":
        part["name"] = "../unsafe"
    elif problem == "full_hash":
        entry["expected"]["sha256"] = "a" * 64
    else:
        transport["verified_run_commit"] = "wrong"
    before = snapshots(run[1])
    report = call(run, parts_root=parts, transport=transport)
    assert report["overall_status"] == "INCOMPLETE"
    assert report["errors"]
    assert not report["temporary_files"]
    assert snapshots(run[1]) == before


def test_failed_copy_preserves_temporary_and_invalid_final_evidence(run, monkeypatch):
    path = missing(run)
    before = snapshots(run[1])
    def fail(source, output, **kwargs):
        output.write(b"partial evidence")
        raise OSError("simulated transfer interruption")
    monkeypatch.setattr(publication.shutil, "copyfileobj", fail)
    report = call(run, completed_root=run[0])
    assert report["overall_status"] == "INCOMPLETE"
    assert path.read_bytes() == b"partial evidence"
    assert report["invalid_partial_destinations"] == [str(path)]
    assert report["periods"]["verified_benign"]["files"][path.name]["status"] == "INVALID_PARTIAL"
    temporary = Path(report["temporary_files"][0])
    assert publication.digest(temporary) == publication.digest(run[0] / path.parent.name / path.name)
    assert all(snapshots(run[1])[key] == value for key, value in before.items())
    assert not report["deleted_verified_temporary_files"]
    # A retry refuses the mismatched existing final, rather than overwriting it.
    after = snapshots(run[1])
    assert "existing artifact mismatch" in call(run, completed_root=run[0])["errors"][0]
    assert snapshots(run[1]) == after


def test_destination_race_never_overwrites(run, monkeypatch):
    path = missing(run)
    publish = publication.copy_verified_to_final
    def race(temporary, final, spec, audit, report):
        final.write_bytes(b"concurrent writer")
        publish(temporary, final, spec, audit, report)
    monkeypatch.setattr(publication, "copy_verified_to_final", race)
    report = call(run, completed_root=run[0])
    assert report["overall_status"] == "INCOMPLETE"
    assert path.read_bytes() == b"concurrent writer"
    assert Path(report["temporary_files"][0]).is_file()


def test_exclusive_create_handles_race_after_destination_check(run, monkeypatch):
    final, temporary = existing_temporary(run, "hetero_graph_edges_forward.parquet")
    original_open = Path.open
    def racing_open(path, mode="r", *args, **kwargs):
        if path == final and mode == "xb" and not path.exists():
            with original_open(final, "wb") as writer:
                writer.write(b"concurrent destination")
        return original_open(path, mode, *args, **kwargs)
    monkeypatch.setattr(Path, "open", racing_open)
    report = call(run)
    assert report["overall_status"] == "INCOMPLETE"
    assert final.read_bytes() == b"concurrent destination"
    assert temporary.is_file()
    assert report["copy_results"][0]["status"] == "DESTINATION_CONFLICT"
    assert report["invalid_partial_destinations"] == []


def existing_temporary(run, name, suffix="nhv7lc4g"):
    final = missing(run, name=name)
    temporary = final.parent / f".{name}.{suffix}.partial"
    shutil.copyfile(run[0] / final.parent.name / name, temporary)
    return final, temporary


def test_reuse_both_verified_temporaries_without_any_reconstruction(run, monkeypatch):
    pairs = [existing_temporary(run, name) for name in
             ("hetero_graph_edges_forward.parquet", "hetero_graph_edges_bidirectional.parquet")]
    def forbidden(*args, **kwargs):
        pytest.fail("verified temporaries must bypass chunks/reconstruction/rename/link")
    monkeypatch.setattr(publication, "recovery_sources", forbidden)
    monkeypatch.setattr(publication.tempfile, "mkstemp", forbidden)
    monkeypatch.setattr(publication.os, "rename", forbidden)
    monkeypatch.setattr(publication.os, "link", forbidden)
    report = call(run)
    assert report["overall_status"] == "COMPLETE"
    assert set(report["reused_temporary_files"]) == {str(t) for _, t in pairs}
    assert report["reconstructed_temporary_files"] == []
    assert set(report["deleted_verified_temporary_files"]) == {str(t) for _, t in pairs}
    for final, temporary in pairs:
        assert not temporary.exists()
        assert publication.digest(final) == publication.digest(run[0] / final.parent.name / final.name)
    before = snapshots(run[1])
    assert call(run)["restored_files"] == []
    assert snapshots(run[1]) == before


def test_reuse_bidirectional_and_reconstruct_only_forward_from_parts(run, tmp_path, monkeypatch):
    bidirectional, temporary = existing_temporary(run, "hetero_graph_edges_bidirectional.parquet")
    forward = missing(run)
    parts = tmp_path / "forward_parts_only"
    transport = publication.pack_sources(run[2], run[0], parts,
                                          ["verified_benign/" + forward.name], chunk_bytes=100)
    recovery = publication.recovery_sources
    requested = []
    def observed(role, name, *args):
        requested.append(name)
        return recovery(role, name, *args)
    monkeypatch.setattr(publication, "recovery_sources", observed)
    report = call(run, parts_root=parts, transport=transport)
    assert report["overall_status"] == "COMPLETE"
    assert requested == [forward.name]
    assert report["reused_temporary_files"] == [str(temporary)]
    assert len(report["reconstructed_temporary_files"]) == 1
    assert forward.name in report["reconstructed_temporary_files"][0]
    assert all(copy["status"] == "VERIFIED" for copy in report["copy_results"])


def test_invalid_temp_evidence_preserved_while_valid_temp_is_reused(run):
    final, temporary = existing_temporary(run, "hetero_graph_edges_forward.parquet", "verified")
    corrupt = final.parent / f".{final.name}.broken.partial"
    corrupt.write_bytes(b"old failed reconstruction")
    report = call(run)
    assert report["overall_status"] == "COMPLETE"
    assert report["reused_temporary_files"] == [str(temporary)]
    assert corrupt.read_bytes() == b"old failed reconstruction"
    assert any(t["status"] == "MISMATCH" for t in report["temporary_inspections"])


def test_final_verification_failure_does_not_delete_source(run, monkeypatch):
    final, temporary = existing_temporary(run, "hetero_graph_edges_forward.parquet")
    def bad_copy(source, output, **kwargs):
        output.write(b"bad bytes despite successful return")
    monkeypatch.setattr(publication.shutil, "copyfileobj", bad_copy)
    report = call(run)
    assert report["overall_status"] == "INCOMPLETE"
    assert report["copy_results"][0]["status"] == "INVALID_PARTIAL"
    assert temporary.is_file() and final.is_file()
    assert not report["deleted_verified_temporary_files"]


def test_cleanup_only_after_final_hash_size_and_rows_verified(run, monkeypatch):
    final, temporary = existing_temporary(run, "hetero_graph_edges_forward.parquet")
    spec = publication.expected_files(run[2])["verified_benign"][final.name]
    unlink = Path.unlink
    def guarded_unlink(path, *args, **kwargs):
        assert path == temporary
        assert publication.inspect(final, spec, run[2]["hybrid_graphs"]["verified_benign"])["status"] == "VALID"
        return unlink(path, *args, **kwargs)
    monkeypatch.setattr(Path, "unlink", guarded_unlink)
    report = call(run)
    assert report["overall_status"] == "COMPLETE"
    assert report["copy_results"][0]["temporary_deleted"]


def test_cleanup_failure_preserves_valid_final_and_temp(run, monkeypatch):
    final, temporary = existing_temporary(run, "hetero_graph_edges_forward.parquet")
    def denied(*args, **kwargs):
        raise PermissionError("retain source")
    monkeypatch.setattr(Path, "unlink", denied)
    report = call(run)
    assert report["overall_status"] == "COMPLETE"
    assert final.is_file() and temporary.is_file()
    assert report["warnings"]


def test_verify_only_and_missing_folder_are_read_only(run):
    missing(run)
    report = call(run, verify_only=True, completed_root=run[0])
    assert report["overall_status"] == "INCOMPLETE"
    assert not report["temporary_files"]
    shutil.rmtree(run[1] / publication.OUTPUT_NAMES["evaluation"])
    report = call(run, completed_root=run[0])
    assert "folder is missing" in report["errors"][0]
    assert not (run[1] / publication.OUTPUT_NAMES["evaluation"]).exists()


def test_manifest_counts_and_audit_metadata_are_enforced(run):
    manifest = deepcopy(run[2])
    manifest["hybrid_graphs"]["evaluation"]["process_node_count"] = 999
    report = publication.resume(run[1], manifest, checkout={})
    assert report["overall_status"] == "INCOMPLETE"
    assert "row_count differs" in " ".join(report["periods"]["evaluation"]["files"]["hetero_process_nodes.parquet"]["errors"])
    assert "graph audit metadata differs" in " ".join(report["periods"]["evaluation"]["files"]["graph_connectivity_audit.json"]["errors"])


def test_git_guard_allows_only_unchanged_descendants(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    def git(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()
    git("init", "-b", "eda08")
    git("config", "user.email", "fixture@example.invalid")
    git("config", "user.name", "fixture")
    for name in (publication.BUILDER_PATH, publication.DEPENDENCY_PATH, publication.AUDIT_PATH):
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("verified")
    git("add", ".")
    git("commit", "-m", "verified")
    monkeypatch.setattr(publication, "RUN_COMMIT", git("rev-parse", "HEAD"))
    assert publication.verify_checkout(repo)["branch"] == "eda08"
    (repo / "new.txt").write_text("new resume runner")
    git("add", "new.txt")
    git("commit", "-m", "descendant")
    assert publication.verify_checkout(repo)["git_head"] == git("rev-parse", "HEAD")
    (repo / publication.BUILDER_PATH).write_text("changed builder")
    with pytest.raises(publication.PublicationError, match="changed"):
        publication.verify_checkout(repo)
    git("add", publication.BUILDER_PATH)
    git("commit", "-m", "changed logic")
    with pytest.raises(publication.PublicationError, match="changed"):
        publication.verify_checkout(repo)
    git("checkout", "-b", "wrong")
    with pytest.raises(publication.PublicationError, match="branch"):
        publication.verify_checkout(repo)


def test_notebook_startup_order_and_no_execution_outputs():
    repo = Path(__file__).resolve().parents[1]
    notebook = json.loads((repo / "colab/resume_sysclient0201_hybrid_graph_publication.ipynb").read_text())
    cells = ["".join(cell["source"]) for cell in notebook["cells"] if cell["cell_type"] == "code"]
    assert "drive.mount" in cells[0]
    assert "clone" in cells[1] and "--ff-only" in cells[1]
    assert "git HEAD:" in cells[2] and publication.RUN_COMMIT in cells[2]
    assert "--is-ancestor" in cells[2]
    assert "Google Drive mounted:" in cells[3]
    assert "folder.is_dir()" in cells[3]
    assert "resume_sysclient0201_hybrid_graph_publication" in cells[-1]
    assert not any("prepare_sysclient0201_hybrid_graph" in cell for cell in cells)
    for cell in notebook["cells"]:
        if cell["cell_type"] == "code":
            compile("".join(cell["source"]), "resume_notebook", "exec")
            assert cell["execution_count"] is None and cell["outputs"] == []
