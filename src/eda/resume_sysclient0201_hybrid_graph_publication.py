"""Publish missing *completed bytes*, never build or transform a graph.

The immutable real-run audit is the artifact manifest. All existing outputs in
both periods are inspected before any graph write. A mismatch fails closed.
Recovery accepts complete local outputs or lossless transport parts; each source
and the assembled temporary file must match the original run's SHA256 and size.
Final publication uses exclusive-create streamed copying, then full readback
verification, without rename/link operations. Verified temporary reconstructions
are reused before consulting recovery chunks. Only a successfully published and
reverified temporary source may be removed; failed-copy evidence is preserved.
Historical publication_status.json markers are never replaced.
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile

import pyarrow.parquet as pq

RUN_COMMIT = "3636eb8fee627034063c3800d202dbbc08822546"
AUDIT_PATH = "reports/sysclient0201_hybrid_graph_real_run_v1.json"
BUILDER_PATH = "src/eda/build_period_heterogeneous_graph.py"
DEPENDENCY_PATH = "src/eda/eda_05_entity_dictionary.py"
ROLES = ("verified_benign", "evaluation")
OUTPUT_NAMES = {r: f"eda_10_sysclient0201_hybrid_graph_{r}_v1" for r in ROLES}
FILES = {
    "hetero_process_nodes.parquet": "process_node_count",
    "hetero_entity_nodes.parquet": "total_entity_node_count",
    "hetero_graph_edges_forward.parquet": "forward_edge_count",
    "hetero_graph_edges_bidirectional.parquet": "bidirectional_edge_count",
    "relation_type_mapping.csv": "bidirectional_relation_count",
    "graph_connectivity_audit.json": None,
}
METRICS = (
    "process_node_count", "file_node_count", "module_node_count", "destination_node_count",
    "forward_edge_count", "bidirectional_edge_count", "create_edge_count",
    "weakly_connected_component_count", "largest_component_process_count",
    "percentage_process_nodes_in_largest_component", "shared_context_entity_count",
    "create_families_connected_through_shared_context_count",
    "maximum_context_node_degree", "p95_context_node_degree",
)


class PublicationError(RuntimeError):
    """Unsafe or incomplete publication: preserve all existing artifacts."""


def digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def verify_checkout(repo: Path) -> dict:
    """Descendants are allowed only with identical builder/dependency/audit bytes."""
    head = git(repo, "rev-parse", "HEAD")
    branch = git(repo, "branch", "--show-current")
    if branch != "eda08":
        raise PublicationError(f"STOP: branch must be eda08, observed {branch}")
    if subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", RUN_COMMIT, head],
                      capture_output=True).returncode:
        raise PublicationError("STOP: HEAD is not the verified run commit or its descendant")
    hashes = {}
    for name in (BUILDER_PATH, DEPENDENCY_PATH, AUDIT_PATH):
        original = subprocess.check_output(["git", "-C", str(repo), "show", f"{RUN_COMMIT}:{name}"])
        expected = hashlib.sha256(original).hexdigest()
        committed = subprocess.check_output(["git", "-C", str(repo), "show", f"HEAD:{name}"])
        if hashlib.sha256(committed).hexdigest() != expected or digest(repo / name) != expected:
            raise PublicationError(f"STOP: verified builder/dependency/manifest changed: {name}")
        hashes[name] = expected
    return {"branch": branch, "git_head": head, "verified_run_commit": RUN_COMMIT,
            "verified_source_sha256": hashes}


def expected_files(manifest: dict) -> dict:
    if not manifest["both_hybrid_graphs_completed"] or not manifest["compatibility_audit_passed"]:
        raise PublicationError("STOP: manifest does not record a completed compatible run")
    result = {}
    for role in ROLES:
        audit = manifest["hybrid_graphs"][role]
        entries = manifest["publication"][role]
        files = entries["published_files"] + entries["missing_files"]
        if len(files) != len(FILES) or {f["name"] for f in files} != set(FILES):
            raise PublicationError(f"STOP: incomplete/duplicate manifest entries: {role}")
        result[role] = {}
        for file in files:
            name = file["name"]
            if name in audit["output_sha256"] and audit["output_sha256"][name] != file["sha256"]:
                raise PublicationError(f"STOP: conflicting manifest hashes: {role}/{name}")
            result[role][name] = {"size_bytes": int(file["size"]), "sha256": file["sha256"],
                                  "row_count": audit[FILES[name]] if FILES[name] else None}
    return result


def inspect(path: Path, expected: dict, audit: dict, *, artifact_name: str | None = None) -> dict:
    info = {"path": str(path), "exists": path.exists() or path.is_symlink(),
            "expected": expected, "size_bytes": None, "sha256": None,
            "row_count": None, "status": "MISSING", "errors": []}
    if not info["exists"]:
        return info
    info["status"] = "MISMATCH"
    try:
        if not path.is_file() or path.is_symlink():
            raise PublicationError("artifact is not a regular, non-symlink file")
        info.update(size_bytes=path.stat().st_size, sha256=digest(path))
        for key in ("size_bytes", "sha256"):
            if info[key] != expected[key]:
                info["errors"].append(f"{key} differs from completed run")
        suffix = Path(artifact_name or path.name).suffix
        if suffix == ".parquet":
            parquet = pq.ParquetFile(path)
            info.update(row_count=parquet.metadata.num_rows, columns=parquet.schema_arrow.names,
                        column_types={f.name: str(f.type) for f in parquet.schema_arrow})
        elif suffix == ".csv":
            with path.open(newline="", encoding="utf-8") as handle:
                reader = csv.DictReader(handle)
                info["columns"] = reader.fieldnames
                info["row_count"] = sum(1 for _ in reader)
        else:
            actual = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(actual, dict):
                raise PublicationError("graph audit must be a JSON object")
            info["graph_audit_values"] = {k: actual[k] for k in METRICS}
            if actual != audit:
                info["errors"].append("graph audit metadata differs from completed run")
        if info["row_count"] != expected["row_count"]:
            info["errors"].append("row_count differs from completed run")
        if not info["errors"]:
            info["status"] = "VALID"
    except (OSError, ValueError, KeyError, TypeError, PublicationError) as error:
        info["errors"].append(str(error))
    return info


def inventory(root: Path, manifest: dict) -> dict:
    expected = expected_files(manifest)
    result = {}
    for role in ROLES:
        folder = root / OUTPUT_NAMES[role]
        result[role] = {"output_directory": str(folder), "folder_exists": folder.is_dir(),
                        "files": {name: inspect(folder / name, spec, manifest["hybrid_graphs"][role])
                                  for name, spec in expected[role].items()}}
        result[role]["overall_status"] = (
            "COMPLETE" if folder.is_dir() and all(f["status"] == "VALID" for f in result[role]["files"].values())
            else "INCOMPLETE")
    return result


def assert_no_mismatches(state: dict) -> None:
    mismatches = [f"{role}/{name}: {', '.join(f['errors'])}"
                  for role, group in state.items() for name, f in group["files"].items()
                  if f["status"] == "MISMATCH"]
    if mismatches:
        raise PublicationError("STOP: existing artifact mismatch; no overwrite: " + "; ".join(mismatches))


def safe_part(root: Path, name: str) -> Path:
    if not name or Path(name).name != name or name in (".", ".."):
        raise PublicationError("STOP: unsafe transport part name")
    path = root / name
    if path.is_symlink():
        raise PublicationError("STOP: symlink transport part")
    return path


def recovery_sources(role: str, name: str, spec: dict, audit: dict,
                     completed_root: Path | None, parts_root: Path | None,
                     transport: dict | None) -> list[Path]:
    if completed_root is not None:
        source = completed_root / OUTPUT_NAMES[role] / name
        checked = inspect(source, spec, audit)
        if checked["status"] == "MISMATCH":
            raise PublicationError(f"STOP: completed source mismatch: {source}: {checked['errors']}")
        if checked["status"] == "VALID":
            return [source]
    entry = (transport or {}).get("files", {}).get(f"{role}/{name}")
    if entry is None or parts_root is None:
        raise PublicationError(f"STOP: missing completed recovery bytes for {role}/{name}; NO rebuild")
    if transport.get("verified_run_commit") != RUN_COMMIT or entry["expected"] != spec:
        raise PublicationError("STOP: transport manifest conflicts with completed run")
    combined = hashlib.sha256()
    total = 0
    paths = []
    parts = entry["parts"]
    if not parts or len({p["name"] for p in parts}) != len(parts):
        raise PublicationError("STOP: empty or duplicate transport parts")
    for index, part in enumerate(parts):
        if part["index"] != index:
            raise PublicationError("STOP: unordered transport parts")
        path = safe_part(parts_root, part["name"])
        if not path.is_file() or path.stat().st_size != part["size_bytes"]:
            raise PublicationError(f"STOP: missing/short transport part: {path}")
        hasher = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
                hasher.update(block)
                combined.update(block)
                total += len(block)
        if hasher.hexdigest() != part["sha256"]:
            raise PublicationError(f"STOP: transport part hash mismatch: {path}")
        paths.append(path)
    if total != spec["size_bytes"] or combined.hexdigest() != spec["sha256"]:
        raise PublicationError(f"STOP: combined recovery bytes differ from completed run: {role}/{name}")
    return paths


def verified_temporary(folder: Path, name: str, spec: dict, audit: dict,
                       report: dict) -> Path | None:
    """Inspect existing reconstruction evidence without changing or deleting it."""
    selected = None
    for path in sorted(folder.glob(f".{name}.*.partial")):
        checked = inspect(path, spec, audit, artifact_name=name)
        report["temporary_inspections"].append(checked)
        if checked["status"] == "VALID" and selected is None:
            selected = path
    return selected


def copy_verified_to_final(temporary: Path, final: Path, spec: dict, audit: dict,
                           report: dict) -> None:
    """Drive-compatible copy; final files are never opened with truncate/replace."""
    if final.exists() or final.is_symlink():
        raise PublicationError(f"STOP: final destination appeared before copy: {final}")
    source = inspect(temporary, spec, audit, artifact_name=final.name)
    if source["status"] != "VALID":
        raise PublicationError(f"STOP: temporary source does not verify: {temporary}: {source['errors']}")
    result = {"source": str(temporary), "destination": str(final), "status": "COPYING",
              "temporary_deleted": False}
    report["copy_results"].append(result)
    created = False
    try:
        # O_EXCL prevents a concurrent existing destination from being overwritten.
        # Google Drive FUSE supports ordinary file creation/copy, not renameat2.
        with final.open("xb") as output:
            created = True
            with temporary.open("rb") as source_handle:
                shutil.copyfileobj(source_handle, output, length=8 * 1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        checked = inspect(final, spec, audit)
        result["final_verification"] = checked
        if checked["status"] != "VALID":
            raise PublicationError(f"final verification failed: {checked['errors']}")
        result["status"] = "VERIFIED"
    except (OSError, PublicationError, ValueError, TypeError) as error:
        result["status"] = "INVALID_PARTIAL" if created else "DESTINATION_CONFLICT"
        if created:
            report["invalid_partial_destinations"].append(str(final))
        raise PublicationError(
            f"STOP: copy/verification failed: {final}: {error}; "
            f"{'final marked INVALID_PARTIAL; ' if created else ''}verified temporary preserved: {temporary}"
        ) from error
    # Recheck the source before deleting evidence: if it changed during copying,
    # retain it. An interrupted/failed copy never reaches this cleanup branch.
    if inspect(temporary, spec, audit, artifact_name=final.name)["status"] == "VALID":
        try:
            temporary.unlink()
            result["temporary_deleted"] = True
            report["deleted_verified_temporary_files"].append(str(temporary))
        except OSError as error:
            report["warnings"].append(f"Verified final retained; temporary cleanup failed: {temporary}: {error}")
    else:
        report["warnings"].append(f"Verified final retained; changed temporary source preserved: {temporary}")


def resume(root: Path, manifest: dict, *, checkout: dict,
           completed_root: Path | None = None, parts_root: Path | None = None,
           transport: dict | None = None, verify_only: bool = False) -> dict:
    report = {"schema_version": "hybrid_graph_publication_verification_v1",
              "timestamp_utc": datetime.now(timezone.utc).isoformat(), **checkout,
              "overall_status": "INCOMPLETE", "restored_files": [], "already_valid_files": [],
              "temporary_files": [], "temporary_inspections": [], "reused_temporary_files": [],
              "reconstructed_temporary_files": [], "deleted_verified_temporary_files": [],
              "copy_results": [], "invalid_partial_destinations": [], "warnings": [],
              "publication_strategy": "exclusive_create_streamed_copy_with_readback_v1",
              "errors": [], "graph_rebuild_attempted": False}
    state = inventory(root, manifest)
    report["periods"] = state
    report["already_valid_files"] = [f"{r}/{n}" for r, g in state.items()
                                     for n, f in g["files"].items() if f["status"] == "VALID"]
    try:
        assert_no_mismatches(state)  # check BOTH periods before writing anything
        if any(not g["folder_exists"] for g in state.values()):
            raise PublicationError("STOP: an expected output folder is missing; confirm Drive mount/folder")
        missing = [(r, n, f["expected"]) for r, g in state.items()
                   for n, f in g["files"].items() if f["status"] == "MISSING"]
        if missing and verify_only:
            raise PublicationError("Verification only: expected artifacts remain missing")
        # Preflight ALL missing recovery bytes before any output writes.
        plans = []
        for role, name, spec in missing:
            audit = manifest["hybrid_graphs"][role]
            temporary = verified_temporary(root / OUTPUT_NAMES[role], name, spec, audit, report)
            sources = [] if temporary else recovery_sources(role, name, spec, audit,
                                                           completed_root, parts_root, transport)
            plans.append((role, name, spec, temporary, sources))
        for role, name, spec, temporary, sources in plans:
            final = root / OUTPUT_NAMES[role] / name
            now = inspect(final, spec, manifest["hybrid_graphs"][role])
            if now["status"] == "VALID":
                report["already_valid_files"].append(f"{role}/{name}")
                continue
            if now["status"] != "MISSING":
                raise PublicationError(f"STOP: destination changed during recovery: {final}")
            if temporary is None:
                descriptor, temporary_name = tempfile.mkstemp(prefix=f".{name}.", suffix=".partial", dir=final.parent)
                temporary = Path(temporary_name)
                report["reconstructed_temporary_files"].append(str(temporary))
                report["temporary_files"].append(str(temporary))
                with os.fdopen(descriptor, "wb") as output:
                    for source in sources:
                        with source.open("rb") as handle:
                            for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
                                output.write(block)
                    output.flush()
                    os.fsync(output.fileno())
            else:
                report["reused_temporary_files"].append(str(temporary))
                report["temporary_files"].append(str(temporary))
            copy_verified_to_final(temporary, final, spec, manifest["hybrid_graphs"][role], report)
            report["restored_files"].append(f"{role}/{name}")
    except (PublicationError, OSError, ValueError, KeyError, TypeError) as error:
        report["errors"].append(str(error))
    state = inventory(root, manifest)  # full final readback, including SHA256
    report["periods"] = state
    for path in report["invalid_partial_destinations"]:
        for group in state.values():
            for file in group["files"].values():
                if file["path"] == path:
                    file["status"] = "INVALID_PARTIAL"
                    group["overall_status"] = "INCOMPLETE"
    if not report["errors"]:
        try:
            assert_no_mismatches(state)
            if all(f["status"] == "VALID" for g in state.values() for f in g["files"].values()):
                report["overall_status"] = "COMPLETE"
            else:
                raise PublicationError("STOP: expected artifacts missing at final verification")
        except PublicationError as error:
            report["errors"].append(str(error))
    report["graph_audit_values"] = {
        role: state[role]["files"]["graph_connectivity_audit.json"].get("graph_audit_values")
        for role in ROLES
    }
    return report


def pack_sources(manifest: dict, completed_root: Path, directory: Path,
                 requested: list[str], chunk_bytes: int = 64 * 1024 * 1024) -> dict:
    """Lossless transport, not Parquet regeneration. Only explicitly requested files."""
    expected = expected_files(manifest)
    if chunk_bytes <= 0 or chunk_bytes > 64 * 1024 * 1024:
        raise PublicationError("STOP: transport chunks must be 1..64 MiB")
    selected = []
    for key in requested:
        role, name = key.split("/", 1)
        if role not in ROLES or name not in FILES or key in [k for k, *_ in selected]:
            raise PublicationError("STOP: unknown/duplicate requested artifact")
        source = completed_root / OUTPUT_NAMES[role] / name
        spec = expected[role][name]
        if inspect(source, spec, manifest["hybrid_graphs"][role])["status"] != "VALID":
            raise PublicationError(f"STOP: completed source does not verify: {source}")
        selected.append((key, source, spec))
    directory.mkdir(parents=True, exist_ok=False)
    transport = {"schema_version": "completed_graph_bytes_transport_v1", "verified_run_commit": RUN_COMMIT,
                 "files": {}}
    for key, source, spec in selected:
        parts = []
        with source.open("rb") as handle:
            index = 0
            while block := handle.read(chunk_bytes):
                name = key.replace("/", "__") + f".part{index:04d}"
                with (directory / name).open("xb") as output:
                    output.write(block)
                parts.append({"name": name, "index": index, "size_bytes": len(block),
                              "sha256": hashlib.sha256(block).hexdigest()})
                index += 1
        transport["files"][key] = {"expected": spec, "parts": parts}
    with (directory / "transport_manifest.json").open("x", encoding="utf-8") as handle:
        json.dump(transport, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return transport


def print_report(report: dict) -> None:
    print(f"HEAD {report.get('git_head')} | {report['overall_status']}")
    for role, group in report.get("periods", {}).items():
        print(f"{role}: {group['output_directory']}")
        for name, file in group["files"].items():
            print(f"  {file['status']:8} {name} bytes={file['size_bytes']} rows={file['row_count']} SHA256={file['sha256']}")
        values = report.get("graph_audit_values", {}).get(role)
        if values:
            print("  audit:", json.dumps(values, sort_keys=True))
    print("restored:", report.get("restored_files", []))
    print("already valid:", report.get("already_valid_files", []))
    print("reused temporary:", report.get("reused_temporary_files", []))
    print("invalid/partial final destinations:", report.get("invalid_partial_destinations", []))
    for warning in report.get("warnings", []):
        print("WARNING:", warning)
    for error in report.get("errors", []):
        print("BLOCKER:", error)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--completed-root", type=Path)
    parser.add_argument("--parts-root", type=Path)
    parser.add_argument("--transport-manifest", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    # Reserve a NEW report before changing any graph bytes. Never truncate a report
    # or accidentally use a graph artifact as the reporting destination.
    args.report.parent.mkdir(parents=True, exist_ok=True)
    report_handle = args.report.open("x", encoding="utf-8")
    identity = {"verified_run_commit": RUN_COMMIT}
    try:
        identity.update(git_head=git(args.repo, "rev-parse", "HEAD"),
                        branch=git(args.repo, "branch", "--show-current"))
        checkout = verify_checkout(args.repo)
        manifest = json.loads((args.repo / AUDIT_PATH).read_text())
        transport = json.loads(args.transport_manifest.read_text()) if args.transport_manifest else None
        report = resume(args.data_root, manifest, checkout=checkout, completed_root=args.completed_root,
                        parts_root=args.parts_root, transport=transport, verify_only=args.verify_only)
    except (PublicationError, OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        report = {**identity, "overall_status": "INCOMPLETE", "errors": [str(error)],
                  "graph_rebuild_attempted": False}
    # Reports are new files, not replacements for historical publication markers.
    with report_handle as handle:
        json.dump(report, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")
    print_report(report)
    print("Verification report:", args.report)
    return 0 if report["overall_status"] == "COMPLETE" else 1


if __name__ == "__main__":
    sys.exit(main())
