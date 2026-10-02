# DARPA OpTC Research Log

Append-only chronological record. Keep current-state summaries in `RESEARCH_CONTEXT.md`; do not rewrite past log entries to match later conclusions. Corrections should be appended as new entries.

## 2026-09-30 23:11 PDT — Initial durable context reconstruction

- **Git commit before work:** `98eefffacb85609359df306e4ba23f06394a79e5`
- **Goal:** reconstruct repository-backed project state and create a durable handoff without modifying research code or starting model training.
- **Files changed:**
  - `RESEARCH_CONTEXT.md` (created)
  - `RESEARCH_LOG.md` (created)
- **Commands/scripts run:**
  - Git branch, HEAD, log, status, remote, tracked-file, and tree inspection.
  - `rg`, `find`, `sed`, `du`, and targeted source/test inspection for EDA9, EDA10, hosts, features, splits, RGCN, and saved metadata.
  - `python3 -m pytest -q tests/test_eda09_provenance_graph.py tests/test_eda10_continuous_process_structure.py tests/test_period_map_artifact.py`
  - `python3 -m pytest -q`
  - `python3 -m pytest -q tests`
  - Read-only hardware/filesystem inspection.
- **Datasets/hosts used:** no raw dataset, cache, or host run artifact was executed. The six named cohort hosts were documentation-audited only: `sysclient0201`, `sysclient0104`, `sysclient0069`, `sysclient0203`, `sysclient0051`, and `sysclient0351`.
- **Actual numerical results:**
  - Focused EDA9/EDA10/period-map verification: **89 passed**.
  - Canonical `tests/` suite: **519 passed**, 3 timestamp deprecation warnings.
  - Root test discovery: **6 collection errors** caused by duplicate test module filenames in untracked review directories.
  - Corrected archive catalog: **874.8 GB** compressed, tracked in repository documentation/output.
  - Period-map metadata: **180,648,918** pilot events, tracked in repository provenance.
  - Available machine observed: Apple M4, 10 CPU cores, 24 GB unified memory, approximately 104 GiB free filesystem space.
- **Errors/problems:**
  - The repository is public, so the confidential long-term research direction was not written.
  - Six-host caches, EDA10 outputs, ground-truth mappings, feature artifacts, RGCN-ready graphs, model code, embeddings, and evaluations are not present.
  - The tracked EDA1 outputs are internally stale/inconsistent: one README records a `/private/tmp` zero-byte test run, the ledger records a local 2019-09-16 archive, and the master inventory marks all ten archives pending.
  - The tracked period-map provenance scopes the split to the fixed 10 GB pilot, while historical context applies the same boundaries to a full SysClient0201 experiment; full-host validity needs revalidation.
- **Decisions made:**
  - Applied evidence precedence: saved run artifacts > code/tests > supplied historical context > `NEEDS VERIFICATION`.
  - Kept exact supplied results as historical claims instead of marking them `COMPLETE`.
  - Chose SysClient0201 artifact recovery/readiness verification as the immediate next milestone.
  - Did not start RGCN or One-Class SVM work.
- **What remains unfinished:** locate external artifacts and hashes; recover the exact common 70-feature schema; recover ground-truth mapping code/results; reconcile process universes; decide context-node initialization, RGCN objective, sampling, and score alignment.
- **Git commit after work:** `98eefffacb85609359df306e4ba23f06394a79e5` (documentation changes remain uncommitted).

## 2026-10-01 22:10 PDT — Hybrid period graph connectivity builder v1

- **Git commit before work:** `98eefffacb85609359df306e4ba23f06394a79e5` on `eda08`.
- **Goal:** build and audit one already-separated period's heterogeneous provenance connectivity, preserving CREATE topology/family metadata while sharing context nodes across families.
- **Files changed:** created `src/eda/build_period_heterogeneous_graph.py` and `tests/test_period_heterogeneous_graph.py`; updated affected sections of `RESEARCH_CONTEXT.md`; appended this log entry. EDA10 is unchanged.
- **Commands/scripts run:** read-only Git/source/contract inspection; `python3 -m pytest -q tests/test_period_heterogeneous_graph.py`; `python3 -m pytest -q tests`; `python3 -m src.eda.build_period_heterogeneous_graph --help`; `git diff --check` and EDA10 diff verification.
- **Datasets/hosts used:** synthetic pytest fixtures only; no real six-host or SysClient0201 period artifacts were available locally.
- **Actual numerical results:** focused tests **48 passed**; canonical suite **567 passed**, 3 pre-existing timestamp deprecation warnings. Synthetic two-family shared-FILE fixture produced 3 PROCESS nodes, 1 FILE node, 1 CREATE edge, 2 behavior edges, 1 weak component containing all 3 processes, and 1 shared context entity connecting 2 CREATE families. Synthetic 100-family common-MODULE fixture retained all 100 links and the shared context node. These are test results, not dataset results.
- **Errors/problems:** the real feature-schema layout, common 70-feature list, and already-separated input paths remain unavailable. V1's compact-table memory/runtime needs production measurement. Legacy EDA10 unbracketed IPv6 address/port strings can be ambiguous; explicit bracketed endpoints are required for unambiguous port identity.
- **Decisions made:** defined a new explicit six-file output contract and `period_heterogeneous_graph_v1` schema version; parameterized input columns and feature-list JSON key; hashed node/edge IDs with period role; retained original process features/metadata; excluded linkage columns from the predictive allowlist; used conservative EDA5 path normalization and typed endpoint keys; retained high-degree entities; audited unique-neighbor degrees and transitive family sharing. Count columns use EDA10 defaults when present, otherwise documented unit row weights.
- **What remains unfinished:** recover real period inputs/schema, verify period provenance and process-universe alignment, build the two periods independently, and compare connectivity audits. No RGCN, One-Class SVM, feature fitting, ground-truth remapping, or real-period run occurred.
- **Git commit after work:** `98eefffacb85609359df306e4ba23f06394a79e5`; all new implementation/tests/documentation remain uncommitted.
