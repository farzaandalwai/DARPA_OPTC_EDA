# DARPA OpTC Research Context

> **Purpose:** concise, durable project handoff and current-state source of truth.
>
> **Evidence precedence:** executed repository artifacts and saved run metadata > current code and tests > explicitly supplied historical context > `NEEDS VERIFICATION`. A historical claim is not promoted to current fact merely because it appears in this file.
>
> **Last Updated:** 2026-10-03 (America/Los_Angeles)
>
> **Last Verified:** 2026-10-03
>
> **Verified Git HEAD before adapter commit:** `b95302d2766660add5cda8c3ed2378e5a8047c07`
> **Verified completed graph-run commit:** `3636eb8fee627034063c3800d202dbbc08822546`
> **Verified publication / pre-hub-audit HEAD:** `671d2487744612ee662bfb0994a99baf50f6c989`
> **Repository visibility:** public GitHub repository. Confidential research direction is intentionally excluded.

## 1. One-paragraph project summary

This project studies large-scale endpoint telemetry from the corrected DARPA Operationally Transparent Cyber (OpTC) dataset using provenance graphs, leakage-safe temporal separation, graph representation learning, anomaly detection and investigation workflows. EDA stages through EDA10, the hybrid graph builder, a lossless historical behavior adapter and thin Colab runners are implemented. Both real SysClient0201 hybrid graphs are complete locally and published/verified in Drive. Sharing context increases largest-component PROCESS concentration from 57.836% to 99.990% in training and 77.543% to 98.532% in evaluation. The training-first hub-control audit now tests 19 mask/weight policies without modifying either full graph or EDA10. MODULEs dominate exposure, but FILE/DESTINATION sharing alone still produces a 98.187% training giant component. No RGCN, OCSVM, embeddings, or model evaluation occurred; no detection-performance claim is supported. Other six-host claims remain unverified.

## 2. Current research objective

### Current objective

Interpret the completed training-first hub-control audit and decide acceptable cross-family-context loss versus message-passing exposure before any model training. Publication is complete. Full provenance artifacts remain untouched; filtered policies exist only as context masks and audit results. Utility/noise and detection performance are not yet measured.

Publication completed in Colab at `671d2487744612ee662bfb0994a99baf50f6c989`, using verified temporary reuse and an exclusive-create normal streamed copy with final hash/count readback (no atomic rename/link requirement). Both periods are 6/6 COMPLETE in `publication_verification_5850b2b5d6254a36b8ed00df6a26f4b3.json`, Drive file ID `1Ah-f_12t6zF3owcHq8vTK28J_mDkRhQd`; a readback copy is preserved in ignored local run storage. Bidirectional temporary bytes were reused, forward bytes were reconstructed from existing parts, and only successfully verified temporary copies were removed. Ten valid artifacts, historical markers, and 17 recovery parts remained untouched. Earlier PARTIAL statements below describe historical execution/publication steps, not current completeness.

### Long-term private research direction

Intentionally omitted. This repository is public, so confidential research directions must not be described, inferred, or added here without explicit authorization and a repository-visibility review.

## 3. Repository state

- **Repository:** `farzaandalwai/DARPA_OPTC_EDA`
- **Local path:** `/Users/farzu/Desktop/DARPA_OPTC_EDA`
- **Remote:** `https://github.com/farzaandalwai/DARPA_OPTC_EDA.git`
- **Visibility:** public, verified 2026-09-30
- **Branch:** `eda08`, tracking `origin/eda08`
- **HEAD before adapter commit:** `b95302d2766660add5cda8c3ed2378e5a8047c07` (`Add guarded SysClient0201 Colab hybrid graph runner`), pushed to `origin/eda08`.
- **Important directories:**
  - `src/eda/` — canonical ingestion and EDA1–EDA10 code.
  - `tests/` — canonical test suite.
  - `data/period_maps/` — tracked period policy and provenance.
  - `outputs/` — tracked EDA1 outputs plus empty placeholders for later artifacts.
  - `configs/` — example path configuration only.
  - `reports/` — saved real-artifact compatibility audit with exact schemas, features, counts, and source hashes; no raw data.
  - `colab/` — thin SysClient0201 hybrid graph runner.
- **Important scripts:**
  - `src/eda/build_pilot_member_inventory.py`
  - `src/eda/select_pilot_manifest.py`
  - `src/eda/build_normalized_pilot_cache.py`
  - `src/eda/build_period_heterogeneous_graph.py` — new hybrid graph builder and CLI.
  - `src/eda/prepare_sysclient0201_hybrid_graph.py` — real-artifact compatibility gate, local role partitioning, builder invocation and comparison.
  - `src/eda/adapt_structure_scoped_behavior_links.py` — audited, lossless conversion of historical explicit-period behavior evidence.
  - `src/eda/eda_01_dataset_intake.py` through `src/eda/eda_10_continuous_process_structure.py`
  - `src/eda/optc_streaming_parser.py`, `src/eda/cache_resume.py`, and `src/eda/manifest_utils.py`
- **Important notebooks:** `colab/run_sysclient0201_hybrid_graph.ipynb`; mounts Drive, synchronizes `eda08` into `/content/DARPA_OPTC_EDA`, prints branch/HEAD, confirms mount, then invokes repository logic. No saved execution outputs.
- **Completed-run publication notebook:** `colab/resume_sysclient0201_hybrid_graph_publication.ipynb`; use this instead of the build notebook for the existing output folders. It never calls the graph builder or modifies EDA10/context identity/training policy. No saved execution outputs.
- **Tracked artifacts:** EDA1 outputs and schema/connectivity audit reports, not raw data or models. Complete real graph outputs, adapter links and input snapshots are preserved under ignored `data/local_runs/sysclient0201_hybrid_graph_v1/{artifacts,work}/`.
- **Saved metadata/configuration:** `data/period_maps/optc_pilot_period_map_v1.{csv,md}`, `configs/eda_01_*_paths.example.json`, EDA1 intake CSV/TXT files, and code-generated run schemas.
- **Untracked pre-existing material:** `.cursor/`, six EDA9/EDA10 review directories, and corresponding ZIP files. These review copies contain source/tests/diffs, not executed research artifacts. They also cause repository-root `pytest` collection-name collisions.
- **Verification:** `python3 -m pytest -q tests` passed **519 tests** with 3 timestamp deprecation warnings on 2026-09-30. Focused EDA9/EDA10/period-map tests passed **89 tests**. Running `python3 -m pytest -q` from the repository root failed at collection with 6 import-file-mismatch errors because duplicate test filenames exist in the untracked review directories.
- **Current verification:** adapter/builder/runner focused suite **102 passed**; canonical suite **621 passed**, 3 pre-existing timestamp warnings, on 2026-10-02. Tests are synthetic; the separately saved real-run report contains dataset measurements.
- **Publication-resume verification:** safety suite **27 passed**; latest canonical suite **648 passed**, 3 pre-existing timestamp warnings. Drive artifacts and recovery parts separately verified by readback; a local-only recovery rehearsal passed, while final Drive publication still awaits Colab.
- **Current verification (2026-10-03):** publication complete at `671d248`; training-first hub audit **26 focused tests**, canonical `python3 -m pytest -q tests` **677 passed**, 3 pre-existing timestamp warnings. Hub audit source/tests/docs are working-tree changes, not a new pushed commit. See Section 24 for executed dataset findings.
- **State caveat:** the branch name remains `eda08` even though commits on it include EDA9 and EDA10. Treat commit identity, not the branch label, as authoritative.
- **Tracked EDA1-output conflict:** `outputs/eda_01_intake/README_eda01_intake.txt` records a `/private/tmp` zero-byte test run, `T1_dataset_intake_ledger.csv` records a local 12.5 GB 2019-09-16 archive, and `T1B_master_archive_inventory.csv` marks all ten archives pending. These files came from different/stale runs and must not be combined as one current intake result.

## 4. Dataset

- **Dataset:** DARPA Operationally Transparent Cyber (OpTC), corrected archives.
- **Corrected archive dates:** 2019-09-16 through 2019-09-25.
- **Corrected archive total:** approximately **874.8 GB compressed**, verified in `data/README_data.md` and the tracked EDA1 catalog.
- **Earlier normalized pilot:**
  - **180,648,918 events** — verified in `data/period_maps/optc_pilot_period_map_v1.md` for `pilot_manifest_10gb_v1`.
  - **1,807 Parquet chunks, 77 columns, 46 selected members** — historical supplied context only; no cache metadata or manifest containing these figures is present. **NEEDS VERIFICATION.**
- The original exploratory six-host pilot selected for cache/EDA coverage is not the same concept as the current six-host malicious cohort below. Do not transfer host membership or completeness claims between them without the relevant manifests and run metadata.
- Raw archives and Parquet caches are ignored by Git. Their absence from the public checkout does not prove they never existed, but it prevents current verification.

## 5. Current six-host cohort

The current malicious cohort defined by supplied historical context is:

| Scenario | Host |
|---|---|
| SC1 | `sysclient0201` |
| SC1 | `sysclient0104` |
| SC2 | `sysclient0069` |
| SC2 | `sysclient0203` |
| SC3 | `sysclient0051` |
| SC3 | `sysclient0351` |

Current checkout artifact audit:

| Host | Normalized cache | EDA10 outputs | Ground-truth mapping | Split/features/RGCN-ready graph |
|---|---|---|---|---|
| `sysclient0201` | Historical claim; absent locally | Historical claim; absent locally | Historical claim; absent locally | Historical claim of full preparation; absent locally; **NEEDS VERIFICATION** |
| `sysclient0104` | Historical claim; absent locally | Historical claim; absent locally | Historical claim; absent locally | Not claimed complete; absent locally |
| `sysclient0069` | Historical claim; absent locally | Historical claim; absent locally | Historical claim; absent locally | Not claimed complete; absent locally |
| `sysclient0203` | Historical claim; absent locally | Historical claim; absent locally | Historical claim; absent locally | Not claimed complete; absent locally |
| `sysclient0051` | Historical claim; absent locally | Historical claim; absent locally | Historical claim; absent locally | Not claimed complete; absent locally |
| `sysclient0351` | Historical claim; absent locally | Historical claim; absent locally | Historical claim; absent locally | Not claimed complete; absent locally |

Historical known state supplied for this reconstruction: all six hosts had normalized caches, EDA10, and ground-truth mapping, while only `sysclient0201` had the full leakage-safe split, features, and RGCN-ready graph. The repository neither confirms nor supersedes that state because none of those run artifacts is present. Do **not** say that all six completed RGCN preparation.

Tracked source explicitly names `SysClient0201` in EDA9/EDA10 semantics and scope notes. No tracked reference to the other five cohort hostnames was found; their membership currently comes only from the supplied historical context.

## 6. Provenance semantics

- `PROCESS CREATE` defines the process-family skeleton.
- Valid parent→child CREATE edges determine weakly connected process components. FILE, MODULE, and DESTINATION/FLOW relationships add behavioral context but do **not** determine EDA10 component membership.
- `structure_id` is a deterministic identifier for one CREATE-connected process family in a particular host/range and analysis-rule version. It is derived from the sorted component process IDs.
- One hop means one directed `PROCESS CREATE` edge. A path with 15 hops contains 16 process nodes.
- An observed root has CREATE indegree zero only within the analyzed interval. Its real parent may precede the left boundary. Observed leaves may likewise continue beyond the right boundary.
- A singleton structure is exactly one chain-universe process with zero valid CREATE indegree and zero valid CREATE outdegree.
- EDA10's chain universe contains processes supported by valid CREATE topology or FILE/MODULE/FLOW acting-process observations. Ambiguous PROCESS OPEN/TERMINATE-only observations are excluded from chain metrics.
- UUIDs and IDs are evidence and linkage keys. They may determine deterministic process identity, but they must never be predictive features.
- A self-UUID CREATE (`actorID == objectID`) conservatively retains the child identity and suppresses the unresolved parent-child edge.
- **Unlabeled does not mean benign.** Use `unlabeled` or `not attack-associated`, never `benign`, unless verified-benign policy explicitly applies.

## 7. EDA9

**Canonical module:** `src/eda/eda_09_provenance_graph.py`

**Canonical tests:** `tests/test_eda09_provenance_graph.py`

EDA9 is an event-level provenance graph prototype for one host and one bounded interval. It preserves event traceability via `raw_event_id` and event-locator metadata, creates HOST, USER, PROCESS, FILE, and DESTINATION nodes, and emits host-process, user-process, process-create-process, process-file, and process-destination relations. It records process-semantics assumptions and contains a bounded semantics-probe mode.

Main entry points and helpers:

- `build_parser` / `validate_run_config` — CLI and safety/configuration validation.
- `_process_instance_id` / `_resolve_process_instance` — deterministic UUID-first or path/PID instance resolution.
- `_probe_process_semantics` — bounded empirical checks; publishes no graph.
- `run_eda09` — streams events, emits graph rows, summarizes assumptions and reconciliation.
- `main` — CLI entry point.

Expected outputs under the caller-provided `--output-dir` are `nodes.csv`, `edges.csv`, and `graph_summary.json`. The output directory must not already exist. No authoritative EDA9 run output is present in the current checkout. Historical context says EDA9 was a prototype and was not executed as the authoritative six-host output; repository state is consistent with that statement.

## 8. EDA10

**Canonical module:** `src/eda/eda_10_continuous_process_structure.py`

**Canonical tests:** `tests/test_eda10_continuous_process_structure.py`

EDA10 streams a full host/range, resolves EDA9-compatible process instances, compacts CREATE edges and FILE/MODULE/FLOW behavior, builds CREATE-only weak components, computes SCC/cycle and root-to-leaf metrics, assigns deterministic `structure_id` values, and publishes atomically. Its important helpers include `validate_run_config`, `_resolve_host_time_bounds`, `_resolve_process_instance`, `_upsert_process`, `_upsert_create_edge`, `_iterative_scc`, `_component_ids`, `_build_behavior_compact_table`, and `run_eda10`.

Expected outputs under the caller-provided `--output-dir`:

- `process_instances.parquet`
- `process_create_edges_compact.parquet`
- `process_behavior_compact.parquet`
- `structure_summary.parquet`
- `chain_metrics.json`
- `graph_summary.json`

Optional CSV mirrors are produced only with `--export-csv`. The code records deliverable hashes and Git commit in `graph_summary.json`. No fixed repository output path is encoded, and none of these outputs exists in the current checkout. The canonical EDA10 module also has no ground-truth input and says that future labels should map `raw_event_id` → normalized event → deterministic process ID → `structure_id`; therefore any historical EDA10 attack overlay is an external/downstream artifact, not an output proven by this module.

## 9. Exact six-host structure statistics

The following figures are preserved from supplied historical context. No corresponding `graph_summary.json`, `structure_summary.parquet`, or ground-truth overlay is present, so every row **NEEDS VERIFICATION** against recovered artifacts.

| Host | Process nodes | Valid CREATE edges | Structures | Attack-associated structures |
|---|---:|---:|---:|---:|
| `sysclient0201` | 79,497 | 74,092 | 5,405 | 9 |
| `sysclient0104` | 36,752 | 35,101 | 1,652 | 1 |
| `sysclient0069` | 40,132 | 37,954 | 2,178 | 1 |
| `sysclient0203` | 40,041 | 38,301 | 1,741 | 1 |
| `sysclient0051` | 46,899 | 44,540 | 2,360 | 30 |
| `sysclient0351` | 91,919 | 85,192 | 6,727 | 2 |
| **Total** | — | — | **20,063** | **44** |

Historical label split: **44 attack-associated structures**, **20,019 unlabeled structures**. Never relabel the 20,019 as benign.

## 10. SysClient0201 detailed state

All values in this section are supplied historical results and **NEED VERIFICATION** against recovered run metadata unless explicitly noted as code behavior.

- Normalized events: **35,806,004** across **359 chunks**.
- Chain-universe process nodes: **79,497**.
- `process_instances` rows: **84,892**.
- Valid CREATE edges: **74,092**.
- Structures: **5,405**.
- Singleton structures: **4,562**; non-singletons: **843**.
- Cyclic structures: **0**; self loops: **0**.
- Identity conflicts: **108**.
- Leaves: **49,969**.
- Self-UUID CREATEs suppressed: **750**.
- Longest CREATE path: **15 hops / 16 process nodes**.

Largest structures:

1. `struct_ac309a4577e227418ac608d6`: 41,277 processes, 41,276 edges, depth 15, 0 mapped malicious events; **unlabeled / not attack-associated, not confirmed benign**.
2. `struct_1d0411a82c1f9e2c70479dce`: 29,308 processes, 29,307 edges, depth 10, 34,770 mapped malicious events; attack-associated.
3. `struct_a5487aa8687d0dc562f2bcb0`: 1,043 processes, 1,042 edges, depth 11, 1,101 mapped malicious events; attack-associated by the supplied mapping count.

The two largest structures contain approximately **88.8%** of the 79,497 chain-universe process nodes. This concentration is descriptive; it is not evidence that the largest unlabeled family is benign.

## 11. Ground-truth policy

A New Hope mapping policy:

`malicious event → actorID → exact process instance → actor process structure`

- The `objectID` target does not automatically make the target object's process structure attack-associated.
- Do not guess process identity from PID or path.
- Unmapped events remain unmapped.
- Do not confuse malicious event count with malicious process count.

Historical six-host totals, all **NEEDS VERIFICATION** because the mapping artifact is absent:

- Corrected ground-truth events: **110,191**.
- Actor-mapped: **110,184**.
- Unmapped: **7**.

Historical `sysclient0201` totals:

- Ground-truth UUIDs found in cache: **36,045**.
- Actor-mapped events: **36,038**.
- Unmapped: **7**.
- Attack-associated structures: **9**.
- **34,770 / 36,038** mapped malicious events occur in the largest attack-associated structure, approximately **96.48%**.

Current-repository conflict: the EDA10 code does not implement this overlay, and no ground-truth file, mapping script, or mapping result is tracked. Recover the downstream mapping implementation and audit exact actor-ID/process-ID joins before treating these numbers as current.

## 12. Leakage-safe split

Repository-verified period boundaries from `data/period_maps/optc_pilot_period_map_v1.csv` are half-open intervals:

- **Verified-benign training:** 2019-09-16 23:32:49.231 through 2019-09-23 04:00:00 UTC.
- **Evaluation:** 2019-09-23 04:00:00 through 2019-09-25 18:38:15.052001 UTC.

The period-map provenance explicitly scopes these boundaries to `pilot_manifest_10gb_v1`; it warns not to generalize the map without revalidation and says evaluation does not mean every event is malicious.

SysClient0201 split counts confirmed against the readable Drive split summary on 2026-10-01 (underlying raw events were not reprocessed):

| Period | Raw events | Mapped events | Process nodes | Valid CREATE edges | Components | Attack components |
|---|---:|---:|---:|---:|---:|---:|
| Train | 31,429,978 | 31,424,146 | 71,369 | 66,554 | 4,815 | 0 |
| Evaluation | 4,376,026 | 4,375,631 | 8,376 | 7,538 | 838 | 11 |

Drive split metadata states components were rebuilt independently inside each period. Real split-node IDs, full/split family metadata and CREATE pairs/counts reconcile exactly with both feature-period tables. This verifies input consistency, not a rerun of the historical split-generation logic or full-cache period-map validation.

## 13. Feature engineering

Historical feature state:

- V1: 49 engineered process features.
- V2 additions: 22.
- Candidate total: 71.
- Final common schema: 70.
- `event__DESTINATION__OPEN` was removed because it had zero variance in SysClient0201 training.

The 2026-10-01 Drive audit recovered `eda_10_sysclient0201_period_features_v1/period_process_feature_columns_v1.json` (71 candidates) and `eda_10_sysclient0201_rgcn_graph_v1/rgcn_model_feature_policy_v1.json` (`process_features`, final ordered 70). The ordered removal rule matches, and all selected columns are present, finite and numeric in both real PROCESS tables. Exact names and source hashes are saved in `reports/sysclient0201_hybrid_graph_compatibility_audit_v1.json`. No feature engineering or fitting was performed.

Critical rules:

- Use one fitted/common feature schema across all hosts; never drop features independently per host.
- Fit any vocabulary/statistics on verified-benign training data only.
- Exclude UUIDs, raw IDs, deterministic node IDs, and other linkage identifiers from predictive features.

## 14. Heterogeneous RGCN-ready graph

SysClient0201 graph counts below match the readable historical Drive summary. On 2026-10-02, legacy PROCESS, behavior and CREATE source tables were validated and their period-isolated topology measured directly. The old builder source remains absent; the separate old combined-edge file was not rerun/revalidated.

- PROCESS nodes: **79,745 total** = 71,369 train + 8,376 evaluation.
- Context entity types: FILE, MODULE, DESTINATION.
- Forward relations:
  - `PROCESS_CREATE_PROCESS`
  - `PROCESS_DESTINATION_MESSAGE`
  - `PROCESS_DESTINATION_START`
  - `PROCESS_FILE_CREATE`
  - `PROCESS_FILE_DELETE`
  - `PROCESS_FILE_MODIFY`
  - `PROCESS_FILE_READ`
  - `PROCESS_FILE_RENAME`
  - `PROCESS_FILE_WRITE`
  - `PROCESS_MODULE_LOAD`
- With reverse edges: **20 relation types**.
- Train graph: 296,758 entity nodes; 2,746,371 forward compact edges; 5,492,742 bidirectional edges.
- Evaluation graph: 45,940 entity nodes; 312,156 forward compact edges; 624,312 bidirectional edges.
- Historical validations: no cross-structure process edges and no entity hash collisions.

Potential universe mismatch requiring reconciliation: the historical RGCN graph has 79,745 PROCESS nodes, while historical full-period EDA10 reports 79,497 chain-universe process nodes and 84,892 `process_instances` rows. The difference may reflect period-specific inclusion rules, but no saved artifact explains it. Do not assume these universes align.

No RGCN encoder, PyTorch/DGL/PyG dependency, training script, model checkpoint, embeddings, or evaluation artifact was found. Therefore the RGCN has **not been shown to be trained or evaluated** in this repository.

### Hybrid period graph implementation (2026-10-01)

`src/eda/build_period_heterogeneous_graph.py` now defines the 10 forward relations above and `REV__<forward_relation>` counterparts. It takes one period's PROCESS feature/node table, CREATE edge table, behavior table, feature-schema JSON, output path, and period role. EDA10 default columns are `process_id`, `structure_id`, `parent_process_id`, `child_process_id`, `behavior_type`, `action_raw`, and `behavior_key`; all input column names are configurable. Present `period_role` columns must match the requested role. Without role columns, already-separated period membership is a caller assertion; no timestamp splitting is performed.

Output schema version is `period_heterogeneous_graph_v1`. Its six files are `hetero_process_nodes.parquet`, `hetero_entity_nodes.parquet`, `hetero_graph_edges_forward.parquet`, `hetero_graph_edges_bidirectional.parquet`, `relation_type_mapping.csv`, and `graph_connectivity_audit.json`. PROCESS metadata and original feature columns are preserved; predictive features are an explicit numeric allowlist selected from JSON using configurable `--feature-list-key`. This is a new input contract, not a recovered external feature schema.

Context IDs include period role, node type, canonical value, and configured host scope; they exclude family IDs. FILE/MODULE identity uses EDA5 separator-only path normalization. DESTINATION uses canonical address/port/protocol. Bracketed IPv6 endpoints are required to disambiguate ports; a valid unbracketed IPv6 endpoint is treated as address-only. Single-host inputs may set `--host-scope`; multi-host tables should set `--host-column`. Context degree counts unique PROCESS neighbors. All high-degree entities are retained; family sharing, weak components, degree summaries, CREATE reconciliation, feature policy, and hashes are audited.

Both real-period graphs have been built locally; connectivity is saved below. Production Colab runtime/peak memory have not been measured. V1 loads compact tables into memory and streams bidirectional output in batches. EDA10 is unchanged. The new opt-in `exact_behavior_key_v1` policy bypasses all path/endpoint reinterpretation and host scoping for the controlled historical comparison; the generic `canonical_v1` default is unchanged.

### Real-artifact compatibility gate and Colab runner (2026-10-01)

Authentic Drive downloads were audited locally, without modifying source artifacts or executing a Colab runtime. All 12 named files, including the optional old graph summary, were readable. The saved audit distinguishes intended Colab paths from its local execution environment.

- Artifact root: `/content/drive/MyDrive/DARPA_OPTC_EDA/`; known feature, leakage-safe split and previous RGCN groups are explicit in the runner.
- Train/evaluation PROCESS feature rows: **71,369 / 8,376**; CREATE rows: **66,554 / 7,538**. Both schemas and topology consistency pass.
- PROCESS identifier: `process_id`; full EDA10 family identifier: `reference_full_structure_id`; period-rebuilt family identifier: `split_structure_id`. The runner retains both and maps the full reference to canonical `structure_id`.
- `period_process_activity_raw_v1.parquet`: **77,656 rows**, explicitly assigned **69,469 verified_benign / 8,187 evaluation**. Columns are only `period_role`, `process_id`, `reference_full_structure_id`, `actor_event_count`, `first_actor_event_time`, `last_actor_event_time`, `malicious_actor_event_count`.
- **BLOCKER:** no `behavior_type`, `action_raw`, `behavior_key` or `attach_event_count`. Explicit period assignment is safe, but aggregate counts cannot reconstruct FILE/MODULE/DESTINATION links. No behavior partition or real graph was produced.
- Do not recover links by timestamp-splitting original full-timeline compact behavior. The runner requires an inspected, explicitly assigned behavior artifact and re-audits before partitioning locally under `/content/`.
- Intended output directories are `eda_10_sysclient0201_hybrid_graph_verified_benign_v1` and `eda_10_sysclient0201_hybrid_graph_evaluation_v1` under the Drive artifact root. Existing outputs are never overwritten.
- The old summary stores node/edge counts, not WCC concentration, degree or family-sharing statistics; those comparisons remain unavailable. No pruning or model training occurred.

### Historical adapter and first real controlled experiment (2026-10-02)

The earlier blocker is resolved by `eda_10_sysclient0201_rgcn_graph_v1/hetero_behavior_edges_forward_v1.parquet` and `hetero_process_nodes_v1.parquet`. The adapter joins `(period_role, source_node_id)` to historical PROCESS `(period_role, node_id)`; 248 node IDs recur across periods, so a global-ID-only join would be unsafe. It keeps raw keys and metadata, maps all nine behavior relations exactly, sums duplicate counts and reconciles min/max evidence times. It never assigns periods from timestamps or uses old target IDs as new identity.

- **Reconciliation:** 2,984,435 source links become 2,679,817 train and 304,618 evaluation links; this real input has no duplicate collapsed links. All **28,320,862 behavior events** reconcile, including each period/relation. Unmatched PROCESS sources, period mismatches and family mismatches are all zero.
- **Controlled inputs:** all 70 PROCESS features and both original family columns match historical PROCESS nodes exactly; historical CREATE topology and event counts match both current CREATE tables. Canonical `structure_id` is explicitly mapped from period-rebuilt `split_structure_id` for this comparison; full EDA10 `reference_full_structure_id` remains untouched metadata. Family metrics use 4,815 train / 838 evaluation period-local families.
- **Train:** 71,369 PROCESS, 55,758 FILE, 2,844 MODULE, 142 DESTINATION; 2,746,371 forward edges and 66,554 CREATE edges. WCCs **4,815 old → 8 hybrid**; largest-component PROCESS count **41,277 → 71,362**, concentration **57.836% → 99.990%**. Shared contexts **35,316**, families connected through shared context **4,808**; context max/p95 degree **63,784 / 37**.
- **Evaluation:** 8,376 PROCESS, 13,249 FILE, 1,413 MODULE, 357 DESTINATION; 312,156 forward edges and 7,538 CREATE edges. WCCs **838 old → 124 hybrid**; largest-component PROCESS count **6,495 → 8,253**, concentration **77.543% → 98.532%**. Shared contexts **5,325**, connected families **715**; context max/p95 degree **7,273 / 30**.
- **Hubs:** `\\windows\\system32\\kernel32.dll`, `\\systemroot\\system32\\ntdll.dll`, `\\windows\\system32\\user32.dll` lead both periods. Degree means unique PROCESS neighbors, not event multiplicity. Full top-10 lists, input/output hashes, adapter audits and measured old baselines are in `reports/sysclient0201_hybrid_graph_real_run_v1.json`.
- **Interpretation:** scope sharing produces near-total PROCESS component collapse. Whether that context is useful or noisy for representation learning is unmeasured. No pruning, training or EDA10 changes occurred.
- **Execution/publication:** this was a local execution using authentic Drive snapshots, not a Colab runtime. Complete local data are preserved in ignored `data/local_runs/sysclient0201_hybrid_graph_v1/`. Evaluation's six outputs are uploaded and SHA256-readback verified. Training's four smaller outputs are similarly verified, but the 339 MiB forward and 684 MiB bidirectional files exceed connector limits. Both Drive folders have explicit `publication_status.json`; training publication is partial, not complete.
- **Colab safety:** the updated notebook audits historical sources, runs the adapter, audits controlled compatibility, feeds both explicit local link files directly to the existing builder and prints measured old/hybrid connectivity. It still refuses existing destinations. Preserve/resolve the existing partial/completed Drive folders before a fresh Colab rerun; do not overwrite them implicitly.

## 15. Intended first model experiment

Planned design:

`verified-benign training graph → RGCN representation learning → PROCESS embeddings → One-Class SVM fit only on verified-benign embeddings → evaluation PROCESS anomaly scores → comparison with A New Hope labels → local suspicious-neighborhood extraction → investigation/explanation`

- Primary anomaly-scoring unit: PROCESS node.
- FILE, MODULE, and DESTINATION nodes: contextual nodes.
- Do not train the first experiment as a whole-structure binary classifier.
- Suspicious-subgraph extraction hops describe an investigation neighborhood. They are not the same as RGCN layer depth/message-passing radius.
- Representation learning objective, sampling strategy, feature initialization, and score-alignment contract are unresolved and must be fixed before training.

## 16. Open questions / blockers

1. **FILE node features:** no implementation or artifact found. **NEEDS VERIFICATION.**
2. **MODULE node features:** no implementation or artifact found. **NEEDS VERIFICATION.**
3. **DESTINATION node features:** no implementation or artifact found. **NEEDS VERIFICATION.**
4. **RGCN encoder:** none found in code, dependencies, or artifacts.
5. **Training objective:** not implemented or documented in the repository. **NEEDS VERIFICATION.**
6. **Learning regime:** unsupervised, self-supervised, reconstruction-based, contrastive, or other formulation is unresolved.
7. **Embedding handoff to One-Class SVM:** no serialization schema, ordering contract, or training code found.
8. **Score alignment:** no artifact maps anomaly-score rows back to deterministic process IDs, period, structure IDs, and event-level ground truth.
9. **Sampling:** no full-batch feasibility result or neighbor/subgraph sampling strategy is defined for the historical graph scale.
10. **Available hardware:** observed 2026-09-30 as an Apple M4 MacBook Air with 10 CPU cores and 24 GB unified memory; approximately 104 GiB filesystem space was free. EDA10 defaults to a 4 GB DuckDB memory limit and 2 threads. No PyTorch/MPS/CUDA stack is declared in `requirements.txt`, so accelerator readiness is **NEEDS VERIFICATION**.
11. **Artifact locations and hashes:** SysClient0201 feature/split/policy artifacts have been recovered and hashed; other six-host caches/results remain unknown.
12. **Graph publication:** behavior compatibility is resolved and both graphs are complete locally. Training's two edge files exceed transfer limits; direct Colab/Drive filesystem publication remains unfinished.
13. **Ground-truth overlay implementation:** absent; actorID mapping needs code and audit trail.
14. **Period-map scope:** repository provenance limits the current period map to the fixed 10 GB pilot; full-host use must be revalidated.
15. **Test discovery:** root-level `pytest` is blocked by duplicate untracked review-copy test filenames; canonical `pytest tests` succeeds.

## 17. OCR-APT / ProvAgent comparison

Supplied research context says existing OCR-APT/ProvAgent work already covers important aspects of provenance graphs, graph-based anomaly detection, attack investigation, and LLM/agent workflows. No related paper, citation, note, reproduction code, or comparison result exists in the repository, so the literature characterization and any detailed comparison **NEED VERIFICATION** before publication.

The defensible present framing is experimental reproduction/foundation/comparison plus empirical testing of this project's graph construction and detection design. EDA10 uses a CREATE-defined process-family skeleton with rich contextual behavior; a future comparison may build a broader heterogeneous connectivity scheme similar to existing work. Broader connectivity is an empirical alternative, not automatically superior, because it may merge unrelated process families or amplify leakage/noise.

## 18. Public communication constraints

This repository is public. Public-safe topics include DARPA OpTC, large-scale endpoint telemetry, provenance graphs, graph neural networks, anomaly detection, temporal context, LLM/agentic cybersecurity investigation, and experimental comparison with existing work.

The confidential long-term research direction is deliberately not named or described in this file. It must not be added to a public README, public repository documentation, LinkedIn, a resume, public slides, conference outreach, or emails to outsiders without explicit authorization. If future documentation needs the private direction, first move it to an access-controlled location or obtain explicit permission to disclose it. Never infer or reconstruct omitted confidential content from this nondisclosure rule.

## 19. Completed vs planned table

| Item | Status | Evidence | Artifact/path | Last verified |
|---|---|---|---|---|
| Streaming/cache/EDA1–EDA10 code | COMPLETE | Canonical modules import and canonical suite passes | `src/eda/`, `tests/` | 2026-09-30 |
| Canonical repository test suite | COMPLETE | 677 passed, 3 pre-existing deprecation warnings | `tests/` | 2026-10-03 |
| Root-level test discovery | BLOCKED | 6 collection errors from duplicate untracked review tests | Untracked `eda09_*_review/`, `eda10_*_review/` | 2026-09-30 |
| Pilot period map | COMPLETE | Tracked CSV, provenance, tests | `data/period_maps/optc_pilot_period_map_v1.{csv,md}` | 2026-09-30 |
| EDA9 authoritative run | PLANNED | Builder/tests exist; no run output found | Expected caller-provided output directory | 2026-09-30 |
| Six-host normalized caches | NEEDS VERIFICATION | Historical claim only; ignored/external artifacts absent | Unknown | 2026-09-30 |
| Six-host EDA10 runs | NEEDS VERIFICATION | Historical claim only; no outputs/hashes found | Unknown | 2026-09-30 |
| Six-host ground-truth mapping | NEEDS VERIFICATION | Historical counts only; mapper/artifacts absent | Unknown | 2026-09-30 |
| Exact six-host structure statistics | NEEDS VERIFICATION | Supplied historical figures only | Unknown EDA10/overlay outputs | 2026-09-30 |
| SysClient0201 split artifact compatibility | COMPLETE | Real schemas, IDs, metadata, CREATE topology/counts reconcile | Saved compatibility audit; historical source generation not rerun | 2026-10-01 |
| 70-feature policy compatibility | COMPLETE | Exact ordered policy applies to both real PROCESS tables | Saved compatibility audit; Drive policy JSON | 2026-10-01 |
| SysClient0201 historical RGCN graph | NEEDS VERIFICATION | Drive summary readable; edge validation and builder source absent | `eda_10_sysclient0201_rgcn_graph_v1` on Drive | 2026-10-01 |
| Hybrid period-wide graph builder | COMPLETE | Implementation and 48 synthetic tests pass; real runs pending | `src/eda/build_period_heterogeneous_graph.py`, `tests/test_period_heterogeneous_graph.py` | 2026-10-01 |
| Historical behavior adapter | COMPLETE | All real events/relations reconcile; explicit-role source join and raw keys | `src/eda/adapt_structure_scoped_behavior_links.py`; saved real-run report | 2026-10-02 |
| Thin Colab runner | COMPLETE | Historical audit/adapter/control/independent builds and measured comparison | `colab/run_sysclient0201_hybrid_graph.ipynb`; runtime not executed | 2026-10-02 |
| Real-period hybrid connectivity experiment | COMPLETE | Both graphs executed locally, near-total component collapse measured | Ignored local run; saved real-run report | 2026-10-02 |
| Drive graph publication | COMPLETE | Colab report verifies both periods 6/6 with exact hashes/counts | `publication_verification_5850b2b5d6254a36b8ed00df6a26f4b3.json` | 2026-10-02 |
| Training-first hub-control audit | COMPLETE | 19 policies, frozen TRAIN masks/weights, both periods measured; no labels/models | `reports/sysclient0201_hub_control_audit_v1.json`; ignored detailed outputs | 2026-10-03 |
| Non-PROCESS node initialization | BLOCKED | No implementation or documented decision | None | 2026-09-30 |
| RGCN encoder and objective | PLANNED | No implementation/dependency found | None | 2026-09-30 |
| RGCN training / PROCESS embeddings | PLANNED | No executed result or checkpoint found | None | 2026-09-30 |
| One-Class SVM fit and evaluation scoring | PLANNED | No code or result found | None | 2026-09-30 |
| A New Hope model evaluation | PLANNED | No score/label evaluation artifact found | None | 2026-09-30 |
| Local suspicious-neighborhood investigation | PLANNED | Intended workflow only | None | 2026-09-30 |
| OCR-APT / ProvAgent empirical comparison | PLANNED | Contextual proposal; no repo work product | None | 2026-09-30 |

## 20. Current next step

### CURRENT NEXT EXPERIMENT

**After the training-first hub audit:** review the shortlist (MODULE family-frequency >1%, all-type family-frequency >5%, degree-IDF weighted full graph) and decide loss/exposure tolerances, frozen identity versus unseen-hub treatment, relation/reverse normalization, weight shape/floor, sampling/layer depth, and a training-only validation design. There is no automatically selected winner. Full graphs remain unchanged. Do not start RGCN or One-Class SVM work without a new explicit request.

## 21. Research safeguards

- `unlabeled != benign`.
- An attack-associated structure does not imply every process in it is malicious.
- Event count does not equal process count.
- Do not say the RGCN was trained or evaluated without an executed result artifact.
- Make no performance claim without a saved evaluation artifact and reproducible metric definition.
- Never use UUIDs, IDs, hashes, or other linkage identifiers as predictive features.
- Fit feature transformations/vocabularies only on verified-benign training data and prevent train/evaluation topology leakage.
- Rebuild period components independently when the experimental design requires leakage isolation.
- Preserve exact actorID-based ground-truth mapping; do not guess from PID/path and do not promote objectID targets automatically.
- Keep one common cross-host feature schema; do not drop features independently by host.
- Do not publicly disclose the omitted confidential research direction.
- Treat PLANNED, historical, and `NEEDS VERIFICATION` work as incomplete.

## 22. Last session summary

- Implemented `build_period_heterogeneous_graph.py` and 48 focused synthetic tests.
- Shared context identity across CREATE families while preserving process-family metadata and CREATE topology.
- Namespaced node/edge IDs by period; validated supplied period columns and referenced processes.
- Defined all 10 forward and 10 reverse relations and the six-file output contract.
- Added connectivity, degree, family-sharing, feature-policy, hash, and topology reconciliation audits.
- Preserved high-degree entities and left EDA10 unchanged.
- Committed and pushed builder/tests/research docs in `367ff8ff2a99f96363609469a3b54632dc5c58f6`, leaving review archives/directories and `.cursor/` untracked.
- Created the thin Colab runner plus repository audit/orchestration module and focused contract tests.
- Recovered historical explicit-period behavior links and added the lossless adapter, exact-key policy and controlled PROCESS/CREATE equivalence gate. EDA10 is unchanged.
- Ran both real hybrid graphs locally and measured the old source topology; largest PROCESS share increases to 99.990% / 98.532%, driven by common Windows module hubs.
- All 28,320,862 behavior events reconcile with zero source/period/family mismatches. Saved full audits/hashes/baselines; complete data are preserved in ignored local storage.
- Evaluation is fully uploaded and verified; training's two large edge files hit connector limits. Drive status markers distinguish graph completion from partial publication. No original Drive source was modified.
- Focused tests 102 passed; canonical tests 621 passed, 3 pre-existing warnings. No Colab runtime, pruning, model implementation or training occurred.

## 23. Next-session startup instructions

“When a new ChatGPT/Codex session starts:
1. Read this file fully.
2. Inspect git HEAD.
3. Check the Last Updated and Last Verified sections.
4. Do not assume PLANNED work is complete.
5. Continue from CURRENT NEXT EXPERIMENT.”

## 24. Training-first hub-control audit (2026-10-03)

`src/eda/audit_hybrid_graph_hubs.py` reads only PROCESS linkage/family/period columns, context identity/type columns, forward relations and available event counts from the completed graphs. It checks the four consumed source files per period against the immutable real-run manifest and rechecks hashes after execution. No labels/features are loaded or fitted; all PROCESS nodes, CREATE rows/weights and context identities remain unchanged. Only masks/profiles/weight candidates/JSON audits are written to a fresh, separate output directory; no filtered edge Parquets are generated. `scipy` supplies sparse connectivity/neighborhood operations, not model code.

TRAIN has 4,815 CREATE families. Policies comprise FULL_SHARED; per-type degree and family percentiles 99/99.5/99.9; all-type and MODULE-only family-frequency bands 1/5/10%; a degree-ranked policy matching the 1%-family policy's exact per-type removal budget; MODULE-off and CREATE-only diagnostics; and degree/family/geometric inverse-frequency weighted full profiles. Percentile ties are retained. The numeric cutoffs and exact `(node_type, host_scope, canonical_key)` exclusion lists, plus candidate weights, are frozen before evaluation is opened. Evaluation applies those exact identity lists; unseen contexts remain retained with weight 1. The two type-off diagnostic rules also exclude unseen identities of those types. Evaluation metrics are reporting only, never used to select policies.

Executed local results (source hashes match completed authentic Drive snapshots):

- **Baselines:** TRAIN full 71,362/71,369 PROCESS (99.99019182%), 8 WCCs; CREATE-only 41,277 (57.83603525%), 4,815 WCCs. Evaluation full 8,253/8,376 (98.53151862%), 124 WCCs; CREATE-only 6,495 (77.54297994%), 838 WCCs. CREATE counts remain 66,554/7,538 for every variant.
- **MODULEs are not necessary for collapse:** removing every MODULE context leaves TRAIN 70,075 PROCESS (98.18688786%) in its largest component, 1,289 WCCs, 3,527 bridged families, and max context degree 11,458. Evaluation remains 7,946 PROCESS (94.86628462%), 431 WCCs. MODULE LOAD supplies 71.17974847% of TRAIN compact context edges; FILE/DESTINATION sharing still sustains a giant component.
- **Extreme per-type degree pruning is insufficient:** P99.9 removes just 60 TRAIN contexts, retains 83.38338028% of context edges, but leaves 71,351 PROCESS (99.97477897%) in the largest component and max degree 41,032. P99 still leaves 99.41991621% connected despite retaining only 45.67386504% of context edges.
- **Family frequency and degree answer different questions:** same budget of 57 FILE +126 MODULE contexts, with zero DESTINATION removed: family-frequency >1% (more than 48.15 TRAIN families) yields 497 bridged families, 4,319 WCCs, 93.04459920% largest PROCESS share and 30.00186207% context-edge retention. Matched degree ranking yields 1,573 bridged families, 3,243 WCCs, 94.49761101% share and 27.90959233% retention. Degree controls the maximum more strongly (1,856 vs family policy 6,232); family frequency controls cross-family bridging more strongly. Neither metric dominates all objectives. TRAIN degree/family Spearman: FILE 0.73250532, MODULE 0.81015724, DESTINATION 0.35427308.
- **MODULE-only >1% shortlist:** removes 126/2,844 MODULEs, retains every FILE/DESTINATION, 3,557 bridged families, 38.20518341% of context edges, and 98.23032409% largest PROCESS share. Sampled median 2-hop PROCESS count falls 64,225 →5,818; max context degree remains 11,458. Frozen evaluation largest share is 95.06924546%, with 37.99676972% context edges retained.
- **All-type >5% shortlist:** excludes 138 TRAIN contexts (36 FILE, 102 MODULE, zero DESTINATION), retains 1,524 bridged families, 33.61662382% of context edges, and 94.50321568% largest PROCESS share. Sampled 2-hop PROCESS median/p95 are 515.5/10,458. Evaluation largest share is 92.46657116%, edge retention 37.47677419%. The stronger >1% policy excludes 183 contexts and lowers the sampled median to 7, but leaves only 497 bridged families; preserving useful context has not been established.
- **Weighted full shortlist:** degree-IDF retains all nodes/edges; TRAIN's top 1% of contexts carry 84.64397403% of unique process-context incidence mass before weights and 56.64216605% afterward. Total weighted mass is 24.30983438% of raw mass. Family and geometric weighting give top-1% shares 59.61411290%/57.83981856%. These are static incidence proxies, not learned-message or detection measurements. Connectivity and raw 2-hop neighborhoods are unchanged, so weighting does not solve memory/sampling exposure by itself.

Neighborhoods: 1-hop counts are exact over the full PROCESS universe. 2-hop counts are exact per seed for 64 deterministic SHA256 PROCESS-ID samples per period, identical across policies; reported sample quantiles are **not population quantiles**. Large WCCs alone do not establish noisy or harmful context, and these policies do not establish improved detection.

Full outputs are ignored under `data/local_runs/sysclient0201_hub_control_v1_verified/`: per-context degree/family/event/rank profiles; relation-specific profiles/distributions; per-period masks; frozen TRAIN policy/weight tables; per-period candidate weights; top-10 remaining hubs; all variant metrics; CSV comparison; file hashes. Repository-safe summary: `reports/sysclient0201_hub_control_audit_v1.json`. Verified run took 27.22 seconds locally. Detailed audit source SHA256: `38fbf5c8b4bd7eba9df38622fb3d55c7ebe0783b59a3b3709aa605667d383ddf`. No source/EDA10 changes or model training occurred.

Reproduce with a NEW separate output folder:

```sh
python3 -m src.eda.audit_hybrid_graph_hubs \
  --train-dir data/local_runs/sysclient0201_hybrid_graph_v1/artifacts/eda_10_sysclient0201_hybrid_graph_verified_benign_v1 \
  --evaluation-dir data/local_runs/sysclient0201_hybrid_graph_v1/artifacts/eda_10_sysclient0201_hybrid_graph_evaluation_v1 \
  --output-dir data/local_runs/sysclient0201_hub_control_repeat \
  --real-run-manifest reports/sysclient0201_hybrid_graph_real_run_v1.json \
  --two-hop-sample-size 64
```
