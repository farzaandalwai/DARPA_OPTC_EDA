=================================================================
  DARPA OpTC — EDA 1: Dataset Intake and Version Control
  README — Intake Run Summary
=================================================================

  Run timestamp        : 2026-06-28 00:50:59
  Raw data directory   : /Users/farzu/Desktop/DARPA_OPTC_EDA/data/corrected
  Selected version     : corrected

-----------------------------------------------------------------
SELECTED DATASET VERSION
-----------------------------------------------------------------

  SELECTED_DATASET_VERSION = "corrected"

  Allowed values:
    corrected  — include only files containing 'corrected' in path/name
    original   — include only files containing 'original' in path/name
    both       — include both; unknown-version files still flagged 'review'
    review_all — no version filter; every readable file is included

-----------------------------------------------------------------
INCLUSION RULE
-----------------------------------------------------------------

  A file receives included_yes_no = 'yes' only when ALL of:
    1. Filename does not start with '.' or '~' (not hidden/temp).
    2. File is not zero bytes.
    3. Smoke-test parser did not raise a parse / open error.
    4. Inferred dataset version matches SELECTED_DATASET_VERSION.

  included_yes_no = 'no' when:
    - Fails checks 1–3, OR
    - Confirmed version does not match selected version.
      (exclusion_reason = wrong_dataset_version)

  included_yes_no = 'review' when:
    - Passes structural checks but version is ambiguous.
      (exclusion_reason = dataset_version_unknown_needs_manual_review)
    Fill in manual_review_note after inspecting the file.

-----------------------------------------------------------------
SMOKE-TEST PARSING — READABILITY ONLY
-----------------------------------------------------------------

  The smoke test confirms a file can be opened and parsed.
  It does NOT count rows, compute statistics, assess data
  quality, or perform any content or attack analysis.

  .tar files:
    Opens archive, peeks at first 20 member names, closes immediately.
    The archive is NEVER extracted.
    parse_status = 'tar_open_success' means the file is a valid tar.

  .csv / .tsv:  reads first 5 rows via pandas.
  .json / .jsonl: reads first 5 lines via json.loads.
  Other formats: not_attempted_or_unknown_format.

-----------------------------------------------------------------
TAR ARCHIVE POLICY
-----------------------------------------------------------------

  The .tar archive was NOT extracted at EDA-01 stage.
  Internal file types (endpoint/network/ground-truth) are
  catalogued inside the archive in EDA-02.

  Reason: EDA-01 scope is limited to:
    - Verifying the archive exists and is readable
    - Recording checksum, file size, date label, and version
    - Confirming the archive is not corrupted

-----------------------------------------------------------------
REVIEW ROWS — ACTION REQUIRED
-----------------------------------------------------------------

  Rows where included_yes_no = 'review' have an ambiguous
  dataset version. They are readable but cannot be confirmed
  as belonging to the selected release.

  Before using in downstream EDA phases:
    1. Open T1_dataset_intake_ledger.csv.
    2. Find all rows where included_yes_no = 'review'.
    3. Inspect file path and name manually.
    4. Write your decision in manual_review_note column.
    5. Re-save before handing to EDA-02.

-----------------------------------------------------------------
SCOPE BOUNDARIES — WHAT THIS SCRIPT DOES NOT DO
-----------------------------------------------------------------

  - No attack analysis
  - No final dataset statistics
  - No MITRE label assignment
  - No suspicious / malicious classification
  - No host-level or row-level filtering
  - No sampling

-----------------------------------------------------------------
FILE COUNTS FOR THIS RUN
-----------------------------------------------------------------

  Total files catalogued : 1
  Included (yes)         : 1
  Needs review (review)  : 0
  Excluded (no)          : 0

-----------------------------------------------------------------
OUTPUTS
-----------------------------------------------------------------

  T1_dataset_intake_ledger.csv        — one row per file
  T2_analysis_scope_table.csv         — six-row scope summary
  F1_file_coverage_chart.png          — bar chart: MB by source type
  README_eda01_intake.txt             — this file

=================================================================

=================================================================
  MASTER ARCHIVE INVENTORY EXPANSION
  Added by eda_01_master_archive_inventory.py  —  2026-06-28 12:37:47
=================================================================

  EDA 1 has moved from single-archive validation to a broad
  corrected-archive inventory covering all 10 official OpTC
  daily archives (2019-09-16 through 2019-09-25).

-----------------------------------------------------------------
WHAT CHANGED
-----------------------------------------------------------------

  Previously:  EDA-01 catalogued only the locally present
               2019-09-16.tar file.

  Now:         T1B_master_archive_inventory.csv lists all 10
               corrected archives.  Archives that have been
               downloaded receive a full treatment:
                 - SHA-256 checksum (streaming, no full load)
                 - Tar smoke test (peek at 20 member names)
                 - File coverage summary (all members classified
                   by path keyword, no content read)
                 - Estimated extracted size (sum of tar member
                   metadata sizes, no extraction)
               Archives not yet downloaded are still listed with
               pending placeholder values.

-----------------------------------------------------------------
WHAT HAS NOT BEEN DONE
-----------------------------------------------------------------

  - No archive has been fully extracted
  - No event rows have been read or counted
  - No event-level statistics have been computed
  - No attack or benign claims have been made
  - No MITRE labels have been assigned
  - Final modeling dates have not been selected
    (Processing Priority = pending_scientific_selection for all)

-----------------------------------------------------------------
BENIGN / ATTACK CANDIDATE COLUMNS
-----------------------------------------------------------------

  Both columns contain "candidate_only_needs_gt_review" for
  every archive.  This is an intake placeholder, not a verified
  classification.  Ground-truth alignment is deferred to EDA-02.

-----------------------------------------------------------------
STORAGE NOTE
-----------------------------------------------------------------

  See S1_storage_feasibility_report.txt for a full assessment
  of available disk space vs total corrected-archive catalog size.

=================================================================
