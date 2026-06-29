=================================================================
  DARPA OpTC — EDA 1: Dataset Intake and Version Control
  README — Intake Run Summary
=================================================================

  Run timestamp        : 2026-06-29 00:03:39
  Raw data directory   : /private/tmp/optc_test_data
  Selected version     : review_all
  Checksum             : Checksum disabled (pass --checksum to enable).

-----------------------------------------------------------------
SELECTED DATASET VERSION
-----------------------------------------------------------------

  --dataset-version review_all

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
    4. Inferred dataset version matches --dataset-version.

  included_yes_no = 'no':  fails any of 1–3, or confirmed wrong version.
  included_yes_no = 'review':  readable but version is ambiguous.
    Fill in manual_review_note column after inspecting.

-----------------------------------------------------------------
SMOKE-TEST PARSING — READABILITY ONLY
-----------------------------------------------------------------

  The smoke test confirms a file can be opened and parsed.
  It does NOT count rows, compute statistics, assess data
  quality, or perform any content or attack analysis.

  .tar files:
    Opens archive, peeks at first 20 member names, closes immediately.
    The archive is NEVER extracted.

  .csv / .tsv  : reads first 5 rows via pandas.
  .json / .jsonl : reads first 5 lines via json.loads.
  Other formats  : not_attempted_or_unknown_format.

-----------------------------------------------------------------
TAR ARCHIVE POLICY
-----------------------------------------------------------------

  The .tar archive was NOT extracted at EDA-01 stage.
  Internal file types are catalogued inside the archive in EDA-02.

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
  Included (yes)         : 0
  Needs review (review)  : 0
  Excluded (no)          : 1

-----------------------------------------------------------------
OUTPUTS
-----------------------------------------------------------------

  T1_dataset_intake_ledger.csv        — one row per file
  T2_analysis_scope_table.csv         — scope summary table
  F1_file_coverage_chart.png          — bar chart: MB by source type
  README_eda01_intake.txt             — this file

=================================================================
