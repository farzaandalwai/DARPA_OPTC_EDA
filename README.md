# DARPA OpTC EDA

Exploratory data analysis code and deliverables for the DARPA Operationally
Transparent Cyber (OpTC) dataset.

---

## Important policies

> **Do not commit raw archives.**
> `.tar`, `.gz`, `.json.gz`, and all extracted data files are listed in
> `.gitignore`. Only code and EDA output artefacts are tracked by Git.

> **Do not fully extract archives.**
> EDA scripts open `.tar` files for metadata inspection only (member names,
> sizes). No file content is ever decompressed or written to disk.

---

## Where the raw data lives

| Environment | Path |
|---|---|
| **Google Colab** | `/content/drive/MyDrive/DARPA_OPTC_EDA/corrected_archives` |
| **Local Mac** | `/Users/farzu/Desktop/DARPA_OPTC_EDA/data/corrected` |
| **Local Mac via Drive Desktop** | Wherever Google Drive Desktop mounts your Drive |

Raw archives are stored in Google Drive only. The Git repo stores code and
EDA output deliverables.

---

## Quick start

### Install dependencies

```bash
pip install -r requirements.txt
```

### EDA 1 — Single-folder dataset intake (T1, T2, F1)

**Local Mac:**

```bash
python3 src/eda/eda_01_dataset_intake.py \
    --project-root /Users/farzu/Desktop/DARPA_OPTC_EDA \
    --raw-data-dir /Users/farzu/Desktop/DARPA_OPTC_EDA/data/corrected
```

**Google Colab:**

```python
# Mount Drive first
from google.colab import drive
drive.mount('/content/drive')

!python3 src/eda/eda_01_dataset_intake.py \
    --project-root /content/drive/MyDrive/DARPA_OPTC_EDA_REPO \
    --raw-data-dir /content/drive/MyDrive/DARPA_OPTC_EDA/corrected_archives
```

Optional flags:

| Flag | Default | Notes |
|---|---|---|
| `--dataset-version` | `corrected` | One of `corrected`, `original`, `both`, `review_all` |
| `--checksum` | off | Streaming SHA-256 per file. Slow for large archives. |
| `--no-tar-smoke-test` | — | Disable tar smoke test |
| `--output-dir` | `<project-root>/outputs/eda_01_intake` | Override output root |

---

### EDA 1 — Master corrected-archive inventory (T1B, S1)

**Local Mac:**

```bash
python3 src/eda/eda_01_master_archive_inventory.py \
    --project-root /Users/farzu/Desktop/DARPA_OPTC_EDA \
    --corrected-dir /Users/farzu/Desktop/DARPA_OPTC_EDA/data/corrected
```

**Google Colab:**

```python
!python3 src/eda/eda_01_master_archive_inventory.py \
    --project-root /content/drive/MyDrive/DARPA_OPTC_EDA_REPO \
    --corrected-dir /content/drive/MyDrive/DARPA_OPTC_EDA/corrected_archives
```

Optional flags:

| Flag | Default | Notes |
|---|---|---|
| `--checksum` | off | Streaming SHA-256 per archive. |
| `--no-tar-smoke-test` | — | Disable tar smoke test. |
| `--estimate-extracted-size` | off | Sum tar member sizes (all members). Slow for large archives. |

**With all tests enabled (slow):**

```bash
python3 src/eda/eda_01_master_archive_inventory.py \
    --project-root /Users/farzu/Desktop/DARPA_OPTC_EDA \
    --corrected-dir /Users/farzu/Desktop/DARPA_OPTC_EDA/data/corrected \
    --checksum \
    --estimate-extracted-size
```

---

## EDA 1 outputs

All outputs are written to `outputs/eda_01_intake/` and duplicated to
`outputs/tables/` (CSVs) and `outputs/figures/` (charts).

| File | Description |
|---|---|
| `T1_dataset_intake_ledger.csv` | One row per file in raw-data-dir |
| `T2_analysis_scope_table.csv` | Six-row scope summary table |
| `F1_file_coverage_chart.png` | Bar chart: file size by source type |
| `T1B_master_archive_inventory.csv` | One row per corrected archive (all 10) |
| `S1_storage_feasibility_report.txt` | Disk space vs catalog size |
| `README_eda01_intake.txt` | Auto-generated run summary |

---

## Project structure

```
DARPA_OPTC_EDA/
├── configs/                        # Path config examples (not secrets)
│   ├── eda_01_colab_paths.example.json
│   └── eda_01_local_paths.example.json
├── data/                           # Raw archives — gitignored
│   └── README_data.md
├── outputs/
│   ├── eda_01_intake/              # EDA 1 primary outputs
│   ├── eda_02_schema/              # EDA 2 primary outputs
│   ├── eda_03_time/                # EDA 3 primary outputs
│   ├── tables/                     # Duplicate CSVs (all EDAs)
│   ├── figures/                    # Duplicate charts (all EDAs)
│   ├── json/                       # Future structured metadata
│   ├── graphs/                     # Future graph objects
│   └── evidence/                   # Future evidence snapshots
├── reports/                        # Human-readable reports (future)
├── src/
│   └── eda/
│       ├── optc_streaming_parser.py         ← shared streaming engine
│       ├── eda_01_dataset_intake.py
│       ├── eda_01_master_archive_inventory.py
│       ├── eda_02_schema_quality_audit.py
│       └── eda_03_time_window_selection.py
├── .gitignore
├── README.md
└── requirements.txt
```

---

## EDA 2 — Schema and Data-Quality Audit (pilot)

Streams events from `.json.gz` members inside `.tar` archives without extraction,
then produces a field-reliability table and a data-quality issue log.

### Colab (pilot on one archive)

```bash
python3 src/eda/eda_02_schema_quality_audit.py \
  --project-root /content/DARPA_OPTC_EDA_REPO \
  --corrected-dir /content/drive/MyDrive/DARPA_OPTC_EDA/corrected_archives \
  --archives 2019-09-16.tar \
  --max-members 25 \
  --max-events 50000
```

### Local Mac (pilot on one archive)

```bash
python3 src/eda/eda_02_schema_quality_audit.py \
  --project-root /Users/farzu/Desktop/DARPA_OPTC_EDA \
  --corrected-dir /Users/farzu/Desktop/DARPA_OPTC_EDA/data/corrected \
  --archives 2019-09-16.tar \
  --max-members 25 \
  --max-events 50000
```

**Outputs:**

| File | Description |
|------|-------------|
| `outputs/eda_02_schema/T3_field_reliability_audit.csv` | Per-field missingness, uniqueness, keep/review/drop |
| `outputs/eda_02_schema/T4_data_quality_issue_log.csv` | Parse errors, timestamp failures, duplicate IDs, gaps |
| `outputs/eda_02_schema/F2_timestamp_coverage_plot.png` | Hourly event count showing temporal coverage |
| `outputs/eda_02_schema/README_eda02_schema_quality.txt` | Run metadata and limitation notes |

---

## EDA 3 — Time Alignment and Window Selection (pilot)

Streams events, parses timestamps, and compares five candidate window sizes
(1min, 5min, 15min, 1h, 1d) to recommend a primary and backup window.

### Colab (pilot on one archive)

```bash
python3 src/eda/eda_03_time_window_selection.py \
  --project-root /content/DARPA_OPTC_EDA_REPO \
  --corrected-dir /content/drive/MyDrive/DARPA_OPTC_EDA/corrected_archives \
  --archives 2019-09-16.tar \
  --max-members 25 \
  --max-events 50000
```

### Local Mac (pilot on one archive)

```bash
python3 src/eda/eda_03_time_window_selection.py \
  --project-root /Users/farzu/Desktop/DARPA_OPTC_EDA \
  --corrected-dir /Users/farzu/Desktop/DARPA_OPTC_EDA/data/corrected \
  --archives 2019-09-16.tar \
  --max-members 25 \
  --max-events 50000
```

**Outputs:**

| File | Description |
|------|-------------|
| `outputs/eda_03_time/T5_window_size_comparison.csv` | Per-window event density, entity diversity, recommendation |
| `outputs/eda_03_time/F3_event_volume_over_time.png` | Event count per recommended window over time |
| `outputs/eda_03_time/F4_entity_diversity_over_time.png` | Unique hosts/processes/destinations per window |
| `outputs/eda_03_time/N1_window_recommendation_note.txt` | Primary and backup window recommendation with rationale |
| `outputs/eda_03_time/README_eda03_time_alignment.txt` | Run metadata and limitation notes |

---

## Streaming parser (utility module)

`src/eda/optc_streaming_parser.py` is imported by EDA 2 and EDA 3.
It can also be used as a CLI smoke-test:

```bash
python3 src/eda/optc_streaming_parser.py \
  --archives /path/to/2019-09-16.tar \
  --max-members 3 --max-events 200 \
  --output-csv /tmp/sample_events.csv
```

---

## EDA scope boundaries

All scripts (EDA 1–3) strictly enforce:

- No archive extraction to disk
- No attack analysis or benign classification
- No MITRE label assignment
- No malicious / suspicious claims
- No ground-truth overlays (deferred to EDA 10)
- Pilot outputs clearly labeled `[PILOT SAMPLE]` when `--max-members` or `--max-events` limits are active
