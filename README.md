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
│   ├── tables/                     # Duplicate CSVs
│   ├── figures/                    # Duplicate charts
│   ├── json/                       # Future structured metadata
│   ├── graphs/                     # Future graph objects
│   └── evidence/                   # Future evidence snapshots
├── reports/                        # Human-readable reports (future)
├── src/
│   └── eda/
│       ├── eda_01_dataset_intake.py
│       └── eda_01_master_archive_inventory.py
├── .gitignore
├── README.md
└── requirements.txt
```

---

## EDA scope boundaries

EDA 1 (all scripts) strictly enforces:

- No archive extraction
- No event-level row reading
- No final dataset statistics
- No attack analysis
- No MITRE label assignment
- No malicious / benign classification
- No host-level or row-level filtering
