# Data Directory

Raw OpTC archives are **not stored in this Git repository**.

## Where the raw archives live

| Environment | Path |
|---|---|
| Google Colab | `/content/drive/MyDrive/DARPA_OPTC_EDA/corrected_archives` |
| Local Mac (example) | `/Users/farzu/Desktop/DARPA_OPTC_EDA/data/corrected` |
| Local Mac via Drive Desktop | Wherever Google Drive Desktop mounts your Drive |

## Official corrected-archive catalog

| Archive | Compressed size |
|---|---|
| 2019-09-16.tar | 12.5 GB |
| 2019-09-17.tar | 87.2 GB |
| 2019-09-18.tar | 64.9 GB |
| 2019-09-19.tar | 116.0 GB |
| 2019-09-20.tar | 83.7 GB |
| 2019-09-21.tar | 115.3 GB |
| 2019-09-22.tar | 115.8 GB |
| 2019-09-23.tar | 112.0 GB |
| 2019-09-24.tar | 104.3 GB |
| 2019-09-25.tar | 63.1 GB |
| **Total** | **874.8 GB** |

## How to run EDA 1 scripts

Pass the archive directory via `--corrected-dir` (master inventory) or
`--raw-data-dir` (single-folder intake):

```bash
# Local Mac
python3 src/eda/eda_01_master_archive_inventory.py \
  --project-root /Users/farzu/Desktop/DARPA_OPTC_EDA \
  --corrected-dir /Users/farzu/Desktop/DARPA_OPTC_EDA/data/corrected

# Colab
python3 src/eda/eda_01_master_archive_inventory.py \
  --project-root /content/drive/MyDrive/DARPA_OPTC_EDA_REPO \
  --corrected-dir /content/drive/MyDrive/DARPA_OPTC_EDA/corrected_archives
```

## Policies

- **Do not commit** any `.tar`, `.gz`, `.json.gz`, or extracted data files.
- **Do not fully extract** archives. EDA scripts open archives for metadata
  inspection only and never decompress file contents.
- Outputs (CSV, PNG, TXT) produced by EDA scripts **are** committed because
  they are small and serve as auditable deliverables.
