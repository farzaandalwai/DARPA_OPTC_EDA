# OpTC Pilot Period Map v1

## Scientific meaning

This period map applies only to `pilot_manifest_10gb_v1` and the fixed 10 GB
pilot. Its intervals are half-open: `[start_time, end_time)`.

- `verified_benign` means the source period preceding the evaluation/red-team
  dates.
- `evaluation` means data from the evaluation dates. It does not mean every
  event is malicious; benign activity continued during the evaluation/red-team
  period.
- The map defines no attack or malicious period role and must not be used to
  label every September 23–25 event as an attack.

## Project scope

- Manifest: `pilot_manifest_10gb_v1`
- Cache schema: `optc_normalized_v3`
- Cache events: `180,648,918`
- Archive dates: 2019-09-16 through 2019-09-25
- Stored timestamps: naive UTC

## Official sources

- OpTC data repository: https://github.com/FiveDirections/OpTC-data
- Red-team ground-truth PDF:
  https://raw.githubusercontent.com/FiveDirections/OpTC-data/master/OpTCRedTeamGroundTruth.pdf
- Dataset DOI: https://doi.org/10.57745/UXCWOC

## Ground-truth PDF

- Filename: `OpTCRedTeamGroundTruth.pdf`
- Size: `453,244` bytes
- SHA-256:
  `5986d23b81169221a491f7a8302fce140b12638ef4cf9b3a894ed3cb2fad9567`
- First extracted dated red-team action: `09/23/19 11:23:29`

The PDF does not state the timezone beside this timestamp. Therefore, this
timestamp is not used as the period boundary.

## Exact archive evidence

- `2019-09-22.tar`
  - first: `2019-09-22T04:00:00.000000 UTC`
  - last: `2019-09-23T03:59:59.999000 UTC`
  - events: `20,183,409`
- `2019-09-23.tar`
  - first: `2019-09-23T04:00:00.002000 UTC`
  - last: `2019-09-24T03:59:59.999000 UTC`
  - events: `18,423,861`

## Period totals

- verified_benign: `126,400,024` events
- evaluation: `54,248,894` events
- reconciliation: `180,648,918` events

## Boundary rationale

The archive-day transition occurs at 04:00 UTC. September 2019 was UTC−04 for
the exercise's local calendar alignment. The three-millisecond data gap across
the September 22→23 transition contains no selected pilot events.

The map conservatively classifies the entire September 23 archive as
evaluation rather than treating pre-ground-truth hours as verified benign.
This prevents evaluation-day information from leaking into baseline fitting.

## Limitations

- This is a derived, evidence-backed period map, not a file directly supplied
  inside the corrected archive release.
- It assigns period roles, not event-level malicious labels.
- Ground-truth event alignment remains EDA 10.
- The map must not be generalized beyond the fixed pilot without revalidation.
