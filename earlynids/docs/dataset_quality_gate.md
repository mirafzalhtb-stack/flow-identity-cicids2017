# Dataset Quality Gate (v4.1, extended in v4.2 and v4.3)

Implementation: `src/datasets/quality_gate.py`. It runs automatically at the end of `scripts.match_labels` and can be re-run with `scripts.quality_gate`. `scripts.make_splits` refuses to create training splits unless a **passed** gate report exists for the exact same file (size + SHA-256 of the first 16 MiB).

## Reported quantities
Total PCAP flows · valid early-prefix flows · matchable flows · total / invalid CSV records · unique / ambiguous-same-label / ambiguous-shared-row / conflicting / time-inconsistent / unmatched / invalid flows · trusted samples · match, unmatched, conflict, ambiguous, time-inconsistent and invalid-CSV rates · trusted class distribution (binary and per label) · per-capture distribution (flows, valid, trusted, status counts) · start-offset statistics for unique matches · duration-difference statistics (unique and mismatched) · orientation counts · 12-hour-shift count · match reasons · excluded samples by reason · invalid CSV records by reason · thresholds and per-check results with hints.

Rates use the **matchable** denominator: valid early-prefix flows with valid key fields. Mid-stream and continuation flows are reported but not counted against the label matcher.

## Outputs (written even when the gate fails)
`<prefix>.quality_gate.json`, `<prefix>.quality_gate_checks.csv`, `<prefix>.exclusions_by_reason.csv`, `<prefix>.capture_summary.csv`. `match_labels` also writes `<prefix>.label_stats.json`, `<prefix>.invalid_csv_rows.csv`, `<prefix>.problem_flows.csv`, and the full labelled table with all flows. Raw inputs are only read, never modified.

## Thresholds — PROVISIONAL ENGINEERING THRESHOLDS
These were chosen before any real data were seen and are not statistically derived. Their purpose is to stop obviously broken inputs (wrong time zone, wrong CSV day, schema mix-ups), not to certify label quality.

| Check | Default | Rationale |
|---|---|---|
| `min_match_rate` | 0.90 | A wrong time zone or wrong file typically drops this near 0. CICFlowMeter segmentation differences are expected to cost some percent (unknown, to be measured) |
| `max_unmatched_rate` | 0.10 | Same reasoning |
| `max_conflict_rate` | 0.01 | Conflicts should be rare. More indicates label errors or a too-wide tolerance |
| `max_ambiguous_rate` | 0.05 | Ambiguity indicates tuple reuse within the tolerance or CSV duplication |
| `max_time_inconsistent_rate` | 0.05 | High values indicate a duration-unit or segmentation mismatch |
| `max_invalid_csv_rate` | 0.01 | Malformed records among **non-empty** rows (v4.2 definition). Indicates a format mismatch |
| `max_empty_row_rate` | 1.0 (report-only) | v4.2. Fully empty rows are not label records; the count is reported prominently, see the lineage audit |
| `min_trusted_coverage` | 0.0 (report-only) | v4.2. Trusted / valid-prefix flows |
| `min_trusted_per_class` | 100 | Minimum for any meaningful binary evaluation. Not a power analysis |
| `require_both_classes` | true | Benign-only captures (e.g. Monday) fail when gated alone. Gate the concatenated dataset, or gate per day with this set to false and record it |

After the first real-data audit: review each threshold against the observed distributions and record the decision and date here **before** model training. Lowering a threshold to "make the gate pass" requires a written justification.

## Exit codes
`match_labels` / `quality_gate`: 0 passed, 4 failed (with actionable `FAILED <check>` lines), 2 invalid input. `make_splits`: 4 if the gate report is missing, failed or belongs to another file.

## Provisional vs validated thresholds (v4.2)
The report contains `threshold_status`. A threshold becomes "validated" only when it is listed in `quality_gate.validated_thresholds` with a reference to a dated justification in this file (e.g. `{max_conflict_rate: "docs/dataset_quality_gate.md#review-2026-12-01"}`). The gate does not change any threshold on its own.

### Review log
(empty: no real-data review has taken place yet)

## v4.3 — three separate verdicts
* `capture_integrity`: all integrity checks (match / unmatched / conflict / ambiguous / time-inconsistent / invalid / empty / coverage / unique ids), evaluated on the whole table **and for every capture**. `passed` == this verdict. Exit code 4 only when it fails.
* `class_coverage`: `class_counts` (both classes ≥ `min_trusted_per_class`).
* `training_eligible` = integrity AND coverage. `make_splits` requires it.

A BENIGN-only capture (Monday) can pass integrity but is never training-eligible on its own. Eligibility is decided on the combined table (`scripts.combine_labelled`, `scope: dataset`). Thresholds are unchanged and remain provisional.
