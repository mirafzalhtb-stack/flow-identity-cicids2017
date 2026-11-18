# Label Matching Policy (v4.1, extended in v4.2 and v4.3)

Implementation: `src/labeling/cicids2017.py`. Status: implemented and tested on synthetic fixtures. **Real CIC-IDS2017 CSVs have not been inspected.**

## 1. Principles
1. Only an unambiguous, time-consistent, one-to-one match is trusted.
2. A shared label never resolves ambiguity between candidate sessions.
3. Every decision carries a reason and numeric evidence. No uncalibrated confidence scores.
4. Uncertain flows are kept (nothing is deleted) and excluded from supervised samples.
5. Unmatched never means BENIGN.
6. The official labels are assumed to contain errors (Engelen et al. 2021; Lanvin et al. 2022). The audit makes them visible but cannot correct them.

## 2. Inputs and normalisation
* CSV headers: whitespace collapsed, BOM removed, lower-cased. Required fields: source/destination IP and port, protocol, timestamp, duration, label. A missing or duplicated required column raises `LabelSchemaError` (CLI exit 2). Feature-only CSVs without IPs or timestamps cannot be matched to PCAP flows by this method.
* Timestamps: parsed with the configured formats in order. Resolution is 1 s if the format has seconds, otherwise 60 s. They are converted to UTC with the **mandatory** `utc_offset_hours`. Optional `ambiguous_12h` adds a +12 h candidate for hours < 12 without AM/PM.
* Duration: converted with `duration_unit` (default `us`, VERIFY).
* Labels: non-ASCII characters → `-`, whitespace collapsed, `BENIGN` case-normalised.
* Key: protocol + unordered pair of (IP, port) endpoints, so direction does not matter. Orientation is reported separately.

## 2b. File formats (v4.2)
CSV and Parquet label files share one internal schema (`load_label_files`). Parquet is streamed in batches, reading only the required columns. Timestamp kinds: string (formats + offset), naive datetime (local + offset), tz-aware datetime (exact UTC, offset not applied), epoch (`timestamp_epoch_unit`, UTC). Each row keeps `source_file`, `source_row` and `row_id`. `Flow ID` is kept as `csv_flow_id` if present. Only files with endpoint identifiers can be matched. The `machine_learning/` tables are not used for matching.

## 3. Invalid CSV records
Rejected with one reason each (first failing check): `empty_row` (every required field empty, v4.2), `missing_<field>`, `unsupported_protocol`, `malformed_timestamp`, `invalid_duration` (non-numeric or negative), `invalid_port`, `invalid_ip`. They are written to `<output>.invalid_csv_rows.csv` and counted by reason in the label stats and the gate.

## 4. Candidate stages for each PCAP flow
For each CSV row with the same key (and each 12-hour alternative), with tol = `start_tolerance_s` + resolution:

| Stage | Condition |
|---|---|
| key | same protocol and endpoint pair |
| overlap | [csv_start − tol, csv_start + csv_duration + tol] intersects [flow_start, flow_end] |
| start-aligned | \|csv_start − flow_start\| ≤ tol |
| consistent | start-aligned **and** \|csv_duration − expected\| ≤ `duration_abs_tolerance_s` + `duration_rel_tolerance` · max(csv_duration, expected), where expected = flow duration, or min(flow duration, `csv_active_timeout_s`) if set |

## 5. Decision table
| Status | Rule | Trusted |
|---|---|---|
| `unique` | exactly 1 consistent row, all start-aligned rows share one label, and that row is not the unique match of another PCAP flow | **yes** (if `valid_early_prefix`) |
| `ambiguous_same_label` | ≥ 2 consistent rows, one label. Reason `exact_duplicate_csv_rows` or `multiple_consistent_rows_same_label` | no |
| `ambiguous_shared_row` | the single consistent row is also the unique match of another PCAP flow (checked globally) | no |
| `conflict` | start-aligned rows with ≥ 2 distinct labels | no |
| `time_inconsistent` | `duration_mismatch` (start-aligned, not consistent) or `start_misaligned` (overlap but not start-aligned) | no |
| `unmatched` | `no_csv_row_with_same_key` or `no_csv_row_overlapping_flow_time` | no |
| `invalid_flow` | flow record has missing or invalid key fields or times | no |

`collapse_exact_duplicate_rows: true` (default false) treats identical rows (same start, duration, label, orientation) as one. This is a documented, opt-in deviation for known CSV duplication.

## 6. Recorded evidence per flow
`match_status, match_reason, label, binary_label, matched_row_id, n_key_rows, n_overlap_rows, n_start_aligned, n_consistent, start_offset_s (CSV − PCAP, signed), duration_diff_s (CSV − expected), orientation, used_12h_shift, candidate_row_ids, candidate_labels, trusted, exclusion_reason`.

## 7. Provisional tolerances
`start_tolerance_s = 1.0`, `duration_abs_tolerance_s = 1.0`, `duration_rel_tolerance = 0.10`. These are engineering choices made before seeing real data. After the first real audit, review the distributions in the quality-gate report (`timestamp_alignment_unique_s`, `duration_diff_*`). Record any change with its justification **before** training. Never tune tolerances on test-set performance.

## 8. Known consequences
* With 1-second CSV timestamps, two sessions on the same 5-tuple less than about 2 s apart cannot be distinguished. Both become `conflict` or ambiguous. This is intended.
* CICFlowMeter and EarlyNIDS segment flows differently (FIN handling, timeouts). This produces `duration_mismatch`. If the CSV tool caps flow duration, set `csv_active_timeout_s` (VERIFY first).
* Only flow-level labels exist. No packet-level onset is inferred.

## v4.3 — identity evidence (`matching_mode: evidence_v43`, default)
Same candidate stages as above. When **several** candidates are loosely consistent, a candidate is trusted only with strict identity evidence: its duration residual is within `strict_duration_abs_s` + `strict_duration_rel`·max(duration) (and its packet counts agree, if `packet_check: require`), **and** every other candidate misses that strict tolerance by at least `identity_margin`. Labels are never used to choose. Start-aligned rows with different labels remain a `conflict`. A selected row that is also a consistent candidate of another flow is `ambiguous_shared_row`. Flows cut by the end of a capture are right-censored (one-sided duration check). With `csv_active_timeout_s`, the expected duration is the extractor's window statistic (`window_last_rel_ts`), flagged approximate if unavailable. New reasons: `disambiguated_by_duration_residual`, `insufficient_identity_margin`, `no_candidate_meets_strict_identity`, `multiple_strict_candidates`, `selected_row_is_candidate_of_other_flow`. `matching_mode: legacy_v41` reproduces v4.1/v4.2 exactly. Every trusted sample records `matched_source_file` and `matched_source_row`.
