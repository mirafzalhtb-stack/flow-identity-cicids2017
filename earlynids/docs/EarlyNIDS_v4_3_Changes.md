# EarlyNIDS v4.3 — Changes

Date: 2026-11-01. **Base:** the prompt names `EarlyNIDS_v4_2_2.zip`, but that archive was **not attached**. v4.3 was built from the delivered `EarlyNIDS_v4_2.zip` (147 tests passing at baseline). Any local modification you made in `v4_2_2` is not included. Diff your copy against `src/labeling/cicids2017.py` and `src/datasets/quality_gate.py` before replacing it.

Real CIC-IDS2017 data was **not** available here. The real-data numbers below (6,838 flows, the 5370 and NTP cases, the sensitivity table) are the researcher's reported observations. They were reconstructed as synthetic fixtures, not re-measured.

## 1. Task A — Code audit (how the v4.2 code actually works)

| Question | Location | v4.2 behaviour |
|---|---|---|
| Flow key | `src/preprocessing/packet.py::PacketRecord.canonical_key`; `src/labeling/cicids2017.py::canonical_keys`, `_flow_keys` | (ip_version, proto, min(endpoint), max(endpoint)) on packed IP+port. The label side uses the same unordered endpoint pair (hex-encoded) + protocol. Direction-independent on both sides |
| TCP segmentation | `src/preprocessing/flows.py::FlowExtractor.process_record` | Ends on RST; on FIN seen in **both** directions; a pure SYN after the handshake → `restart`; idle timeout 120 s (`_sweep`); capacity; EOF. Late packets within 5 s after close are counted, not turned into flows |
| UDP segmentation | same | **Idle timeout only** (120 s). `active_timeout` exists but defaults to `None`, so a UDP conversation with gaps < 120 s is one flow of any length |
| Orientation | `flows.py::_create`; matcher `orientation` column | Initiator = SYN sender (SYN-ACK destination, else first sender). The matcher keys are unordered. `orientation` (same/reversed) is reported but not used for selection |
| Candidate selection | `cicids2017.py::_match_chunk` | key merge → start-aligned (\|Δstart\| ≤ `start_tolerance_s` + resolution) → consistent (\|Δduration\| ≤ `duration_abs_tolerance_s` + `duration_rel_tolerance`·max) → `unique` iff exactly one consistent row. Several → ambiguous. Differing labels among start-aligned rows → conflict |
| Duration tolerance | same | Absolute 1 s + 10 %. **For a 20 ms flow the tolerance is about 1.002 s**, so 1 µs, 4 µs and 240 µs rows are all "consistent" |
| Trusted | `cicids2017.py::label_flows` | `match_status == 'unique'` and `valid_early_prefix` |
| Shared rows | `cicids2017.py::match_flows` | Only when the same row is *selected* by two flows |
| Gate | `src/datasets/quality_gate.py::evaluate` | One pass/fail over all checks, including `class_counts` → a BENIGN-only day fails like a matching failure |

### Defects (each reproduced, each now has a regression test)

| ID | Defect | Evidence | Fix | Test |
|---|---|---|---|---|
| D43-1 | Absolute duration tolerance dominates short flows. Several same-label rows are indistinguishable | Probe on the reconstructed `monday-000005370` case: ambiguous at 1.0 s and 0.1 s | Evidence mode: duration-scaled strict identity + explicit margin (§2) | `test_very_short_tcp_flow_disambiguated_by_duration_residual` |
| D43-2 | `csv_active_timeout_s` used `min(duration, T)` as the expected duration. That is not the duration of the first fixed-length segment (the last packet before T) | Probe: NTP 684.019 s vs CSV 72.018 s → still `duration_mismatch` with T = 120 | Extractor records `window_last_rel_ts`. The matcher uses it (exact) or flags `expected_duration_exact = False` | `test_long_udp_flow_with_csv_active_timeout_uses_window_duration`, `test_active_timeout_without_window_stats_is_flagged_approximate` |
| D43-3 | Flows cut by end of capture (smoke runs) were compared two-sided, so a longer CSV row looked inconsistent | Code review + test | `eof_censoring`: one-sided residual (only a CSV row *shorter* than observed contradicts) | `test_eof_truncated_flow_is_right_censored` |
| D43-4 | A label row that is a consistent candidate of two PCAP flows could be trusted by one of them | Code review | Evidence mode: the selected row must not be a consistent candidate of any other flow (global, chunk-safe) | `test_reused_label_row_across_flows_is_shared` |
| D43-5 | Trusted samples were traceable to `matched_row_id` only | Code review | `matched_source_file`, `matched_source_row` (+ residuals, runner-up) | `test_very_short_tcp_flow_...` |
| D43-6 | Gate conflated label-matching integrity with class coverage | Monday: matching fine, gate FAIL | Three verdicts: `capture_integrity`, `class_coverage`, `training_eligible` | `test_benign_only_capture_passes_integrity_but_is_not_training_eligible` |
| D43-7 | `label_frame_from_records` dropped optional columns (packet counts, flow id) | Test failure during v4.3 work | Shared `column_mapping()` | `test_packet_evidence_report_and_require` |
| D43-8 | No per-direction packet counts in flow records, so packet evidence was impossible | Code review | `n_fwd_packets`, `n_bwd_packets`, window counts | `test_extractor_bidirectional_counts` |

### Hypotheses (NOT fixed; they need real-data checks)
* **H1.** The tiny same-tuple rows (1 µs, 4 µs, 240 µs) are fragments created by the label tool after a FIN. Engelen et al. (2021) report that the original CICFlowMeter ended TCP flows at the first FIN. Check: the candidate evidence of such flows in `candidate_evidence.csv`.
* **H2.** The NTP 684 s vs 72 s discrepancy comes from a fixed 120 s flow cut in the label tool (72 s would then be the last packet before 120 s). Check: variant `evidence_1s_T120` in the sensitivity cell. If it does not move NTP flows to `unique`, H2 is rejected.
* **H3.** The TCP 445 discrepancy: no hypothesis tested. Inspect its candidate evidence.
* The idle-timeout semantics of the label tool are unknown. EarlyNIDS segmentation is **not** claimed to be CICFlowMeter-equivalent.

## 2. Task B — Safer matching (`matching_mode: evidence_v43`, new default)
For each flow, candidate set C = start-aligned **and** loosely consistent rows (unchanged v4.2 tolerances). Then:
1. Any start-aligned rows with different labels → `conflict`. Labels are used only to **detect** conflicts, never to choose.
2. |C| = 1 → `unique` (`single_consistent_row`). `identity_basis` records whether it also meets the strict criterion.
3. |C| ≥ 2 → strict identity S: duration residual ≤ `strict_duration_abs_s` (1 ms) + `strict_duration_rel` (1 %) × max(duration). With `packet_check: require`, packet counts must also agree (orientation-aware, ≤ `packet_tolerance`).
   * |S| = 1 and the best other candidate misses the strict tolerance by ≥ `identity_margin` (2×) → `unique` (`disambiguated_by_duration_residual`).
   * |S| = 1 but margin too small → `ambiguous_same_label` (`insufficient_identity_margin`).
   * |S| = 0 → `no_candidate_meets_strict_identity`. |S| ≥ 2 → `multiple_strict_candidates` or `exact_duplicate_csv_rows`.
4. Global: a row selected twice, or selected by one flow while being a consistent candidate of another → `ambiguous_shared_row`.
5. Durations: right-censored at EOF (one-sided); exact window duration when the label tool cuts at `csv_active_timeout_s`.
6. Recorded per flow: `n_strict`, `identity_basis`, `matched_source_file/row`, `expected_duration_s`, `expected_duration_exact`, `duration_censored`, `selected_duration_residual_s`, `selected_packet_residual`, `runner_up_row_id`, `runner_up_duration_residual_s`, `runner_up_miss_ratio`.
7. Deterministic: explicit stable sort orders; order-invariant per flow (tested).
8. `matching_mode: legacy_v41` reproduces v4.1/v4.2 exactly, including D43-2, for reproducibility.

All new numeric parameters are **provisional** and documented in the config. Gate thresholds are **unchanged**.

## 3. Task C — Flow segmentation
* **No default segmentation change.** Rationale: the root cause of the NTP/TCP-445 differences is not established (H2/H3). Changing segmentation silently would alter the research data definition.
* New reporting window (`flows.window_s: 120`): `window_last_rel_ts`, `window_fwd_packets`, `window_bwd_packets` (no effect on flow boundaries). Plus `n_fwd_packets`, `n_bwd_packets`.
* Optional CIC-like cut: existing `flows.active_timeout: 120` (continuation segments are marked invalid early samples). Before/after on a synthetic NTP-like flow: default → 1 flow, 684.019 s, `eof`; with `active_timeout: 120` → first segment 72.018 s, `active_timeout`, then continuation segments (`test_extractor_window_statistics_and_segmentation_before_after`).
* Compatibility: flow tables from v4.2 lack the new columns. The matcher then works without packet evidence and marks window-based expectations as approximate.

## 4. Task D — Transition audit
* `src/labeling/transitions.py` + `scripts/compare_matching_runs.py`: per-flow table and JSON summary. Transition matrices; ambiguous→unique, unique→time-inconsistent, unique→ambiguous, selected row changed, new conflicts, new shared rows, candidate-count changes, binary-label changes, with examples.
* `scripts/duration_sensitivity.py`: re-matches the same flows under named variants (legacy and evidence), writes `labelled_<variant>.parquet`, the transition audit, and `candidate_evidence.csv` (all candidates of every changed flow) for identity review. No variant is declared optimal.
* `candidate_evidence()` API for manual inspection of any flow.

## 5. Task E — Quality gate
`evaluate(..., scope)` now returns:
* `capture_integrity` — integrity checks globally **and per capture**.
* `class_coverage` — class counts.
* `training_eligible` = both.

`passed` = integrity, for compatibility. `match_labels` exits 4 only on integrity failure. `make_splits` requires `training_eligible`; older v4.2 gate reports, which lack the field, are rejected. New `scripts/combine_labelled.py` concatenates days (streamed, nothing dropped, duplicate captures rejected, label stats aggregated) and gates at dataset scope. Thresholds unchanged.

**Intentional test change:** `test_gate_fails_with_named_check[class_counts]` now expects integrity PASS + not eligible.

## 6. Task F — Notebook
`notebooks/EarlyNIDS_v4_3_Colab.ipynb` (generator `scripts/build_colab_notebook_v43.py`):
1. Mount Drive; locate the ZIP; validate paths.
2. Disk space check; unpack; install; pytest.
3. Layout check; explicit, versioned config with a decision log.
4. Mon/Tue/Wed smoke runs (300k frames); cross-day offset validation (`scripts.summarize_offsets`).
5. Gate table (integrity / coverage / eligibility).
6. Duration sensitivity (reproduces the 1 s / 100 ms / 10 ms experiment + evidence variants + the T = 120 s hypothesis); candidate review.
7. Complete days one at a time (resumable, optional local cache); dataset gate.

New CLI `scripts/summarize_offsets.py`.

## 7. Other
`process_day` passes the evidence report to `match_labels`, as before. `make_splits` reads only metadata columns from Parquet. Shipped configs are validated by a test.
