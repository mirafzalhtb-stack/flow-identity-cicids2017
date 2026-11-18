# Changelog

## v4.3.0 — 2026-11-01 (details: docs/EarlyNIDS_v4_3_Changes.md)
### Changed
- Default `matching_mode: evidence_v43`: strict duration-scaled identity evidence with an explicit margin for multi-candidate flows; reused label rows detected across flows; EOF right-censoring; correct expected duration under `csv_active_timeout_s`. `legacy_v41` reproduces v4.2.
- Gate split into `capture_integrity` (also per capture), `class_coverage`, `training_eligible`. `match_labels` exits 4 only on integrity failure. `make_splits` requires `training_eligible`.
### Added
- Extractor: `n_fwd_packets`, `n_bwd_packets`, `window_s`, `window_last_rel_ts`, `window_fwd/bwd_packets` (no segmentation change).
- Packet-count evidence (`packet_check`), traceability columns (`matched_source_file/row`), runner-up evidence.
- `scripts/duration_sensitivity.py`, `scripts/compare_matching_runs.py`, `scripts/combine_labelled.py`, `scripts/summarize_offsets.py`, `src/labeling/transitions.py`, `candidate_evidence()`.
- `notebooks/EarlyNIDS_v4_3_Colab.ipynb`, `requirements-lock.txt`. 35 new tests (182 total).
### Fixed
- D43-1 … D43-8 (see the changes document).

## v4.2.0 — 2026-11-01 (real-data integration support; details in docs/v4_2_change_log.md)
### Added
- Native Parquet label files (`load_label_files`, streamed with pyarrow), type-aware timestamps (string / naive / tz-aware / epoch), row provenance (`source_row`, `csv_flow_id`).
- Lineage / discrepancy audit (`src/labeling/lineage.py`, `scripts/audit_label_lineage.py`).
- Candidate-offset evidence (`offset_evidence`), `match_labels --offset-report` / `--accept-offset-disagreement`.
- `scripts/check_dataset_layout.py`, `scripts/process_day.py` (resumable per-day pipeline), `src/utils/paths.py`, Colab notebook + generator, `configs/cicids2017_colab.yaml`.
- Gate: `trusted_coverage`, `empty_row_rate`, `threshold_status`, `validated_thresholds`. `load_manifest_for_training`. `assert_prefix_only`.
- `extract_flows --max-frames`, atomic `.partial` writes with a completion marker.
- 40 new tests (147 total).
### Fixed
- Fully empty label rows misreported as `missing_src_ip` (now `empty_row`). Offset report schema without matches. 12-hour ambiguity outside the candidate range. Float protocol / datetime timestamps from Parquet.
### Unchanged
- Conservative matching policy (`unique` only), thresholds, exit codes, overwrite protection, split strategies, immutable manifests.

## v4.1.0 — 2026-11-01 (corrective release; see docs/v4_1_defect_audit.md)
### Changed (behaviour)
- Label matching rewritten (vectorised, chunked): only a **unique**, start-aligned, duration-consistent, one-to-one match is trusted. New statuses `ambiguous_same_label`, `ambiguous_shared_row`, `conflict`, `time_inconsistent`, `unmatched`, `invalid_flow`, each with a reason and numeric evidence. `accepted_statuses` removed (config error if present). Invalid CSV records are reported per reason.
- `match_labels` runs the new dataset quality gate and exits 4 on failure (reports kept).
- `make_splits` requires a passed gate report for the exact input file. Manifests are immutable and hashed.
- Split strategy `group` renamed `initiator` (initiator-disjoint only). Docs no longer claim host-disjointness for it.
- Packet length falls back to the captured length when the IPv4 length field is 0 (TSO). Tunnelled packets are skipped as `nested`.
- All CLIs: actionable errors, exit codes 0/1/2/3/4/5/6, `--overwrite` required to replace outputs.
### Added
- `src/datasets/quality_gate.py`, `scripts/quality_gate.py`, `scripts/time_offset_diagnostics.py`, `src/utils/cli.py`.
- Split strategies `host_components` (strict, with infeasibility error) and `hybrid` (per-capture time windows + embargo). Prefix-assignment check. Extended leakage report.
- Counters `skipped_nested`, `ip_len_from_capture`, `truncated_frames`, `suspicious_forward_jumps`.
- `inspect_label_csv` reports schema matchability and duplicated headers.
- 66 new tests; 11 superseded v4 labeling tests removed (107 total). Docs: defect audit, label policy, quality gate, split protocol, validation report, Uzbek report.
### Removed
- `LabelIndex` API and `tests/test_v4_labeling.py` (intents ported; two expectations deliberately reversed).

## v4.0.0 — 2026-11-01 (Phase 0 + Phase 1)
### Added
- `src/preprocessing/packet.py`: IP-layer packet parsing (IPv4/IPv6, TCP/UDP), explicit skip reasons, malformed-frame tolerance.
- `src/preprocessing/flows.py`: streaming bidirectional flow extractor with FIN/RST termination, session restart on tuple reuse, post-close grace, lazy idle timeout, optional active timeout, LRU capacity with continuation tracking, SYN/data retransmission handling, timestamp-anomaly counters, packet conservation check, `valid_early_prefix` flag.
- `src/preprocessing/io.py`: batched Parquet writer and v3-compatible CSV writer; reader.
- `src/preprocessing/synthetic.py`: 10 synthetic scenarios with documented expected outcomes.
- `src/labeling/cicids2017.py`: configurable CIC-IDS2017 flow-label matcher (mandatory UTC offset, timestamp resolution-aware tolerance, 12-hour ambiguity option, orientation diagnostics, conflict/unmatched handling) and label audit.
- `src/datasets/splits.py`: chronological (with embargo), capture-day and host-group splits; manifests; leakage report.
- `src/datasets/validation.py`: flow-table validation.
- `src/utils/common.py`: YAML config, logging, seeding, file fingerprints, environment info.
- `scripts/`: `extract_flows`, `inspect_label_csv`, `match_labels`, `make_splits`, `validate_dataset`, `make_synthetic_v4`.
- `configs/preprocessing.yaml`; placeholder `training/calibration/stopping.yaml` (planned).
- 44 new pytest tests (52 total including the 8 v3 tests).
- Research documentation in `docs/`.

### Fixed (relative to v3 behaviour; v3 files themselves unchanged)
- Merged TCP sessions on 5-tuple reuse (D1); frame-length feature (D2); flow fragmentation on capacity eviction (D3); mid-stream prefixes treated as early samples (D4); vacuous capacity test (D5); SYN-ACK-first initiator inversion (D6).
- Fresh-interpreter Scapy link-layer registration bug found during v4 benchmarking (all frames parsed as Raw).

## v3 — prior
Engineering prototype: streaming prefix extractor, GRU smoke baseline, 8 tests.
