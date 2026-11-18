# EarlyNIDS v4.3 — data foundation for early network intrusion detection research

**Status:** Phase 0 (audits) and Phase 1 (data foundation, corrected in v4.1) are implemented and tested on **synthetic data only** (182 tests, Linux, Python 3.13; Windows and Google Colab not executed; the Colab notebook's Python code was executed on a fake Drive tree with synthetic data). No real CIC-IDS2017 data has been processed in development; real-data validation is pending and must be run by the researcher (Colab notebook). No detection result exists. Nothing here is evidence of detection performance.

| Component | State |
|---|---|
| v3 prototype (`src/preprocess.py`, `src/gru_baseline.py`, …) | Preserved unchanged; its 8 tests still pass |
| v4 PCAP → flow prefixes (`src/preprocessing`) | Implemented, tested (synthetic) |
| v4.1 conservative CIC-IDS2017 label matching (`src/labeling`) | Implemented, tested (synthetic CSV). Real CSV format **not yet inspected** |
| v4.1 dataset quality gate (`src/datasets/quality_gate.py`) | Implemented, tested. Thresholds provisional |
| v4.1 split strategies capture / chronological / initiator / host_components / hybrid | Implemented, tested (synthetic) |
| v4.2 native Parquet label files (shared CSV/Parquet schema) | Implemented, tested (synthetic Parquet). Real HF schema not seen |
| v4.3 identity-evidence matching (`evidence_v43`, default; `legacy_v41` kept), transition audit, duration sensitivity, integrity/coverage/eligibility gate, dataset combination | Implemented, tested (synthetic) |
| v4.2 lineage audit (`traffic_labels` vs `machine_learning`), offset evidence, resumable per-day processing, Colab notebook | Implemented, tested (synthetic) |
| GRU baselines, calibration, stopping, evaluation, figures | Planned (Phases 2–5). See `docs/` |

## Setup (Windows PowerShell, Python 3.13)

```powershell
cd 'D:\PhD\EarlyNIDS'
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest
```

## Synthetic smoke run (engineering check only)

```powershell
python -m scripts.make_synthetic_v4 --output data\raw\synthetic_v4.pcap
python -m scripts.extract_flows --pcap data\raw\synthetic_v4.pcap --capture-id synthetic `
    --output data\interim\synthetic_flows.parquet --config configs\preprocessing.yaml
python -m scripts.validate_dataset --input data\interim\synthetic_flows.parquet
```

## Google Colab (v4.3: `notebooks/EarlyNIDS_v4_3_Colab.ipynb`; the v4.2 notebook is kept for reference)
Upload `EarlyNIDS_v4_2.zip` to `MyDrive/EarlyNIDS/code/`, open `notebooks/EarlyNIDS_v4_2_Colab.ipynb` in Colab, and run it top to bottom. It uses only the CLIs below and processes one day at a time, with resume. Core commands:

```bash
# v4.3 additions
python -m scripts.duration_sensitivity --flows F --labels L --config C --out-dir D --baseline legacy_1s --variant "legacy_1s:matching_mode=legacy_v41,duration_abs_tolerance_s=1.0" --variant "evidence_1s:matching_mode=evidence_v43"
python -m scripts.compare_matching_runs --run a=A.parquet --run b=B.parquet --baseline a --out-dir D
python -m scripts.summarize_offsets --evidence monday=E1.json --evidence tuesday=E2.json --configured 0.0
python -m scripts.combine_labelled --input day1/labelled.parquet --input day2/labelled.parquet --config C --output all.parquet
# v4.2
python -m scripts.check_dataset_layout --root /content/drive/MyDrive/EarlyNIDS/datasets/CIC-IDS2017 --output layout.json
python -m scripts.inspect_label_csv --files "/content/drive/MyDrive/EarlyNIDS/datasets/CIC-IDS2017/traffic_labels/*" --output inspect.json
python -m scripts.audit_label_lineage --dir-a <root>/traffic_labels --dir-b <root>/machine_learning --out-dir lineage
python -m scripts.process_day --root <root> --day monday --out-root <runs> --config run_config.yaml [--max-frames N] [--local-cache /content/pcap_cache]
```
`process_day` stops before label matching until you set `labeling.utc_offset_hours` yourself after reviewing `offset_evidence.json`.

## Real CIC-IDS2017 workflow (once the files are in `data\raw`)

Needed: the Monday–Friday PCAPs and the labelled flow CSVs that contain source/destination IP and port, protocol, timestamp and duration (expected in `GeneratedLabelledFlows.zip`; verify). Feature-only CSVs without IPs and timestamps cannot be matched to PCAP flows.

```powershell
# 1. Inspect label CSVs FIRST (both archives); nothing is modified
python -m scripts.inspect_label_csv --csv "data\raw\labels\*.csv" --output results\label_csv_inspection.json

# 2. Extract one day first
python -m scripts.extract_flows --pcap data\raw\Monday-WorkingHours.pcap --capture-id monday `
    --output data\interim\monday_flows.parquet --config configs\preprocessing.yaml

# 3. Determine the CSV time-zone offset (diagnostic), then set labeling.utc_offset_hours in the config
python -m scripts.time_offset_diagnostics --flows data\interim\monday_flows.parquet `
    --labels "data\raw\labels\Monday*.csv" --config configs\preprocessing.yaml

# 4. Match labels + quality gate (exit 4 = gate failed; all reports are kept)
python -m scripts.match_labels --flows data\interim\monday_flows.parquet `
    --labels "data\raw\labels\Monday*.csv" --config configs\preprocessing.yaml `
    --output data\processed\monday_labelled.parquet
echo "exit code: $LASTEXITCODE"

# 5. Validate, then split (requires a PASSED gate report for exactly this file)
python -m scripts.validate_dataset --input data\processed\monday_labelled.parquet
python -m scripts.make_splits --input data\processed\all_labelled.parquet `
    --config configs\preprocessing.yaml --out-dir data\manifests\split_v1
```

Label files may be `.csv` or `.parquet` (v4.2). `match_labels --offset-report offset_evidence.json` refuses a configured offset that contradicts the evidence.

Exit codes: 0 ok · 1 unexpected error · 2 invalid input · 3 no eligible packets · 4 quality gate/validation failed · 5 output exists (use `--overwrite` or a new path) · 6 packet conservation violated.

Only `trusted` flows (unique label match + valid early prefix) are used for supervision. Ambiguous, conflicting, time-inconsistent and unmatched flows are kept with `match_status`, `match_reason` and `exclusion_reason`, and are never labelled BENIGN.

## Output schema (one row per flow)
Flow tables: `flow_uid, capture_id, source_file, ip_version, protocol, src_ip/src_port (initiator), dst_ip/dst_port, start_time, end_time, duration, observed_packets, observed_bytes, packet_count (stored prefix length), prefix_complete, start_reason {syn, udp, midstream, continuation}, end_reason {fin, rst, restart, idle_timeout, active_timeout, capacity, eof}, valid_early_prefix, n_retrans_prefix, n_out_of_order`, plus per-packet lists `pkt_rel_ts, pkt_iat, pkt_direction, pkt_ip_len, pkt_payload_len, pkt_tcp_flags, pkt_ttl, pkt_retrans`. CSV output additionally contains the v3-compatible `features_json`.

## Documentation map
* Audit of earlier versions: `docs/repository_audit.md`
* Label matching: `docs/label_matching_policy.md`, `docs/dataset_quality_gate.md`, `docs/split_protocol.md`
* v4.3 changes: `docs/EarlyNIDS_v4_3_Changes.md`
* Limitations: `docs/known_limitations.md`

Labelled tables add: `match_status, match_reason, label, binary_label, matched_row_id, n_key_rows, n_overlap_rows, n_start_aligned, n_consistent, start_offset_s, duration_diff_s, orientation, used_12h_shift, candidate_row_ids, candidate_labels, trusted, exclusion_reason` (`supervised_eligible` is kept as an alias of `trusted`).
