# Repository Audit — EarlyNIDS v3

Audit date: 2026-11-01. Input: `EarlyNIDS_v3.zip` (9 files, 383 lines of Python).
Environment used for the audit: Linux, Python 3.13.18, scapy 2.x, numpy, scikit-learn, torch 2.15 (CPU). The researcher's target is Windows + Python 3.13. Windows was **not** tested.

## 1. Inventory

| File | Role | Lines |
|---|---|---|
| `src/preprocess.py` | Streaming PCAP → 20-packet prefix CSV, unlabeled | 131 |
| `src/gru_baseline.py` | Single GRU trained on prefixes ≤ 20, evaluated with truncation k = 3/5/10/20 | 126 |
| `src/make_synthetic.py` | 37-packet synthetic PCAP (1 TCP + 2 UDP flows) | 30 |
| `src/make_smoke_data.py` | Artificial labeled sequences (attack = large packets) | 18 |
| `tests/test_pipeline.py`, `tests/test_v3.py` | 8 unit tests | 78 |

Entry points: `python -m src.preprocess`, `python -m src.gru_baseline`, `python -m src.make_synthetic`, `python -m src.make_smoke_data`.

Data structure: one CSV row per flow; `features_json` = list of `[frame_length, inter-arrival, direction ±1]`.

## 2. Test status

All 8 v3 tests pass (re-run 2026-11-01; they also pass inside the v4 test suite). The tests check engineering behaviour on 3 synthetic flows only.

## 3. Confirmed defects (reproduced with probes, `probe_v3.py`)

| # | Defect | Evidence | Impact | v4 status |
|---|---|---|---|---|
| D1 | **No TCP FIN/RST handling.** Two TCP sessions on the same 5-tuple 5 s apart became **one** flow (10 packets). | Probe 1: 2 sessions → 1 flow | Merged sessions; wrong prefixes; label matching against CIC rows fails | Fixed (`end_reason` fin/rst/restart) |
| D2 | **Packet length = frame length** (`len(pkt)`), including the 14-byte Ethernet header. A 40-byte IP SYN became 54. | Probe 1 | Feature depends on capture link type, not traffic | Fixed (IP-layer length) |
| D3 | **Capacity eviction fragments live flows.** With `max_active=1`, 2 interleaved flows produced **12** rows; each fragment starts mid-connection. | Probe 2: 2 flows → 12 rows | Duplicate, non-causal "early prefixes" | Fixed (`start_reason='continuation'`, excluded) |
| D4 | Flows first observed mid-stream (no SYN) are treated as normal prefixes. | Code review | Prefix is not the start of the connection → invalid early-detection sample | Fixed (`valid_early_prefix=False`) |
| D5 | `test_capacity_eviction` asserts `capacity_evictions >= 0`, which is always true. | Code review | Test cannot fail | Replaced by a test with exact expectations |
| D6 | Initiator = sender of the first observed packet, even when that packet is a SYN-ACK. | Code review | Direction inverted for such flows | Fixed |
| D7 | Only 3 features; no TCP flags, protocol, payload length. | Code review | Weaker than the core-paper feature sets (P44 uses flags, lengths, TTL, port) | v4 stores flags, payload, TTL, retrans flag; feature choice is a Phase 2 decision |

## 4. Methodological weaknesses (not bugs)

1. `gru_baseline.py` trains one model on 20-packet prefixes and tests on truncated prefixes. This is a *prefix-sensitivity test*, not GRU-3/5/10/20 baselines, and the README says so. Training on full prefixes and testing on short ones creates a train/test mismatch that favours long horizons.
2. Smoke data separate classes by packet size, so any score is meaningless. README states this.
3. The default split is a random flow split. `--real-data` uses `GroupShuffleSplit` on `capture_id`, which with ≥3 groups can put all attack types of one day into the test set, so class coverage is not checked before training. It checks only that both classes are present.
4. No class-imbalance handling, AUROC, AUPRC, FNR, calibration, checkpoint saving or multiple seeds.
5. `best_state` stays `None` if every validation loss is NaN, and then `load_state_dict(None)` crashes.
6. Expiry heap: entries are pushed only at flow creation and rebuilt every `cleanup_interval` packets, so timeouts are only approximately enforced between rebuilds (documented in code).
7. CSV output for millions of flows; no provenance (source file, capture id) in rows.

## 5. Hidden assumptions

* Timestamps are monotonic (regressions are only counted).
* One 5-tuple equals one session within the timeout.
* `capture_id` exists in labelled CSVs (it is not produced by `preprocess.py`).

## 6. Data leakage review

v3 trains only on artificial data, so no real leakage exists yet. Risks for real data: random splits; normalisation is log1p (no fitted statistics, so no fit-on-test leakage); hyperparameters are not tuned on test (validation is used for model selection, which is correct).

## 7. Dependencies

`requirements.txt` lists scapy, numpy, scikit-learn, torch. pandas/pyarrow/pyyaml/pytest/matplotlib are added in v4. No unnecessary dependencies were found.

## 8. Decision

The architecture is small and sound enough to keep. v3 files are preserved unchanged under `src/` and their tests still run. The v4 data foundation is added as new packages (`src/preprocessing`, `src/labeling`, `src/datasets`, `src/utils`) instead of rewriting v3 in place, so v3 commands keep working.

## 9. Additional defect found during v4 work

Benchmarking v4 in a fresh interpreter showed that importing only `scapy.utils.PcapReader` makes Scapy return `Raw` frames (no Ethernet dissector registered), so **every packet was skipped as non-IP**. Unit tests had not caught it because test modules imported the layers first. v4 imports `scapy.all` in the reader, `extract_flows` exits with code 3 when no eligible packets are found, and a subprocess regression test covers the case. (v3 is not affected because it imports `scapy.all`.)
