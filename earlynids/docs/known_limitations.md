# Known Limitations (v4.3)

## Validation status
| Item | Implemented | Tested | Validated on synthetic data | Validated on real data |
|---|---|---|---|---|
| Packet parsing (IPv4/IPv6, TCP/UDP, skips) | Yes | Yes | Yes | **No** |
| Flow reconstruction (FIN/RST/restart/timeout/capacity) | Yes | Yes | Yes | **No** |
| Conservative label matcher (v4.1) | Yes | Yes | Yes (synthetic CSV) | **No** (CSV formats not inspected) |
| Dataset quality gate (v4.1) | Yes | Yes | Yes | **No** (thresholds provisional) |
| Splits: capture / chronological / initiator / host_components / hybrid + immutable manifests | Yes | Yes | Yes | **No** (host_components feasibility on CIC unknown) |
| CLI exit codes and overwrite protection (v4.1) | Yes | Yes | n/a | Windows not tested |
| GRU baselines, calibration, stopping, evaluation, figures | No (v3 GRU only) | — | — | — |

## Engineering limitations
1. **Throughput:** about 5,000–5,400 packets/s single-threaded on a 2-vCPU Xeon cloud VM (v4.1 re-measurement), 230 MB peak RSS for a 143k-packet synthetic PCAP. Profiling: about 73 % of the time is spent in Scapy dissection and about 6 % in EarlyNIDS code. This is a synthetic benchmark, not a real-traffic measurement. A full CIC-IDS2017 week will take hours. Possible later options: multiprocessing per file, or a dpkt-based parser behind the same `PacketRecord` interface.
2. IPv6 extension headers are counted as payload. IPv4 options are handled via IHL.
3. Non-first IPv4 fragments are skipped (counted). Reassembly is not implemented.
4. FIN-based closure happens when both FINs are seen. A half-closed connection that keeps sending data after one FIN stays one flow (intended).
5. TCP sequence wrap-around and SACK are not interpreted. Retransmission detection is a heuristic (same direction, seq, payload length) limited to the prefix.
6. The initiator heuristic for midstream flows may be wrong. Such flows are excluded from early-detection samples anyway.
7. Recently-closed and evicted-key memories are bounded (`closed_memory`). Beyond that bound, a late packet may create a midstream flow (still excluded from samples).
8. Windows/PowerShell was not tested in this session. The code uses `pathlib` and has no POSIX-specific calls.

## Scientific limitations
1. Flow-level labels only. No attack-onset ground truth, so "detection delay" means flow-start-to-decision.
2. CIC-IDS2017 label errors (E7, E8). The label version must be chosen and reported.
3. CICFlowMeter and v4 segment flows differently (FIN handling, timeouts). Some unmatched or multi-matched flows are expected and are reported, not hidden.
4. Synthetic tests show engineering correctness only. They say nothing about detection performance.
5. The literature audit covers 11 of about 44 papers plus a targeted search. The novelty status is preliminary.
9. **Label matching memory:** about 540 MB peak RSS for 200k CSV rows × 200k flows (synthetic). The CSV label table grows about linearly, roughly 200 bytes per valid row, so a full CIC-IDS2017 CSV set may need a few GB. Not measured on real data. Process day by day.
10. Ties in `start_time` at a chronological boundary can fall into different partitions if `embargo_s = 0` (the default is 60 s).
11. A far-future timestamp would idle-expire active flows. This is counted (`suspicious_forward_jumps`), not corrected.

## Label-specific limitations (v4.1)
* With 1-second CSV timestamps, sessions on the same 5-tuple less than about 2 s apart are indistinguishable (conflict or ambiguous by design).
* Tolerances and gate thresholds are provisional engineering choices.
* The `ambiguous_12h` and `csv_active_timeout_s` options exist, but whether CIC-IDS2017 needs them is unknown until the CSVs are inspected.

## v4.2 additions
* Parquet label support is tested on synthetic files only. The schema of the Hugging Face `bvsam/cic-ids-2017` files has not been seen in development.
* Lineage audit: observations only. It cannot tell why two tables differ, and it loads one file pair fully into memory.
* Offset evidence assumes that endpoint-matched flows mostly belong to the same sessions. With heavy tuple reuse (scans, floods) several offsets may align (`no_clear_winner`).
* Google Colab and Windows were not executed. Colab runtime limits (session length, disk, RAM) are not controlled by the code. Use one day per session and the resume support.

## v4.3 additions
* Strict identity tolerances and the margin are provisional. No labelled ground truth exists to calibrate them.
* Flow segmentation is not CICFlowMeter-equivalent. The window statistics and the optional `active_timeout` only allow the fixed-cut hypothesis to be tested.
* Packet-count evidence is report-only by default. Counting conventions of the label tool are unverified.
