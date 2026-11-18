# Flow identity ambiguity in CIC-IDS2017

Code and result tables for the paper
**"Flow Identity Ambiguity in CIC-IDS2017: Evidence from TCP Termination and Timestamp Granularity"**
(A2M4RA 2027 workshop, under review).

The paper asks what happens when flows are extracted again from the CIC-IDS2017 packet captures and
then matched to the published label tables. This repository contains:

| Folder | Content |
|---|---|
| `earlynids/` | EarlyNIDS v4.3, the flow extractor and label matcher used in the paper, with its unit tests |
| `audit/` | One script per result of the paper (see the table below) |
| `audit/inputs/` | The hand-picked flows used in the packet-level audits (20 Monday, 15 FTP, 15 SSH) |
| `results/` | The result tables reported in the paper |

No CIC-IDS2017 data is included. Download it as described below.

## 1. Data

* **Label tables:** Hugging Face dataset [`bvsam/cic-ids-2017`](https://huggingface.co/datasets/bvsam/cic-ids-2017),
  commit `70bac6246d99cf046186a02e1cce6883e2ffe7ea`, folder `traffic_labels/`. These Parquet files were
  converted from the CIC `TrafficLabelling` CSVs, and their timestamps were normalised to UTC by the
  mirror's author. We therefore use a label time offset of 0.
* **Packet captures:** `pcap/Monday-WorkingHours.pcap` and `pcap/Tuesday-WorkingHours.pcap` from the
  same mirror (the original CIC captures).

```bash
pip install -r requirements.txt
python - <<'PY'
from huggingface_hub import hf_hub_download
REV = "70bac6246d99cf046186a02e1cce6883e2ffe7ea"
for f in ["traffic_labels/Monday-WorkingHours.pcap_ISCX.csv.parquet",
          "traffic_labels/Tuesday-WorkingHours.pcap_ISCX.csv.parquet"]:
    hf_hub_download("bvsam/cic-ids-2017", f, repo_type="dataset", revision=REV, local_dir="data")
PY
```

Please cite the original dataset: I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani, *Toward generating a
new intrusion detection dataset and intrusion traffic characterization*, ICISSP 2018.

## 2. Extract and match flows with EarlyNIDS v4.3

The flow rules (Table 1 of the paper) are in `earlynids/src/preprocessing/flows.py` and the
configuration in `earlynids/configs/`. Main settings: at most 20 prefix packets, 120 s idle timeout,
no active timeout, 5 s post-close period, flow closed by FIN in both directions or by any RST.

```bash
cd earlynids
pip install -r requirements.txt
python -m pytest                       # unit tests on synthetic traffic
# Monday, full day, with label matching (writes <runs>/full/monday/labelled.parquet)
python -m scripts.process_day --root ../data --day monday --out-root <runs>/full --config <run_config.yaml>
# Tuesday attack windows: cut the PCAP to the window, then extract flows
python -m scripts.extract_flows --pcap tuesday_ftp_1215_1225.pcapng --capture-id tuesday_ftp_1215_1225 \
    --output <runs>/attack_window/tuesday_ftp/full/flows.parquet --config configs/preprocessing.yaml
```

Windows used in the paper (UTC): smoke run 11:53–12:12, FTP-Patator 12:15–12:25, SSH-Patator 17:19–17:31
on 4 July 2017. A window can be cut with `editcap -A "2017-07-04 12:15:00" -B "2017-07-04 12:25:00"`
(set `TZ=UTC`).

The audit scripts expect this layout inside `<runs>`:

```
<runs>/full/monday/labelled.parquet
<runs>/smoke/tuesday/flows.parquet
<runs>/attack_window/tuesday_ftp/full/flows.parquet
<runs>/attack_window/tuesday_ssh/full/flows.parquet
```

## 3. Reproduce the paper

All scripts take `--labels data/traffic_labels --runs <runs> --out results`.

| Script | Paper | Main numbers |
|---|---|---|
| `a01_label_timestamps.py` | Sec. 4.2 | Tuesday: 0 of 445,909 timestamps have seconds; Monday: 522,220 of 529,918 do |
| `a02_monday_funnel_dp.py` | Sec. 3.3, Table 2, Fig. 2(a) | 356,159 → 37,669 → 21,411 → 15,809 pairs; within 2 packets: FIN 99.95%, RST 73.19% |
| `a03_tuesday_smoke_multiplicity.py` | Sec. 4.2, Fig. 2(b) | candidate coverage and multiplicity by end reason |
| `a04_attack_windows.py` | Sec. 4.3, Table 3 | FTP 287 and SSH 461 two-candidate flows; label policies |
| `a05_pcap_audit.py` | Sec. 3.4, 4.1, 4.3 | packet-level checks of the flows in `audit/inputs/` |
| `a06_random_sample.py` | Sec. 3.4, 4.1 | whole-day context; random sample of 150 pairs (seed 2027) and a tcpdump filter |
| `a07_random_pcap_audit.py` | Sec. 4.1 | FIN boundary within 1 ms in 149/150; ΔP ≤ post-close packets in 150/150 |
| `make_figures.py` | Fig. 2 | `fig_monday_dp.pdf`, `fig_tuesday_multiplicity.pdf` |

```bash
python audit/a01_label_timestamps.py          --labels data/traffic_labels --runs <runs>
python audit/a02_monday_funnel_dp.py          --labels data/traffic_labels --runs <runs>
python audit/a03_tuesday_smoke_multiplicity.py --labels data/traffic_labels --runs <runs> --previous-minute
python audit/a04_attack_windows.py            --labels data/traffic_labels --runs <runs>
python audit/a05_pcap_audit.py --sample audit/inputs/monday_audit_sample20.csv --print-bpf   # then tcpdump
python audit/a05_pcap_audit.py --sample audit/inputs/monday_audit_sample20.csv \
    --pcap monday_sample.pcap --labels data/traffic_labels --day monday --margin 0.001
# random audit (seed 2027, fixed before the audit)
python audit/a06_random_sample.py --labels data/traffic_labels --runs <runs> --out results
tcpdump -r Monday-WorkingHours.pcap -F results/random_audit_sample150.bpf -w monday_sample150.pcap
python audit/a07_random_pcap_audit.py --labels data/traffic_labels --pcap monday_sample150.pcap --out results
python audit/make_figures.py --results results --out figures
```

## 4. Definitions and notes

* **ΔP** = packets of CSV record 1 + packets of CSV record 2 − EarlyNIDS `observed_packets`. The same
  sign is used everywhere. `packet_count` is the stored prefix length (at most 20) and is not used for
  packet comparisons.
* **Candidates** are CSV records with the same five-tuple (direct) or the swapped five-tuple (reverse)
  whose minute equals the flow's start minute. This rule finds candidates; it does not assign labels.
* **Row ids.** `candidate_row_ids` in EarlyNIDS outputs are 0-based row positions in the day's label table.
* In the Tuesday smoke run, the minute rule alone leaves 83 flows without a candidate; with
  `--previous-minute`, 5 of them find a record in the preceding minute (78 left).
* The audit samples in `audit/inputs/` were chosen by hand. The random sample of `a06` (seed 2027) checks that their results generalise.
* The results describe how flows are cut and matched. They do not show whether the original labels
  are correct, and no detection model is trained.

## License

Code: MIT (see `LICENSE`). CIC-IDS2017 data is not redistributed here and keeps its own terms.
