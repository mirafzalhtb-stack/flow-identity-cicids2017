"""Sections 3.4 and 4.1/4.3: packet-level audit of selected flows against the raw capture.

For every sampled flow the script reads the packets of its five-tuple (both directions) between
start_time - margin and end_time + margin, and reports packet counts per direction, SYN/FIN/RST
counts, the time of the first forward FIN, and, when CSV candidate row ids are given, the CSV
packet counts and how far the first forward FIN is from the end of the direct CSV record.

Reading a full-day PCAP (10+ GB) with scapy is slow. Cut it first with tcpdump, e.g.:
    python audit/a05_pcap_audit.py --sample S --print-bpf          # prints a filter
    tcpdump -r Monday-WorkingHours.pcap -w monday_sample.pcap '<filter>'

Example:
    python audit/a05_pcap_audit.py --labels L --runs R --day monday \
        --sample audit/inputs/monday_audit_sample20.csv --pcap monday_sample.pcap --margin 0.001

Output: pcap_audit_<sample name>.csv
"""
import argparse
from pathlib import Path

import pandas as pd

from common import load_labels, row_ids, save

FIN, SYN, RST = 0x01, 0x02, 0x04


def read_sample(path: Path) -> pd.DataFrame:
    df = pd.read_parquet(path) if path.suffix == ".parquet" else pd.read_csv(path)
    for c in ("candidate_row_ids", "candidate_ids"):
        if c in df.columns:
            df["ids"] = df[c].map(row_ids)
            break
    else:
        df["ids"] = [[] for _ in range(len(df))]
    return df


def bpf(sample: pd.DataFrame) -> str:
    parts = [f"(host {r.src_ip} and host {r.dst_ip} and port {int(r.src_port)} and port {int(r.dst_port)})"
             for r in sample.itertuples()]
    return "tcp and (" + " or ".join(parts) + ")"


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--sample", type=Path, required=True)
    p.add_argument("--pcap", type=Path)
    p.add_argument("--labels", type=Path)
    p.add_argument("--day", choices=["monday", "tuesday"], default="monday")
    p.add_argument("--margin", type=float, default=0.001, help="seconds read beyond the EarlyNIDS start/end")
    p.add_argument("--out", type=Path, default=Path("results"))
    p.add_argument("--print-bpf", action="store_true")
    a = p.parse_args()
    sample = read_sample(a.sample)
    if a.print_bpf:
        print(bpf(sample))
        return
    from scapy.all import IP, IPv6, TCP, PcapReader  # imported here: only needed for the audit

    keys = {}
    for r in sample.itertuples():
        k = frozenset([(r.src_ip, int(r.src_port)), (r.dst_ip, int(r.dst_port))])
        keys[k] = r
    pk = {r.flow_uid: [] for r in sample.itertuples()}
    with PcapReader(str(a.pcap)) as reader:
        for pkt in reader:
            ip = pkt[IP] if IP in pkt else (pkt[IPv6] if IPv6 in pkt else None)
            if ip is None or TCP not in pkt:
                continue
            t = pkt[TCP]
            r = keys.get(frozenset([(ip.src, int(t.sport)), (ip.dst, int(t.dport))]))
            if r is None:
                continue
            ts = float(pkt.time)
            if r.start_time - a.margin <= ts <= r.end_time + a.margin:
                fwd = ip.src == r.src_ip and int(t.sport) == int(r.src_port)
                pk[r.flow_uid].append((ts, fwd, int(t.flags)))

    lab = load_labels(a.labels, a.day) if a.labels is not None else None
    rows = []
    for r in sample.itertuples():
        ps = sorted(pk[r.flow_uid])
        fins = [ts for ts, fwd, fl in ps if fwd and fl & FIN]
        row = {
            "flow_uid": r.flow_uid, "end_reason": getattr(r, "end_reason", None),
            "pcap_packets": len(ps), "pcap_fwd": sum(f for _, f, _ in ps), "pcap_bwd": sum(not f for _, f, _ in ps),
            "syn": sum(bool(fl & SYN) for *_, fl in ps), "fin": sum(bool(fl & FIN) for *_, fl in ps),
            "rst": sum(bool(fl & RST) for *_, fl in ps),
            "first_fwd_fin_ms": round((fins[0] - r.start_time) * 1000, 6) if fins else None,
            "observed_packets": getattr(r, "observed_packets", None),
        }
        if lab is not None and r.ids:
            c = lab.loc[r.ids]
            direct = c[c["Source IP"] == r.src_ip]
            row["csv_fwd_total"] = int(sum(x["Total Fwd Packets"] if x["Source IP"] == r.src_ip else x["Total Backward Packets"]
                                           for _, x in c.iterrows()))
            row["csv_bwd_total"] = int(sum(x["Total Backward Packets"] if x["Source IP"] == r.src_ip else x["Total Fwd Packets"]
                                           for _, x in c.iterrows()))
            if len(direct) and fins:
                dur_ms = direct["Flow Duration"].iloc[0] / 1000.0  # CICFlowMeter duration is in microseconds
                row["direct_csv_duration_ms"] = dur_ms
                row["fin_alignment_error_ms"] = round(row["first_fwd_fin_ms"] - dur_ms, 6)
        rows.append(row)
    out = pd.DataFrame(rows)
    print(out.to_string(index=False))
    a.out.mkdir(parents=True, exist_ok=True)
    save(out, a.out, f"pcap_audit_{a.sample.stem}.csv")


if __name__ == "__main__":
    main()
