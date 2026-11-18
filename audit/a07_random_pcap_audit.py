"""Section 4.1: automatic PCAP audit of the random sample (H1 FIN boundary, H2 post-close packets, H3 RST tail).

First cut the Monday capture with the filter written by a06:
    tcpdump -r Monday-WorkingHours.pcap -F results/random_audit_sample150.bpf -w monday_sample150.pcap
Then:
    python audit/a07_random_pcap_audit.py --labels data/traffic_labels --pcap monday_sample150.pcap --out results

Output: random_audit_results150.csv
"""
import argparse
from pathlib import Path
import re
import pandas as pd
from scapy.all import PcapReader, IP, TCP

pd.set_option("display.width", 220, "display.max_columns", 40)
_p = argparse.ArgumentParser(description=__doc__)
_p.add_argument("--labels", type=Path, required=True)
_p.add_argument("--pcap", type=Path, required=True)
_p.add_argument("--out", type=Path, default=Path("results"))
_a = _p.parse_args()
OUT = _a.out
PCAP = _a.pcap
GRACE = 5.0      # EarlyNIDS post_close_grace
LATE = 120.0     # look further, up to the idle timeout
FIN, SYN, RST, ACK = 0x01, 0x02, 0x04, 0x10
def ids(x): return [int(float(s)) for s in re.split(r"[;,|]", str(x)) if s.strip()]

sample = pd.read_csv(OUT / "random_audit_sample150.csv")
lab = pd.read_parquet(_a.labels / "Monday-WorkingHours.pcap_ISCX.csv.parquet")
lab.columns = [c.strip() for c in lab.columns]
lab = lab.reset_index(drop=True)

# ---- read packets once
key_of = {}
for r in sample.itertuples():
    key_of[frozenset([(r.src_ip, int(r.src_port)), (r.dst_ip, int(r.dst_port))])] = r
pk = {r.flow_uid: [] for r in sample.itertuples()}
with PcapReader(str(PCAP)) as rd:
    for p in rd:
        if IP not in p or TCP not in p:
            continue
        ip, t = p[IP], p[TCP]
        r = key_of.get(frozenset([(ip.src, int(t.sport)), (ip.dst, int(t.dport))]))
        if r is None:
            continue
        ts = float(p.time)
        if r.start_time - 0.001 <= ts <= r.end_time + LATE:
            fwd = ip.src == r.src_ip and int(t.sport) == int(r.src_port)
            pk[r.flow_uid].append((ts, fwd, int(t.flags)))

def flagstr(f):
    return "".join(c for c, b in (("S", SYN), ("F", FIN), ("R", RST), ("A", ACK)) if f & b) or "-"

rows = []
for r in sample.itertuples():
    ps = sorted(pk[r.flow_uid])
    inside = [x for x in ps if x[0] <= r.end_time + 1e-6]
    grace = [x for x in ps if r.end_time + 1e-6 < x[0] <= r.end_time + GRACE and not (x[2] & SYN and not x[2] & ACK)]
    late = [x for x in ps if r.end_time + GRACE < x[0] <= r.end_time + LATE]
    fins = [x[0] for x in ps if x[1] and x[2] & FIN]
    rsts = [x for x in ps if x[2] & RST]
    c = lab.loc[ids(r.candidate_row_ids)]
    csv_total = int((c["Total Fwd Packets"] + c["Total Backward Packets"]).sum())
    direct = c[c["Source IP"].astype(str).str.strip() == r.src_ip]
    first_fin_ms = (fins[0] - r.start_time) * 1000 if fins else None
    dur_ms = direct["Flow Duration"].iloc[0] / 1000.0 if len(direct) else None
    after_rst = [x for x in ps if rsts and x[0] > rsts[0][0]]
    rows.append({
        "flow_uid": r.flow_uid, "group": r.sample_group, "end_reason": r.end_reason, "dp": r.dp,
        "observed": r.observed_packets, "pcap_inside": len(inside), "csv_total": csv_total,
        "grace_pkts": len(grace), "late_pkts": len(late),
        "h1_fin_error_ms": round(first_fin_ms - dur_ms, 3) if first_fin_ms is not None and dur_ms is not None else None,
        "h2_csv_eq_observed_plus_grace": csv_total == r.observed_packets + len(grace),
        "h2b_csv_eq_observed_plus_grace_late": csv_total == r.observed_packets + len(grace) + len(late),
        "has_fwd_fin": bool(fins), "n_rst": len(rsts),
        "first_rst_dir": ("fwd" if rsts[0][1] else "bwd") if rsts else None,
        "after_rst_pkts": len(after_rst),
        "after_rst_flags": " ".join(f"{'>' if x[1] else '<'}{flagstr(x[2])}" for x in after_rst[:6]),
        "grace_flags": " ".join(f"{'>' if x[1] else '<'}{flagstr(x[2])}" for x in grace[:6]),
    })
res = pd.DataFrame(rows)
res.to_csv(OUT / "random_audit_results150.csv", index=False)

print("=== PACKETS FOUND ===")
print("flows with 0 packets in PCAP:", int((res.pcap_inside == 0).sum()), "/", len(res))
print("pcap_inside == observed:", int((res.pcap_inside == res.observed).sum()), "/", len(res))

print("\n=== H1: FIRST FORWARD FIN vs DIRECT CSV DURATION ===")
h1 = res.dropna(subset=["h1_fin_error_ms"])
print(h1.groupby("group").agg(flows=("flow_uid", "size"),
      within_1ms=("h1_fin_error_ms", lambda s: int((s.abs() <= 1).sum())),
      median_abs_err_ms=("h1_fin_error_ms", lambda s: round(s.abs().median(), 4))).to_string())
print("flows without a forward FIN:", res.groupby("group")["has_fwd_fin"].apply(lambda s: int((~s).sum())).to_dict())

print("\n=== H2: CSV PACKETS = OBSERVED + POST-CLOSE PACKETS ===")
print(res.groupby("group").agg(flows=("flow_uid", "size"),
      eq_grace=("h2_csv_eq_observed_plus_grace", "sum"),
      eq_grace_or_late=("h2b_csv_eq_observed_plus_grace_late", "sum"),
      median_grace=("grace_pkts", "median"), median_late=("late_pkts", "median")).to_string())

print("\n=== H3: RST FLOWS — WHAT COMES AFTER THE FIRST RST ===")
rr = res[res.end_reason == "rst"]
print(rr.groupby("group").agg(flows=("flow_uid", "size"),
      rst_fwd=("first_rst_dir", lambda s: int((s == "fwd").sum())),
      multi_rst=("n_rst", lambda s: int((s > 1).sum())),
      median_after_rst=("after_rst_pkts", "median"), max_after_rst=("after_rst_pkts", "max")).to_string())
print("\nMost common packet patterns after the first RST (C_rst_tail):")
print(rr[rr.group == "C_rst_tail"]["after_rst_flags"].value_counts().head(10).to_string())
print("\nMost common post-close patterns (B_fin_random):")
print(res[res.group == "B_fin_random"]["grace_flags"].value_counts().head(8).to_string())
print("\nSaved:", OUT / "random_audit_results150.csv")
print("done")
