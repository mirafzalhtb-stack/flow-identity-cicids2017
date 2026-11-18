"""Section 4.1: whole-day Monday context and the random audit sample (seed 2027).

    python audit/a06_random_sample.py --labels data/traffic_labels --runs <runs> --out results

Outputs: monday_whole_day_context.csv, random_audit_sample150.csv, random_audit_sample150.bpf
"""
import argparse
from pathlib import Path
import re
import numpy as np
import pandas as pd

pd.set_option("display.width", 220, "display.max_columns", 40)
_p = argparse.ArgumentParser(description=__doc__)
_p.add_argument("--labels", type=Path, required=True)
_p.add_argument("--runs", type=Path, required=True)
_p.add_argument("--out", type=Path, default=Path("results"))
_a = _p.parse_args()
OUT = _a.out; OUT.mkdir(parents=True, exist_ok=True)
SEED = 2027
def hdr(t): print("\n" + "=" * 70 + f"\n=== {t} ===\n" + "=" * 70)
def ids(x): return [int(float(s)) for s in re.split(r"[;,|]", str(x)) if s.strip() and s.strip() != "None"]

# ------------------------------------------------------------------ data
mon = pd.read_parquet(_a.runs / "full/monday/labelled.parquet",
                      columns=["flow_uid", "protocol", "src_ip", "src_port", "dst_ip", "dst_port",
                               "start_time", "end_time", "end_reason", "start_reason", "valid_early_prefix",
                               "match_status", "match_reason", "candidate_row_ids", "observed_packets"])
lab = pd.read_parquet(_a.labels / "Monday-WorkingHours.pcap_ISCX.csv.parquet")
lab.columns = [c.strip() for c in lab.columns]
lab = lab.reset_index(drop=True)
src = lab["Source IP"].astype(str).str.strip().to_numpy()
pk = (lab["Total Fwd Packets"] + lab["Total Backward Packets"]).to_numpy()

mon["ids"] = mon["candidate_row_ids"].map(lambda x: ids(x) if x is not None else [])
mon["n_cand"] = mon["ids"].map(len)
pop_mask = ((mon.match_reason == "no_candidate_meets_strict_identity") & (mon.n_cand == 2)
            & mon.end_reason.isin(["fin", "rst"]))
mon["n_direct"] = 0
mon.loc[pop_mask, "n_direct"] = [sum(src[i] == s for i in c) for c, s in zip(mon.loc[pop_mask, "ids"], mon.loc[pop_mask, "src_ip"])]
mon["in_population"] = pop_mask & (mon["n_direct"] == 1)
mon.loc[mon.in_population, "dp"] = [int(pk[c].sum()) - o for c, o in zip(mon.loc[mon.in_population, "ids"], mon.loc[mon.in_population, "observed_packets"])]
print("Population size (should be 15,809):", int(mon.in_population.sum()))

# ------------------------------------------------------------------ A. whole-day context
hdr("A. WHOLE-DAY CONTEXT (TCP flows by end reason)")
tcp = mon[mon.protocol == 6]
ctx = tcp.groupby("end_reason").agg(
    flows=("flow_uid", "size"),
    unique_match=("match_status", lambda s: int((s == "unique").sum())),
    strict_failure=("match_reason", lambda s: int((s == "no_candidate_meets_strict_identity").sum())),
    in_population=("in_population", "sum"),
)
for c in ["unique_match", "strict_failure", "in_population"]:
    ctx[c + "_pct"] = (100 * ctx[c] / ctx["flows"]).round(2)
print(ctx.to_string())
print("\nAll Monday flows:", len(mon), "| TCP flows:", len(tcp),
      "| population share of TCP FIN/RST flows:",
      round(100 * mon.in_population.sum() / tcp.end_reason.isin(["fin", "rst"]).sum(), 2), "%")
ctx.to_csv(OUT / "monday_whole_day_context.csv")

# ------------------------------------------------------------------ B/C. random samples
hdr("B/C. RANDOM AUDIT SAMPLES (seed 2027)")
pop = mon[mon.in_population].copy()
rng = np.random.default_rng(SEED)
def pick(df, n, tag):
    take = df.sample(n=min(n, len(df)), random_state=SEED)
    return take.assign(sample_group=tag)
sample = pd.concat([
    pick(pop[pop.end_reason == "fin"], 50, "B_fin_random"),
    pick(pop[(pop.end_reason == "rst") & (pop.dp <= 2)], 50, "B_rst_random_within2"),
    pick(pop[(pop.end_reason == "rst") & (pop.dp >= 3)], 50, "C_rst_tail"),
])
sample["candidate_row_ids"] = sample["ids"].map(lambda c: ";".join(map(str, c)))
cols = ["flow_uid", "sample_group", "end_reason", "dp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
        "start_time", "end_time", "observed_packets", "candidate_row_ids"]
sample[cols].to_csv(OUT / "random_audit_sample150.csv", index=False)
print(sample.groupby("sample_group").agg(flows=("flow_uid", "size"), dp_min=("dp", "min"),
                                          dp_median=("dp", "median"), dp_max=("dp", "max")).to_string())

# tcpdump filter (one pass over the Monday PCAP)
parts = [f"(host {r.src_ip} and host {r.dst_ip} and port {int(r.src_port)} and port {int(r.dst_port)})"
         for r in sample.itertuples()]
bpf = "tcp and (" + " or ".join(parts) + ")"
(OUT / "random_audit_sample150.bpf").write_text(bpf)
print("\nBPF filter length:", len(bpf), "characters ->", OUT / "random_audit_sample150.bpf")
print("Time range of the sample (UTC):", pd.to_datetime(sample.start_time.min(), unit="s"), "→",
      pd.to_datetime(sample.end_time.max(), unit="s"))
print("\ndone")
