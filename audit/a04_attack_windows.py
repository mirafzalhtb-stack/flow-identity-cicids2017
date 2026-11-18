"""Section 4.3 and Table 3: Tuesday FTP-Patator and SSH-Patator attack windows.

Part 1 (segmentation): direct, same-minute candidates.
  FTP: valid early-prefix flows whose candidates are all FTP-Patator and that have exactly two
       candidates (paper: 287 flows).
  SSH: valid SYN-started flows to the attack endpoint with at least one candidate; of these the
       two-candidate flows (paper: 580 and 461).
  Delta P = packets(CSV 1) + packets(CSV 2) - observed_packets(EarlyNIDS).

Part 2 (Table 3): direct and reverse candidates for every extracted flow, and three policies:
  first candidate in CSV order, majority label, discard flows with more than one candidate.

Outputs: attack_window_dp.csv, table3_label_policies.csv, <window>_policy_per_flow.csv
"""
import pandas as pd

from common import RUN_FILES, load_labels, minute_candidates, parse_args, save

WINDOWS = {"tuesday_ftp": "FTP-Patator", "tuesday_ssh": "SSH-Patator"}
SSH_ENDPOINT = ("192.168.10.50", 22)


def segmentation(name, attack, fl, lab):
    direct = minute_candidates(fl, lab, reverse=False)
    g = direct.groupby("flow_uid")
    per = pd.DataFrame({"n_cand": g.size(), "labels": g["Label"].agg(lambda s: "|".join(sorted(set(s)))),
                        "csv_packets": g["packets"].sum()})
    f = fl.set_index("flow_uid").join(per, how="inner")
    f = f[f["valid_early_prefix"].astype(bool)]
    if name == "tuesday_ftp":
        f = f[f["labels"] == attack]
    else:
        f = f[(f["dst_ip"] == SSH_ENDPOINT[0]) & (f["dst_port"] == SSH_ENDPOINT[1]) & (f["start_reason"] == "syn")]
    selected = len(f)
    two = f[f["n_cand"] == 2].copy()
    two["dp"] = two["csv_packets"] - two["observed_packets"]
    t = two.groupby(["end_reason", "dp"]).size().rename("flows").reset_index()
    t.insert(0, "window", name)
    print(f"\n{name}: selected flows with candidates = {selected}, two-candidate flows = {len(two)}")
    print(t.to_string(index=False))
    return t


def policies(name, attack, fl, lab):
    pairs = minute_candidates(fl, lab, reverse=True)
    g = pairs.groupby("flow_uid")
    per = pd.DataFrame({
        "n_cand": g.size(),
        "labels": g["Label"].agg(lambda s: "|".join(sorted(set(s)))),
        "first": g["Label"].first(),
        "majority": g["Label"].agg(lambda s: s.mode().iloc[0] if len(s.mode()) == 1 else "TIE"),
    })
    per = fl.set_index("flow_uid")[["end_reason", "valid_early_prefix"]].join(per)
    per["n_cand"] = per["n_cand"].fillna(0).astype(int)
    multi = per[per.n_cand >= 2]
    row = {
        "window": name, "flows": len(per),
        "no_candidate": int((per.n_cand == 0).sum()), "one_candidate": int((per.n_cand == 1).sum()),
        "multi_candidate": len(multi),
        "multi_with_mixed_labels": int(multi.labels.str.contains(r"\|", na=False).sum()),
        "attack_first": int((per["first"] == attack).sum()),
        "attack_majority": int((per["majority"] == attack).sum()),
        "majority_ties": int((per["majority"] == "TIE").sum()),
        "first_vs_majority_differ": int(((per["first"] != per["majority"]) & per["first"].notna()).sum()),
        "discard_ambiguous_removed": len(multi),
        "discard_removed_attack": int(multi.labels.str.contains(attack, na=False).sum()),
        "attack_after_discard": int(((per.n_cand == 1) & (per["first"] == attack)).sum()),
    }
    return row, per


def main():
    a = parse_args(__doc__)
    lab = load_labels(a.labels, "tuesday")
    seg, rows = [], []
    for name, attack in WINDOWS.items():
        fl = pd.read_parquet(a.runs / RUN_FILES[name])
        seg.append(segmentation(name, attack, fl, lab))
        row, per = policies(name, attack, fl, lab)
        rows.append(row)
        save(per, a.out, f"{name}_policy_per_flow.csv", index=True)
    save(pd.concat(seg), a.out, "attack_window_dp.csv")
    table = pd.DataFrame(rows)
    print("\n", table.T.to_string())
    save(table, a.out, "table3_label_policies.csv")


if __name__ == "__main__":
    main()
