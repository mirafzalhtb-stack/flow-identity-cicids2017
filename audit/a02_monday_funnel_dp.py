"""Section 3.3, Table 2 and Fig. 2(a): Monday selection funnel and signed packet difference.

Selection: strict-identity failures (match_reason == no_candidate_meets_strict_identity) with exactly
two CSV candidates, ended by FIN or RST, whose two candidates are one direct and one reverse record.
Delta P = packets(CSV 1) + packets(CSV 2) - observed_packets(EarlyNIDS).

Outputs: monday_funnel.csv, monday_population.csv, table2_monday_dp_counts.csv,
         table2_monday_dp_tolerance.csv, monday_wilson.csv
"""
import pandas as pd

from common import RUN_FILES, load_labels, parse_args, row_ids, save, wilson


def main():
    a = parse_args(__doc__)
    cols = ["flow_uid", "src_ip", "end_reason", "match_reason", "candidate_row_ids", "observed_packets"]
    mon = pd.read_parquet(a.runs / RUN_FILES["monday_labelled"], columns=cols)
    lab = load_labels(a.labels, "monday")
    mon["ids"] = mon["candidate_row_ids"].map(row_ids)
    mon["n_cand"] = mon["ids"].map(len)

    fail = mon[mon["match_reason"] == "no_candidate_meets_strict_identity"]
    two = fail[(fail["n_cand"] == 2) & fail["end_reason"].isin(["fin", "rst"])].copy()
    src = lab["Source IP"].to_numpy()
    pk = lab["packets"].to_numpy()
    two["n_direct"] = [sum(src[i] == s for i in ids) for ids, s in zip(two["ids"], two["src_ip"])]
    two["orientation"] = two["n_direct"].map({2: "direct-direct", 1: "direct-reverse", 0: "reverse-reverse"})
    two["csv_packets"] = [int(pk[ids].sum()) for ids in two["ids"]]
    two["dp"] = two["csv_packets"] - two["observed_packets"]

    funnel = pd.DataFrame([
        ("all EarlyNIDS flows", len(mon)),
        ("strict-identity failures", len(fail)),
        ("  with 0 candidates", int((fail.n_cand == 0).sum())),
        ("  with 1 candidate", int((fail.n_cand == 1).sum())),
        ("  with 2 candidates", int((fail.n_cand == 2).sum())),
        ("  with >=3 candidates", int((fail.n_cand >= 3).sum())),
        ("2 candidates, FIN or RST", len(two)),
        ("  direct-direct (set aside)", int((two.orientation == "direct-direct").sum())),
        ("  reverse-reverse (set aside)", int((two.orientation == "reverse-reverse").sum())),
        ("  direct-reverse (analysed)", int((two.orientation == "direct-reverse").sum())),
    ], columns=["step", "flows"])
    print(funnel.to_string(index=False))
    save(funnel, a.out, "monday_funnel.csv")

    pop = two[two["orientation"] == "direct-reverse"]
    save(pop.drop(columns=["ids"]), a.out, "monday_population.csv")

    bins = pd.cut(pop["dp"], [-1e9, -0.5, 0.5, 1.5, 2.5, 1e9], labels=["<0", "0", "+1", "+2", ">=+3"])
    counts = pd.crosstab(pop["end_reason"], bins).reindex(columns=["<0", "0", "+1", "+2", ">=+3"], fill_value=0)
    print("\nDelta P counts:\n", counts)
    save(counts, a.out, "table2_monday_dp_counts.csv", index=True)

    tol = pd.DataFrame({f"|dP|<={k}": pop.groupby("end_reason")["dp"].apply(lambda s, k=k: round((s.abs() <= k).mean() * 100, 2))
                        for k in range(6)})
    print("\nShare within k packets (%):\n", tol)
    save(tol, a.out, "table2_monday_dp_tolerance.csv", index=True)

    w = []
    for end, g in pop.groupby("end_reason"):
        k, n = int((g["dp"].abs() <= 2).sum()), len(g)
        lo, hi = wilson(k, n)
        w.append({"end_reason": end, "pairs": n, "within_2": k, "share_pct": round(100 * k / n, 2),
                  "wilson_low_pct": round(100 * lo, 2), "wilson_high_pct": round(100 * hi, 2)})
    w = pd.DataFrame(w)
    print("\n", w.to_string(index=False))
    save(w, a.out, "monday_wilson.csv")


if __name__ == "__main__":
    main()
