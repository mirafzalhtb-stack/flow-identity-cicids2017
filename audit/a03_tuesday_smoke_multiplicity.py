"""Section 4.2 and Fig. 2(b): candidate multiplicity in the benign-only Tuesday smoke run.

Direct five-tuple candidates whose CSV minute equals the flow's start minute. With
--previous-minute, a CSV record in the minute before the flow start also counts (this recovers
5 flows whose CSV timestamp falls in the preceding minute).

Outputs: tuesday_smoke_candidates.csv, fig2b_tuesday_multiplicity.csv
"""
import pandas as pd

from common import RUN_FILES, load_labels, minute_candidates, parse_args, save


def counts(flows, pairs):
    n = pairs.groupby("flow_uid").size()
    f = flows.set_index("flow_uid")[["end_reason"]].join(n.rename("n_cand")).fillna({"n_cand": 0})
    return f


def main():
    a = parse_args(__doc__, lambda p: p.add_argument("--previous-minute", action="store_true"))
    fl = pd.read_parquet(a.runs / RUN_FILES["tuesday_smoke"])
    lab = load_labels(a.labels, "tuesday")
    pairs = minute_candidates(fl, lab, reverse=False)
    if a.previous_minute:
        shifted = lab.assign(minute=lab["minute"] + pd.Timedelta(minutes=1))
        prev = minute_candidates(fl, shifted, reverse=False)
        pairs = pd.concat([pairs, prev[~prev.flow_uid.isin(pairs.flow_uid)]])
    f = counts(fl, pairs)
    summary = pd.DataFrame({
        "flows": [len(f)],
        "no_candidate": [int((f.n_cand == 0).sum())],
        "one_candidate": [int((f.n_cand == 1).sum())],
        "multiple_candidates": [int((f.n_cand >= 2).sum())],
        "coverage_pct": [round(100 * (f.n_cand > 0).mean(), 2)],
        "previous_minute_rule": [a.previous_minute],
    })
    print(summary.to_string(index=False))
    save(summary, a.out, "tuesday_smoke_candidates.csv")
    by_end = f.groupby("end_reason").agg(flows=("n_cand", "size"), multiple=("n_cand", lambda s: int((s >= 2).sum())))
    by_end["multiple_pct"] = (100 * by_end["multiple"] / by_end["flows"]).round(2)
    print(by_end)
    save(by_end, a.out, "fig2b_tuesday_multiplicity.csv", index=True)


if __name__ == "__main__":
    main()
