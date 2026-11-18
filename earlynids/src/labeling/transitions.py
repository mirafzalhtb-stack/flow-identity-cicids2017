"""Compare label-matching results of several runs on the SAME flows (v4.3, Task D).

Input: labelled tables (any version >= v4.1) keyed by ``flow_uid``. Output: one row per flow
with each run's status / reason / selected row / candidate counts, plus transition flags, and a
JSON summary. Nothing here decides which run is "right": transitions are listed for review.
"""
from __future__ import annotations

from typing import Dict, List

import pandas as pd

KEEP = ("match_status", "match_reason", "matched_row_id", "n_consistent", "n_start_aligned", "n_strict",
        "binary_label", "label", "trusted", "selected_duration_residual_s", "runner_up_row_id", "runner_up_miss_ratio")


def _norm(df: pd.DataFrame, name: str) -> pd.DataFrame:
    cols = [c for c in KEEP if c in df.columns]
    out = df[["flow_uid", *cols]].copy()
    if out["flow_uid"].duplicated().any():
        raise ValueError(f"run {name}: duplicated flow_uid")
    out.columns = ["flow_uid"] + [f"{c}@{name}" for c in cols]
    return out


def compare_runs(runs: Dict[str, pd.DataFrame], baseline: str) -> (pd.DataFrame, dict):
    if baseline not in runs:
        raise ValueError(f"baseline {baseline!r} not among runs {list(runs)}")
    names = list(runs)
    sets = {n: set(df["flow_uid"]) for n, df in runs.items()}
    common = set.intersection(*sets.values())
    table = None
    for n in names:
        part = _norm(runs[n][runs[n]["flow_uid"].isin(common)], n)
        table = part if table is None else table.merge(part, on="flow_uid", how="inner")
    table = table.sort_values("flow_uid").reset_index(drop=True)
    summary: dict = {"baseline": baseline, "runs": names, "common_flows": len(common),
                     "flows_not_in_all_runs": {n: len(sets[n] - common) for n in names},
                     "status_counts": {n: runs[n]["match_status"].value_counts().to_dict() for n in names},
                     "comparisons": {}}
    b = baseline
    for n in names:
        if n == b:
            continue
        sb, sn = table[f"match_status@{b}"], table[f"match_status@{n}"]
        rb = table.get(f"matched_row_id@{b}")
        rn = table.get(f"matched_row_id@{n}")
        both_unique = (sb == "unique") & (sn == "unique")
        row_changed = both_unique & (pd.to_numeric(rb, errors="coerce") != pd.to_numeric(rn, errors="coerce"))
        flags = {
            "ambiguous_to_unique": sb.str.startswith("ambiguous") & (sn == "unique"),
            "unique_to_time_inconsistent": (sb == "unique") & (sn == "time_inconsistent"),
            "unique_to_ambiguous": (sb == "unique") & sn.str.startswith("ambiguous"),
            "selected_row_changed": row_changed,
            "new_conflict": (sb != "conflict") & (sn == "conflict"),
            "new_shared_row": (sb != "ambiguous_shared_row") & (sn == "ambiguous_shared_row"),
            "candidate_count_changed": (table.get(f"n_consistent@{b}") != table.get(f"n_consistent@{n}"))
            if f"n_consistent@{b}" in table and f"n_consistent@{n}" in table else pd.Series(False, index=table.index),
            "binary_label_changed": both_unique & (table.get(f"binary_label@{b}") != table.get(f"binary_label@{n}"))
            if f"binary_label@{b}" in table else pd.Series(False, index=table.index),
        }
        for k, v in flags.items():
            table[f"{k}:{b}->{n}"] = v.fillna(False).astype(bool)
        summary["comparisons"][f"{b}->{n}"] = {
            "transition_matrix": pd.crosstab(sb, sn).to_dict(),
            "counts": {k: int(v.fillna(False).sum()) for k, v in flags.items()},
            "examples": {k: table.loc[v.fillna(False).astype(bool), "flow_uid"].head(10).tolist() for k, v in flags.items()},
        }
    # A selected label row must not change between runs AND carry a different label: report it explicitly.
    summary["note"] = ("Transitions are observations. A flow becoming 'unique' is not evidence of correctness; review "
                       "the candidate evidence (candidate_evidence.csv) for those flows.")
    return table, summary
