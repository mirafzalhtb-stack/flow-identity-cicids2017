"""Data-lineage audit between two versions of the CIC-IDS2017 flow tables.

Typical use: compare ``traffic_labels/`` (flows with identifiers: IPs, ports,
timestamps) with ``machine_learning/`` (feature-only benchmark tables) file by
file, e.g. the Thursday WebAttacks pair whose row counts differ.

The audit reports **observations** (counts, schemas, label distributions,
null/invalid values, duplicates, row-hash containment, feature statistics).
It never states a cause. Statements in ``evidence`` are deterministic facts,
e.g. "after removing N rows whose common columns are all null, row counts are
equal". Interpreting them is left to the researcher.

Memory: one file pair is loaded at a time.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from .cicids2017 import MISSING_TOKENS, normalize_header, normalize_label

READ_SUFFIXES = (".parquet", ".csv")


def pair_key(name: str) -> str:
    """'Thursday-...WebAttacks.pcap_ISCX.csv.parquet' -> 'thursday-...webattacks.pcap_iscx'."""
    n = name.lower()
    changed = True
    while changed:
        changed = False
        for suf in (".parquet", ".csv"):
            if n.endswith(suf):
                n = n[: -len(suf)]
                changed = True
    return n


def pair_files(dir_a: Path, dir_b: Path) -> Tuple[List[Tuple[str, Optional[Path], Optional[Path]]], List[str]]:
    def listing(d):
        return {pair_key(p.name): p for p in sorted(Path(d).iterdir()) if p.suffix.lower() in READ_SUFFIXES}
    a, b = listing(dir_a), listing(dir_b)
    keys = sorted(set(a) | set(b))
    warnings = [f"no counterpart for {k} in {'B' if k in a else 'A'}" for k in keys if (k in a) != (k in b)]
    return [(k, a.get(k), b.get(k)) for k in keys], warnings


def read_table(path: Path, encoding: str = "latin-1") -> pd.DataFrame:
    path = Path(path)
    if path.suffix.lower() == ".parquet":
        return pd.read_parquet(path)
    return pd.read_csv(path, encoding=encoding, low_memory=False)


def _norm_columns(df: pd.DataFrame) -> Tuple[pd.DataFrame, List[str]]:
    names = [normalize_header(c) for c in df.columns]
    dup = sorted({n for n in names if names.count(n) > 1})
    seen: Dict[str, int] = {}
    uniq = []
    for n in names:  # keep duplicates distinguishable, reported separately
        k = seen.get(n, 0)
        uniq.append(n if k == 0 else f"{n}#{k}")
        seen[n] = k + 1
    out = df.copy()
    out.columns = uniq
    return out, dup


def _null_mask(df: pd.DataFrame) -> pd.DataFrame:
    m = df.isna()
    obj = [c for c in df.columns if df[c].dtype == object or pd.api.types.is_string_dtype(df[c])]
    for c in obj:
        m[c] = m[c] | df[c].astype(str).str.strip().isin(MISSING_TOKENS)
    return m


def _canonical(df: pd.DataFrame, cols: List[str]) -> pd.DataFrame:
    """Type-independent representation for row hashing (int 5 == float 5.0 == '5')."""
    out = {}
    for c in cols:
        s = df[c]
        num = pd.to_numeric(s, errors="coerce")
        if s.notna().sum() and num.notna().sum() == s.notna().sum():
            out[c] = num.astype(float).round(9)  # vectorised; int 5 and float 5.0 hash identically
        else:
            out[c] = s.astype(str).str.strip().where(s.notna(), "")
    return pd.DataFrame(out)


def _row_hashes(df: pd.DataFrame, cols: List[str]) -> np.ndarray:
    return pd.util.hash_pandas_object(_canonical(df, cols), index=False).to_numpy()


def _label_col(cols: List[str]) -> Optional[str]:
    return "label" if "label" in cols else None


def _feature_stats(df: pd.DataFrame, cols: List[str]) -> Dict[str, dict]:
    st = {}
    for c in cols:
        x = pd.to_numeric(df[c], errors="coerce").replace([np.inf, -np.inf], np.nan).dropna()
        if len(x):
            st[c] = {"n": int(len(x)), "mean": float(x.mean()), "std": float(x.std()), "p50": float(x.median()),
                     "p99": float(x.quantile(.99))}
    return st


def compare_pair(a: pd.DataFrame, b: pd.DataFrame, name: str = "", max_feature_columns: int = 25) -> dict:
    a, dup_a = _norm_columns(a)
    b, dup_b = _norm_columns(b)
    ca, cb = list(a.columns), list(b.columns)
    common = [c for c in ca if c in set(cb)]
    rep: dict = {"pair": name, "rows_a": int(len(a)), "rows_b": int(len(b)), "row_difference_a_minus_b": int(len(a) - len(b)),
                 "schema": {"n_columns_a": len(ca), "n_columns_b": len(cb), "common": len(common),
                            "only_a": [c for c in ca if c not in set(cb)], "only_b": [c for c in cb if c not in set(ca)],
                            "duplicated_normalized_headers_a": dup_a, "duplicated_normalized_headers_b": dup_b,
                            "dtype_mismatches": {c: [str(a[c].dtype), str(b[c].dtype)] for c in common
                                                 if str(a[c].dtype) != str(b[c].dtype)}}}
    na, nb = _null_mask(a), _null_mask(b)
    all_null_a = na[common].all(axis=1) if common else pd.Series(False, index=a.index)
    all_null_b = nb[common].all(axis=1) if common else pd.Series(False, index=b.index)
    rep["nulls"] = {
        "rows_all_columns_null_a": int(na.all(axis=1).sum()), "rows_all_columns_null_b": int(nb.all(axis=1).sum()),
        "rows_all_common_null_a": int(all_null_a.sum()), "rows_all_common_null_b": int(all_null_b.sum()),
        "rows_any_null_a": int(na.any(axis=1).sum()), "rows_any_null_b": int(nb.any(axis=1).sum()),
        "top_null_columns_a": {k: int(v) for k, v in na.sum().sort_values(ascending=False).head(10).items() if v},
        "top_null_columns_b": {k: int(v) for k, v in nb.sum().sort_values(ascending=False).head(10).items() if v},
    }
    num_common = [c for c in common if pd.api.types.is_numeric_dtype(a[c]) or pd.api.types.is_numeric_dtype(b[c])]
    def inf_count(df):
        return int(sum(np.isinf(pd.to_numeric(df[c], errors="coerce")).sum() for c in num_common))
    rep["invalid_values"] = {"infinite_values_a": inf_count(a), "infinite_values_b": inf_count(b)}
    lab = _label_col(common)
    if lab:
        la = a.loc[~all_null_a, lab].dropna().map(normalize_label).value_counts()
        lb = b.loc[~all_null_b, lab].dropna().map(normalize_label).value_counts()
        labels = sorted(set(la.index) | set(lb.index))
        rep["labels"] = {l: {"a": int(la.get(l, 0)), "b": int(lb.get(l, 0)), "a_minus_b": int(la.get(l, 0) - lb.get(l, 0))}
                         for l in labels}
    if common:
        ha = _row_hashes(a.loc[~all_null_a], common)
        hb = _row_hashes(b.loc[~all_null_b], common)
        sa, sb = pd.Series(ha), pd.Series(hb)
        rep["duplicates"] = {"duplicate_rows_common_cols_a": int(sa.duplicated().sum()),
                             "duplicate_rows_common_cols_b": int(sb.duplicated().sum()),
                             "duplicate_rows_all_cols_a": int(a.loc[~all_null_a].duplicated().sum()),
                             "duplicate_rows_all_cols_b": int(b.loc[~all_null_b].duplicated().sum())}
        set_a, set_b = set(ha.tolist()), set(hb.tolist())
        rep["containment"] = {
            "columns_used": len(common),
            "fraction_b_rows_found_in_a": float(np.isin(hb, ha).mean()) if len(hb) else None,
            "fraction_a_rows_found_in_b": float(np.isin(ha, hb).mean()) if len(ha) else None,
            "distinct_rows_a": len(set_a), "distinct_rows_b": len(set_b),
            "note": "Rows compared on all common columns after excluding all-null rows; type-normalised hashing.",
        }
    feats = [c for c in num_common if c != lab][:max_feature_columns]
    fa = _feature_stats(a.loc[~all_null_a], feats)
    fb = _feature_stats(b.loc[~all_null_b], feats)
    diffs = {}
    for c in feats:
        if c in fa and c in fb:
            denom = max(abs(fa[c]["mean"]), 1e-12)
            diffs[c] = {"mean_a": fa[c]["mean"], "mean_b": fb[c]["mean"], "rel_mean_diff": abs(fa[c]["mean"] - fb[c]["mean"]) / denom,
                        "p50_a": fa[c]["p50"], "p50_b": fb[c]["p50"]}
    rep["feature_distributions"] = diffs
    rep["evidence"] = _evidence(rep)
    rep["discrepancies"] = _discrepancies(rep)
    return rep


def _evidence(rep: dict) -> List[str]:
    ev = []
    ra, rb = rep["rows_a"], rep["rows_b"]
    nla, nlb = rep["nulls"]["rows_all_common_null_a"], rep["nulls"]["rows_all_common_null_b"]
    ev.append(f"rows: A={ra}, B={rb}, A-B={ra - rb}.")
    if nla or nlb:
        ev.append(f"rows whose common columns are all null/empty: A={nla}, B={nlb}.")
        if ra - nla == rb - nlb:
            ev.append("after removing those all-null rows, the row counts of A and B are equal.")
        else:
            ev.append(f"after removing those all-null rows, counts still differ by {(ra - nla) - (rb - nlb)}.")
    c = rep.get("containment")
    if c and c["fraction_b_rows_found_in_a"] is not None:
        ev.append(f"{c['fraction_b_rows_found_in_a']:.4%} of non-null B rows have an identical row (on {c['columns_used']} "
                  f"common columns) in A; {c['fraction_a_rows_found_in_b']:.4%} of non-null A rows are found in B.")
    if rep["schema"]["only_a"] or rep["schema"]["only_b"]:
        ev.append(f"columns only in A: {len(rep['schema']['only_a'])}; only in B: {len(rep['schema']['only_b'])}.")
    if rep.get("labels"):
        changed = {k: v["a_minus_b"] for k, v in rep["labels"].items() if v["a_minus_b"]}
        ev.append(f"non-null label count differences (A-B): {changed if changed else 'none'}.")
    return ev


def _discrepancies(rep: dict) -> List[dict]:
    out = []
    def add(kind, severity, detail):
        out.append({"type": kind, "severity": severity, "detail": detail})
    if rep["rows_a"] != rep["rows_b"]:
        add("row_count_mismatch", "high", f"A={rep['rows_a']} B={rep['rows_b']}")
    if rep["nulls"]["rows_all_common_null_a"] or rep["nulls"]["rows_all_common_null_b"]:
        add("all_null_rows", "high", f"A={rep['nulls']['rows_all_common_null_a']} B={rep['nulls']['rows_all_common_null_b']}")
    if rep["schema"]["duplicated_normalized_headers_a"] or rep["schema"]["duplicated_normalized_headers_b"]:
        add("duplicated_headers", "medium", f"A={rep['schema']['duplicated_normalized_headers_a']} B={rep['schema']['duplicated_normalized_headers_b']}")
    if rep["schema"]["dtype_mismatches"]:
        add("dtype_mismatch", "low", f"{len(rep['schema']['dtype_mismatches'])} common columns differ in dtype")
    if rep.get("labels") and any(v["a_minus_b"] for v in rep["labels"].values()):
        add("label_distribution_difference", "high", "non-null label counts differ")
    c = rep.get("containment")
    if c and c["fraction_b_rows_found_in_a"] is not None and c["fraction_b_rows_found_in_a"] < 0.999:
        add("rows_not_contained", "high", f"only {c['fraction_b_rows_found_in_a']:.4%} of B rows found in A")
    d = rep.get("duplicates", {})
    if d.get("duplicate_rows_common_cols_a") or d.get("duplicate_rows_common_cols_b"):
        add("duplicate_rows", "medium", json.dumps(d))
    if rep["invalid_values"]["infinite_values_a"] or rep["invalid_values"]["infinite_values_b"]:
        add("infinite_values", "medium", json.dumps(rep["invalid_values"]))
    big = {k: v["rel_mean_diff"] for k, v in rep["feature_distributions"].items() if v["rel_mean_diff"] > 0.01}
    if big:
        add("feature_distribution_shift", "medium", f"{len(big)} common numeric features differ in mean by >1%")
    return out


def audit_directories(dir_a: Path, dir_b: Path, encoding: str = "latin-1") -> dict:
    pairs, warnings = pair_files(dir_a, dir_b)
    reports = []
    for key, pa, pb in pairs:
        if pa is None or pb is None:
            reports.append({"pair": key, "missing": "A" if pa is None else "B"})
            continue
        r = compare_pair(read_table(pa, encoding), read_table(pb, encoding), key)
        r["file_a"], r["file_b"] = str(pa), str(pb)
        reports.append(r)
    summary = [{"pair": r["pair"], "rows_a": r.get("rows_a"), "rows_b": r.get("rows_b"),
                "difference": r.get("row_difference_a_minus_b"),
                "all_null_rows_a": r.get("nulls", {}).get("rows_all_common_null_a"),
                "discrepancies": ";".join(d["type"] for d in r.get("discrepancies", [])) or ("missing_" + r["missing"] if "missing" in r else "")}
               for r in reports]
    return {"dir_a": str(dir_a), "dir_b": str(dir_b), "pairs": reports, "summary": summary, "warnings": warnings,
            "note": "Observations only. No cause is inferred; see 'evidence' per pair."}


def render_markdown(audit: dict) -> str:
    lines = ["# Label-table lineage audit", "", f"A = `{audit['dir_a']}`  ", f"B = `{audit['dir_b']}`", "",
             "Observations only; causes are not inferred.", "",
             "| Pair | Rows A | Rows B | A−B | All-null rows A | Discrepancies |", "|---|---|---|---|---|---|"]
    for s in audit["summary"]:
        lines.append(f"| {s['pair']} | {s['rows_a']} | {s['rows_b']} | {s['difference']} | {s['all_null_rows_a']} | {s['discrepancies']} |")
    for r in audit["pairs"]:
        lines += ["", f"## {r['pair']}"]
        if "missing" in r:
            lines.append(f"Counterpart missing in {r['missing']}.")
            continue
        lines += [f"- {e}" for e in r["evidence"]]
    if audit["warnings"]:
        lines += ["", "## Warnings"] + [f"- {w}" for w in audit["warnings"]]
    return "\n".join(lines) + "\n"
