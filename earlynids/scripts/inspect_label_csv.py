r"""Inspect real label files (CSV or Parquet) BEFORE configuring the matcher. Nothing is modified.

Reports raw and normalised headers, column dtypes (Parquet: Arrow types), whether the file is
matchable to PCAP flows, duplicated headers, timestamp dtype/patterns/examples, hour histogram,
protocol and label values, duration ranges, nulls, and the total row count (Parquet metadata).

    python -m scripts.inspect_label_csv --files "<root>\traffic_labels\*.parquet" --output results\label_inspection.json
    python -m scripts.inspect_label_csv --csv data\raw\labels\*.csv        (v4.1 flag, still supported)
"""
from __future__ import annotations

import argparse
import glob
import json
import re
from collections import Counter
from pathlib import Path

import pandas as pd

from src.labeling.cicids2017 import LabelConfig, LabelSchemaError, normalize_header, resolve_columns
from src.utils.cli import InputError, guard_outputs, run_cli


def pattern(ts: str) -> str:
    return re.sub(r"\d", "9", str(ts).strip())


def read_head(path: Path, nrows: int, encoding: str):
    """Return (head DataFrame with native dtypes, dtype map, total rows or None)."""
    if path.suffix.lower() == ".parquet":
        import pyarrow.parquet as pq
        pf = pq.ParquetFile(path)
        batches, n = [], 0
        for b in pf.iter_batches(batch_size=min(nrows, 65536)):
            batches.append(b.to_pandas())
            n += b.num_rows
            if n >= nrows:
                break
        head = pd.concat(batches, ignore_index=True).head(nrows) if batches else pd.DataFrame(
            columns=pf.schema_arrow.names)
        types = {f.name: str(f.type) for f in pf.schema_arrow}
        return head, types, pf.metadata.num_rows
    head = pd.read_csv(path, nrows=nrows, encoding=encoding, dtype=str, keep_default_na=False)
    return head, {c: "string(csv)" for c in head.columns}, None


def inspect(path: Path, nrows: int, encoding: str) -> dict:
    head, types, total = read_head(path, nrows, encoding)
    cols = {c: normalize_header(c) for c in head.columns}
    out = {"file": path.name, "format": path.suffix.lower().lstrip("."), "total_rows": total,
           "rows_inspected": int(len(head)), "n_columns": len(cols), "raw_headers": list(cols),
           "normalized_headers": list(cols.values()),
           "dtypes": {cols[c]: t for c, t in types.items() if c in cols}}
    try:
        resolve_columns(cols.keys(), LabelConfig())
        out["matchable_with_default_columns"] = True
    except LabelSchemaError as exc:
        out["matchable_with_default_columns"] = False
        out["schema_problem"] = str(exc).split(". Found")[0]
    vals = list(cols.values())
    out["duplicated_normalized_headers"] = sorted({c for c in vals if vals.count(c) > 1})
    df = head.rename(columns=cols)
    df = df.loc[:, ~df.columns.duplicated()]
    out["rows_all_null_in_head"] = int(df.isna().all(axis=1).sum() + (df.astype(str).apply(
        lambda s: s.str.strip().isin(["", "nan", "None"])).all(axis=1) & ~df.isna().all(axis=1)).sum())
    if "timestamp" in df:
        ts = df["timestamp"]
        out["timestamp_dtype"] = str(ts.dtype)
        txt = ts.dropna().astype(str)
        out["timestamp_patterns"] = Counter(map(pattern, txt)).most_common(8)
        out["timestamp_examples"] = txt.head(5).tolist()
        hours = Counter(int(m.group(1)) for m in (re.search(r"[ T](\d{1,2}):", t) for t in txt) if m)
        out["hour_histogram"] = dict(sorted(hours.items()))
    for c in ("protocol", "label"):
        if c in df:
            out[f"{c}_values"] = {repr(k): int(v) for k, v in Counter(df[c].astype(str)).most_common(25)}
    if "flow duration" in df:
        d = pd.to_numeric(df["flow duration"], errors="coerce")
        out["flow_duration"] = {"min": float(d.min()), "median": float(d.median()), "max": float(d.max()),
                                "n_negative": int((d < 0).sum()), "n_non_numeric": int(d.isna().sum())}
    out["null_counts_top"] = {k: int(v) for k, v in df.isna().sum().sort_values(ascending=False).head(10).items() if v}
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--files", nargs="+", default=None, help="CSV and/or Parquet files or glob patterns")
    ap.add_argument("--csv", nargs="+", default=None, help="alias of --files (v4.1)")
    ap.add_argument("--nrows", type=int, default=200_000)
    ap.add_argument("--encoding", default="latin-1")
    ap.add_argument("--output", type=Path, default=None)
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args(argv)
    pats = (a.files or []) + (a.csv or [])
    if not pats:
        raise InputError("give --files (or --csv) with at least one path or pattern")
    files = []
    for pat in pats:
        hits = sorted(glob.glob(pat))
        files += [Path(h) for h in hits] if hits else [Path(pat)]
    for f in files:
        if not f.is_file():
            raise InputError(f"label file not found: {f}")
    if a.output:
        guard_outputs([a.output], a.overwrite)
    res = [inspect(f, a.nrows, a.encoding) for f in files]
    txt = json.dumps(res, indent=2, ensure_ascii=True, default=str)
    print(txt)
    if a.output:
        a.output.write_text(txt, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli(main))
