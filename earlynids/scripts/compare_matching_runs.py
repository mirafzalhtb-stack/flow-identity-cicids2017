r"""Compare labelled outputs of several matching runs on the same flows (transition audit).

    python -m scripts.compare_matching_runs --run tol1s=runs/a/labelled.parquet --run tol100ms=runs/b/labelled.parquet `
        --run tol10ms=runs/c/labelled.parquet --baseline tol1s --out-dir results\transitions

Writes transitions.csv (one row per flow) and transitions_summary.json. Exit 0 ok, 2 invalid input, 5 outputs exist.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.labeling.transitions import compare_runs
from src.preprocessing.io import read_flows
from src.utils.cli import InputError, guard_outputs, require_file, run_cli
from src.utils.common import setup_logging, write_json


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", action="append", required=True, help="NAME=PATH to a labelled table (repeat)")
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args(argv)
    setup_logging()
    runs = {}
    for spec in a.run:
        if "=" not in spec:
            raise InputError(f"--run must be NAME=PATH, got {spec!r}")
        name, path = spec.split("=", 1)
        if name in runs:
            raise InputError(f"duplicate run name {name!r}")
        runs[name] = read_flows(require_file(Path(path), f"labelled table for run {name}"))
    outs = [a.out_dir / "transitions.csv", a.out_dir / "transitions_summary.json"]
    guard_outputs(outs, a.overwrite)
    table, summary = compare_runs(runs, a.baseline)
    table.to_csv(outs[0], index=False)
    write_json(summary, outs[1])
    print(json.dumps({k: v["counts"] for k, v in summary["comparisons"].items()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli(main))
