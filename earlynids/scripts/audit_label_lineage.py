r"""Compare two label-table directories file by file (e.g. traffic_labels vs machine_learning).

    python -m scripts.audit_label_lineage --dir-a <root>/traffic_labels --dir-b <root>/machine_learning `
        --out-dir results\lineage

Writes lineage_audit.json, lineage_audit.md, lineage_summary.csv. Observations only (no causes inferred).
One file pair is loaded at a time. Exit 0 ok, 2 invalid input, 5 outputs exist.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from src.labeling.lineage import audit_directories, render_markdown
from src.utils.cli import InputError, guard_outputs, run_cli
from src.utils.common import setup_logging, write_json


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir-a", required=True, type=Path, help="e.g. traffic_labels (with flow identifiers)")
    ap.add_argument("--dir-b", required=True, type=Path, help="e.g. machine_learning (feature tables)")
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args(argv)
    setup_logging()
    for d in (a.dir_a, a.dir_b):
        if not d.is_dir():
            raise InputError(f"directory not found: {d}")
    outs = [a.out_dir / n for n in ("lineage_audit.json", "lineage_audit.md", "lineage_summary.csv")]
    guard_outputs(outs, a.overwrite)
    audit = audit_directories(a.dir_a, a.dir_b)
    write_json(audit, outs[0])
    outs[1].write_text(render_markdown(audit), encoding="utf-8")
    pd.DataFrame(audit["summary"]).to_csv(outs[2], index=False)
    print(json.dumps(audit["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli(main))
