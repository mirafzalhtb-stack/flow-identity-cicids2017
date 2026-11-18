r"""Evidence for the label-time-zone offset (diagnostic only; never applied automatically).

    python -m scripts.time_offset_diagnostics --flows data\interim\monday_flows.parquet `
        --labels "<root>\traffic_labels\Monday*" --config configs\preprocessing.yaml --output results\monday_offset.json

Labels are parsed with utc_offset_hours = 0 (local clock read as UTC); candidate offsets from -14 h to +14 h
(0.5 h steps) are scored on endpoint-matched flows. Exit 0 ok, 2 invalid input, 5 output exists.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.match_labels import expand
from src.labeling.cicids2017 import config_from_dict, load_label_files, offset_evidence, time_offset_diagnostics
from src.preprocessing.io import read_flows
from src.utils.cli import guard_outputs, require_file, run_cli
from src.utils.common import load_yaml, setup_logging, write_json


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--flows", required=True, type=Path)
    ap.add_argument("--labels", required=True, nargs="+")
    ap.add_argument("--config", type=Path, required=True)
    ap.add_argument("--output", type=Path, default=None)
    ap.add_argument("--max-flows", type=int, default=200_000, help="deterministic sample size for scoring")
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args(argv)
    setup_logging()
    conf = dict(load_yaml(require_file(a.config, "config")).get("labeling", {}))
    conf["utc_offset_hours"] = 0.0  # parse as local clock; the candidates reveal the offset
    cfg = config_from_dict(conf)
    files = expand(a.labels)
    for f in files:
        require_file(f, "label file")
    if a.output:
        guard_outputs([a.output], a.overwrite)
    labels, invalid, stats = load_label_files(files, cfg)
    flows = read_flows(require_file(a.flows, "flow table"))
    rep = offset_evidence(flows, labels, cfg, max_flows=a.max_flows)
    rep["hour_rounded_histogram"] = time_offset_diagnostics(flows, labels)
    rep["label_files"] = stats
    rep["invalid_label_rows"] = int(len(invalid))
    rep["configured_utc_offset_hours"] = load_yaml(a.config).get("labeling", {}).get("utc_offset_hours")
    if a.output:
        write_json(rep, a.output)
    short = {k: rep.get(k) for k in ("evidence_best_offset_hours", "ranking", "flags", "configured_utc_offset_hours", "note")}
    print(json.dumps(short, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli(main))
