r"""Re-run label matching for several configuration variants on the same flows (diagnostic only).

    python -m scripts.duration_sensitivity --flows runs\smoke\monday\flows.parquet `
        --labels "<root>\traffic_labels\Monday*" --config run_config.yaml --out-dir results\sensitivity `
        --variant "legacy_1s:matching_mode=legacy_v41,duration_abs_tolerance_s=1.0" `
        --variant "legacy_100ms:matching_mode=legacy_v41,duration_abs_tolerance_s=0.1" `
        --variant "legacy_10ms:matching_mode=legacy_v41,duration_abs_tolerance_s=0.01" `
        --variant "evidence_1s:matching_mode=evidence_v43,duration_abs_tolerance_s=1.0" --baseline legacy_1s

For every variant: labelled_<name>.parquet (evidence columns, no packet lists). Then the transition
audit (transitions.csv / transitions_summary.json) and candidate_evidence.csv with ALL candidates of
every flow whose status or selected row differs between variants. No quality gate is applied and no
variant is declared optimal. Exit 0 ok, 2 invalid input, 5 outputs exist.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
from pathlib import Path

import pandas as pd

from scripts.match_labels import expand
from src.labeling.cicids2017 import candidate_evidence, config_from_dict, label_flows, load_label_files
from src.labeling.transitions import compare_runs
from src.preprocessing.io import LIST_COLUMNS, read_flows
from src.utils.cli import InputError, guard_outputs, require_file, run_cli
from src.utils.common import load_yaml, setup_logging, write_json

FIELDS = {f.name: f.type for f in dataclasses.fields(__import__("src.labeling.cicids2017", fromlist=["LabelConfig"]).LabelConfig)}


def parse_variant(spec: str):
    if ":" not in spec:
        raise InputError(f"--variant must be NAME:key=value,...; got {spec!r}")
    name, body = spec.split(":", 1)
    kv = {}
    for item in filter(None, body.split(",")):
        k, _, v = item.partition("=")
        k = k.strip()
        if k not in FIELDS:
            raise InputError(f"variant {name}: unknown labeling option {k!r}")
        kv[k] = json.loads(v) if v.strip() not in ("evidence_v43", "legacy_v41", "off", "report", "require") else v.strip()
    return name.strip(), kv


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--flows", required=True, type=Path)
    ap.add_argument("--labels", required=True, nargs="+")
    ap.add_argument("--config", required=True, type=Path)
    ap.add_argument("--variant", action="append", required=True)
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument("--max-review-flows", type=int, default=2000, help="cap on flows exported to candidate_evidence.csv")
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args(argv)
    setup_logging()
    base = dict(load_yaml(require_file(a.config, "config")).get("labeling", {}))
    if base.get("utc_offset_hours") is None:
        raise InputError("labeling.utc_offset_hours must be set in the config")
    variants = dict(parse_variant(v) for v in a.variant)
    if a.baseline not in variants:
        raise InputError("--baseline must name one of the variants")
    outs = [a.out_dir / f"labelled_{n}.parquet" for n in variants] + \
           [a.out_dir / "transitions.csv", a.out_dir / "transitions_summary.json", a.out_dir / "candidate_evidence.csv"]
    guard_outputs(outs, a.overwrite)
    flows = read_flows(require_file(a.flows, "flow table"))
    files = expand(a.labels)
    for f in files:
        require_file(f, "label file")
    results, cfgs = {}, {}
    for name, kv in variants.items():
        cfg = config_from_dict({**base, **kv})
        labels, _, _ = load_label_files(files, cfg)
        lab = label_flows(flows, labels, cfg)
        lab = lab.drop(columns=[c for c in LIST_COLUMNS if c in lab.columns])
        lab.to_parquet(a.out_dir / f"labelled_{name}.parquet", index=False)
        results[name], cfgs[name] = lab, (cfg, labels)
    table, summary = compare_runs(results, a.baseline)
    table.to_csv(a.out_dir / "transitions.csv", index=False)
    flag_cols = [c for c in table.columns if ":" in c and "->" in c]
    changed = table.loc[table[flag_cols].any(axis=1), "flow_uid"].head(a.max_review_flows)
    sub = flows[flows["flow_uid"].isin(set(changed))]
    ev = []
    for name, (cfg, labels) in cfgs.items():
        ce = candidate_evidence(sub, labels, cfg)
        ev.append(ce.assign(variant=name))
    pd.concat(ev, ignore_index=True).to_csv(a.out_dir / "candidate_evidence.csv", index=False)
    summary["variants"] = {n: kv for n, kv in variants.items()}
    summary["flows_exported_for_review"] = int(len(changed))
    write_json(summary, a.out_dir / "transitions_summary.json")
    print(json.dumps({k: v["counts"] for k, v in summary["comparisons"].items()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli(main))
