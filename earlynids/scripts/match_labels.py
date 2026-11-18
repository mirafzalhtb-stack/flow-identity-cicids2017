r"""Match extracted flows to CIC-IDS2017 labelled flow files (CSV or Parquet), then run the quality gate.

    python -m scripts.match_labels --flows data\interim\monday_flows.parquet `
        --labels "data\raw\labels\Monday*.csv" --config configs\preprocessing.yaml `
        --output data\processed\monday_labelled.parquet

Writes (all preserved even if the gate fails):
  <output>                          all flows + match evidence (nothing deleted)
  <output>.label_stats.json         CSV record counts and invalid reasons
  <output>.invalid_csv_rows.csv     every rejected CSV record with its reason
  <output>.problem_flows.csv        non-trusted flows with evidence
  <output>.quality_gate.json / *_checks.csv / exclusions_by_reason.csv / capture_summary.csv

Exit codes: 0 gate passed, 4 gate failed, 2 invalid input, 5 output exists.
"""
from __future__ import annotations

import argparse
import glob
import logging
from pathlib import Path

from src.datasets.quality_gate import GateConfig, evaluate, format_failures, write_reports
import json

from src.labeling.cicids2017 import config_from_dict, label_flows, load_label_files
from src.preprocessing.io import read_flows
from src.utils.cli import EXIT_GATE_FAILED, InputError, guard_outputs, require_file, run_cli
from src.utils.common import file_fingerprint, load_yaml, setup_logging, write_json

log = logging.getLogger("match_labels")


def expand(patterns):
    files = []
    for pat in patterns:
        hits = sorted(glob.glob(pat))
        files += [Path(h) for h in hits] if hits else [Path(pat)]
    return files


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--flows", required=True, type=Path)
    ap.add_argument("--labels", required=True, nargs="+")
    ap.add_argument("--config", type=Path, required=True)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--offset-report", type=Path, default=None,
                    help="JSON from scripts.time_offset_diagnostics; the configured offset must agree with its evidence")
    ap.add_argument("--accept-offset-disagreement", action="store_true",
                    help="proceed although the configured offset differs from the evidence (recorded in the gate report)")
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args(argv)
    setup_logging()
    require_file(a.flows, "flow table")
    require_file(a.config, "config file")
    files = expand(a.labels)
    for f in files:
        require_file(f, "label file")
    if a.output.suffix.lower() not in (".parquet", ".csv"):
        raise InputError("--output must end with .parquet or .csv")
    conf = load_yaml(a.config)
    cfg = config_from_dict(conf.get("labeling", {}))
    gate_cfg = GateConfig(**conf.get("quality_gate", {}))
    cfg.validate()
    offset_info = {"configured_utc_offset_hours": cfg.utc_offset_hours, "evidence_report": None,
                   "evidence_best_offset_hours": None, "agrees": None, "disagreement_accepted": False}
    if a.offset_report:
        ev = json.loads(require_file(a.offset_report, "offset report").read_text(encoding="utf-8"))
        best = ev.get("evidence_best_offset_hours")
        offset_info.update(evidence_report=str(a.offset_report), evidence_best_offset_hours=best,
                           evidence_flags=ev.get("flags", []),
                           agrees=(best is not None and float(best) == float(cfg.utc_offset_hours)))
        if not offset_info["agrees"]:
            if not a.accept_offset_disagreement:
                raise InputError(f"configured utc_offset_hours={cfg.utc_offset_hours} disagrees with the evidence "
                                 f"({best}) in {a.offset_report}. Fix the config, or pass --accept-offset-disagreement "
                                 "with a documented justification.")
            offset_info["disagreement_accepted"] = True
            log.warning("offset disagreement accepted explicitly: configured %s vs evidence %s", cfg.utc_offset_hours, best)
    else:
        log.warning("no --offset-report given: the configured utc_offset_hours=%s is not checked against evidence",
                    cfg.utc_offset_hours)
    stem = a.output.with_suffix("")
    sidecars = [Path(str(stem) + s) for s in (".label_stats.json", ".invalid_csv_rows.csv", ".problem_flows.csv",
                                              ".quality_gate.json")]
    guard_outputs([a.output, *sidecars], a.overwrite)

    labels, invalid, per_file = load_label_files(files, cfg)
    csv_stats = {"total_csv_records": int(sum(v["rows"] for v in per_file.values())),
                 "valid_csv_records": int(len(labels)), "invalid_csv_records": int(len(invalid)),
                 "invalid_by_reason": {str(k): int(v) for k, v in invalid["reason"].value_counts().items()},
                 "files": per_file, "label_rows_by_class": {str(k): int(v) for k, v in labels["csv_label"].value_counts().items()},
                 "config": {k: (list(v) if isinstance(v, tuple) else v) for k, v in cfg.__dict__.items()}}
    flows = read_flows(a.flows)
    labelled = label_flows(flows, labels, cfg)
    if a.output.suffix.lower() == ".parquet":
        labelled.to_parquet(a.output, index=False)
    else:
        labelled.to_csv(a.output, index=False)
    write_json(csv_stats, sidecars[0])
    invalid.to_csv(sidecars[1], index=False)
    problem = labelled[~labelled["trusted"]]
    problem.drop(columns=[c for c in problem.columns if c.startswith("pkt_")]).to_csv(sidecars[2], index=False)

    report = evaluate(labelled, csv_stats, gate_cfg)
    report["time_offset"] = offset_info
    report["inputs"] = {"labelled": file_fingerprint(a.output), "flows": file_fingerprint(a.flows),
                        "label_files": [str(f) for f in files]}
    paths = write_reports(report, labelled, stem)
    log.info("status counts: %s", report["totals"])
    for line in format_failures(report):
        (log.error if "[integrity]" in line else log.warning)(line)
    if not report["passed"]:
        log.error("label-matching INTEGRITY FAILED; reports kept at %s. Do not train on this data.", paths["json"])
        return EXIT_GATE_FAILED
    log.info("label-matching integrity PASSED (%s); training_eligible=%s%s", paths["json"], report["training_eligible"],
             "" if report["training_eligible"] else " (class coverage not met: this table alone must not be used "
             "for binary training; combine captures with scripts.combine_labelled)")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli(main))
