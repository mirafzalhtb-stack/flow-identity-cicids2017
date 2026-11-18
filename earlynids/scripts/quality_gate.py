r"""Re-evaluate the dataset quality gate on an existing labelled table (e.g. after revising thresholds).

    python -m scripts.quality_gate --labelled data\processed\monday_labelled.parquet --config configs\preprocessing.yaml

Exit codes: 0 passed, 4 failed, 2 invalid input.
"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from src.datasets.quality_gate import GateConfig, evaluate, format_failures, write_reports
from src.preprocessing.io import read_flows
from src.utils.cli import EXIT_GATE_FAILED, InputError, require_file, run_cli
from src.utils.common import file_fingerprint, load_yaml, setup_logging

log = logging.getLogger("quality_gate")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--labelled", required=True, type=Path)
    ap.add_argument("--label-stats", type=Path, default=None, help="default: <labelled>.label_stats.json")
    ap.add_argument("--config", type=Path, required=True)
    ap.add_argument("--report-prefix", type=Path, default=None, help="default: <labelled without suffix>.regate")
    ap.add_argument("--scope", choices=["capture", "dataset"], default="capture")
    a = ap.parse_args(argv)
    setup_logging()
    require_file(a.labelled, "labelled table")
    stats_path = a.label_stats or Path(str(a.labelled.with_suffix("")) + ".label_stats.json")
    require_file(stats_path, "label stats JSON (written by scripts.match_labels)")
    df = read_flows(a.labelled)
    if "match_status" not in df.columns:
        raise InputError("input has no match_status column; run scripts.match_labels first")
    report = evaluate(df, json.loads(stats_path.read_text(encoding="utf-8")),
                      GateConfig(**load_yaml(require_file(a.config, "config")).get("quality_gate", {})), scope=a.scope)
    report["inputs"] = {"labelled": file_fingerprint(a.labelled)}
    prefix = a.report_prefix or Path(str(a.labelled.with_suffix("")) + ".regate")
    paths = write_reports(report, df, prefix)
    for line in format_failures(report):
        log.warning(line)
    if not report["passed"]:
        log.error("integrity FAILED (%s)", paths["json"])
        return EXIT_GATE_FAILED
    log.info("integrity PASSED; training_eligible=%s (%s)", report["training_eligible"], paths["json"])
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli(main))
