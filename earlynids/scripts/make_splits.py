r"""Create leakage-aware train/val/calib/test partitions and an immutable split manifest.

    python -m scripts.make_splits --input data\processed\all_labelled.parquet `
        --gate-report data\processed\all_labelled.quality_gate.json `
        --config configs\preprocessing.yaml --out-dir data\manifests\split_v1

Only trusted flows (unique label match + valid early prefix) are assigned.
Refuses to run unless the quality-gate report PASSED for exactly this input file.
Exit codes: 0 ok, 2 invalid input, 4 gate missing/failed or leakage detected, 5 output exists.
"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from src.datasets.splits import InfeasibleSplitError, SplitConfig, assign_partitions, build_manifest, write_manifest
from src.preprocessing.io import read_flows
from src.utils.cli import EXIT_GATE_FAILED, InputError, OutputExistsError, require_file, run_cli
from src.utils.common import file_fingerprint, load_yaml, setup_logging

log = logging.getLogger("make_splits")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", required=True, type=Path)
    ap.add_argument("--config", type=Path, required=True)
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument("--gate-report", type=Path, default=None, help="default: <input>.quality_gate.json")
    ap.add_argument("--skip-gate-check", action="store_true",
                    help="engineering smoke runs only; recorded in the manifest as gate_check_skipped=true")
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args(argv)
    setup_logging()
    require_file(a.input, "labelled table")
    cfg = SplitConfig(**load_yaml(require_file(a.config, "config file")).get("splits", {}))
    fp = file_fingerprint(a.input, full_hash=True)
    gate_path = a.gate_report or Path(str(a.input.with_suffix("")) + ".quality_gate.json")
    gate_info = {"gate_check_skipped": bool(a.skip_gate_check), "gate_report": str(gate_path),
                 # A manifest made without a passed gate is for diagnostics only and must be rejected by
                 # any supervised-training loader (Phase 2).
                 "diagnostic_only": bool(a.skip_gate_check)}
    if a.skip_gate_check:
        log.warning("--skip-gate-check: manifest will be marked diagnostic_only=true (not valid for training)")
    if not a.skip_gate_check:
        if not gate_path.exists():
            log.error("quality gate report not found: %s. Run scripts.match_labels first.", gate_path)
            return EXIT_GATE_FAILED
        gate = json.loads(gate_path.read_text(encoding="utf-8"))
        if not gate.get("passed"):
            log.error("quality gate FAILED for this dataset (%s); refusing to create training splits.", gate_path)
            return EXIT_GATE_FAILED
        if not gate.get("training_eligible"):
            log.error("dataset is not training-eligible (%s): class coverage not met or report predates v4.3. "
                      "Combine captures (scripts.combine_labelled) and re-gate.", gate_path)
            return EXIT_GATE_FAILED
        g_fp = gate.get("inputs", {}).get("labelled", {})
        fp16 = file_fingerprint(a.input)  # same scope as the gate report (first 16 MiB)
        if g_fp.get("size_bytes") != fp16["size_bytes"] or g_fp.get("sha256") != fp16["sha256"]:
            log.error("gate report was produced for a different file (size/hash mismatch); re-run the gate.")
            return EXIT_GATE_FAILED
    if a.input.suffix.lower() == ".parquet":  # metadata only: packet lists are not needed for assignment
        import pyarrow.parquet as pq
        from src.preprocessing.io import LIST_COLUMNS
        names = [c for c in pq.read_schema(a.input).names if c not in LIST_COLUMNS]
        df = pq.read_table(a.input, columns=names).to_pandas()
    else:
        df = read_flows(a.input)
    if "trusted" not in df.columns:
        raise InputError("input is not labelled by v4.1 (no 'trusted' column); run scripts.match_labels")
    n0 = len(df)
    df = df[df["trusted"].astype(bool)].reset_index(drop=True)
    try:
        part = assign_partitions(df, cfg)
    except InfeasibleSplitError as exc:
        log.error("%s", exc)
        return EXIT_GATE_FAILED
    man = build_manifest(df, part, cfg, extra={"input": fp, "n_input_flows": n0, "n_trusted_flows": len(df),
                                               **gate_info})
    try:
        write_manifest(df, part, man, a.out_dir, overwrite=a.overwrite)
    except FileExistsError as exc:
        raise OutputExistsError(str(exc)) from exc
    for w in man["warnings"]:
        log.warning(w)
    log.info("counts: %s; guarantees: %s", {k: v["flows"] for k, v in man["counts"].items()}, man["guarantees"])
    if any("overlap" in w for w in man["warnings"]):
        return EXIT_GATE_FAILED
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli(main))
