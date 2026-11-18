r"""Combine per-capture labelled tables into one dataset table and run the DATASET-scope gate.

    python -m scripts.combine_labelled --input runs\full\monday\labelled.parquet --input runs\full\tuesday\labelled.parquet `
        --config run_config.yaml --output runs\dataset\all_labelled.parquet

Each input's sidecar ``<input>.label_stats.json`` (written by match_labels) is required so that label-file
statistics are aggregated, not lost. Files are appended one at a time (bounded memory). Nothing is dropped.
Training eligibility (both classes, every capture's integrity) is decided here, on the combined table.
Exit codes: 0 integrity passed (see training_eligible), 4 integrity failed, 2 invalid input, 5 outputs exist.
"""
from __future__ import annotations

import argparse
import json
import logging
from collections import Counter
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from src.datasets.quality_gate import GateConfig, evaluate, format_failures, write_reports
from src.preprocessing.io import LIST_COLUMNS
from src.utils.cli import EXIT_GATE_FAILED, InputError, guard_outputs, require_file, run_cli
from src.utils.common import file_fingerprint, load_yaml, setup_logging, write_json

log = logging.getLogger("combine_labelled")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", action="append", required=True, type=Path, help="labelled .parquet (repeat)")
    ap.add_argument("--config", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args(argv)
    setup_logging()
    if a.output.suffix.lower() != ".parquet":
        raise InputError("--output must be a .parquet file")
    stats_files = []
    for p in a.input:
        require_file(p, "labelled table")
        if p.suffix.lower() != ".parquet":
            raise InputError(f"{p}: only .parquet labelled tables can be combined")
        stats_files.append(require_file(p.with_name(p.stem + ".label_stats.json"), "label stats sidecar"))
    stem = a.output.with_suffix("")
    stats_out = Path(str(stem) + ".label_stats.json")
    guard_outputs([a.output, stats_out, Path(str(stem) + ".quality_gate.json")], a.overwrite)
    gate_cfg = GateConfig(**load_yaml(require_file(a.config, "config")).get("quality_gate", {}))

    schemas = [pq.read_schema(p) for p in a.input]
    schema = pa.unify_schemas(schemas, promote_options="permissive")
    seen_caps = Counter()
    tmp = a.output.with_name(a.output.name + ".partial")
    writer = pq.ParquetWriter(tmp, schema)
    try:
        for p in a.input:
            t = pq.read_table(p)
            for name in schema.names:
                if name not in t.column_names:
                    t = t.append_column(name, pa.nulls(t.num_rows, schema.field(name).type))
            t = t.select(schema.names).cast(schema)
            for c in set(t.column("capture_id").to_pylist()):
                seen_caps[c] += 1
            writer.write_table(t)
    finally:
        writer.close()
    dup_caps = [c for c, k in seen_caps.items() if k > 1]
    if dup_caps:
        tmp.unlink()
        raise InputError(f"capture ids appear in more than one input: {dup_caps} (same day combined twice?)")
    tmp.replace(a.output)

    agg = {"total_csv_records": 0, "valid_csv_records": 0, "invalid_csv_records": 0, "invalid_by_reason": Counter(),
           "files": {}, "label_rows_by_class": Counter(), "inputs": [str(p) for p in a.input]}
    for sf in stats_files:
        st = json.loads(sf.read_text(encoding="utf-8"))
        for k in ("total_csv_records", "valid_csv_records", "invalid_csv_records"):
            agg[k] += int(st.get(k, 0))
        agg["invalid_by_reason"].update(st.get("invalid_by_reason", {}))
        agg["label_rows_by_class"].update(st.get("label_rows_by_class", {}))
        agg["files"].update(st.get("files", {}))
    agg["invalid_by_reason"] = dict(agg["invalid_by_reason"])
    agg["label_rows_by_class"] = dict(agg["label_rows_by_class"])
    write_json(agg, stats_out)

    cols = [c for c in schema.names if c not in LIST_COLUMNS]
    df = pq.read_table(a.output, columns=cols).to_pandas()
    report = evaluate(df, agg, gate_cfg, scope="dataset")
    report["inputs"] = {"labelled": file_fingerprint(a.output), "parts": [str(p) for p in a.input]}
    paths = write_reports(report, df, stem)
    for line in format_failures(report):
        (log.error if "[integrity]" in line else log.warning)(line)
    log.info("combined %d captures, %d flows; integrity=%s training_eligible=%s (%s)", len(seen_caps), len(df),
             report["passed"], report["training_eligible"], paths["json"])
    return 0 if report["passed"] else EXIT_GATE_FAILED


if __name__ == "__main__":
    raise SystemExit(run_cli(main))
