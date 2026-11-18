r"""Process ONE capture day end-to-end with resume support (Colab-friendly).

    python -m scripts.process_day --root /content/drive/MyDrive/EarlyNIDS/datasets/CIC-IDS2017 `
        --day monday --out-root /content/drive/MyDrive/EarlyNIDS/runs/v4_2 --config run_config.yaml

Steps (each skipped if its completed output already exists; ``--force`` redoes them):
  1. extract flows from <root>/pcap/<Day>*.pcap           -> <out>/<day>/flows.parquet (+ .stats.json)
  2. time-offset evidence vs <root>/traffic_labels/<Day>* -> <out>/<day>/offset_evidence.json
  3. conservative label matching + quality gate           -> <out>/<day>/labelled.parquet (+ reports)
     (only if labeling.utc_offset_hours is set in the config; otherwise stops after step 2)
A status file <out>/<day>/day_status.json records every step and exit code.

Exit codes: the first non-zero step exit code (2 invalid input, 3 no packets, 4 gate failed, ...),
or 0. Step 2 never selects the offset; it only produces evidence.
"""
from __future__ import annotations

import argparse
import json
import logging
import shutil
import time
from pathlib import Path

from scripts import extract_flows, match_labels, time_offset_diagnostics
from src.utils.cli import InputError, run_cli
from src.utils.common import load_yaml, setup_logging, write_json
from src.utils.paths import day_files, normalize_root

log = logging.getLogger("process_day")


def _completed_extraction(out: Path, pcap: Path, max_frames) -> bool:
    stats = Path(str(out) + ".stats.json")
    if not (out.exists() and stats.exists()):
        return False
    st = json.loads(stats.read_text(encoding="utf-8"))
    same_input = st.get("input", {}).get("size_bytes") == pcap.stat().st_size
    same_mode = st.get("max_frames") == max_frames
    if st.get("completed") and same_input and same_mode:
        return True
    raise InputError(f"{out} exists but was produced from a different input or --max-frames setting; "
                     "use --force to redo it or choose another --out-root")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", required=True, help="dataset root with pcap/ and traffic_labels/")
    ap.add_argument("--day", required=True, choices=["monday", "tuesday", "wednesday", "thursday", "friday"])
    ap.add_argument("--out-root", required=True, type=Path)
    ap.add_argument("--config", required=True, type=Path)
    ap.add_argument("--max-frames", type=int, default=None, help="smoke test on the first N frames only")
    ap.add_argument("--local-cache", type=Path, default=None,
                    help="copy the PCAP to this local directory first (faster than reading from Drive)")
    ap.add_argument("--keep-cache", action="store_true")
    ap.add_argument("--force", action="store_true", help="redo completed steps (passes --overwrite)")
    a = ap.parse_args(argv)
    setup_logging()
    root = normalize_root(a.root)
    files = day_files(root, a.day)
    if len(files["pcap"]) != 1:
        raise InputError(f"{a.day}: expected exactly one PCAP in {root / 'pcap'}, found {[p.name for p in files['pcap']]}")
    if not files["labels"]:
        raise InputError(f"{a.day}: no label files in {root / 'traffic_labels'}")
    pcap = files["pcap"][0]
    conf = load_yaml(a.config)
    out = a.out_root / a.day
    out.mkdir(parents=True, exist_ok=True)
    status_path = out / "day_status.json"
    status = json.loads(status_path.read_text()) if status_path.exists() else {"day": a.day, "steps": {}}
    status.update(root=str(root), pcap=pcap.name, label_files=[p.name for p in files["labels"]],
                  max_frames=a.max_frames)
    ow = ["--overwrite"] if a.force else []

    def record(step, code, **extra):
        status["steps"][step] = {"exit_code": code, "time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **extra}
        write_json(status, status_path)

    # 1. extraction
    flows = out / "flows.parquet"
    if not a.force and _completed_extraction(flows, pcap, a.max_frames):
        log.info("[resume] extraction already complete: %s", flows)
        record("extract", 0, skipped=True)
    else:
        src = pcap
        if a.local_cache:
            a.local_cache.mkdir(parents=True, exist_ok=True)
            src = a.local_cache / pcap.name
            if not (src.exists() and src.stat().st_size == pcap.stat().st_size):
                log.info("copying %s to local cache %s", pcap.name, src)
                shutil.copy2(pcap, src)
        cmd = ["--pcap", str(src), "--capture-id", a.day, "--output", str(flows), "--config", str(a.config), *ow]
        if a.max_frames:
            cmd += ["--max-frames", str(a.max_frames)]
        code = run_cli(extract_flows.main, cmd)
        if a.local_cache and not a.keep_cache and src != pcap and src.exists():
            src.unlink()
        record("extract", code)
        if code:
            return code
    labels = [str(p) for p in files["labels"]]

    # 2. offset evidence
    ev = out / "offset_evidence.json"
    if ev.exists() and not a.force:
        log.info("[resume] offset evidence exists: %s", ev)
        record("offset_evidence", 0, skipped=True)
    else:
        code = run_cli(time_offset_diagnostics.main, ["--flows", str(flows), "--labels", *labels,
                                                      "--config", str(a.config), "--output", str(ev), *ow])
        record("offset_evidence", code)
        if code:
            return code

    # 3. matching + gate
    if conf.get("labeling", {}).get("utc_offset_hours") is None:
        log.warning("labeling.utc_offset_hours is not set: stopping before label matching. Review %s, set the offset "
                    "explicitly in %s, then re-run this command (completed steps are skipped).", ev, a.config)
        record("match_labels", None, skipped=True, reason="utc_offset_hours not configured")
        return 0
    labelled = out / "labelled.parquet"
    gate = out / "labelled.quality_gate.json"
    if labelled.exists() and gate.exists() and not a.force:
        log.info("[resume] labelling already done: %s", labelled)
        passed = json.loads(gate.read_text()).get("passed")
        record("match_labels", 0 if passed else 4, skipped=True)
        return 0 if passed else 4
    code = run_cli(match_labels.main, ["--flows", str(flows), "--labels", *labels, "--config", str(a.config),
                                       "--output", str(labelled), "--offset-report", str(ev), *ow])
    record("match_labels", code)
    return code


if __name__ == "__main__":
    raise SystemExit(run_cli(main))
