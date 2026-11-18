r"""Extract bidirectional flow prefixes from a PCAP file (streaming).

    python -m scripts.extract_flows --pcap data\raw\Monday-WorkingHours.pcap `
        --capture-id monday --output data\interim\monday_flows.parquet --config configs\preprocessing.yaml

Output is written to ``<output>.partial`` and renamed only after success, so an interrupted run
(e.g. a Colab disconnect) never leaves a file that looks complete. ``--max-frames`` stops early for
smoke tests; such outputs are marked ``"partial_capture": true`` in the stats.

Exit codes: 0 ok, 2 invalid input, 3 no eligible packets, 5 output exists, 6 conservation violated.
"""
from __future__ import annotations

import argparse
import itertools
import logging
import os
import time
from pathlib import Path

from src.preprocessing.flows import FlowConfig, extract_flows, iter_pcap
from src.preprocessing.io import FlowWriter
from src.utils.cli import (EXIT_CONSERVATION, EXIT_NO_ELIGIBLE_PACKETS, InputError, guard_outputs,
                           require_file, run_cli)
from src.utils.common import environment_info, file_fingerprint, load_yaml, setup_logging, write_json

log = logging.getLogger("extract_flows")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pcap", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path, help=".parquet or .csv")
    ap.add_argument("--capture-id", required=True, help="e.g. capture day; used for provenance and splits")
    ap.add_argument("--config", type=Path, default=None)
    ap.add_argument("--stats", type=Path, default=None, help="default: <output>.stats.json")
    ap.add_argument("--full-hash", action="store_true", help="hash the whole PCAP (slow for large files)")
    ap.add_argument("--max-frames", type=int, default=None, help="stop after N frames (smoke tests only)")
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args(argv)
    setup_logging()
    require_file(a.pcap, "PCAP file")
    if a.max_frames is not None and a.max_frames < 1:
        raise InputError("--max-frames must be >= 1")
    if a.config:
        require_file(a.config, "config file")
    if a.output.suffix.lower() not in (".parquet", ".csv"):
        raise InputError("--output must end with .parquet or .csv")
    stats_path = a.stats or a.output.with_suffix(a.output.suffix + ".stats.json")
    guard_outputs([a.output, stats_path], a.overwrite)
    conf = load_yaml(a.config).get("flows", {})
    cfg = FlowConfig(**conf, capture_id=a.capture_id, source_file=a.pcap.name)
    fmt = "csv" if a.output.suffix.lower() == ".csv" else "parquet"
    partial = a.output.with_name(a.output.name + ".partial")
    if partial.exists():
        log.warning("removing stale partial output from an interrupted run: %s", partial)
        partial.unlink()
    log.info("extracting %s -> %s (%s)", a.pcap, a.output, fmt)
    t0 = time.perf_counter()
    writer = FlowWriter(partial, fmt=fmt)
    frames = iter_pcap(a.pcap)
    if a.max_frames:
        frames = itertools.islice(frames, a.max_frames)
    try:
        stats = extract_flows(frames, cfg, writer)
    finally:
        writer.close()
    elapsed = time.perf_counter() - t0
    partial_capture = bool(a.max_frames) and stats["frames_seen"] >= a.max_frames
    report = {"stats": stats, "config": cfg.__dict__, "input": file_fingerprint(a.pcap, a.full_hash),
              "output": str(a.output), "elapsed_s": elapsed, "completed": True,
              "partial_capture": partial_capture, "max_frames": a.max_frames,
              "packets_per_s": stats["frames_seen"] / elapsed if elapsed else None,
              "environment": environment_info()}
    os.replace(partial, a.output)  # atomic on the same filesystem
    write_json(report, stats_path)
    if partial_capture:
        log.warning("PARTIAL capture (first %d frames): smoke-test output, not a complete day", a.max_frames)
    log.info("flows=%d valid_early=%d frames=%d in %.1fs conservation_ok=%s",
             stats["flows_emitted"], stats["valid_early_prefix_flows"], stats["frames_seen"], elapsed,
             stats["conservation_ok"])
    if stats["no_eligible_packets_warning"]:
        log.error("no eligible TCP/UDP packets in %d frames; check the link type and dissectors", stats["frames_seen"])
        return EXIT_NO_ELIGIBLE_PACKETS
    if not stats["conservation_ok"]:
        log.error("packet conservation violated; see %s", stats_path)
        return EXIT_CONSERVATION
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli(main))
