r"""Cross-check time-offset evidence from several capture days (independent validation of the offset).

    python -m scripts.summarize_offsets --evidence monday=runs/smoke/monday/offset_evidence.json `
        --evidence tuesday=runs/smoke/tuesday/offset_evidence.json --configured 0.0 --output offsets.json

Each day's evidence was computed independently (its own PCAP and label files). The configured offset is
supported only if EVERY day's best candidate equals it and no day carries flags.
Exit 0 consistent, 4 inconsistent/flagged (review required), 2 invalid input.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.utils.cli import EXIT_GATE_FAILED, InputError, guard_outputs, require_file, run_cli
from src.utils.common import setup_logging, write_json


def summarize(evidence: dict, configured) -> dict:
    rows, problems = [], []
    for day, ev in evidence.items():
        best = ev.get("evidence_best_offset_hours")
        rank = ev.get("ranking") or []
        support = rank[0]["support"] if rank else None
        runner = rank[1] if len(rank) > 1 else None
        rows.append({"day": day, "best_offset_hours": best, "support": support,
                     "runner_up_offset_hours": runner["offset_hours"] if runner else None,
                     "runner_up_support": runner["support"] if runner else None,
                     "flags": ev.get("flags", []), "flows_considered": ev.get("flows_considered")})
        if best is None:
            problems.append(f"{day}: no evidence (no endpoint matches)")
        elif configured is not None and float(best) != float(configured):
            problems.append(f"{day}: best offset {best} != configured {configured}")
        if ev.get("flags"):
            problems.append(f"{day}: flags {ev['flags']}")
    bests = {r["best_offset_hours"] for r in rows if r["best_offset_hours"] is not None}
    if len(bests) > 1:
        problems.append(f"days disagree on the best offset: {sorted(bests)}")
    return {"configured_utc_offset_hours": configured, "days": rows, "consistent": not problems,
            "problems": problems,
            "note": "Agreement across independently processed days supports, but does not prove, the offset."}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--evidence", action="append", required=True, help="DAY=PATH to offset_evidence.json (repeat)")
    ap.add_argument("--configured", type=float, default=None)
    ap.add_argument("--output", type=Path, default=None)
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args(argv)
    setup_logging()
    ev = {}
    for spec in a.evidence:
        if "=" not in spec:
            raise InputError(f"--evidence must be DAY=PATH, got {spec!r}")
        day, path = spec.split("=", 1)
        ev[day] = json.loads(require_file(Path(path), f"evidence for {day}").read_text(encoding="utf-8"))
    rep = summarize(ev, a.configured)
    if a.output:
        guard_outputs([a.output], a.overwrite)
        write_json(rep, a.output)
    for r in rep["days"]:
        print(f"{r['day']:10s} best={r['best_offset_hours']} support={r['support']} "
              f"runner_up={r['runner_up_offset_hours']}({r['runner_up_support']}) flags={len(r['flags'])}")
    for p in rep["problems"]:
        print("PROBLEM:", p)
    return 0 if rep["consistent"] else EXIT_GATE_FAILED


if __name__ == "__main__":
    raise SystemExit(run_cli(main))
