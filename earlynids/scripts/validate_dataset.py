r"""Validate a flow table (extracted or labelled). Exit 0 ok, 4 validation failed, 2 invalid input."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.datasets.validation import validate_flows
from src.preprocessing.io import read_flows
from src.utils.cli import EXIT_GATE_FAILED, require_file, run_cli


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", required=True, type=Path)
    ap.add_argument("--max-packets", type=int, default=20)
    a = ap.parse_args(argv)
    rep = validate_flows(read_flows(require_file(a.input, "flow table")), a.max_packets)
    print(json.dumps(rep, indent=2))
    return 0 if rep["ok"] else EXIT_GATE_FAILED


if __name__ == "__main__":
    raise SystemExit(run_cli(main))
