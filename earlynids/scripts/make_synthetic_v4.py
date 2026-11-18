"""Write the v4 synthetic engineering fixture PCAP (no attack traffic, no labels)."""
from __future__ import annotations

import argparse
from pathlib import Path

from src.preprocessing.synthetic import write_all


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, default=Path("data/raw/synthetic_v4.pcap"))
    a = ap.parse_args(argv)
    print(f"wrote {write_all(a.output)} frames to {a.output}")
    return 0


if __name__ == "__main__":
    from src.utils.cli import run_cli
    raise SystemExit(run_cli(main))
