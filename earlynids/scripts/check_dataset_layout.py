r"""Check the CIC-IDS2017 dataset layout: presence, counts, sizes, Parquet metadata, day mapping.

    python -m scripts.check_dataset_layout --root /content/drive/MyDrive/EarlyNIDS/datasets/CIC-IDS2017 --output layout.json

This is a presence/size check, not an integrity verification. Exit 0 ok, 4 problems found, 2 invalid input.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.utils.cli import EXIT_GATE_FAILED, InputError, guard_outputs, run_cli
from src.utils.common import setup_logging, write_json
from src.utils.paths import inspect_layout, normalize_root


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", required=True)
    ap.add_argument("--output", type=Path, default=None)
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args(argv)
    setup_logging()
    root = normalize_root(a.root)
    if not root.is_dir():
        raise InputError(f"dataset root not found: {root}. In Colab, mount Drive first (drive.mount('/content/drive')).")
    rep = inspect_layout(root)
    if a.output:
        guard_outputs([a.output], a.overwrite)
        write_json(rep, a.output)
    print(json.dumps({k: rep[k] for k in ("root", "ok", "problems")}, indent=2))
    for sub, e in rep["subdirs"].items():
        print(f"{sub}: {e['n_files']} files ({e['expected']} expected), {e['total_gib']} GiB")
    return 0 if rep["ok"] else EXIT_GATE_FAILED


if __name__ == "__main__":
    raise SystemExit(run_cli(main))
