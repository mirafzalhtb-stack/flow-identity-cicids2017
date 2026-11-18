"""Dataset layout and path handling (local, Windows and Google Colab / Drive).

The expected CIC-IDS2017 layout (from the researcher's Drive) is:

    <root>/pcap/*.pcap                (5 files, one per day)
    <root>/traffic_labels/*.parquet   (8 files, flows WITH identifiers)
    <root>/machine_learning/*.parquet (8 files, feature tables)

Day-to-file mapping uses case-insensitive day-name prefixes because the official
file names are not consistently capitalised (e.g. 'Wednesday-workingHours.pcap').
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional

DAYS = ("monday", "tuesday", "wednesday", "thursday", "friday")
LABEL_SUFFIXES = (".parquet", ".csv")
COLAB_DRIVE_DEFAULT = "/content/drive/MyDrive/EarlyNIDS/datasets/CIC-IDS2017"


def in_colab() -> bool:
    try:
        import google.colab  # noqa: F401
        return True
    except ImportError:
        return Path("/content").is_dir() and "COLAB_RELEASE_TAG" in os.environ


def normalize_root(root) -> Path:
    """Expand ~ and env vars, strip quotes/whitespace (copy-paste from Drive UI), resolve."""
    text = str(root).strip().strip('"').strip("'")
    return Path(os.path.expandvars(os.path.expanduser(text))).resolve()


def _files(d: Path, suffixes) -> List[Path]:
    if not d.is_dir():
        return []
    return sorted(p for p in d.iterdir() if p.is_file() and p.suffix.lower() in suffixes)


def day_of(name: str) -> Optional[str]:
    low = name.lower()
    return next((d for d in DAYS if low.startswith(d)), None)


def day_files(root, day: str, label_subdir: str = "traffic_labels") -> Dict[str, List[Path]]:
    root = normalize_root(root)
    day = day.lower()
    if day not in DAYS:
        raise ValueError(f"unknown day {day!r}; use one of {DAYS}")
    pcaps = [p for p in _files(root / "pcap", (".pcap", ".pcapng")) if day_of(p.name) == day]
    labels = [p for p in _files(root / label_subdir, LABEL_SUFFIXES) if day_of(p.name) == day]
    return {"pcap": pcaps, "labels": labels}


def inspect_layout(root, expected: Optional[Dict[str, int]] = None) -> dict:
    """File presence, counts and sizes. NOT an integrity verification (no reference hashes exist here)."""
    root = normalize_root(root)
    expected = expected or {"pcap": 5, "traffic_labels": 8, "machine_learning": 8}
    rep = {"root": str(root), "root_exists": root.is_dir(), "in_colab": in_colab(), "subdirs": {}, "problems": [],
           "note": "Presence/size observations only; this is not cryptographic integrity verification."}
    if not root.is_dir():
        rep["problems"].append(f"dataset root not found: {root}")
        return rep
    for sub, n_exp in expected.items():
        suffixes = (".pcap", ".pcapng") if sub == "pcap" else LABEL_SUFFIXES
        files = _files(root / sub, suffixes)
        entry = {"exists": (root / sub).is_dir(), "n_files": len(files), "expected": n_exp,
                 "total_gib": round(sum(f.stat().st_size for f in files) / 2**30, 3),
                 "files": [{"name": f.name, "bytes": f.stat().st_size, "day": day_of(f.name)} for f in files]}
        if sub != "pcap":
            for item, f in zip(entry["files"], files):
                if f.suffix.lower() == ".parquet":
                    try:
                        import pyarrow.parquet as pq
                        md = pq.ParquetFile(f).metadata
                        item.update(rows=md.num_rows, columns=md.num_columns, row_groups=md.num_row_groups)
                    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
                        item["read_error"] = str(exc)
                        rep["problems"].append(f"cannot read parquet metadata: {f.name}: {exc}")
        if not entry["exists"]:
            rep["problems"].append(f"missing directory: {root / sub}")
        elif len(files) != n_exp:
            rep["problems"].append(f"{sub}: found {len(files)} files, expected {n_exp}")
        rep["subdirs"][sub] = entry
    for d in DAYS:
        mapped = day_files(root, d)
        rep.setdefault("day_mapping", {})[d] = {"pcap": [p.name for p in mapped["pcap"]],
                                                "traffic_labels": [p.name for p in mapped["labels"]]}
        if len(mapped["pcap"]) != 1:
            rep["problems"].append(f"{d}: expected exactly 1 PCAP, found {len(mapped['pcap'])}")
        if not mapped["labels"]:
            rep["problems"].append(f"{d}: no traffic_labels file")
    rep["ok"] = not rep["problems"]
    return rep
