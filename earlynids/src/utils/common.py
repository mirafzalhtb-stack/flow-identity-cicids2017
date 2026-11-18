"""Shared helpers: config loading, logging, seeding, provenance."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import random
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


def load_yaml(path: Optional[Path]) -> Dict[str, Any]:
    if path is None:
        return {}
    import yaml
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def setup_logging(level: str = "INFO", log_file: Optional[Path] = None) -> None:
    handlers = [logging.StreamHandler(sys.stderr)]
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO), handlers=handlers,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s", force=True)


def set_seed(seed: int) -> None:
    random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)
    try:
        import numpy as np
        np.random.seed(seed)
    except ImportError:
        pass
    try:
        import torch
        torch.manual_seed(seed)
    except ImportError:
        pass


def file_fingerprint(path: Path, full_hash: bool = False, chunk: int = 1 << 20) -> Dict[str, Any]:
    """Size + mtime always; SHA-256 of the first 16 MiB (or whole file if full_hash)."""
    p = Path(path)
    st = p.stat()
    h = hashlib.sha256()
    read = 0
    with open(p, "rb") as fh:
        while True:
            if not full_hash and read >= 16 * chunk:
                break
            buf = fh.read(chunk)
            if not buf:
                break
            h.update(buf)
            read += len(buf)
    return {"path": str(p), "name": p.name, "size_bytes": st.st_size,
            "mtime_utc": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
            "sha256": h.hexdigest(), "sha256_scope": "full" if full_hash else "first_16MiB"}


def environment_info() -> Dict[str, Any]:
    info = {"python": sys.version.split()[0], "platform": platform.platform(),
            "time_utc": datetime.now(timezone.utc).isoformat()}
    for mod in ("numpy", "pandas", "pyarrow", "scapy", "sklearn", "torch"):
        try:
            m = __import__(mod)
            info[mod] = getattr(m, "__version__", getattr(m, "VERSION", "?"))
        except ImportError:
            info[mod] = None
    return info


def write_json(obj: Any, path: Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")
