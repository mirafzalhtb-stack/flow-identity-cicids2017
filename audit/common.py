"""Shared helpers for the paper's audit scripts.

Every script takes the same three locations:

* ``--labels``  folder with the CIC-IDS2017 ``traffic_labels`` Parquet files
                (Hugging Face mirror ``bvsam/cic-ids-2017``; timestamps already in UTC)
* ``--runs``    folder with the EarlyNIDS v4.3 outputs (see README for the layout)
* ``--out``     folder for result tables (default: ``results/``)
"""
from __future__ import annotations

import argparse
import math
import re
from pathlib import Path

import pandas as pd

LABEL_FILES = {
    "monday": "Monday-WorkingHours.pcap_ISCX.csv.parquet",
    "tuesday": "Tuesday-WorkingHours.pcap_ISCX.csv.parquet",
}
KEY = ["Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol"]


def parse_args(description: str, extra=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=description)
    p.add_argument("--labels", type=Path, required=True, help="folder with traffic_labels/*.parquet")
    p.add_argument("--runs", type=Path, required=True, help="folder with EarlyNIDS v4.3 outputs")
    p.add_argument("--out", type=Path, default=Path("results"), help="output folder")
    if extra:
        extra(p)
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    return a


def load_labels(folder: Path, day: str) -> pd.DataFrame:
    """Load one day's label table. Row position (0-based) is the CSV row id used by EarlyNIDS."""
    df = pd.read_parquet(folder / LABEL_FILES[day])
    df.columns = [c.strip() for c in df.columns]
    df = df.reset_index(drop=True)
    df["row_id"] = df.index
    df["Label"] = df["Label"].astype(str).str.strip()
    for c in ("Source IP", "Destination IP"):
        df[c] = df[c].astype(str).str.strip()
    for c in ("Source Port", "Destination Port", "Protocol"):
        df[c] = df[c].astype("int64")
    df["Timestamp"] = pd.to_datetime(df["Timestamp"])
    df["minute"] = df["Timestamp"].dt.floor("min")
    df["packets"] = df["Total Fwd Packets"] + df["Total Backward Packets"]
    return df


def row_ids(value) -> list[int]:
    """Parse EarlyNIDS 'candidate_row_ids' strings such as '241;242'."""
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return []
    return [int(float(s)) for s in re.split(r"[;,|]", str(value)) if s.strip() and s.strip() != "None"]


def minute_candidates(flows: pd.DataFrame, labels: pd.DataFrame, reverse: bool = True) -> pd.DataFrame:
    """Candidate pairs (flow_uid, row_id, direction): same five-tuple and same start minute.

    The minute rule is the [t_CSV, t_CSV + 60 s) window of the paper. Direct candidates keep the
    EarlyNIDS orientation; reverse candidates swap addresses and ports.
    """
    f = flows.copy()
    f["minute"] = pd.to_datetime(f["start_time"], unit="s").dt.floor("min")
    for c in ("src_port", "dst_port", "protocol"):
        f[c] = f[c].astype("int64")
    lab = labels[KEY + ["minute", "row_id", "Label", "packets"]]
    out = [f.merge(lab, left_on=["src_ip", "src_port", "dst_ip", "dst_port", "protocol", "minute"],
                   right_on=KEY + ["minute"])[["flow_uid", "row_id", "Label", "packets"]].assign(direction="direct")]
    if reverse:
        out.append(f.merge(lab, left_on=["dst_ip", "dst_port", "src_ip", "src_port", "protocol", "minute"],
                           right_on=KEY + ["minute"])[["flow_uid", "row_id", "Label", "packets"]].assign(direction="reverse"))
    return pd.concat(out).drop_duplicates(["flow_uid", "row_id"]).sort_values(["flow_uid", "row_id"])


def wilson(k: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    """Wilson 95% interval for k successes out of n."""
    if n == 0:
        return float("nan"), float("nan")
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return c - h, c + h


def save(df: pd.DataFrame, out: Path, name: str, index: bool = False) -> None:
    path = out / name
    df.to_csv(path, index=index)
    print(f"saved {path}")


# Default locations of EarlyNIDS v4.3 outputs inside --runs (the layout produced by
# earlynids/scripts/process_day.py and extract_flows.py in our runs).
RUN_FILES = {
    "monday_labelled": "full/monday/labelled.parquet",
    "tuesday_smoke": "smoke/tuesday/flows.parquet",
    "tuesday_ftp": "attack_window/tuesday_ftp/full/flows.parquet",
    "tuesday_ssh": "attack_window/tuesday_ssh/full/flows.parquet",
}
