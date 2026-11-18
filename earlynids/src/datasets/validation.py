"""Validation of extracted / labelled flow tables before they enter experiments."""
from __future__ import annotations

from typing import List

REQUIRED = ("flow_uid", "capture_id", "protocol", "src_ip", "src_port", "dst_ip", "dst_port",
            "start_time", "end_time", "observed_packets", "packet_count", "start_reason",
            "end_reason", "valid_early_prefix", "pkt_iat", "pkt_direction", "pkt_ip_len")


def validate_flows(df, max_packets: int) -> dict:
    errors: List[str] = []
    warnings: List[str] = []
    missing = [c for c in REQUIRED if c not in df.columns]
    if missing:
        return {"ok": False, "errors": [f"missing columns: {missing}"], "warnings": []}
    if df["flow_uid"].duplicated().any():
        errors.append(f"{int(df['flow_uid'].duplicated().sum())} duplicated flow_uid values")
    lens = df["pkt_direction"].map(len)
    if (lens != df["packet_count"]).any():
        errors.append("packet_count does not equal stored prefix length")
    if (df["packet_count"] > max_packets).any():
        errors.append("prefix longer than max_packets")
    if (df["packet_count"] > df["observed_packets"]).any():
        errors.append("prefix longer than observed packets")
    if (df["end_time"] < df["start_time"]).any():
        errors.append("end_time < start_time")
    for col in ("pkt_iat", "pkt_ip_len"):
        bad = df[col].map(lambda xs: any((x is None) or (x != x) or x < 0 for x in xs))
        if bad.any():
            errors.append(f"{int(bad.sum())} flows contain negative/NaN values in {col}")
    if (df["packet_count"] == 0).any():
        errors.append("empty prefixes present")
    dir_bad = df["pkt_direction"].map(lambda xs: len(xs) > 0 and xs[0] != 1)
    if dir_bad.any():
        # Only possible for SYN-ACK-first flows, where the first packet is a response.
        warnings.append(f"{int(dir_bad.sum())} flows whose first stored packet is from the responder")
    n_invalid = int((~df["valid_early_prefix"].astype(bool)).sum())
    if n_invalid:
        warnings.append(f"{n_invalid} flows are not valid early-detection samples (midstream/continuation)")
    if "match_status" in df.columns:
        trusted = df["trusted"].astype(bool)
        if (trusted & df["binary_label"].isna()).any():
            errors.append("trusted flows without binary_label")
        if (trusted & (df["match_status"] != "unique")).any():
            errors.append("trusted flows whose match_status is not 'unique'")
        if (trusted & ~df["valid_early_prefix"].astype(bool)).any():
            errors.append("trusted flows that are not valid early prefixes")
        if (df["binary_label"].notna() & (df["match_status"] != "unique")).any():
            errors.append("binary_label assigned to a non-unique match")
    return {"ok": not errors, "errors": errors, "warnings": warnings, "n_flows": int(len(df))}
