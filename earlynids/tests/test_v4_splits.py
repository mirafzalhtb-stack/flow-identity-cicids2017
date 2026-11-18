"""Leakage-aware split tests."""
import pandas as pd
import pytest

from src.datasets.splits import PARTITIONS, SplitConfig, assign_partitions, build_manifest
from src.datasets.validation import validate_flows


def frame(n=400):
    rows = []
    for i in range(n):
        rows.append({"flow_uid": f"c-{i:05d}", "capture_id": "day1" if i < n // 2 else "day2",
                     "start_time": float(i * 10), "end_time": float(i * 10 + 3),
                     "src_ip": f"10.0.{i % 37}.1", "dst_ip": "10.9.9.9",
                     "binary_label": "ATTACK" if i % 3 == 0 else "BENIGN"})
    return pd.DataFrame(rows)


def test_chronological_order_and_embargo():
    df = frame()
    part = assign_partitions(df, SplitConfig(embargo_s=25.0))
    used = {p: df[part == p] for p in PARTITIONS}
    for a, b in zip(PARTITIONS, PARTITIONS[1:]):
        assert used[a]["end_time"].max() < used[b]["start_time"].min()
    assert (part == "excluded").sum() > 0  # embargo removed boundary flows
    man = build_manifest(df, part, SplitConfig())
    assert man["leakage"]["chronological_order_ok"]
    assert all(v == 0 for v in man["leakage"]["flow_overlap"].values())


def test_flow_crossing_boundary_is_excluded():
    df = frame()
    df.loc[239, "end_time"] = 5000.0  # long flow crossing the train/val boundary
    part = assign_partitions(df, SplitConfig(embargo_s=1.0))
    assert part[239] == "excluded"


def test_initiator_split_initiator_disjoint_and_deterministic():
    df = frame()
    cfg = SplitConfig(strategy="initiator", seed=7)
    p1, p2 = assign_partitions(df, cfg), assign_partitions(df, cfg)
    assert (p1 == p2).all()
    hosts = {p: set(df.loc[p1 == p, "src_ip"]) for p in PARTITIONS}
    for i, a in enumerate(PARTITIONS):
        for b in PARTITIONS[i + 1:]:
            assert not (hosts[a] & hosts[b])


def test_capture_split():
    df = frame()
    cfg = SplitConfig(strategy="capture", capture_assignment={"day1": "train", "day2": "test"})
    part = assign_partitions(df, cfg)
    assert set(part[df.capture_id == "day1"]) == {"train"}
    assert set(part[df.capture_id == "day2"]) == {"test"}
    man = build_manifest(df, part, cfg)
    assert "partition val is empty" in man["warnings"] and "partition calib is empty" in man["warnings"]


def test_duplicate_flow_uid_rejected():
    df = frame()
    df.loc[1, "flow_uid"] = df.loc[0, "flow_uid"]
    with pytest.raises(ValueError):
        assign_partitions(df, SplitConfig())


def test_bad_fractions_rejected():
    with pytest.raises(ValueError):
        SplitConfig(fractions={"train": 0.5, "val": 0.1, "calib": 0.1, "test": 0.1}).validate()


def test_validation_catches_errors():
    df = pd.DataFrame([{"flow_uid": "a", "capture_id": "c", "protocol": 6, "src_ip": "1", "src_port": 1,
                        "dst_ip": "2", "dst_port": 2, "start_time": 1.0, "end_time": 0.5,
                        "observed_packets": 1, "packet_count": 2, "start_reason": "syn",
                        "end_reason": "eof", "valid_early_prefix": True,
                        "pkt_iat": [0.0, -1.0], "pkt_direction": [1, -1], "pkt_ip_len": [40, 40]}])
    rep = validate_flows(df, max_packets=20)
    assert not rep["ok"] and len(rep["errors"]) >= 3
