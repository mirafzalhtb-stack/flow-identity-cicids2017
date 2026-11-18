"""v4.1 split strategies, guarantees and manifest immutability."""
import json

import pandas as pd
import pytest

from src.datasets.splits import (PARTITIONS, InfeasibleSplitError, SplitConfig, assign_partitions,
                                 build_manifest, check_prefix_assignment, write_manifest)


def frame(n=400, star=False):
    rows = []
    for i in range(n):
        rows.append({"flow_uid": f"c-{i:05d}", "capture_id": "thu" if i < n // 2 else "fri",
                     "start_time": float(i * 10), "end_time": float(i * 10 + 3),
                     "src_ip": f"10.0.{i % 40}.1",
                     "dst_ip": "192.168.10.50" if star else f"10.9.{i % 40}.9",
                     "binary_label": "ATTACK" if i % 3 == 0 else "BENIGN"})
    return pd.DataFrame(rows)


def test_group_strategy_name_rejected_with_guidance():
    with pytest.raises(ValueError, match="renamed"):
        SplitConfig(strategy="group").validate()


def test_initiator_split_is_not_reported_host_disjoint():
    df = frame(star=True)
    cfg = SplitConfig(strategy="initiator")
    part = assign_partitions(df, cfg)
    man = build_manifest(df, part, cfg)
    assert man["guarantees"]["initiator_disjoint"] and not man["guarantees"]["host_disjoint"]
    assert all(v == 0 for v in man["leakage"]["initiator_overlap"].values())
    assert man["leakage"]["any_endpoint_overlap"]["train-test"] >= 1  # shared server is visible


def test_host_components_strictly_disjoint():
    df = frame()  # each src 10.0.k.1 talks only to 10.9.k.9 -> 40 components
    cfg = SplitConfig(strategy="host_components")
    part = assign_partitions(df, cfg)
    man = build_manifest(df, part, cfg)
    assert man["guarantees"]["host_disjoint"]
    assert all(v == 0 for v in man["leakage"]["any_endpoint_overlap"].values())
    assert not any("BUG" in w for w in man["warnings"])
    assert (part != "excluded").all()


def test_host_components_infeasible_with_shared_server():
    with pytest.raises(InfeasibleSplitError):
        assign_partitions(frame(star=True), SplitConfig(strategy="host_components"))


def test_host_components_with_excluded_shared_server():
    df = frame(star=True)
    cfg = SplitConfig(strategy="host_components", exclude_hosts=["192.168.10.50"])
    part = assign_partitions(df, cfg)
    man = build_manifest(df, part, cfg)
    assert man["guarantees"]["host_disjoint_exceptions"] == ["192.168.10.50"]
    eps = {p: (set(df.loc[part == p, "src_ip"]) | set(df.loc[part == p, "dst_ip"])) - {"192.168.10.50"} for p in PARTITIONS}
    assert not (eps["train"] & eps["test"])


def test_hybrid_whole_capture_and_time_windows():
    df = frame()
    plan = {"thu": "train", "fri": [{"until_fraction": 0.5, "partition": "calib"}, {"partition": "test"}]}
    cfg = SplitConfig(strategy="hybrid", hybrid_plan=plan, embargo_s=15.0)
    part = assign_partitions(df, cfg)
    assert set(part[df.capture_id == "thu"]) == {"train"}
    fri = df.capture_id == "fri"
    cal, tst = df[fri & (part == "calib")], df[fri & (part == "test")]
    assert len(cal) and len(tst)
    assert cal.end_time.max() < tst.start_time.min()  # explicit temporal boundary
    assert (part[fri] == "excluded").sum() >= 1       # embargo at the internal boundary
    man = build_manifest(df, part, cfg)
    assert man["leakage"]["time_overlap_within_capture"]["calib-test"] == 0
    assert man["leakage"]["capture_overlap"]["calib-test"] == ["fri"]


def test_hybrid_absolute_boundary():
    df = frame()
    plan = {"fri": [{"until_utc": 3000.0, "partition": "val"}, {"partition": "test"}]}
    part = assign_partitions(df, SplitConfig(strategy="hybrid", hybrid_plan=plan, embargo_s=0))
    assert df.loc[part == "val", "start_time"].max() < 3000.0 <= df.loc[part == "test", "start_time"].min()
    assert set(part[df.capture_id == "thu"]) == {"excluded"}  # captures not in the plan are excluded


@pytest.mark.parametrize("plan", [
    {"fri": [{"partition": "test"}, {"partition": "val"}]},                                  # open window not last
    {"fri": [{"until_fraction": 0.7, "partition": "val"}, {"until_fraction": 0.3, "partition": "calib"}, {"partition": "test"}]},
    {"fri": [{"until_fraction": 0.5, "partition": "nope"}, {"partition": "test"}]},
    {"fri": [{"until_fraction": 0.5, "until_utc": 1.0, "partition": "val"}, {"partition": "test"}]},
])
def test_hybrid_plan_validation(plan):
    with pytest.raises(ValueError):
        SplitConfig(strategy="hybrid", hybrid_plan=plan).validate()


def test_chronological_crossing_flow_excluded_even_without_embargo():
    df = frame()
    df.loc[239, "end_time"] = 5000.0
    part = assign_partitions(df, SplitConfig(embargo_s=0.0))
    assert part[239] == "excluded"


def test_manifest_immutable_and_hashed(tmp_path):
    df = frame()
    cfg = SplitConfig()
    part = assign_partitions(df, cfg)
    man = build_manifest(df, part, cfg)
    out = tmp_path / "split_v1"
    write_manifest(df, part, man, out)
    saved = json.loads((out / "split_manifest.json").read_text())
    assert saved["seed"] == 42 and saved["config"]["strategy"] == "chronological" and len(saved["assignment_sha256"]) == 64
    with pytest.raises(FileExistsError):
        write_manifest(df, part, man, out)
    write_manifest(df, part, man, out, overwrite=True)  # explicit overwrite allowed


def test_prefix_assignment_check():
    assign = pd.DataFrame({"flow_uid": ["a", "b"], "partition": ["train", "test"]})
    prefixes = pd.Series(["a", "a", "a", "b", "b"])  # several prefixes per flow
    assert check_prefix_assignment(prefixes, assign)["ok"]
    bad = pd.concat([assign, pd.DataFrame({"flow_uid": ["a"], "partition": ["test"]})])
    rep = check_prefix_assignment(prefixes, bad)
    assert not rep["ok"] and rep["flows_in_multiple_partitions"] == 1
    assert not check_prefix_assignment(pd.Series(["zzz"]), assign)["ok"]
