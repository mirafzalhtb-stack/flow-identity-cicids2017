"""v4.2: lineage/discrepancy audit and time-offset evidence."""
import json

import numpy as np
import pandas as pd
import pytest

from scripts import audit_label_lineage
from src.labeling.cicids2017 import LabelConfig, label_frame_from_records, offset_evidence
from src.labeling.lineage import audit_directories, compare_pair, pair_key, render_markdown


def tl_ml_pair(n=300, n_null=200, seed=0):
    rng = np.random.default_rng(seed)
    feats = pd.DataFrame({" Flow Duration": rng.integers(0, 10**6, n), " Total Fwd Packets": rng.integers(1, 50, n),
                          "Flow Bytes/s": rng.random(n) * 1e3,
                          " Label": rng.choice(["BENIGN", "Web Attack \x96 Brute Force"], n, p=[.9, .1])})
    ids = pd.DataFrame({"Flow ID": [f"id{i}" for i in range(n)], " Source IP": "192.168.10.5",
                        " Timestamp": "6/7/2017 9:00"})
    tl = pd.concat([ids, feats], axis=1)
    blank = pd.DataFrame({c: [None] * n_null for c in tl.columns})
    tl = pd.concat([tl, blank], ignore_index=True)  # e.g. trailing empty rows
    ml = feats.copy()
    ml[" Total Fwd Packets"] = ml[" Total Fwd Packets"].astype(float)  # dtype drift, same values
    return tl, ml


def test_pair_key_matches_csv_and_parquet_names():
    assert pair_key("Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv.parquet") == \
        pair_key("Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv")


def test_thursday_style_row_count_discrepancy_detected():
    tl, ml = tl_ml_pair()
    rep = compare_pair(tl, ml, "thursday-webattacks")
    types = {d["type"] for d in rep["discrepancies"]}
    assert rep["rows_a"] == 500 and rep["rows_b"] == 300 and rep["row_difference_a_minus_b"] == 200
    assert {"row_count_mismatch", "all_null_rows"} <= types
    assert rep["nulls"]["rows_all_common_null_a"] == 200
    assert any("row counts of A and B are equal" in e for e in rep["evidence"])
    assert rep["containment"]["fraction_b_rows_found_in_a"] == 1.0
    assert set(rep["schema"]["only_a"]) == {"flow id", "source ip", "timestamp"}
    assert "rows_not_contained" not in types and "label_distribution_difference" not in types
    assert "total fwd packets" in rep["schema"]["dtype_mismatches"]


def test_filtered_rows_and_label_difference_detected():
    tl, ml = tl_ml_pair(n_null=0)
    ml = ml[ml[" Label"] == "BENIGN"].reset_index(drop=True)  # B lost all attack rows
    rep = compare_pair(tl, ml)
    types = {d["type"] for d in rep["discrepancies"]}
    assert "label_distribution_difference" in types
    attack = rep["labels"]["Web Attack - Brute Force"]
    assert attack["b"] == 0 and attack["a_minus_b"] > 0
    assert rep["containment"]["fraction_b_rows_found_in_a"] == 1.0
    assert rep["containment"]["fraction_a_rows_found_in_b"] < 1.0


def test_modified_values_not_contained_and_feature_shift():
    tl, ml = tl_ml_pair(n_null=0)
    ml["Flow Bytes/s"] = ml["Flow Bytes/s"] * 1.5
    rep = compare_pair(tl, ml)
    types = {d["type"] for d in rep["discrepancies"]}
    assert "rows_not_contained" in types and "feature_distribution_shift" in types


def test_duplicates_and_infinite_values_reported():
    tl, ml = tl_ml_pair(n_null=0)
    ml = pd.concat([ml, ml.head(5)], ignore_index=True)
    ml.loc[0, "Flow Bytes/s"] = np.inf
    rep = compare_pair(tl, ml)
    assert rep["duplicates"]["duplicate_rows_common_cols_b"] >= 4
    assert rep["invalid_values"]["infinite_values_b"] == 1


def test_lineage_cli_on_directories(tmp_path):
    a, b = tmp_path / "traffic_labels", tmp_path / "machine_learning"
    a.mkdir(); b.mkdir()
    tl, ml = tl_ml_pair()
    tl.to_parquet(a / "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv.parquet", index=False)
    ml.to_parquet(b / "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv.parquet", index=False)
    tl.iloc[:300].to_parquet(a / "Monday-WorkingHours.pcap_ISCX.csv.parquet", index=False)  # no counterpart in B
    out = tmp_path / "lineage"
    assert audit_label_lineage.main(["--dir-a", str(a), "--dir-b", str(b), "--out-dir", str(out)]) == 0
    audit = json.loads((out / "lineage_audit.json").read_text())
    assert any("no counterpart" in w for w in audit["warnings"])
    md = (out / "lineage_audit.md").read_text()
    assert "causes are not inferred" in md and "thursday" in md
    from src.utils.cli import run_cli
    assert run_cli(audit_label_lineage.main, ["--dir-a", str(a), "--dir-b", str(b), "--out-dir", str(out)]) == 5


# ---------------------------------------------------------------- offset evidence
def _labels_and_flows(local_offset=-3.0, n=40, ambiguous_pm=False):
    """Flows at UTC times; label rows written in local time (UTC + local_offset)."""
    cfg0 = LabelConfig(utc_offset_hours=0.0)
    t0 = 1499086800.0  # 13:00 UTC
    recs, flows = [], []
    for i in range(n):
        t = t0 + i * 600
        local = pd.Timestamp(t + local_offset * 3600, unit="s")
        fmt = "%d/%m/%Y %I:%M:%S" if ambiguous_pm else "%d/%m/%Y %H:%M:%S"  # 12-hour clock without AM/PM
        recs.append({"source ip": f"10.0.{i}.1", "source port": "40000", "destination ip": "10.9.9.9",
                     "destination port": "80", "protocol": "6", "timestamp": local.strftime(fmt),
                     "flow duration": "1000000", "label": "BENIGN"})
        flows.append({"flow_uid": f"f{i}", "protocol": 6, "src_ip": f"10.0.{i}.1", "src_port": 40000,
                      "dst_ip": "10.9.9.9", "dst_port": 80, "start_time": t, "end_time": t + 1})
    labels, _ = label_frame_from_records(recs, cfg0)
    _labels_and_flows.last_records = recs
    return pd.DataFrame(flows), labels, cfg0


def test_offset_evidence_identifies_offset_without_applying_it():
    flows, labels, cfg0 = _labels_and_flows(-3.0)
    ev = offset_evidence(flows, labels, cfg0)
    assert ev["evidence_best_offset_hours"] == -3.0
    assert ev["ranking"][0]["support"] == 1.0
    assert not ev["flags"]
    assert "No offset is applied automatically" in ev["note"]
    assert ev["label_timestamp_kinds"] == ["string"]


def test_offset_evidence_flags_12h_ambiguity():
    # local times 10:00..16:30 written on a 12-hour clock without AM/PM -> afternoon rows look like morning
    flows, labels, cfg0 = _labels_and_flows(-3.0, ambiguous_pm=True)
    ev = offset_evidence(flows, labels, cfg0)
    assert ev["evidence_best_offset_hours"] == -3.0
    assert any(f.startswith("possible_12h_ambiguity: offset -15.0 h") for f in ev["flags"])
    # After the researcher explicitly sets offset -3 and ambiguous_12h, the matcher resolves all rows.
    from src.labeling.cicids2017 import label_flows
    cfg = LabelConfig(utc_offset_hours=-3.0, ambiguous_12h=True)
    labels2, _ = label_frame_from_records(_labels_and_flows.last_records, cfg)
    res = label_flows(flows.assign(valid_early_prefix=True), labels2, cfg)
    assert (res.match_status == "unique").all()


def test_offset_evidence_no_matches_flag():
    flows, labels, cfg0 = _labels_and_flows(-3.0)
    flows["src_ip"] = "172.16.0.1"
    ev = offset_evidence(flows, labels, cfg0)
    assert ev["evidence_best_offset_hours"] is None and ev["flags"][0].startswith("no_endpoint_matches")


def test_offset_evidence_no_clear_winner():
    flows, labels, cfg0 = _labels_and_flows(-3.0, n=4)
    # duplicate each label row shifted by +1 h -> two offsets equally supported
    shifted = labels.copy(); shifted["csv_start"] += 3600; shifted["row_id"] += 1000
    ev = offset_evidence(flows, pd.concat([labels, shifted], ignore_index=True), cfg0)
    assert any(f.startswith("no_clear_winner") for f in ev["flags"])
