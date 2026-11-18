"""v4.3: integrity / coverage / eligibility split, dataset combination, transition audit, sensitivity CLI."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import pytest

from scripts import (combine_labelled, compare_matching_runs, duration_sensitivity, extract_flows, make_splits,
                     match_labels)
from src.preprocessing.io import read_flows
from src.preprocessing.synthetic import write_all
from src.utils.cli import run_cli

RELAXED = ("quality_gate:\n  min_match_rate: 0.3\n  max_unmatched_rate: 0.7\n  max_conflict_rate: 0.7\n"
           "  max_ambiguous_rate: 0.7\n  max_time_inconsistent_rate: 0.7\n  min_trusted_per_class: 1\n")


def make_day(tmp_path, day, label_fn, offset=0.0):
    d = tmp_path / day
    d.mkdir()
    pcap = d / f"{day}.pcap"; write_all(pcap)
    flows_p = d / "flows.parquet"
    assert run_cli(extract_flows.main, ["--pcap", str(pcap), "--output", str(flows_p), "--capture-id", day]) == 0
    fl = read_flows(flows_p)
    tz = timezone(timedelta(hours=offset))
    df = pd.DataFrame({" Source IP": fl.src_ip, " Source Port": fl.src_port, " Destination IP": fl.dst_ip,
                       " Destination Port": fl.dst_port, " Protocol": fl.protocol,
                       " Timestamp": [datetime.fromtimestamp(t, tz).strftime("%d/%m/%Y %H:%M:%S") for t in fl.start_time],
                       " Flow Duration": (fl.duration * 1e6).round().astype(int),
                       " Label": [label_fn(i) for i in range(len(fl))]})
    labels = d / "labels.parquet"; df.to_parquet(labels, index=False)
    return d, flows_p, labels


def cfg_file(tmp_path, extra=RELAXED):
    c = tmp_path / "cfg.yaml"
    c.write_text("labeling:\n  utc_offset_hours: 0.0\nsplits:\n  strategy: chronological\n  embargo_s: 0.0\n" + extra)
    return c


def match(d, flows_p, labels, cfg):
    out = d / "labelled.parquet"
    rc = run_cli(match_labels.main, ["--flows", str(flows_p), "--labels", str(labels), "--config", str(cfg),
                                     "--output", str(out)])
    return rc, out, json.loads((d / "labelled.quality_gate.json").read_text())


def test_benign_only_capture_passes_integrity_but_is_not_training_eligible(tmp_path):
    cfg = cfg_file(tmp_path)
    d, f, l = make_day(tmp_path, "monday", lambda i: "BENIGN")
    rc, out, gate = match(d, f, l, cfg)
    assert rc == 0                                   # v4.2 returned 4 here (class_counts)
    assert gate["capture_integrity"]["passed"] and not gate["class_coverage"]["passed"]
    assert gate["training_eligible"] is False and gate["scope"] == "capture"
    assert run_cli(make_splits.main, ["--input", str(out), "--config", str(cfg), "--out-dir", str(tmp_path / "s")]) == 4


def test_combined_dataset_becomes_eligible_and_splits(tmp_path):
    cfg = cfg_file(tmp_path)
    d1, f1, l1 = make_day(tmp_path, "monday", lambda i: "BENIGN")
    d2, f2, l2 = make_day(tmp_path, "friday", lambda i: "DDoS" if i % 2 else "BENIGN")
    _, o1, _ = match(d1, f1, l1, cfg)
    _, o2, _ = match(d2, f2, l2, cfg)
    comb = tmp_path / "all" / "all_labelled.parquet"
    assert run_cli(combine_labelled.main, ["--input", str(o1), "--input", str(o2), "--config", str(cfg),
                                           "--output", str(comb)]) == 0
    gate = json.loads((tmp_path / "all" / "all_labelled.quality_gate.json").read_text())
    assert gate["scope"] == "dataset" and gate["training_eligible"]
    assert set(gate["capture_integrity"]["per_capture"]) == {"monday", "friday"}
    stats = json.loads((tmp_path / "all" / "all_labelled.label_stats.json").read_text())
    assert stats["total_csv_records"] == 24
    df = pd.read_parquet(comb)
    assert len(df) == 24 and df.flow_uid.is_unique and "pkt_iat" in df.columns  # nothing dropped
    assert run_cli(make_splits.main, ["--input", str(comb), "--config", str(cfg), "--out-dir", str(tmp_path / "split")]) == 0
    # same capture twice is rejected
    assert run_cli(combine_labelled.main, ["--input", str(o1), "--input", str(o1), "--config", str(cfg),
                                           "--output", str(tmp_path / "dup.parquet")]) == 2


def test_one_bad_capture_fails_dataset_integrity(tmp_path):
    strict_integrity = RELAXED.replace("max_conflict_rate: 0.7", "max_conflict_rate: 0.0")
    cfg = cfg_file(tmp_path, strict_integrity)
    d1, f1, l1 = make_day(tmp_path, "monday", lambda i: "BENIGN")
    d2, f2, l2 = make_day(tmp_path, "friday", lambda i: "DDoS" if i % 2 else "BENIGN")
    # inject conflicts into Friday's labels: duplicate rows with the other label
    lab = pd.read_parquet(l2)
    flip = lab.copy(); flip[" Label"] = ["BENIGN" if x != "BENIGN" else "DDoS" for x in flip[" Label"]]
    pd.concat([lab, flip], ignore_index=True).to_parquet(l2, index=False)
    rc1, o1, g1 = match(d1, f1, l1, cfg)
    rc2, o2, g2 = match(d2, f2, l2, cfg)
    assert rc2 == 4 and not g2["capture_integrity"]["per_capture"]["friday"]["passed"]
    rc = run_cli(combine_labelled.main, ["--input", str(o1), "--input", str(o2), "--config", str(cfg),
                                         "--output", str(tmp_path / "c.parquet")])
    gate = json.loads((tmp_path / "c.quality_gate.json").read_text())
    assert rc == 4 and not gate["training_eligible"] and gate["capture_integrity"]["per_capture"]["monday"]["passed"]


def test_duration_sensitivity_and_transition_audit(tmp_path):
    cfg = cfg_file(tmp_path)
    d, f, l = make_day(tmp_path, "monday", lambda i: "BENIGN")
    out = tmp_path / "sens"
    rc = run_cli(duration_sensitivity.main, [
        "--flows", str(f), "--labels", str(l), "--config", str(cfg), "--out-dir", str(out), "--baseline", "legacy_1s",
        "--variant", "legacy_1s:matching_mode=legacy_v41,duration_abs_tolerance_s=1.0",
        "--variant", "legacy_10ms:matching_mode=legacy_v41,duration_abs_tolerance_s=0.01",
        "--variant", "evidence_1s:matching_mode=evidence_v43,duration_abs_tolerance_s=1.0"])
    assert rc == 0
    summ = json.loads((out / "transitions_summary.json").read_text())
    assert set(summ["comparisons"]) == {"legacy_1s->legacy_10ms", "legacy_1s->evidence_1s"}
    for comp in summ["comparisons"].values():
        assert set(comp["counts"]) >= {"ambiguous_to_unique", "unique_to_time_inconsistent", "selected_row_changed",
                                       "new_conflict", "new_shared_row", "candidate_count_changed"}
    t = pd.read_csv(out / "transitions.csv")
    assert t.flow_uid.is_unique and "match_status@legacy_10ms" in t.columns
    assert (out / "candidate_evidence.csv").exists()
    # the stand-alone comparison CLI gives the same counts
    out2 = tmp_path / "cmp"
    assert run_cli(compare_matching_runs.main, ["--run", f"legacy_1s={out / 'labelled_legacy_1s.parquet'}",
                                                "--run", f"evidence_1s={out / 'labelled_evidence_1s.parquet'}",
                                                "--baseline", "legacy_1s", "--out-dir", str(out2)]) == 0
    s2 = json.loads((out2 / "transitions_summary.json").read_text())
    assert s2["comparisons"]["legacy_1s->evidence_1s"]["counts"] == summ["comparisons"]["legacy_1s->evidence_1s"]["counts"]
    # bad specs
    assert run_cli(duration_sensitivity.main, ["--flows", str(f), "--labels", str(l), "--config", str(cfg),
                                               "--out-dir", str(tmp_path / "x"), "--baseline", "a",
                                               "--variant", "a:no_such_option=1"]) == 2


def test_transitions_detect_specific_changes():
    from src.labeling.transitions import compare_runs
    a = pd.DataFrame({"flow_uid": ["f1", "f2", "f3", "f4"],
                      "match_status": ["ambiguous_same_label", "unique", "unique", "unique"],
                      "matched_row_id": [None, 10, 11, 12], "n_consistent": [3, 1, 1, 1]})
    b = pd.DataFrame({"flow_uid": ["f1", "f2", "f3", "f4"],
                      "match_status": ["unique", "time_inconsistent", "unique", "conflict"],
                      "matched_row_id": [5, None, 99, None], "n_consistent": [1, 0, 1, 1]})
    table, summ = compare_runs({"a": a, "b": b}, "a")
    c = summ["comparisons"]["a->b"]["counts"]
    assert c["ambiguous_to_unique"] == 1 and c["unique_to_time_inconsistent"] == 1
    assert c["selected_row_changed"] == 1 and c["new_conflict"] == 1 and c["candidate_count_changed"] == 2
    with pytest.raises(ValueError):
        compare_runs({"a": a}, "zzz")


def test_summarize_offsets(tmp_path):
    from scripts import summarize_offsets
    good = {"evidence_best_offset_hours": 0.0, "ranking": [{"offset_hours": 0.0, "support": 0.98}], "flags": []}
    bad = {"evidence_best_offset_hours": -3.0, "ranking": [{"offset_hours": -3.0, "support": 0.6}], "flags": ["low_support: x"]}
    p1, p2 = tmp_path / "m.json", tmp_path / "t.json"
    p1.write_text(json.dumps(good)); p2.write_text(json.dumps(bad))
    assert run_cli(summarize_offsets.main, ["--evidence", f"monday={p1}", "--configured", "0"]) == 0
    assert run_cli(summarize_offsets.main, ["--evidence", f"monday={p1}", "--evidence", f"tuesday={p2}",
                                            "--configured", "0", "--output", str(tmp_path / "o.json")]) == 4
    rep = json.loads((tmp_path / "o.json").read_text())
    assert not rep["consistent"] and any("disagree" in p for p in rep["problems"])


@pytest.mark.parametrize("name", ["preprocessing.yaml", "cicids2017_colab.yaml"])
def test_shipped_configs_validate(name):
    import yaml
    from src.datasets.quality_gate import GateConfig
    from src.datasets.splits import SplitConfig
    from src.labeling.cicids2017 import config_from_dict
    from src.preprocessing.flows import FlowConfig
    c = yaml.safe_load((Path(__file__).resolve().parents[1] / "configs" / name).read_text())
    lab = dict(c["labeling"]); lab["utc_offset_hours"] = 0.0
    cfg = config_from_dict(lab); cfg.validate()
    assert cfg.matching_mode == "evidence_v43"
    FlowConfig(**c["flows"]).validate(); GateConfig(**c["quality_gate"]).validate(); SplitConfig(**c["splits"]).validate()
