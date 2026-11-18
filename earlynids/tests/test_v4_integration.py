"""End-to-end synthetic integration: PCAP -> flows -> labels -> quality gate -> splits.

Engineering validation only. Synthetic labels are arbitrary and carry no security meaning.
(Updated in v4.1: new label-matching outputs and the mandatory quality gate.)
"""
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from scripts import extract_flows, make_splits, match_labels, validate_dataset
from src.preprocessing.io import read_flows
from src.preprocessing.synthetic import write_all

ROOT = Path(__file__).resolve().parents[1]


def _fmt(ts, offset_h):
    return datetime.fromtimestamp(ts, timezone(timedelta(hours=offset_h))).strftime("%d/%m/%Y %H:%M:%S")


def make_label_csv(flows, path, offset, skip=(0, 1), conflict=True):
    rows = []
    for i, f in enumerate(flows.itertuples()):
        if i in skip:
            continue
        rows.append({" Source IP": f.src_ip, " Source Port": f.src_port, " Destination IP": f.dst_ip,
                     " Destination Port": f.dst_port, " Protocol": f.protocol,
                     " Timestamp": _fmt(f.start_time, offset), " Flow Duration": int(f.duration * 1e6),
                     " Label": "BENIGN" if i % 2 else "SyntheticClassX"})
    if conflict:
        c = dict(rows[-1]); c[" Label"] = "OtherLabel"; rows.append(c)
    rows.append({" Source IP": "bad", " Source Port": "1", " Destination IP": "1.1.1.1", " Destination Port": "2",
                 " Protocol": "6", " Timestamp": "garbage", " Flow Duration": "1", " Label": "BENIGN"})
    pd.DataFrame(rows).to_csv(path, index=False)


def write_cfg(path, offset, gate=""):
    path.write_text(f"labeling:\n  utc_offset_hours: {offset}\n" + gate +
                    "splits:\n  strategy: chronological\n  embargo_s: 0.0\n", encoding="utf-8")


def test_end_to_end(tmp_path):
    pcap = tmp_path / "syn.pcap"
    write_all(pcap)
    flows_path = tmp_path / "flows.parquet"
    assert extract_flows.main(["--pcap", str(pcap), "--output", str(flows_path), "--capture-id", "synthetic"]) == 0
    stats = json.loads((tmp_path / "flows.parquet.stats.json").read_text())
    assert stats["stats"]["conservation_ok"]
    flows = read_flows(flows_path)
    assert flows["flow_uid"].is_unique
    assert validate_dataset.main(["--input", str(flows_path)]) == 0

    offset = -3.0
    labels_csv = tmp_path / "labels.csv"
    make_label_csv(flows, labels_csv, offset)
    cfg = tmp_path / "pre.yaml"
    # Strict default gate must FAIL on this deliberately dirty synthetic set.
    write_cfg(cfg, offset)
    out = tmp_path / "labelled.parquet"
    rc = match_labels.main(["--flows", str(flows_path), "--labels", str(labels_csv), "--config", str(cfg), "--output", str(out)])
    assert rc == 4
    gate = json.loads((tmp_path / "labelled.quality_gate.json").read_text())
    assert not gate["passed"] and gate["totals"]["unmatched_flows"] >= 2
    assert gate["totals"]["invalid_csv_records"] == 1 and gate["totals"]["conflicting_labels"] >= 1
    assert out.exists() and (tmp_path / "labelled.problem_flows.csv").exists()  # reports preserved
    lab = pd.read_parquet(out)
    assert len(lab) == len(flows)  # nothing deleted
    assert lab.loc[lab.match_status != "unique", "binary_label"].isna().all()
    assert not lab.loc[~lab.valid_early_prefix, "trusted"].any()
    # make_splits refuses a failed gate
    assert make_splits.main(["--input", str(out), "--config", str(cfg), "--out-dir", str(tmp_path / "s0")]) == 4

    # Relaxed (test-only) thresholds -> gate passes -> splits allowed
    relaxed = ("quality_gate:\n  min_match_rate: 0.5\n  max_unmatched_rate: 0.5\n  max_conflict_rate: 0.5\n"
               "  max_invalid_csv_rate: 0.5\n  max_time_inconsistent_rate: 0.5\n  min_trusted_per_class: 1\n")
    write_cfg(cfg, offset, relaxed)
    out2 = tmp_path / "labelled2.parquet"
    assert match_labels.main(["--flows", str(flows_path), "--labels", str(labels_csv), "--config", str(cfg),
                              "--output", str(out2)]) == 0
    split_dir = tmp_path / "split"
    assert make_splits.main(["--input", str(out2), "--config", str(cfg), "--out-dir", str(split_dir)]) == 0
    man = json.loads((split_dir / "split_manifest.json").read_text())
    assert all(v == 0 for v in man["leakage"]["flow_overlap"].values())
    assign = pd.read_csv(split_dir / "split_assignment.csv")
    lab2 = pd.read_parquet(out2)
    assert set(assign["flow_uid"]) <= set(lab2.loc[lab2.trusted, "flow_uid"])
    # immutability: second run into the same directory is refused
    from src.utils.cli import run_cli
    assert run_cli(make_splits.main, ["--input", str(out2), "--config", str(cfg), "--out-dir", str(split_dir)]) == 5


def test_csv_output_is_v3_compatible(tmp_path):
    pcap = tmp_path / "syn.pcap"
    write_all(pcap)
    out = tmp_path / "flows.csv"
    assert extract_flows.main(["--pcap", str(pcap), "--output", str(out), "--capture-id", "s"]) == 0
    df = pd.read_csv(out)
    feats = json.loads(df.loc[0, "features_json"])
    assert len(feats[0]) == 3 and set(df["label"]) == {"UNLABELED"}
    back = read_flows(out)
    assert list(back.loc[0, "pkt_direction"]) == [x[2] for x in feats]


def test_fresh_interpreter_parses_ethernet(tmp_path):
    """Regression: a fresh process must dissect Ethernet frames (not Raw)."""
    pcap = tmp_path / "syn.pcap"
    write_all(pcap)
    out = tmp_path / "f.parquet"
    r = subprocess.run([sys.executable, "-m", "scripts.extract_flows", "--pcap", str(pcap),
                        "--output", str(out), "--capture-id", "x"], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    stats = json.loads((tmp_path / "f.parquet.stats.json").read_text())["stats"]
    assert stats["eligible_packets"] > 0 and stats["skipped_not_ip"] == 1
