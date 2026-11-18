"""CLI exit codes and quality-gate behaviour (v4.1)."""
import subprocess
import sys
from pathlib import Path

import pandas as pd
import pytest

from src.datasets.quality_gate import GateConfig, evaluate

ROOT = Path(__file__).resolve().parents[1]


def cli(*args):
    return subprocess.run([sys.executable, "-m", *args], cwd=ROOT, capture_output=True, text=True)


def test_missing_pcap_is_actionable_exit_2(tmp_path):
    r = cli("scripts.extract_flows", "--pcap", str(tmp_path / "nope.pcap"), "--output", str(tmp_path / "o.parquet"),
            "--capture-id", "x")
    assert r.returncode == 2
    assert "PCAP file not found" in r.stderr and "Traceback" not in r.stderr


def test_bad_output_suffix_exit_2(tmp_path):
    from src.preprocessing.synthetic import write_all
    p = tmp_path / "s.pcap"; write_all(p)
    r = cli("scripts.extract_flows", "--pcap", str(p), "--output", str(tmp_path / "o.txt"), "--capture-id", "x")
    assert r.returncode == 2


def test_no_overwrite_without_flag(tmp_path):
    from src.preprocessing.synthetic import write_all
    p = tmp_path / "s.pcap"; write_all(p)
    out = tmp_path / "o.parquet"
    assert cli("scripts.extract_flows", "--pcap", str(p), "--output", str(out), "--capture-id", "x").returncode == 0
    r = cli("scripts.extract_flows", "--pcap", str(p), "--output", str(out), "--capture-id", "x")
    assert r.returncode == 5 and "refusing to overwrite" in r.stderr
    assert cli("scripts.extract_flows", "--pcap", str(p), "--output", str(out), "--capture-id", "x",
               "--overwrite").returncode == 0


def test_unsupported_csv_schema_exit_2(tmp_path):
    from src.preprocessing.synthetic import write_all
    p = tmp_path / "s.pcap"; write_all(p)
    flows = tmp_path / "f.parquet"
    assert cli("scripts.extract_flows", "--pcap", str(p), "--output", str(flows), "--capture-id", "x").returncode == 0
    bad = tmp_path / "ml_features_only.csv"
    pd.DataFrame({" Destination Port": [80], " Flow Duration": [1], " Label": ["BENIGN"]}).to_csv(bad, index=False)
    cfg = tmp_path / "c.yaml"; cfg.write_text("labeling:\n  utc_offset_hours: 0\n")
    r = cli("scripts.match_labels", "--flows", str(flows), "--labels", str(bad), "--config", str(cfg),
            "--output", str(tmp_path / "l.parquet"))
    assert r.returncode == 2 and "unsupported label CSV schema" in r.stderr


def test_missing_timezone_exit_2(tmp_path):
    from src.preprocessing.synthetic import write_all
    p = tmp_path / "s.pcap"; write_all(p)
    flows = tmp_path / "f.parquet"
    cli("scripts.extract_flows", "--pcap", str(p), "--output", str(flows), "--capture-id", "x")
    csv = tmp_path / "l.csv"; csv.write_text("a\n1\n")
    cfg = tmp_path / "c.yaml"; cfg.write_text("labeling: {}\n")
    r = cli("scripts.match_labels", "--flows", str(flows), "--labels", str(csv), "--config", str(cfg),
            "--output", str(tmp_path / "l.parquet"))
    assert r.returncode == 2 and "utc_offset_hours" in r.stderr


def test_validate_dataset_failure_exit_4(tmp_path):
    df = pd.DataFrame([{"flow_uid": "a", "capture_id": "c", "protocol": 6, "src_ip": "1.1.1.1", "src_port": 1,
                        "dst_ip": "2.2.2.2", "dst_port": 2, "start_time": 1.0, "end_time": 0.5,
                        "observed_packets": 1, "packet_count": 1, "start_reason": "syn", "end_reason": "eof",
                        "valid_early_prefix": True, "pkt_iat": [0.0], "pkt_direction": [1], "pkt_ip_len": [40]}])
    p = tmp_path / "bad.parquet"; df.to_parquet(p)
    assert cli("scripts.validate_dataset", "--input", str(p)).returncode == 4


def labelled_df(n_unique=200, n_amb=0, n_conf=0, n_unm=0, attack_frac=0.5):
    rows = []
    def add(status, reason, binary=None, trusted=False):
        rows.append({"flow_uid": f"f{len(rows)}", "capture_id": "mon", "valid_early_prefix": True,
                     "match_status": status, "match_reason": reason, "binary_label": binary,
                     "label": None if binary is None else ("X" if binary == "ATTACK" else "BENIGN"),
                     "trusted": trusted, "start_offset_s": 0.1, "duration_diff_s": 0.0, "orientation": "same",
                     "used_12h_shift": False, "exclusion_reason": "" if trusted else f"label:{status}:{reason}"})
    for i in range(n_unique):
        add("unique", "single_consistent_row", "ATTACK" if i < attack_frac * n_unique else "BENIGN", True)
    for _ in range(n_amb):
        add("ambiguous_same_label", "multiple_consistent_rows_same_label")
    for _ in range(n_conf):
        add("conflict", "start_aligned_rows_with_different_labels")
    for _ in range(n_unm):
        add("unmatched", "no_csv_row_with_same_key")
    return pd.DataFrame(rows)


CSV_OK = {"total_csv_records": 1000, "invalid_csv_records": 0}


def test_gate_passes_clean_data():
    rep = evaluate(labelled_df(), CSV_OK, GateConfig())
    assert rep["passed"] and rep["thresholds_provisional"]
    assert rep["totals"]["unique_matches"] == 200


@pytest.mark.parametrize("kw,failing", [
    ({"n_amb": 40}, "ambiguous_rate"),
    ({"n_conf": 10}, "conflict_rate"),
    ({"n_unm": 60}, "match_rate"),
    ({"attack_frac": 0.0}, "class_counts"),
])
def test_gate_fails_with_named_check(kw, failing):
    rep = evaluate(labelled_df(**kw), CSV_OK, GateConfig())
    # v4.3 intentional change: missing class coverage no longer fails label-matching integrity
    # ("passed"), but it always blocks training eligibility.
    assert not rep["training_eligible"]
    if failing == "class_counts":
        assert rep["passed"] and not rep["class_coverage"]["passed"]
    else:
        assert not rep["passed"]
    assert failing in [c["check"] for c in rep["checks"] if not c["passed"]]
    assert all(c["hint"] for c in rep["checks"] if not c["passed"])


def test_gate_invalid_csv_rate():
    rep = evaluate(labelled_df(), {"total_csv_records": 100, "invalid_csv_records": 5}, GateConfig())
    assert not rep["passed"]


def test_gate_duplicate_flow_uid():
    df = labelled_df(); df.loc[1, "flow_uid"] = df.loc[0, "flow_uid"]
    assert not evaluate(df, CSV_OK, GateConfig())["passed"]


def test_gate_config_validation():
    with pytest.raises(ValueError):
        GateConfig(min_match_rate=1.5).validate()


def test_validation_rejects_untrusted_label_leaks():
    from src.datasets.validation import validate_flows
    base = {"flow_uid": "a", "capture_id": "c", "protocol": 6, "src_ip": "1.1.1.1", "src_port": 1,
            "dst_ip": "2.2.2.2", "dst_port": 2, "start_time": 1.0, "end_time": 2.0, "observed_packets": 1,
            "packet_count": 1, "start_reason": "syn", "end_reason": "eof", "valid_early_prefix": True,
            "pkt_iat": [0.0], "pkt_direction": [1], "pkt_ip_len": [40]}
    ok = pd.DataFrame([{**base, "match_status": "unique", "binary_label": "BENIGN", "trusted": True}])
    assert validate_flows(ok, 20)["ok"]
    leak = pd.DataFrame([{**base, "match_status": "ambiguous_same_label", "binary_label": "BENIGN", "trusted": True}])
    rep = validate_flows(leak, 20)
    assert not rep["ok"] and any("not 'unique'" in e for e in rep["errors"])


def test_gate_threshold_status_provisional_vs_validated():
    rep = evaluate(labelled_df(), CSV_OK, GateConfig(validated_thresholds={"max_conflict_rate": "docs/x.md#2026-12"}))
    assert rep["threshold_status"]["max_conflict_rate"].startswith("validated")
    assert rep["threshold_status"]["min_match_rate"] == "provisional" and rep["thresholds_provisional"]
    with pytest.raises(ValueError):
        GateConfig(validated_thresholds={"no_such_threshold": "x"}).validate()
    with pytest.raises(ValueError):
        GateConfig(validated_thresholds={"max_conflict_rate": " "}).validate()


def test_gate_trusted_coverage_check():
    df = labelled_df(n_unm=60)
    rep = evaluate(df, CSV_OK, GateConfig(min_match_rate=0.0, max_unmatched_rate=1.0, min_trusted_coverage=0.9))
    assert not rep["passed"] and rep["rates"]["trusted_coverage"] == pytest.approx(200 / 260)
