"""v4.2: dataset layout / Colab path handling, safe overwrite, resume, notebook-CLI consistency."""
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import pytest

from scripts import check_dataset_layout, extract_flows, process_day
from src.datasets.splits import (SplitConfig, assign_partitions, build_manifest, load_manifest_for_training,
                                 write_manifest)
from src.preprocessing.io import FULL_FLOW_METADATA_COLUMNS, PREFIX_FEATURE_COLUMNS, assert_prefix_only, read_flows
from src.preprocessing.synthetic import write_all
from src.utils.cli import run_cli
from src.utils.paths import day_files, inspect_layout, normalize_root

ROOT = Path(__file__).resolve().parents[1]
PCAPS = ["Monday-WorkingHours.pcap", "Tuesday-WorkingHours.pcap", "Wednesday-workingHours.pcap",
         "Thursday-WorkingHours.pcap", "Friday-WorkingHours.pcap"]
LABELS = ["Monday-WorkingHours.pcap_ISCX.csv.parquet", "Tuesday-WorkingHours.pcap_ISCX.csv.parquet",
          "Wednesday-workingHours.pcap_ISCX.csv.parquet", "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv.parquet",
          "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv.parquet", "Friday-WorkingHours-Morning.pcap_ISCX.csv.parquet",
          "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv.parquet", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv.parquet"]


def fake_layout(tmp_path, with_ml=True):
    root = tmp_path / "MyDrive" / "EarlyNIDS" / "datasets" / "CIC-IDS2017"
    for sub in ("pcap", "traffic_labels") + (("machine_learning",) if with_ml else ()):
        (root / sub).mkdir(parents=True)
    for p in PCAPS:
        (root / "pcap" / p).write_bytes(b"\0" * 10)
    df = pd.DataFrame({" Label": ["BENIGN"]})
    for name in LABELS:
        df.to_parquet(root / "traffic_labels" / name)
        if with_ml:
            df.to_parquet(root / "machine_learning" / name)
    return root


def test_normalize_root_handles_quotes_home_and_spaces(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert normalize_root("  '~/My Drive/x'  ") == (tmp_path / "My Drive" / "x").resolve()
    assert normalize_root('"/content/drive/MyDrive/EarlyNIDS"') == Path("/content/drive/MyDrive/EarlyNIDS").resolve()


def test_day_mapping_is_case_insensitive(tmp_path):
    root = fake_layout(tmp_path)
    wed = day_files(root, "wednesday")
    assert [p.name for p in wed["pcap"]] == ["Wednesday-workingHours.pcap"]
    assert len(day_files(root, "thursday")["labels"]) == 2 and len(day_files(root, "friday")["labels"]) == 3
    with pytest.raises(ValueError):
        day_files(root, "saturday")


def test_inspect_layout_ok_and_problems(tmp_path):
    root = fake_layout(tmp_path)
    rep = inspect_layout(root)
    assert rep["ok"] and rep["subdirs"]["traffic_labels"]["n_files"] == 8
    assert rep["subdirs"]["traffic_labels"]["files"][0]["rows"] == 1  # parquet metadata read
    assert "not cryptographic integrity" in rep["note"]
    (root / "pcap" / PCAPS[0]).unlink()
    shutil.rmtree(root / "machine_learning")
    rep2 = inspect_layout(root)
    assert not rep2["ok"]
    assert any("missing directory" in p for p in rep2["problems"]) and any("monday: expected exactly 1 PCAP" in p for p in rep2["problems"])


def test_check_dataset_layout_exit_codes(tmp_path):
    root = fake_layout(tmp_path)
    assert run_cli(check_dataset_layout.main, ["--root", str(root), "--output", str(tmp_path / "l.json")]) == 0
    assert run_cli(check_dataset_layout.main, ["--root", str(root), "--output", str(tmp_path / "l.json")]) == 5
    assert run_cli(check_dataset_layout.main, ["--root", str(tmp_path / "nope")]) == 2
    (root / "pcap" / PCAPS[1]).unlink()
    assert run_cli(check_dataset_layout.main, ["--root", str(root)]) == 4


def test_extract_partial_marker_and_stale_partial_cleanup(tmp_path):
    pcap = tmp_path / "s.pcap"; write_all(pcap)
    out = tmp_path / "f.parquet"
    stale = tmp_path / "f.parquet.partial"; stale.write_text("interrupted run")
    assert run_cli(extract_flows.main, ["--pcap", str(pcap), "--output", str(out), "--capture-id", "s", "--max-frames", "20"]) == 0
    assert not stale.exists() and out.exists()
    st = json.loads((tmp_path / "f.parquet.stats.json").read_text())
    assert st["completed"] and st["partial_capture"] and st["stats"]["frames_seen"] == 20
    assert run_cli(extract_flows.main, ["--pcap", str(pcap), "--output", str(out), "--capture-id", "s"]) == 5  # no silent overwrite
    assert run_cli(extract_flows.main, ["--pcap", str(pcap), "--output", str(out), "--capture-id", "s", "--max-frames", "0"]) == 2


def _day_dataset(tmp_path, offset=-3.0):
    """Monday PCAP (synthetic) + Parquet labels written in local time UTC+offset."""
    root = tmp_path / "CIC-IDS2017"
    (root / "pcap").mkdir(parents=True); (root / "traffic_labels").mkdir()
    pcap = root / "pcap" / "Monday-WorkingHours.pcap"; write_all(pcap)
    tmp_flows = tmp_path / "ref.parquet"
    assert run_cli(extract_flows.main, ["--pcap", str(pcap), "--output", str(tmp_flows), "--capture-id", "ref"]) == 0
    flows = read_flows(tmp_flows)
    tz = timezone(timedelta(hours=offset))
    df = pd.DataFrame({" Source IP": flows.src_ip, " Source Port": flows.src_port, " Destination IP": flows.dst_ip,
                       " Destination Port": flows.dst_port, " Protocol": flows.protocol,
                       " Timestamp": [datetime.fromtimestamp(t, tz).strftime("%d/%m/%Y %H:%M:%S") for t in flows.start_time],
                       " Flow Duration": (flows.duration * 1e6).astype(int),
                       " Label": ["BENIGN" if i % 2 else "SyntheticAttack" for i in range(len(flows))]})
    df.to_parquet(root / "traffic_labels" / "Monday-WorkingHours.pcap_ISCX.csv.parquet", index=False)
    return root


def _write_cfg(path, offset=None, relaxed=False):
    lines = ["labeling:", f"  utc_offset_hours: {'null' if offset is None else offset}"]
    if relaxed:
        lines += ["quality_gate:", "  min_match_rate: 0.3", "  max_unmatched_rate: 0.7", "  max_conflict_rate: 0.7",
                  "  max_ambiguous_rate: 0.7", "  max_time_inconsistent_rate: 0.7", "  min_trusted_per_class: 1"]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_process_day_resume_and_explicit_offset(tmp_path):
    root = _day_dataset(tmp_path)
    cfg = tmp_path / "run.yaml"; _write_cfg(cfg, None)
    out = tmp_path / "runs"
    args = ["--root", str(root), "--day", "monday", "--out-root", str(out), "--config", str(cfg)]
    # 1st run: extraction + evidence, then STOP (offset not configured) -> nothing labelled
    assert run_cli(process_day.main, args) == 0
    day = out / "monday"
    status = json.loads((day / "day_status.json").read_text())
    assert status["steps"]["match_labels"]["reason"] == "utc_offset_hours not configured"
    assert not (day / "labelled.parquet").exists()
    ev = json.loads((day / "offset_evidence.json").read_text())
    assert ev["evidence_best_offset_hours"] == -3.0
    mtime = (day / "flows.parquet").stat().st_mtime_ns
    # 2nd run with explicit offset (strict gate): extraction resumed (skipped), matching runs, gate fails -> 4
    _write_cfg(cfg, -3.0)
    assert run_cli(process_day.main, args) == 4
    assert (day / "flows.parquet").stat().st_mtime_ns == mtime
    st = json.loads((day / "day_status.json").read_text())["steps"]
    assert st["extract"]["skipped"] and st["offset_evidence"]["skipped"] and st["match_labels"]["exit_code"] == 4
    gate = json.loads((day / "labelled.quality_gate.json").read_text())
    assert not gate["passed"] and gate["time_offset"]["agrees"] is True
    # 3rd run: resume, gate result reused
    assert run_cli(process_day.main, args) == 4
    # relaxed (test-only) thresholds + --force -> passes
    _write_cfg(cfg, -3.0, relaxed=True)
    assert run_cli(process_day.main, args + ["--force"]) == 0
    lab = pd.read_parquet(day / "labelled.parquet")
    assert lab.loc[lab.match_status != "unique", "binary_label"].isna().all()
    assert not lab.loc[~lab.valid_early_prefix, "trusted"].any()  # e.g. the mid-stream flow


def test_process_day_offset_disagreement_blocks(tmp_path):
    root = _day_dataset(tmp_path)
    cfg = tmp_path / "run.yaml"; _write_cfg(cfg, 0.0)
    assert run_cli(process_day.main, ["--root", str(root), "--day", "monday", "--out-root", str(tmp_path / "r"),
                                      "--config", str(cfg)]) == 2


def test_process_day_detects_changed_smoke_setting(tmp_path):
    root = _day_dataset(tmp_path)
    cfg = tmp_path / "run.yaml"; _write_cfg(cfg, None)
    base = ["--root", str(root), "--day", "monday", "--out-root", str(tmp_path / "r"), "--config", str(cfg)]
    assert run_cli(process_day.main, base + ["--max-frames", "30"]) == 0
    assert run_cli(process_day.main, base) == 2  # full run must not silently reuse a partial extraction
    assert run_cli(process_day.main, base + ["--force"]) == 0


def test_process_day_local_cache(tmp_path):
    root = _day_dataset(tmp_path)
    cfg = tmp_path / "run.yaml"; _write_cfg(cfg, None)
    cache = tmp_path / "cache"
    assert run_cli(process_day.main, ["--root", str(root), "--day", "monday", "--out-root", str(tmp_path / "r"),
                                      "--config", str(cfg), "--local-cache", str(cache)]) == 0
    assert cache.exists() and not any(cache.iterdir())  # copy removed after use


def test_manifest_for_training_rejects_diagnostic_and_tampering(tmp_path):
    df = pd.DataFrame({"flow_uid": [f"f{i}" for i in range(20)], "capture_id": "c", "start_time": range(20),
                       "end_time": [x + 0.5 for x in range(20)], "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
                       "binary_label": ["ATTACK", "BENIGN"] * 10})
    cfg = SplitConfig(embargo_s=0)
    part = assign_partitions(df, cfg)
    good, diag = tmp_path / "good", tmp_path / "diag"
    write_manifest(df, part, build_manifest(df, part, cfg), good)
    write_manifest(df, part, build_manifest(df, part, cfg, extra={"diagnostic_only": True}), diag)
    assert load_manifest_for_training(good)["seed"] == 42
    with pytest.raises(ValueError, match="diagnostic_only"):
        load_manifest_for_training(diag)
    f = good / "split_assignment.csv"; f.chmod(0o644); f.write_text(f.read_text().replace("train", "test", 1))
    with pytest.raises(ValueError, match="hash"):
        load_manifest_for_training(good)


def test_prefix_feature_guard():
    assert not set(PREFIX_FEATURE_COLUMNS) & set(FULL_FLOW_METADATA_COLUMNS)
    assert_prefix_only(["pkt_iat", "pkt_ip_len"])
    with pytest.raises(ValueError):
        assert_prefix_only(["pkt_iat", "duration"])


def test_notebook_uses_only_existing_cli_flags():
    nb = json.loads((ROOT / "notebooks" / "EarlyNIDS_v4_2_Colab.ipynb").read_text())
    src = "\n".join("".join(c["source"]) for c in nb["cells"] if c["cell_type"] == "code")
    calls = re.findall(r"python -m (scripts\.\w+)([^\n]*)", src)
    calls += [("scripts." + m.group(1), m.group(2)) for m in re.finditer(r"'scripts\.(\w+)'(.*)", src)]
    assert {c[0] for c in calls} >= {"scripts.check_dataset_layout", "scripts.inspect_label_csv",
                                     "scripts.audit_label_lineage", "scripts.process_day"}
    for module, rest in calls:
        helptext = subprocess.run([sys.executable, "-m", module, "--help"], cwd=ROOT, capture_output=True,
                                  text=True).stdout
        assert helptext, module
        for flag in re.findall(r"--[a-z][a-z0-9-]*", rest):
            assert flag in helptext, f"{module} has no flag {flag}"
