"""v4.3 notebook: (1) every CLI flag used exists; (2) the notebook's Python cells actually run end-to-end on a
fake Drive layout with synthetic data (shell/magic lines are skipped, google.colab is stubbed).
This verifies wiring, not real-data behaviour."""
import json
import re
import subprocess
import sys
import types
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from src.preprocessing.synthetic import write_all

ROOT = Path(__file__).resolve().parents[1]
NB = ROOT / "notebooks" / "EarlyNIDS_v4_3_Colab.ipynb"


def code_cells():
    nb = json.loads(NB.read_text())
    return ["".join(c["source"]) for c in nb["cells"] if c["cell_type"] == "code"]


def test_v43_notebook_flags_exist():
    helps = {}
    for src in code_cells():
        mods = set(re.findall(r"scripts\.(\w+)", src))
        flags = set(re.findall(r"--[a-z][a-z0-9-]*", src))
        if not mods:
            continue
        for m in mods:
            if m not in helps:
                r = subprocess.run([sys.executable, "-m", f"scripts.{m}", "--help"], cwd=ROOT, capture_output=True, text=True)
                assert r.returncode == 0, f"scripts.{m} --help failed"
                helps[m] = r.stdout
        for fl in flags:
            assert any(fl in helps[m] for m in mods), f"flag {fl} not accepted by {sorted(mods)}"


def _fake_drive(tmp_path):
    drive = tmp_path / "drive" / "MyDrive" / "EarlyNIDS"
    ds = drive / "datasets" / "CIC-IDS2017"
    (ds / "pcap").mkdir(parents=True); (ds / "traffic_labels").mkdir(); (ds / "machine_learning").mkdir()
    (drive / "code").mkdir(parents=True)
    (drive / "code" / "EarlyNIDS_v4_3.zip").write_bytes(b"PK")
    for day, cap in (("Monday", "Monday-WorkingHours.pcap"), ("Tuesday", "Tuesday-WorkingHours.pcap"),
                     ("Wednesday", "Wednesday-workingHours.pcap")):
        pcap = ds / "pcap" / cap
        write_all(pcap)
        out = tmp_path / f"{day}.parquet"
        subprocess.run([sys.executable, "-m", "scripts.extract_flows", "--pcap", str(pcap), "--output", str(out),
                        "--capture-id", day.lower()], cwd=ROOT, check=True, capture_output=True)
        fl = pd.read_parquet(out)
        pd.DataFrame({" Source IP": fl.src_ip, " Source Port": fl.src_port, " Destination IP": fl.dst_ip,
                      " Destination Port": fl.dst_port, " Protocol": fl.protocol,
                      " Timestamp": [datetime.fromtimestamp(t, timezone.utc).strftime("%d/%m/%Y %H:%M:%S") for t in fl.start_time],
                      " Flow Duration": (fl.duration * 1e6).round().astype(int),
                      " Label": ["BENIGN" if day == "Monday" or i % 2 else "DoS Hulk" for i in range(len(fl))]}
                     ).to_parquet(ds / "traffic_labels" / f"{cap}_ISCX.csv.parquet", index=False)
    return drive


def test_v43_notebook_runs_end_to_end_on_fake_drive(tmp_path, monkeypatch):
    drive = _fake_drive(tmp_path)
    stub = types.ModuleType("google.colab")
    stub.drive = types.SimpleNamespace(mount=lambda *a, **k: None)
    monkeypatch.setitem(sys.modules, "google", types.ModuleType("google"))
    monkeypatch.setitem(sys.modules, "google.colab", stub)
    monkeypatch.chdir(ROOT)
    ns = {"display": print}

    def run_cell(src):
        src = (src.replace("/content/drive/MyDrive/EarlyNIDS", str(drive))
                  .replace("'/content/EarlyNIDS_v43'", repr(str(ROOT)))
                  .replace("'/content/pcap_cache'", repr(str(tmp_path / "cache")))
                  .replace("shutil.disk_usage('/content')", "shutil.disk_usage(str(tmp_path_))")
                  .replace("('local /content', '/content')", "('local', str(tmp_path_))")
                  .replace("'/content/drive/MyDrive'", "str(tmp_path_)")
                  .replace("UTC_OFFSET_HOURS = None", "UTC_OFFSET_HOURS = 0.0")
                  .replace("JUSTIFICATION = ''", "JUSTIFICATION = 'synthetic test'"))
        lines = [ln for ln in src.splitlines() if not ln.lstrip().startswith(("!", "%"))]
        ns["tmp_path_"] = tmp_path
        exec(compile("\n".join(lines), "<notebook>", "exec"), ns)

    cells = code_cells()
    for src in cells:
        run_cell(src)
    runs = drive / "runs" / "v4_3"
    for day in ("monday", "tuesday", "wednesday"):
        assert (runs / "smoke" / day / "labelled.quality_gate.json").exists(), day
    assert json.loads((runs / "offset_validation.json").read_text())["days"]
    assert (runs / "sensitivity" / "monday" / "transitions_summary.json").exists()
    assert (runs / "full" / "monday" / "labelled.parquet").exists()
    assert "utc_offset_hours=0.0" in (runs / "decisions.log").read_text()
    # Resume: re-running the smoke and full-day cells must skip completed work and keep outputs unchanged.
    full = runs / "full" / "monday" / "labelled.parquet"
    before = full.stat().st_mtime_ns
    smoke_cell = next(c for c in cells if "SMOKE = " in c)
    full_cell = next(c for c in cells if "FULL = " in c)
    run_cell(smoke_cell)
    run_cell(full_cell)
    assert full.stat().st_mtime_ns == before
    status = json.loads((runs / "full" / "monday" / "day_status.json").read_text())
    assert status["steps"]["extract"].get("skipped") and status["steps"]["match_labels"].get("skipped")
