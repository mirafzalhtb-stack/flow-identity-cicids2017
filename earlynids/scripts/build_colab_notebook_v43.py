"""Regenerate notebooks/EarlyNIDS_v4_3_Colab.ipynb:  python scripts/build_colab_notebook_v43.py notebooks/EarlyNIDS_v4_3_Colab.ipynb"""
import json
import sys

cells = []


def md(text):
    cells.append({"cell_type": "markdown", "id": f"c{len(cells):02d}", "metadata": {}, "source": text.strip("\n").splitlines(True)})


def code(text):
    cells.append({"cell_type": "code", "id": f"c{len(cells):02d}", "metadata": {}, "execution_count": None,
                  "outputs": [], "source": text.strip("\n").splitlines(True)})


md("""
# EarlyNIDS v4.3 — CIC-IDS2017 real-data validation (Google Colab)

Data integration and label-matching validation only. **No model training.**

* Raw data on Drive is read-only. Every output goes to `RUN_ROOT` (a new `v4_3` directory, so v4.2 runs are not touched).
* Steps are resumable: completed outputs are detected and skipped. Nothing is overwritten unless you pass `--force` / `--overwrite` yourself.
* The time-zone offset is never chosen automatically. `match_labels` refuses an offset that contradicts the day's evidence.
* Only uniquely supported matches become trusted samples. v4.3 adds identity evidence (duration residuals, margins,
  label-row reuse checks), but uncertain flows stay excluded. Labels are never used to choose a candidate.
* Results here are your real-data findings. The development tests only covered synthetic data.
""")
md("## 1. Mount Google Drive")
code("""
from google.colab import drive
drive.mount('/content/drive')
""")
md("## 2. Paths and the code archive")
code("""
from pathlib import Path
import glob, json, os, shutil, subprocess, sys
DATASET_ROOT = '/content/drive/MyDrive/EarlyNIDS/datasets/CIC-IDS2017'
CODE_DIR     = '/content/drive/MyDrive/EarlyNIDS/code'
RUN_ROOT     = '/content/drive/MyDrive/EarlyNIDS/runs/v4_3'
REPO         = '/content/EarlyNIDS_v43'
LOCAL_CACHE  = '/content/pcap_cache'
zips = sorted(glob.glob(f'{CODE_DIR}/EarlyNIDS_v4_3*.zip'))
assert zips, f'Upload EarlyNIDS_v4_3.zip to {CODE_DIR}'
CODE_ZIP = zips[-1]
assert Path(DATASET_ROOT).is_dir(), f'dataset root not found: {DATASET_ROOT}'
Path(RUN_ROOT).mkdir(parents=True, exist_ok=True)
print('code:', CODE_ZIP); print('runs:', RUN_ROOT)
""")
md("## 3. Disk space (one PCAP is copied to local disk at a time; the largest is about 13 GB)")
code("""
for label, path in (('local /content', '/content'), ('Drive', '/content/drive/MyDrive')):
    u = shutil.disk_usage(path)
    print(f'{label:15s} free {u.free / 2**30:7.1f} GiB of {u.total / 2**30:7.1f} GiB')
free_local = shutil.disk_usage('/content').free / 2**30
if free_local < 25:
    print('WARNING: less than 25 GiB free locally -> run full days WITHOUT --local-cache (slower, reads from Drive).')
""")
md("## 4. Unpack, install, run the unit tests")
code("""
if not Path(REPO).exists():
    import zipfile
    with zipfile.ZipFile(CODE_ZIP) as z:
        z.extractall('/content')
%cd {REPO}
!pip -q install "scapy>=2.5,<3" pyarrow pyyaml
!python -m pytest -q -p no:logging 2>&1 | tail -n 3
""")
md("## 5. Dataset layout")
code("""
!python -m scripts.check_dataset_layout --root "{DATASET_ROOT}" --output "{RUN_ROOT}/layout.json" --overwrite
""")
md("""
## 6. Run configuration (explicit, versioned on Drive)
The v4.2 Monday smoke evidence supported `utc_offset_hours = 0.0`. It still needs **independent** validation on other days (steps 7–8).
Set the value yourself and record the justification. All thresholds stay at their provisional defaults.
""")
code("""
import yaml
CONFIG = f'{RUN_ROOT}/run_config.yaml'
if not Path(CONFIG).exists():
    shutil.copy(f'{REPO}/configs/cicids2017_colab.yaml', CONFIG)
UTC_OFFSET_HOURS = None   # <-- set explicitly, e.g. 0.0 (v4.2 Monday smoke evidence)
JUSTIFICATION = ''        # <-- e.g. 'v4.2 Monday smoke: offset 0.0, support ...; to be confirmed on Tue/Wed smoke'
assert UTC_OFFSET_HOURS is not None and JUSTIFICATION, 'Set UTC_OFFSET_HOURS and JUSTIFICATION first.'
cfg = yaml.safe_load(open(CONFIG))
cfg['labeling']['utc_offset_hours'] = float(UTC_OFFSET_HOURS)
cfg['labeling'].setdefault('matching_mode', 'evidence_v43')
yaml.safe_dump(cfg, open(CONFIG, 'w'), sort_keys=False)
with open(f'{RUN_ROOT}/decisions.log', 'a') as fh:
    fh.write(f'utc_offset_hours={UTC_OFFSET_HOURS} | {JUSTIFICATION}\\n')
print(yaml.safe_dump(cfg['labeling'], sort_keys=False))
""")
md("""
## 7. Smoke tests: Monday, Tuesday, Wednesday (first 300,000 frames each)
Each day: extraction → its own offset evidence → matching (blocked with exit 2 if the evidence disagrees) → gate.
Partial captures are diagnostic only. EOF-cut flows are treated as right-censored by the v4.3 matcher.
""")
code("""
SMOKE = f'{RUN_ROOT}/smoke'
for day in ['monday', 'tuesday', 'wednesday']:
    r = subprocess.run([sys.executable, '-m', 'scripts.process_day', '--root', DATASET_ROOT, '--day', day,
                        '--out-root', SMOKE, '--config', CONFIG, '--max-frames', '300000'])
    print(f'{day}: exit {r.returncode}  (0 ok, 4 integrity failed -> review, 2 input/offset problem)')
""")
md("## 8. Independent timestamp-offset validation across days")
code("""
ev_args = [f'--evidence={d}={SMOKE}/{d}/offset_evidence.json' for d in ['monday', 'tuesday', 'wednesday']
           if Path(f'{SMOKE}/{d}/offset_evidence.json').exists()]
r = subprocess.run([sys.executable, '-m', 'scripts.summarize_offsets', *ev_args, '--configured', str(UTC_OFFSET_HOURS),
                    '--output', f'{RUN_ROOT}/offset_validation.json', '--overwrite'])
print('consistent' if r.returncode == 0 else 'REVIEW REQUIRED (see problems above)')
""")
md("## 9. Smoke gate summaries (integrity vs class coverage vs training eligibility)")
code("""
import pandas as pd
def gate_table(root):
    rows = []
    for p in sorted(Path(root).glob('*/labelled.quality_gate.json')):
        g = json.load(open(p)); t = g['totals']
        rows.append({'day': p.parent.name, 'integrity': g['capture_integrity']['passed'],
                     'class_coverage': g['class_coverage']['passed'], 'training_eligible': g['training_eligible'],
                     'flows': t['pcap_flows'], 'valid': t['valid_early_prefix_flows'], 'unique': t['unique_matches'],
                     'ambiguous': t['ambiguous_same_label'] + t['ambiguous_shared_row'], 'conflict': t['conflicting_labels'],
                     'time_inconsistent': t['time_inconsistent'], 'unmatched': t['unmatched_flows'],
                     'invalid_label_rows': t['malformed_nonempty_csv_records'], 'empty_label_rows': t['empty_csv_records'],
                     'failed': [c['check'] for c in g['checks'] if not c['passed']]})
    return pd.DataFrame(rows)
gate_table(SMOKE)
""")
md("""
## 10. Duration-sensitivity and matching-transition audit (Monday smoke)
Reproduces the v4.2 experiment (legacy mode, 1 s / 100 ms / 10 ms) and compares it with the v4.3 evidence mode.
The last variant tests a **hypothesis** (the label tool cuts flows at 120 s). It is not assumed to be true.
No variant is declared optimal.
""")
code("""
SENS = f'{RUN_ROOT}/sensitivity/monday'
mon_labels = sorted(glob.glob(f'{DATASET_ROOT}/traffic_labels/Monday*'))
variants = [
    'legacy_1s:matching_mode=legacy_v41,duration_abs_tolerance_s=1.0',
    'legacy_100ms:matching_mode=legacy_v41,duration_abs_tolerance_s=0.1',
    'legacy_10ms:matching_mode=legacy_v41,duration_abs_tolerance_s=0.01',
    'evidence_1s:matching_mode=evidence_v43,duration_abs_tolerance_s=1.0',
    'evidence_100ms:matching_mode=evidence_v43,duration_abs_tolerance_s=0.1',
    'evidence_1s_T120:matching_mode=evidence_v43,duration_abs_tolerance_s=1.0,csv_active_timeout_s=120.0',
]
if not Path(f'{SENS}/transitions_summary.json').exists():
    cmd = [sys.executable, '-m', 'scripts.duration_sensitivity', '--flows', f'{SMOKE}/monday/flows.parquet',
           '--labels', *mon_labels, '--config', CONFIG, '--out-dir', SENS, '--baseline', 'legacy_1s']
    for v in variants:
        cmd += ['--variant', v]
    subprocess.run(cmd, check=True)
summ = json.load(open(f'{SENS}/transitions_summary.json'))
counts = pd.DataFrame({n: pd.Series(c) for n, c in summ['status_counts'].items()}).fillna(0).astype(int).T
display(counts)
display(pd.DataFrame({k: v['counts'] for k, v in summ['comparisons'].items()}).T)
""")
md("""
## 11. Identity review of changed flows
Look at **all** candidates of flows that changed status or selected row (e.g. `monday-000005370` if present).
Check whether the selected row is plausibly the same session (start offset, duration residual, orientation, packet residual).
The label column is shown for review only. The matcher never uses it to select.
""")
code("""
ce = pd.read_csv(f'{SENS}/candidate_evidence.csv')
FLOW = 'monday-000005370'
cols = ['variant', 'flow_uid', 'row_id', 'orientation', 'dt', 'csv_duration', 'expected', 'resid', 'miss_ratio',
        'pkt_resid', 'consistent', 'strict', 'csv_label']
if ce.empty:
    print('no flow changed between variants -> nothing to review')
else:
    show = ce[ce.flow_uid == FLOW] if (ce.flow_uid == FLOW).any() else ce[ce.flow_uid == ce.flow_uid.iloc[0]]
    display(show[cols].sort_values(['variant', 'miss_ratio']))
t = pd.read_csv(f'{SENS}/transitions.csv')
flag = [c for c in t.columns if c.startswith('ambiguous_to_unique:legacy_1s->evidence_1s')]
print('ambiguous -> unique (legacy 1 s -> evidence 1 s):', int(t[flag[0]].sum()) if flag else 'n/a')
""")
md("""
## 12. Complete days, one at a time (resumable)
Start with Monday. Review its gate before adding the next day. If Colab disconnects, re-run this cell: completed steps are skipped.
""")
code("""
FULL = f'{RUN_ROOT}/full'
DAYS = ['monday']          # then 'tuesday', 'wednesday', 'thursday', 'friday', one by one
use_cache = shutil.disk_usage('/content').free / 2**30 >= 25
for day in DAYS:
    cmd = [sys.executable, '-m', 'scripts.process_day', '--root', DATASET_ROOT, '--day', day,
           '--out-root', FULL, '--config', CONFIG]
    if use_cache:
        cmd += ['--local-cache', LOCAL_CACHE]
    print('processing', day, '...')
    r = subprocess.run(cmd)
    print(day, 'exit', r.returncode)
gate_table(FULL)
""")
md("""
## 13. Dataset-wide gate (only after all intended days are complete and reviewed)
Per-day integrity must pass for every day, and both classes must be covered. Only then is the combined table
`training_eligible`, which `scripts.make_splits` requires.
""")
code("""
done = [p for p in sorted(Path(FULL).glob('*/labelled.parquet'))]
print('completed days:', [p.parent.name for p in done])
COMBINED = f'{RUN_ROOT}/dataset/all_labelled.parquet'
if len(done) >= 2 and not Path(COMBINED).exists():
    cmd = [sys.executable, '-m', 'scripts.combine_labelled', '--config', CONFIG, '--output', COMBINED]
    for p in done:
        cmd += ['--input', str(p)]
    r = subprocess.run(cmd)
    g = json.load(open(f'{RUN_ROOT}/dataset/all_labelled.quality_gate.json'))
    print('integrity:', g['capture_integrity']['passed'], '| class coverage:', g['class_coverage']['passed'],
          '| training_eligible:', g['training_eligible'])
""")
md("""
## 14. What to send back for review
`layout.json`, `offset_validation.json`, `smoke/*/labelled.quality_gate.json`, `sensitivity/monday/transitions_summary.json`,
a few rows of `candidate_evidence.csv` for changed flows, and the per-day gate table.
Threshold changes (`validated_thresholds`) and the final segmentation/matching profile are decided only after that review.
""")
nb = {"cells": cells, "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
      "language_info": {"name": "python"}, "colab": {"provenance": []}}, "nbformat": 4, "nbformat_minor": 5}
json.dump(nb, open(sys.argv[1], "w"), indent=1)
print("cells", len(cells))
