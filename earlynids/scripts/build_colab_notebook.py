"""Regenerate notebooks/EarlyNIDS_v4_2_Colab.ipynb:  python scripts/build_colab_notebook.py notebooks/EarlyNIDS_v4_2_Colab.ipynb"""
import json, sys
cells = []
def md(text): cells.append({"cell_type": "markdown", "id": f"c{len(cells):02d}", "metadata": {}, "source": text.strip("\n").splitlines(True)})
def code(text): cells.append({"cell_type": "code", "id": f"c{len(cells):02d}", "metadata": {}, "execution_count": None, "outputs": [], "source": text.strip("\n").splitlines(True)})

md("""
# EarlyNIDS v4.2 — CIC-IDS2017 real-data integration (Google Colab)

This notebook runs the **existing v4.2 CLI tools** on the dataset stored in Google Drive, **one capture day at a time**.
It performs data integration and validation only (no model training).

Rules that the code enforces:
* Raw files on Drive are only read, never modified. Outputs go to a separate run directory.
* The label time-zone offset is **never selected automatically**. You set it after reviewing the evidence (step 7).
* Only uniquely matched flows are trusted. A failed quality gate (exit code 4) blocks splitting/training.
* Each step can be resumed: completed outputs are detected and skipped.

Before running: upload `EarlyNIDS_v4_2.zip` to `MyDrive/EarlyNIDS/code/`.
""")
md("## 1. Mount Google Drive")
code("""
from google.colab import drive
drive.mount('/content/drive')
""")
md("## 2. Paths (edit if your Drive layout differs)")
code("""
from pathlib import Path
DATASET_ROOT = '/content/drive/MyDrive/EarlyNIDS/datasets/CIC-IDS2017'
CODE_ZIP     = '/content/drive/MyDrive/EarlyNIDS/code/EarlyNIDS_v4_2.zip'
RUN_ROOT     = '/content/drive/MyDrive/EarlyNIDS/runs/v4_2'      # all outputs (persist across sessions)
REPO         = '/content/EarlyNIDS_v42'                            # code is unpacked to fast local disk
LOCAL_CACHE  = '/content/pcap_cache'                               # one PCAP at a time is copied here
Path(RUN_ROOT).mkdir(parents=True, exist_ok=True)
print(Path(DATASET_ROOT).exists(), Path(CODE_ZIP).exists())
""")
md("## 3. Unpack the code and install dependencies")
code("""
import os, zipfile
if not Path(REPO).exists():
    with zipfile.ZipFile(CODE_ZIP) as z:
        z.extractall('/content')
%cd {REPO}
!pip -q install "scapy>=2.5,<3" pyarrow pyyaml
!python -m pytest -q -p no:logging 2>&1 | tail -n 3
""")
md("## 4. Dataset layout: presence, counts, sizes, Parquet row counts (not an integrity verification)")
code("""
!python -m scripts.check_dataset_layout --root "{DATASET_ROOT}" --output "{RUN_ROOT}/layout.json" --overwrite
""")
md("## 5. Inspect label-file schemas (traffic_labels and machine_learning)")
code("""
!python -m scripts.inspect_label_csv --files "{DATASET_ROOT}/traffic_labels/*" --nrows 50000 --output "{RUN_ROOT}/inspect_traffic_labels.json" --overwrite > /dev/null
!python -m scripts.inspect_label_csv --files "{DATASET_ROOT}/machine_learning/*" --nrows 50000 --output "{RUN_ROOT}/inspect_machine_learning.json" --overwrite > /dev/null
import json
for name in ('inspect_traffic_labels.json', 'inspect_machine_learning.json'):
    for f in json.load(open(f'{RUN_ROOT}/{name}')):
        print(f"{f['file'][:60]:60s} rows={f['total_rows']} matchable={f['matchable_with_default_columns']} "
              f"ts_dtype={f.get('timestamp_dtype')} dup_headers={f['duplicated_normalized_headers']}")
""")
md("""
## 6. Lineage / discrepancy audit (e.g. Thursday WebAttacks: 458,968 vs 170,366 rows)
Observations only; the report never states a cause. Read `lineage_audit.md`.
""")
code("""
!python -m scripts.audit_label_lineage --dir-a "{DATASET_ROOT}/traffic_labels" --dir-b "{DATASET_ROOT}/machine_learning" --out-dir "{RUN_ROOT}/lineage" --overwrite
print(open(f'{RUN_ROOT}/lineage/lineage_audit.md').read()[:6000])
""")
md("""
## 7. Smoke test on real data: first 300,000 frames of Monday + time-offset evidence
`process_day` stops **before** label matching while `labeling.utc_offset_hours` is unset.
""")
code("""
import shutil
CONFIG = f'{RUN_ROOT}/run_config.yaml'
if not Path(CONFIG).exists():
    shutil.copy(f'{REPO}/configs/cicids2017_colab.yaml', CONFIG)   # your editable copy on Drive
!python -m scripts.process_day --root "{DATASET_ROOT}" --day monday --out-root "{RUN_ROOT}/smoke" --config "{CONFIG}" --max-frames 300000
ev = json.load(open(f'{RUN_ROOT}/smoke/monday/offset_evidence.json'))
print('evidence best offset:', ev.get('evidence_best_offset_hours'))
print('ranking:', ev.get('ranking'))
print('flags:', ev.get('flags'))
print('label timestamp kinds:', ev.get('label_timestamp_kinds'), 'resolution:', ev.get('label_timestamp_resolution_s'))
""")
md("""
## 8. Set the offset EXPLICITLY (your decision)
Review `offset_evidence.json` and the CIC-IDS2017 documentation. Write the value and your justification below.
Nothing is applied automatically. If the flags mention `possible_12h_ambiguity`, also review `ambiguous_12h`.
""")
code("""
import yaml
UTC_OFFSET_HOURS = None          # <-- set explicitly, e.g. a number taken from the evidence above
JUSTIFICATION = ''               # <-- e.g. 'offset_evidence: support 0.97, no flags; dataset docs: ...'
assert UTC_OFFSET_HOURS is not None and JUSTIFICATION, 'Set UTC_OFFSET_HOURS and JUSTIFICATION first.'
cfg = yaml.safe_load(open(CONFIG))
cfg['labeling']['utc_offset_hours'] = float(UTC_OFFSET_HOURS)
yaml.safe_dump(cfg, open(CONFIG, 'w'), sort_keys=False)
open(f'{RUN_ROOT}/offset_decision.txt', 'w').write(f'utc_offset_hours={UTC_OFFSET_HOURS}\\n{JUSTIFICATION}\\n')
print(open(CONFIG).read()[:1500])
""")
md("""
## 9. Smoke-test matching + quality gate (partial capture: diagnostic only)
The partial capture contains only the first frames, so many CSV rows have no PCAP counterpart and some
flows are cut at the end. A FAIL here is expected and informative; inspect the reports.
""")
code("""
!python -m scripts.process_day --root "{DATASET_ROOT}" --day monday --out-root "{RUN_ROOT}/smoke" --config "{CONFIG}" --max-frames 300000
g = json.load(open(f'{RUN_ROOT}/smoke/monday/labelled.quality_gate.json'))
print('PASSED:', g['passed']); print(json.dumps(g['totals'], indent=1)); print(json.dumps(g['match_reasons'], indent=1))
for c in g['checks']:
    print(('OK   ' if c['passed'] else 'FAIL ') + c['check'], c['value'], c['threshold'])
""")
md("""
## 10. Full days, one at a time (resumable)
Each day is copied to local disk, processed, and the copy is deleted. If the session disconnects, re-run the
cell: completed steps are skipped. Start with one day and review its reports before the next.
""")
code("""
import subprocess
DAYS = ['monday']   # then add 'tuesday', 'wednesday', 'thursday', 'friday' one by one
for day in DAYS:
    r = subprocess.run(['python', '-m', 'scripts.process_day', '--root', DATASET_ROOT, '--day', day,
                        '--out-root', f'{RUN_ROOT}/full', '--config', CONFIG, '--local-cache', LOCAL_CACHE])
    print(day, 'exit code', r.returncode, '(0 ok, 4 gate failed -> review reports, 2 input problem)')
""")
md("## 11. Review gate results per day")
code("""
import pandas as pd
rows = []
for p in sorted(Path(f'{RUN_ROOT}/full').glob('*/labelled.quality_gate.json')):
    g = json.load(open(p)); t = g['totals']
    rows.append({'day': p.parent.name, 'passed': g['passed'], 'flows': t['pcap_flows'], 'unique': t['unique_matches'],
                 'ambiguous': t['ambiguous_same_label'] + t['ambiguous_shared_row'], 'conflict': t['conflicting_labels'],
                 'time_inconsistent': t['time_inconsistent'], 'unmatched': t['unmatched_flows'],
                 'trusted': t['trusted_samples'], 'failed_checks': [c['check'] for c in g['checks'] if not c['passed']]})
pd.DataFrame(rows)
""")
md("""
## 12. Next steps (not automated here)
* Review `problem_flows.csv`, `invalid_csv_rows.csv`, the lineage audit, and spot-check trusted attack flows.
* Record threshold decisions in `docs/dataset_quality_gate.md` before any training (`validated_thresholds`).
* Concatenate the per-day labelled tables, gate the combined table, then run `scripts.make_splits`.
* Phase 2 (GRU baselines) starts only after the real-data acceptance criteria in `docs/v4_2_data_audit_protocol.md` are met.
""")
nb = {"cells": cells, "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
      "language_info": {"name": "python"}, "colab": {"provenance": []}}, "nbformat": 4, "nbformat_minor": 5}
json.dump(nb, open(sys.argv[1], "w"), indent=1)
print("cells", len(cells))
