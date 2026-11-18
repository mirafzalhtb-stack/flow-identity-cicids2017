"""Dataset quality gate: blocks untrustworthy labelled data from model training.

All thresholds are PROVISIONAL ENGINEERING THRESHOLDS chosen before seeing real
CIC-IDS2017 data. They are not derived from a statistical model and must be
reviewed after the first real-data audit (docs/dataset_quality_gate.md).
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import pandas as pd

GATE_VERSION = "4.3.0"
INTEGRITY_RATE_CHECKS = ("match_rate", "unmatched_rate", "conflict_rate", "ambiguous_rate", "time_inconsistent_rate")
THRESHOLD_NAMES = ("min_match_rate", "max_unmatched_rate", "max_conflict_rate", "max_ambiguous_rate",
                   "max_time_inconsistent_rate", "max_invalid_csv_rate", "max_empty_row_rate", "min_trusted_per_class",
                   "min_trusted_coverage")


@dataclass
class GateConfig:
    min_match_rate: float = 0.90           # unique / valid-prefix flows with valid fields
    max_unmatched_rate: float = 0.10
    max_conflict_rate: float = 0.01
    max_ambiguous_rate: float = 0.05       # ambiguous_same_label + ambiguous_shared_row
    max_time_inconsistent_rate: float = 0.05
    max_invalid_csv_rate: float = 0.01    # malformed records among NON-EMPTY label records
    max_empty_row_rate: float = 1.0       # report-only by default; fully empty rows are not label records
    min_trusted_per_class: int = 100       # per binary class
    require_both_classes: bool = True
    require_unique_flow_uid: bool = True
    min_trusted_coverage: float = 0.0     # trusted / valid-early-prefix flows (0 = report only)
    # Names of thresholds that have been validated on real data, each with a documented
    # justification (e.g. {"max_conflict_rate": "docs/dataset_quality_gate.md#2026-11-20"}).
    # Every threshold NOT listed here is reported as PROVISIONAL.
    validated_thresholds: Optional[Dict[str, str]] = None
    provisional: bool = True

    def validate(self) -> None:
        unknown = set(self.validated_thresholds or {}) - set(THRESHOLD_NAMES)
        if unknown:
            raise ValueError(f"validated_thresholds contains unknown names: {sorted(unknown)}")
        for k, why in (self.validated_thresholds or {}).items():
            if not str(why).strip():
                raise ValueError(f"validated_thresholds[{k}] needs a justification reference")
        for k, v in asdict(self).items():
            if k.startswith(("min_", "max_")) and k != "min_trusted_per_class" and not (0 <= v <= 1):
                raise ValueError(f"{k} must be in [0, 1]")
        if self.min_trusted_per_class < 0:
            raise ValueError("min_trusted_per_class must be >= 0")


def _q(s: pd.Series) -> dict:
    s = pd.to_numeric(s, errors="coerce").dropna()
    if s.empty:
        return {"n": 0}
    return {"n": int(len(s)), "min": float(s.min()), "p01": float(s.quantile(.01)), "p50": float(s.median()),
            "p99": float(s.quantile(.99)), "max": float(s.max()), "mean_abs": float(s.abs().mean())}


HINTS = {
    "match_rate": "Low unique-match rate: check utc_offset_hours (scripts.inspect_label_csv + time_offset diagnostics), "
                  "timestamp_formats, duration_unit and whether the CSV belongs to the same capture day.",
    "unmatched_rate": "Many flows have no CSV row: wrong CSV file/day, or flow segmentation differs (timeouts).",
    "conflict_rate": "Conflicting labels for start-aligned rows: inspect *.problem_flows.csv; consider corrected labels.",
    "ambiguous_rate": "Many ambiguous matches: start tolerance may be too wide or the CSV contains duplicated rows.",
    "time_inconsistent_rate": "Start or duration inconsistent: review start/duration tolerances and csv_active_timeout_s.",
    "invalid_csv_rate": "Many invalid CSV rows: see *.invalid_rows.csv reasons (malformed timestamps, ports, IPs).",
    "class_counts": "Too few trusted samples in a class: more capture days or a review of the label audit are needed.",
    "trusted_coverage": "Low share of trusted samples among valid early-prefix flows; see excluded_by_reason.",
    "empty_row_rate": "Many fully empty label rows; see the lineage audit (scripts.audit_label_lineage).",
    "flow_uid_unique": "Duplicate flow_uid: flows from several extractions were concatenated without unique capture ids.",
}


def _integrity_rates(labelled: pd.DataFrame):
    valid_prefix = labelled["valid_early_prefix"].astype(bool) if "valid_early_prefix" in labelled else pd.Series(True, index=labelled.index)
    status = labelled["match_status"].astype(str)
    base = valid_prefix & (status != "invalid_flow")
    nb = int(base.sum())
    sc = status[base].value_counts().to_dict()
    rate = lambda k: (sum(sc.get(x, 0) for x in k) / nb) if nb else 0.0
    rates = {
        "match_rate": rate(["unique"]),
        "unmatched_rate": rate(["unmatched"]),
        "conflict_rate": rate(["conflict"]),
        "ambiguous_rate": rate(["ambiguous_same_label", "ambiguous_shared_row"]),
        "time_inconsistent_rate": rate(["time_inconsistent"]),
    }
    return rates, sc, nb, valid_prefix, status


def _rate_ok(name: str, value: float, cfg: GateConfig) -> bool:
    lim = {"match_rate": cfg.min_match_rate, "unmatched_rate": cfg.max_unmatched_rate,
           "conflict_rate": cfg.max_conflict_rate, "ambiguous_rate": cfg.max_ambiguous_rate,
           "time_inconsistent_rate": cfg.max_time_inconsistent_rate}[name]
    return value >= lim if name == "match_rate" else value <= lim


def evaluate(labelled: pd.DataFrame, csv_stats: dict, cfg: GateConfig, scope: str = "capture") -> dict:
    """Three separate verdicts (v4.3):

    * capture_integrity  -- label-matching quality; must hold globally AND for every capture.
    * class_coverage     -- enough trusted samples of every required class.
    * training_eligible  -- integrity AND coverage. Only eligible data may be split for training.

    ``passed`` (kept for compatibility with v4.1/v4.2 consumers) now means capture_integrity.
    A BENIGN-only capture (e.g. Monday) can therefore pass integrity while remaining
    ineligible for training.
    """
    cfg.validate()
    if scope not in ("capture", "dataset"):
        raise ValueError("scope must be 'capture' or 'dataset'")
    n = int(len(labelled))
    rates, sc, nb, valid_prefix, status = _integrity_rates(labelled)
    total_csv = int(csv_stats.get("total_csv_records", 0))
    invalid_csv = int(csv_stats.get("invalid_csv_records", 0))
    empty_csv = int(csv_stats.get("invalid_by_reason", {}).get("empty_row", 0))
    nonempty = total_csv - empty_csv
    rates["invalid_csv_rate"] = (invalid_csv - empty_csv) / nonempty if nonempty else 0.0
    rates["empty_row_rate"] = empty_csv / total_csv if total_csv else 0.0
    trusted = labelled["trusted"].astype(bool)
    cls = labelled.loc[trusted, "binary_label"].value_counts().to_dict()
    checks: List[dict] = []

    def check(name, value, ok, threshold, kind="integrity"):
        checks.append({"check": name, "kind": kind, "value": value, "threshold": threshold, "passed": bool(ok),
                       "hint": "" if ok else HINTS.get(name, "")})

    check("match_rate", rates["match_rate"], rates["match_rate"] >= cfg.min_match_rate, f">= {cfg.min_match_rate}")
    check("unmatched_rate", rates["unmatched_rate"], rates["unmatched_rate"] <= cfg.max_unmatched_rate, f"<= {cfg.max_unmatched_rate}")
    check("conflict_rate", rates["conflict_rate"], rates["conflict_rate"] <= cfg.max_conflict_rate, f"<= {cfg.max_conflict_rate}")
    check("ambiguous_rate", rates["ambiguous_rate"], rates["ambiguous_rate"] <= cfg.max_ambiguous_rate, f"<= {cfg.max_ambiguous_rate}")
    check("time_inconsistent_rate", rates["time_inconsistent_rate"], rates["time_inconsistent_rate"] <= cfg.max_time_inconsistent_rate, f"<= {cfg.max_time_inconsistent_rate}")
    check("invalid_csv_rate", rates["invalid_csv_rate"], rates["invalid_csv_rate"] <= cfg.max_invalid_csv_rate, f"<= {cfg.max_invalid_csv_rate}")
    check("empty_row_rate", rates["empty_row_rate"], rates["empty_row_rate"] <= cfg.max_empty_row_rate, f"<= {cfg.max_empty_row_rate}")
    needed = ["ATTACK", "BENIGN"] if cfg.require_both_classes else list(cls)
    ok_cls = all(cls.get(c, 0) >= cfg.min_trusted_per_class for c in needed) and (bool(cls) or not cfg.require_both_classes)
    check("class_counts", {k: int(v) for k, v in cls.items()}, ok_cls, f"each of {needed} >= {cfg.min_trusted_per_class}",
          kind="coverage")
    coverage = float(trusted.sum() / int(valid_prefix.sum())) if int(valid_prefix.sum()) else 0.0
    rates["trusted_coverage"] = coverage
    check("trusted_coverage", coverage, coverage >= cfg.min_trusted_coverage, f">= {cfg.min_trusted_coverage}")
    if cfg.require_unique_flow_uid:
        dup = int(labelled["flow_uid"].duplicated().sum())
        check("flow_uid_unique", dup, dup == 0, "== 0 duplicates")

    per_capture = {}
    for cap_id, sub in labelled.groupby("capture_id", sort=True):
        r, _, nbc, _, _ = _integrity_rates(sub)
        failed = [k for k in INTEGRITY_RATE_CHECKS if not _rate_ok(k, r[k], cfg)]
        per_capture[str(cap_id)] = {"matchable_flows": nbc, "rates": r, "failed": failed, "passed": not failed}
    integrity_ok = all(c["passed"] for c in checks if c["kind"] == "integrity") and \
        all(v["passed"] for v in per_capture.values())
    coverage_ok = all(c["passed"] for c in checks if c["kind"] == "coverage")
    unique = labelled[status == "unique"]
    cap = (labelled.assign(_valid=valid_prefix, _trusted=trusted)
           .groupby("capture_id")
           .agg(flows=("flow_uid", "size"), valid_prefix=("_valid", "sum"), trusted=("_trusted", "sum")))
    cap_status = pd.crosstab(labelled["capture_id"], status)
    cap = cap.join(cap_status)
    excl = labelled.loc[~trusted, "exclusion_reason"].value_counts()
    report = {
        "gate_version": GATE_VERSION,
        "scope": scope,
        "passed": integrity_ok,  # == capture_integrity.passed (see docstring)
        "capture_integrity": {"passed": integrity_ok, "per_capture": per_capture},
        "class_coverage": {"passed": coverage_ok, "required": needed, "min_per_class": cfg.min_trusted_per_class},
        "training_eligible": bool(integrity_ok and coverage_ok),
        "thresholds_provisional": cfg.provisional or len(cfg.validated_thresholds or {}) < len(THRESHOLD_NAMES),
        "threshold_status": {n: ("validated: " + (cfg.validated_thresholds or {})[n]) if n in (cfg.validated_thresholds or {})
                             else "provisional" for n in THRESHOLD_NAMES},
        "thresholds": asdict(cfg),
        "label_file_formats": sorted({v.get("format", "csv") for v in csv_stats.get("files", {}).values()}),
        "totals": {
            "pcap_flows": n, "valid_early_prefix_flows": int(valid_prefix.sum()),
            "matchable_flows": nb, "total_csv_records": total_csv, "invalid_csv_records": invalid_csv,
            "empty_csv_records": empty_csv, "malformed_nonempty_csv_records": invalid_csv - empty_csv,
            "unique_matches": int(sc.get("unique", 0)),
            "ambiguous_same_label": int(sc.get("ambiguous_same_label", 0)),
            "ambiguous_shared_row": int(sc.get("ambiguous_shared_row", 0)),
            "conflicting_labels": int(sc.get("conflict", 0)),
            "time_inconsistent": int(sc.get("time_inconsistent", 0)),
            "unmatched_flows": int(sc.get("unmatched", 0)),
            "invalid_flows": int((status == "invalid_flow").sum()),
            "trusted_samples": int(trusted.sum()),
        },
        "rates": rates,
        "class_distribution_trusted_binary": {k: int(v) for k, v in cls.items()},
        "class_distribution_trusted_label": {k: int(v) for k, v in labelled.loc[trusted, "label"].value_counts().items()},
        "capture_distribution": json.loads(cap.reset_index().to_json(orient="records")),
        "timestamp_alignment_unique_s": _q(unique["start_offset_s"]),
        "duration_diff_unique_s": _q(unique["duration_diff_s"]),
        "duration_diff_mismatched_s": _q(labelled.loc[labelled["match_reason"] == "duration_mismatch", "duration_diff_s"]),
        "orientation_unique": {str(k): int(v) for k, v in unique["orientation"].value_counts().items()},
        "used_12h_shift_unique": int(unique["used_12h_shift"].astype(bool).sum()),
        "match_reasons": {str(k): int(v) for k, v in labelled["match_reason"].value_counts().items()},
        "excluded_by_reason": {str(k): int(v) for k, v in excl.items()},
        "invalid_csv_by_reason": csv_stats.get("invalid_by_reason", {}),
        "csv_files": csv_stats.get("files", {}),
        "checks": checks,
        "note": "Flow-level labels only. Thresholds are provisional engineering thresholds.",
    }
    return report


def write_reports(report: dict, labelled: pd.DataFrame, out_prefix: Path) -> Dict[str, str]:
    out_prefix = Path(out_prefix)
    out_prefix.parent.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": str(out_prefix.with_name(out_prefix.name + ".quality_gate.json")),
        "checks_csv": str(out_prefix.with_name(out_prefix.name + ".quality_gate_checks.csv")),
        "exclusions_csv": str(out_prefix.with_name(out_prefix.name + ".exclusions_by_reason.csv")),
        "captures_csv": str(out_prefix.with_name(out_prefix.name + ".capture_summary.csv")),
    }
    Path(paths["json"]).write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    pd.DataFrame(report["checks"]).assign(value=lambda d: d["value"].astype(str)).to_csv(paths["checks_csv"], index=False)
    pd.Series(report["excluded_by_reason"], name="count").rename_axis("reason").to_csv(paths["exclusions_csv"])
    pd.DataFrame(report["capture_distribution"]).to_csv(paths["captures_csv"], index=False)
    return paths


def format_failures(report: dict) -> List[str]:
    lines = [f"FAILED [{c.get('kind', 'integrity')}] {c['check']}: value={c['value']} required {c['threshold']}. {c['hint']}"
             for c in report["checks"] if not c["passed"]]
    for cap, v in report.get("capture_integrity", {}).get("per_capture", {}).items():
        if not v["passed"]:
            lines.append(f"FAILED [integrity] capture {cap}: {v['failed']}")
    return lines
