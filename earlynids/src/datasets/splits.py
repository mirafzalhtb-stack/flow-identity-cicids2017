"""Leakage-aware partitioning into train / val / calib / test (v4.1).

Strategies (docs/split_protocol.md):

A ``capture``          whole capture groups (e.g. days) -> one partition each.
B ``chronological``    global time order with explicit boundaries and an embargo.
C ``initiator``        hash of the flow initiator IP. Initiator-disjoint only;
                       responders (servers) WILL appear in several partitions.
                       (v4 called this "group" and the docs over-claimed
                       "host-disjoint".)
C' ``host_components`` connected components of the host graph (initiator and
                       responder). Strictly host-disjoint for all hosts except
                       ``exclude_hosts`` (shared infrastructure, listed in the
                       manifest). Raises if a component is too large to split.
D ``hybrid``           per-capture plan: a capture is assigned whole, or cut into
                       time windows (fractions of its own time span or absolute
                       UTC epoch boundaries) with an embargo at each internal cut.

The unit of assignment is the flow (``flow_uid``). Every packet prefix derived
from a flow inherits the flow's partition (see ``check_prefix_assignment``).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

PARTITIONS = ("train", "val", "calib", "test")
STRATEGIES = ("capture", "chronological", "initiator", "host_components", "hybrid")


class InfeasibleSplitError(ValueError):
    pass


@dataclass
class SplitConfig:
    strategy: str = "chronological"
    fractions: Dict[str, float] = field(default_factory=lambda: {
        "train": 0.6, "val": 0.1, "calib": 0.1, "test": 0.2})
    embargo_s: float = 60.0
    capture_assignment: Optional[Dict[str, str]] = None          # strategy A
    hybrid_plan: Optional[Dict[str, Any]] = None                 # strategy D
    exclude_hosts: List[str] = field(default_factory=list)       # strategy C'
    max_component_fraction: float = 0.5                          # strategy C'
    seed: int = 42

    def validate(self) -> None:
        if self.strategy == "group":
            raise ValueError("strategy 'group' was renamed in v4.1: use 'initiator' (initiator-disjoint) "
                             "or 'host_components' (host-disjoint).")
        if self.strategy not in STRATEGIES:
            raise ValueError(f"strategy must be one of {STRATEGIES}")
        if set(self.fractions) != set(PARTITIONS):
            raise ValueError(f"fractions must define exactly {PARTITIONS}")
        if any(v < 0 for v in self.fractions.values()) or abs(sum(self.fractions.values()) - 1) > 1e-9:
            raise ValueError("fractions must be non-negative and sum to 1")
        if self.embargo_s < 0:
            raise ValueError("embargo_s must be >= 0")
        if self.strategy == "capture":
            if not self.capture_assignment:
                raise ValueError("capture strategy requires capture_assignment")
            bad = set(self.capture_assignment.values()) - set(PARTITIONS)
            if bad:
                raise ValueError(f"unknown partitions in capture_assignment: {bad}")
        if self.strategy == "hybrid":
            if not self.hybrid_plan:
                raise ValueError("hybrid strategy requires hybrid_plan")
            for cap, spec in self.hybrid_plan.items():
                windows = [{"partition": spec}] if isinstance(spec, str) else spec
                if not isinstance(windows, list) or not windows:
                    raise ValueError(f"hybrid_plan[{cap}] must be a partition name or a list of windows")
                last = -np.inf
                for i, w in enumerate(windows):
                    if w.get("partition") not in PARTITIONS:
                        raise ValueError(f"hybrid_plan[{cap}][{i}]: unknown partition {w.get('partition')}")
                    has_f, has_t = "until_fraction" in w, "until_utc" in w
                    if i < len(windows) - 1 and not (has_f ^ has_t):
                        raise ValueError(f"hybrid_plan[{cap}][{i}] needs exactly one of until_fraction/until_utc")
                    if i == len(windows) - 1 and (has_f or has_t):
                        raise ValueError(f"hybrid_plan[{cap}]: the last window must be open-ended")
                    if has_f:
                        v = float(w["until_fraction"])
                        if not (0 < v < 1) or v <= last:
                            raise ValueError(f"hybrid_plan[{cap}]: until_fraction must increase within (0, 1)")
                        last = v
                if any("until_fraction" in w for w in windows) and any("until_utc" in w for w in windows):
                    raise ValueError(f"hybrid_plan[{cap}]: do not mix until_fraction and until_utc")
        if not 0 < self.max_component_fraction <= 1:
            raise ValueError("max_component_fraction must be in (0, 1]")


def _hash_unit(text: str, seed: int) -> float:
    h = hashlib.sha256(f"{seed}:{text}".encode()).hexdigest()
    return int(h[:15], 16) / float(16 ** 15)


def _cuts(fractions: Dict[str, float]):
    out, acc = [], 0.0
    for p in PARTITIONS:
        out.append((p, acc, acc + fractions[p]))
        acc += fractions[p]
    return out


def _embargo_mask(s: np.ndarray, e: np.ndarray, boundaries: List[float], embargo: float) -> np.ndarray:
    mask = np.zeros(len(s), dtype=bool)
    for t in boundaries:
        mask |= (s < t) & (e >= t)  # lifetime crosses the boundary
        if embargo > 0:
            mask |= np.abs(s - t) < embargo
    return mask


def _components(df: pd.DataFrame, exclude: set) -> pd.Series:
    """Union-find over initiator/responder IPs; returns a component id per flow."""
    parent: Dict[str, str] = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a, b in zip(df["src_ip"].astype(str), df["dst_ip"].astype(str)):
        ra = find(a) if a not in exclude else None
        rb = find(b) if b not in exclude else None
        if ra and rb and ra != rb:
            parent[ra] = rb
    comp = [find(a) if a not in exclude else (find(b) if b not in exclude else "__excluded__")
            for a, b in zip(df["src_ip"].astype(str), df["dst_ip"].astype(str))]
    return pd.Series(comp, index=df.index)


def assign_partitions(df: pd.DataFrame, cfg: SplitConfig) -> pd.Series:
    cfg.validate()
    if df["flow_uid"].duplicated().any():
        raise ValueError(f"{int(df['flow_uid'].duplicated().sum())} duplicated flow_uid values; fix before splitting")
    part = pd.Series("excluded", index=df.index, dtype=object)
    s = df["start_time"].to_numpy(float)
    e = df["end_time"].to_numpy(float)
    cuts = _cuts(cfg.fractions)

    if cfg.strategy == "capture":
        part = df["capture_id"].astype(str).map(cfg.capture_assignment).fillna("excluded")

    elif cfg.strategy == "chronological":
        order = df.sort_values(["start_time", "flow_uid"]).index
        n = len(order)
        bounds = []
        for p, lo, hi in cuts:
            a, b = int(round(lo * n)), int(round(hi * n))
            part.loc[order[a:b]] = p
            if 0 < b < n:
                bounds.append(float(df.loc[order[b], "start_time"]))
        part[_embargo_mask(s, e, bounds, cfg.embargo_s)] = "excluded"

    elif cfg.strategy == "initiator":
        u = df["src_ip"].astype(str).map(lambda g: _hash_unit(g, cfg.seed))
        for p, lo, hi in cuts:
            part[(u >= lo) & (u < hi)] = p

    elif cfg.strategy == "host_components":
        excl = set(map(str, cfg.exclude_hosts))
        comp = _components(df, excl)
        sizes = comp[comp != "__excluded__"].value_counts()
        n_ok = int(sizes.sum())
        if n_ok == 0:
            raise InfeasibleSplitError("all flows touch excluded hosts; nothing to split")
        largest = sizes.iloc[0] / n_ok
        if largest > cfg.max_component_fraction:
            raise InfeasibleSplitError(
                f"largest host component holds {largest:.1%} of flows (> {cfg.max_component_fraction:.0%}); "
                "strict host-disjoint splitting is infeasible. Shared servers/gateways connect most hosts. "
                "List shared infrastructure in exclude_hosts (it will be reported), or use 'initiator', "
                "'capture' or 'hybrid' and report the limitation.")
        order = sorted(sizes.index, key=lambda c: _hash_unit(c, cfg.seed))
        target = {p: f * n_ok for p, f in cfg.fractions.items()}
        filled = {p: 0 for p in PARTITIONS}
        mapping = {}
        for c in order:  # fill partitions in fixed order, deterministic
            p = next((q for q in PARTITIONS if filled[q] + sizes[c] <= target[q] + 1e-9),
                     min(PARTITIONS, key=lambda q: filled[q] - target[q]))
            mapping[c] = p
            filled[p] += int(sizes[c])
        part = comp.map(mapping).fillna("excluded")

    else:  # hybrid
        caps = df["capture_id"].astype(str)
        for cap, spec in cfg.hybrid_plan.items():
            m = (caps == str(cap)).to_numpy()
            if not m.any():
                continue
            windows = [{"partition": spec}] if isinstance(spec, str) else spec
            if len(windows) == 1:
                part[m] = windows[0]["partition"]
                continue
            t0, t1 = s[m].min(), e[m].max()
            bounds = [t0 + float(w["until_fraction"]) * (t1 - t0) if "until_fraction" in w else float(w["until_utc"])
                      for w in windows[:-1]]
            lo = -np.inf
            for w, hi in zip(windows, bounds + [np.inf]):
                sel = m & (s >= lo) & (s < hi)
                part[sel] = w["partition"]
                lo = hi
            sub = np.zeros(len(df), dtype=bool)
            sub[m] = _embargo_mask(s[m], e[m], bounds, cfg.embargo_s)
            part[sub] = "excluded"
    return part


def leakage_report(df: pd.DataFrame, part: pd.Series) -> dict:
    used = {p: df[part == p] for p in PARTITIONS}
    rep: dict = {"flow_overlap": {}, "initiator_overlap": {}, "any_endpoint_overlap": {},
                 "capture_overlap": {}, "time_overlap_within_capture": {}, "time_ranges": {}}
    eps = {p: set(d["src_ip"].astype(str)) | set(d["dst_ip"].astype(str)) for p, d in used.items()} if "dst_ip" in df else {}
    for p, d in used.items():
        rep["time_ranges"][p] = [float(d["start_time"].min()), float(d["end_time"].max())] if len(d) else None
    for i, a in enumerate(PARTITIONS):
        for b in PARTITIONS[i + 1:]:
            pair = f"{a}-{b}"
            A, B = used[a], used[b]
            rep["flow_overlap"][pair] = int(len(set(A["flow_uid"]) & set(B["flow_uid"])))
            if "src_ip" in df:
                rep["initiator_overlap"][pair] = int(len(set(A["src_ip"]) & set(B["src_ip"])))
            if eps:
                rep["any_endpoint_overlap"][pair] = int(len(eps[a] & eps[b]))
            if "capture_id" in df:
                shared_caps = set(A["capture_id"]) & set(B["capture_id"])
                rep["capture_overlap"][pair] = sorted(map(str, shared_caps))
                ov = 0
                for c in shared_caps:
                    a_c, b_c = A[A["capture_id"] == c], B[B["capture_id"] == c]
                    if a_c["start_time"].min() <= b_c["end_time"].max() and b_c["start_time"].min() <= a_c["end_time"].max():
                        ov += 1
                rep["time_overlap_within_capture"][pair] = ov
    present = [p for p in PARTITIONS if rep["time_ranges"][p] is not None]
    rep["chronological_order_ok"] = all(rep["time_ranges"][a][1] <= rep["time_ranges"][b][0] + 1e-9
                                        for a, b in zip(present, present[1:]))
    return rep


def load_manifest_for_training(out_dir: Path) -> dict:
    """Load and verify a split manifest for supervised use (Phase 2 entry point).

    Refuses diagnostic-only manifests and assignment files whose hash does not match.
    """
    out_dir = Path(out_dir)
    man = json.loads((out_dir / "split_manifest.json").read_text(encoding="utf-8"))
    if man.get("diagnostic_only") or man.get("gate_check_skipped"):
        raise ValueError("manifest is diagnostic_only (created with --skip-gate-check); not valid for training")
    digest = hashlib.sha256((out_dir / "split_assignment.csv").read_bytes()).hexdigest()
    if digest != man.get("assignment_sha256"):
        raise ValueError("split_assignment.csv does not match the manifest hash (modified after creation?)")
    return man


def check_prefix_assignment(prefix_flow_uids: pd.Series, assignment: pd.DataFrame) -> dict:
    """Every prefix row must map to exactly one partition through its flow_uid."""
    amap = assignment.drop_duplicates()
    multi = amap["flow_uid"].duplicated(keep=False)
    missing = ~prefix_flow_uids.isin(amap["flow_uid"])
    return {"ok": not bool(multi.any()) and not bool(missing.any()),
            "flows_in_multiple_partitions": int(amap.loc[multi, "flow_uid"].nunique()),
            "prefixes_without_assignment": int(missing.sum())}


def build_manifest(df: pd.DataFrame, part: pd.Series, cfg: SplitConfig, extra: Optional[dict] = None) -> dict:
    label_col = "binary_label" if "binary_label" in df.columns else None
    counts = {}
    for p in PARTITIONS + ("excluded",):
        sub = df[part == p]
        counts[p] = {"flows": int(len(sub))}
        if label_col:
            counts[p]["by_label"] = {str(k): int(v) for k, v in sub[label_col].value_counts(dropna=False).items()}
        if "label" in sub:
            counts[p]["by_family"] = {str(k): int(v) for k, v in sub["label"].value_counts().items()}
    leak = leakage_report(df, part)
    guarantees = {
        "flow_disjoint": True,
        "initiator_disjoint": cfg.strategy in ("initiator", "host_components"),
        "host_disjoint": cfg.strategy == "host_components",
        "host_disjoint_exceptions": list(cfg.exclude_hosts) if cfg.strategy == "host_components" else None,
        "capture_disjoint": cfg.strategy == "capture",
        "time_ordered": cfg.strategy == "chronological",
    }
    warnings = []
    for p in PARTITIONS:
        if counts[p]["flows"] == 0:
            warnings.append(f"partition {p} is empty")
        elif label_col and df.loc[part == p, label_col].dropna().nunique() < 2:
            warnings.append(f"partition {p} contains fewer than two classes")
    if any(leak["flow_overlap"].values()):
        warnings.append("flow_uid overlap between partitions (must be zero)")
    if guarantees["host_disjoint"]:
        excl = set(map(str, cfg.exclude_hosts))
        used = {p: df[part == p] for p in PARTITIONS}
        for i, a in enumerate(PARTITIONS):
            for b in PARTITIONS[i + 1:]:
                ea = (set(used[a]["src_ip"].astype(str)) | set(used[a]["dst_ip"].astype(str))) - excl
                eb = (set(used[b]["src_ip"].astype(str)) | set(used[b]["dst_ip"].astype(str))) - excl
                if ea & eb:
                    warnings.append(f"host overlap {a}-{b} despite host_components (BUG)")
    man = {"manifest_version": "4.1", "config": asdict(cfg), "seed": cfg.seed, "guarantees": guarantees,
           "counts": counts, "leakage": leak, "warnings": warnings}
    if extra:
        man.update(extra)
    return man


def write_manifest(df: pd.DataFrame, part: pd.Series, manifest: dict, out_dir: Path, overwrite: bool = False) -> None:
    out_dir = Path(out_dir)
    if out_dir.exists() and any(out_dir.iterdir()) and not overwrite:
        raise FileExistsError(f"split directory {out_dir} is not empty; manifests are immutable. "
                              "Choose a new --out-dir (e.g. split_v2) or pass --overwrite.")
    out_dir.mkdir(parents=True, exist_ok=True)
    for f in out_dir.glob("split_*"):
        f.chmod(0o644)  # allow an explicit --overwrite to replace read-only files
    assign_path = out_dir / "split_assignment.csv"
    df[["flow_uid"]].assign(partition=part.values).to_csv(assign_path, index=False)
    manifest = dict(manifest)
    manifest["assignment_sha256"] = hashlib.sha256(assign_path.read_bytes()).hexdigest()
    (out_dir / "split_manifest.json").write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
    for f in (assign_path, out_dir / "split_manifest.json"):
        try:
            f.chmod(0o444)  # read-only marker; best effort on Windows
        except OSError:
            pass
