"""Conservative flow-to-label matching for CIC-IDS2017 style labelled flow CSVs (v4.1).

Scientific-integrity rules enforced here (see docs/label_matching_policy.md):

* Only a **unique** match is trusted. A flow is ``unique`` only when exactly one
  CSV row (i) has the same protocol and unordered endpoint pair, (ii) starts
  within the start tolerance of the flow start, (iii) has a consistent
  duration, (iv) no other start-aligned row carries a different label, and
  (v) that CSV row is not also the unique match of another PCAP flow.
  A shared label is never used to resolve several candidates.
* Every flow receives ``match_status`` + ``match_reason`` + numeric evidence
  (signed start offset, duration difference, candidate counts, orientation).
  No confidence percentages are produced, because none are calibrated.
* Unmatched, ambiguous, conflicting and time-inconsistent flows have
  ``binary_label = None`` and are never labelled BENIGN.
* Format defaults (column names, timestamp formats, duration unit, time zone)
  are placeholders. The real CIC-IDS2017 CSVs have NOT been inspected.
  ``utc_offset_hours`` has no default.
* Flow-level labels are not packet-level onset annotations.

The implementation is vectorised with pandas (merge on a canonical key), so a
multi-million-row CSV does not create one Python object per row (v4 did).
"""
from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd

log = logging.getLogger(__name__)

TRUSTED_STATUS = "unique"
STATUSES = ("unique", "ambiguous_same_label", "ambiguous_shared_row", "conflict",
            "time_inconsistent", "unmatched", "invalid_flow")
PROTO_NAMES = {"6": 6, "tcp": 6, "17": 17, "udp": 17}
REQUIRED_FIELDS = ("src_ip", "src_port", "dst_ip", "dst_port", "protocol", "timestamp", "duration", "label")


class LabelSchemaError(ValueError):
    """The CSV does not contain the columns required for flow matching."""


@dataclass
class LabelConfig:
    utc_offset_hours: Optional[float] = None  # REQUIRED; local time of the CSV timestamps
    columns: Dict[str, str] = field(default_factory=lambda: {
        "src_ip": "source ip", "src_port": "source port",
        "dst_ip": "destination ip", "dst_port": "destination port",
        "protocol": "protocol", "timestamp": "timestamp",
        "duration": "flow duration", "label": "label",
    })
    timestamp_formats: Sequence[str] = ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M",
                                        "%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %I:%M %p")
    duration_unit: str = "us"
    ambiguous_12h: bool = False
    # Provisional engineering tolerances (not empirically calibrated):
    start_tolerance_s: float = 1.0      # added to the timestamp resolution (1 s or 60 s)
    duration_abs_tolerance_s: float = 1.0
    duration_rel_tolerance: float = 0.10
    check_duration: bool = True
    csv_active_timeout_s: Optional[float] = None  # if the CSV tool splits long flows (VERIFY)
    collapse_exact_duplicate_rows: bool = False
    benign_labels: Sequence[str] = ("BENIGN",)
    encoding: str = "latin-1"
    timestamp_epoch_unit: Optional[str] = None  # set ('s','ms','us') only if a file stores epoch numbers; UTC assumed
    optional_columns: Dict[str, str] = field(default_factory=lambda: {
        "flow_id": "flow id", "fwd_packets": "total fwd packets", "bwd_packets": "total backward packets"})
    # ---- v4.3 identity evidence (matching_mode = "evidence_v43"; "legacy_v41" reproduces v4.1/v4.2) ----
    matching_mode: str = "evidence_v43"
    strict_duration_abs_s: float = 0.001   # PROVISIONAL: 1 ms floor (both sources have microsecond timestamps)
    strict_duration_rel: float = 0.01      # PROVISIONAL: 1 % of the longer duration
    identity_margin: float = 2.0           # runner-up must miss the strict tolerance by >= this factor
    packet_check: str = "report"           # off | report | require (needs packet-count columns on both sides)
    packet_tolerance: int = 0              # PROVISIONAL, used only when packet_check = require
    eof_censoring: bool = True             # flows ended by end-of-capture: duration is a lower bound
    chunksize: int = 100_000          # rows per read chunk / Parquet batch (memory/speed trade-off)
    match_chunk_size: int = 100_000   # PCAP flows per merge chunk

    def validate(self) -> None:
        if self.utc_offset_hours is None:
            raise ValueError("utc_offset_hours must be set explicitly after inspecting the label CSVs "
                             "and dataset documentation. No default is assumed.")
        if self.matching_mode not in ("evidence_v43", "legacy_v41"):
            raise ValueError("matching_mode must be 'evidence_v43' or 'legacy_v41'")
        if self.packet_check not in ("off", "report", "require"):
            raise ValueError("packet_check must be off, report or require")
        if self.strict_duration_abs_s < 0 or self.strict_duration_rel < 0 or self.identity_margin < 1:
            raise ValueError("strict tolerances must be >= 0 and identity_margin >= 1")
        if self.packet_tolerance < 0:
            raise ValueError("packet_tolerance must be >= 0")
        if self.timestamp_epoch_unit not in (None, "s", "ms", "us"):
            raise ValueError("timestamp_epoch_unit must be null, s, ms or us")
        if self.duration_unit not in ("us", "ms", "s"):
            raise ValueError("duration_unit must be us, ms or s")
        for name in ("start_tolerance_s", "duration_abs_tolerance_s", "duration_rel_tolerance"):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} must be >= 0")
        if self.start_tolerance_s >= 6 * 3600 and self.ambiguous_12h:
            raise ValueError("start tolerance too large for 12-hour disambiguation")
        missing = [k for k in REQUIRED_FIELDS if k not in self.columns]
        if missing:
            raise ValueError(f"columns mapping lacks {missing}")


def config_from_dict(conf: dict) -> LabelConfig:
    conf = dict(conf)
    if "accepted_statuses" in conf:
        raise ValueError("'accepted_statuses' was removed in v4.1: only unique matches are trusted. "
                         "Delete it from the config.")
    return LabelConfig(**conf)


# ----------------------------------------------------------------- normalisation
def normalize_header(name: str) -> str:
    return re.sub(r"\s+", " ", str(name).replace("﻿", "")).strip().lower()


def normalize_label(label: str) -> str:
    s = "".join(ch if ord(ch) < 128 else "-" for ch in str(label))
    s = re.sub(r"\s+", " ", s).strip()
    s = re.sub(r"-+", "-", s)
    return "BENIGN" if s.upper() == "BENIGN" else s


_IP_CACHE: Dict[str, Optional[str]] = {}


def _ip_hex(ip) -> Optional[str]:
    """Order-preserving fixed-width representation of an IP (v4 < v6), or None."""
    key = str(ip).strip()
    if key in _IP_CACHE:
        return _IP_CACHE[key]
    try:
        a = ipaddress.ip_address(key)
        val = f"{a.version}{a.packed.hex():0>32}"
    except ValueError:
        val = None
    if len(_IP_CACHE) < 2_000_000:
        _IP_CACHE[key] = val
    return val


def endpoint_strings(ips: pd.Series, ports: pd.Series) -> pd.Series:
    """'<ip-hex>:<port5>' or None. Built in Python to stay independent of pandas string dtypes."""
    out = []
    for ip, port in zip(ips.tolist(), ports.tolist()):
        h = _ip_hex(ip)
        try:
            ok = port is not None and port == port and 0 <= float(port) <= 65535 and float(port) == int(float(port))
        except (TypeError, ValueError):
            ok = False
        out.append(f"{h}:{int(float(port)):05d}" if (h is not None and ok) else None)
    return pd.Series(out, index=ips.index, dtype=object)


def canonical_keys(proto: pd.Series, ep_a: pd.Series, ep_b: pd.Series) -> pd.Series:
    out = []
    for pr, a, b in zip(proto.tolist(), ep_a.tolist(), ep_b.tolist()):
        if a is None or b is None or pr is None or pr != pr:
            out.append(None)
            continue
        lo, hi = (a, b) if a <= b else (b, a)
        out.append(f"{int(pr)}|{lo}|{hi}")
    return pd.Series(out, index=ep_a.index, dtype=object)


# ----------------------------------------------------------------- CSV parsing
def resolve_columns(raw_columns: Iterable[str], cfg: LabelConfig) -> Dict[str, str]:
    """Map raw CSV headers to internal field names; raise LabelSchemaError if unsupported."""
    norm: Dict[str, List[str]] = {}
    for c in raw_columns:
        norm.setdefault(normalize_header(c), []).append(c)
    mapping, missing, duplicated = {}, [], []
    for fld in REQUIRED_FIELDS:
        want = cfg.columns[fld]
        raws = norm.get(want, [])
        if not raws:
            missing.append(want)
        elif len(raws) > 1:
            duplicated.append(want)
        else:
            mapping[raws[0]] = fld
    if missing or duplicated:
        raise LabelSchemaError(
            f"unsupported label CSV schema: missing={missing} duplicated={duplicated}. "
            f"Found normalised headers: {sorted(norm)[:40]}... Flow matching needs source/destination "
            "IP and port, protocol, timestamp, duration and label. If this is a file without IPs or "
            "timestamps (e.g. a pure-feature ML CSV), it cannot be matched to PCAP flows. "
            "Run scripts.inspect_label_csv and adjust 'labeling.columns' in the config.")
    return mapping


MISSING_TOKENS = ["", "nan", "NaN", "None", "NaT", "<NA>", "null", "NULL"]


def _timestamps(raw_ts: pd.Series, txt: pd.Series, cfg: LabelConfig):
    """Return (utc_epoch_seconds, resolution_s, kind, has_ampm) for one chunk.

    kind: 'string' (parsed with timestamp_formats, local time + utc_offset_hours),
    'datetime_naive' (local time + utc_offset_hours), 'datetime_tz' (exact, offset ignored),
    'epoch' (numeric with timestamp_epoch_unit, UTC).
    """
    idx = txt.index
    res = pd.Series(np.nan, index=idx)
    has_ampm = pd.Series(False, index=idx)
    if isinstance(raw_ts.dtype, pd.DatetimeTZDtype):
        ts = raw_ts.dt.tz_convert("UTC").dt.tz_localize(None)
        epoch = (ts - pd.Timestamp("1970-01-01")) / pd.Timedelta(seconds=1)
        return epoch.astype(float), res.fillna(1e-6), "datetime_tz", has_ampm
    if pd.api.types.is_datetime64_any_dtype(raw_ts.dtype):
        epoch = (raw_ts - pd.Timestamp("1970-01-01")) / pd.Timedelta(seconds=1)
        return epoch.astype(float) - cfg.utc_offset_hours * 3600.0, res.fillna(1e-6), "datetime_naive", has_ampm
    if cfg.timestamp_epoch_unit is not None:
        num = pd.to_numeric(txt, errors="coerce")
        scale = {"s": 1.0, "ms": 1e3, "us": 1e6}[cfg.timestamp_epoch_unit]
        return num / scale, res.fillna(1.0 / scale), "epoch", has_ampm
    ts = pd.Series(pd.NaT, index=idx, dtype="datetime64[ns]")
    for fmt in cfg.timestamp_formats:
        todo = ts.isna()
        if not todo.any():
            break
        parsed = pd.to_datetime(txt[todo], format=fmt, errors="coerce")
        ok = parsed.notna()
        sel = parsed.index[ok]
        ts.loc[sel] = parsed[ok]
        res.loc[sel] = 1.0 if "%S" in fmt else 60.0
        has_ampm.loc[sel] = "%p" in fmt
    epoch = (ts - pd.Timestamp("1970-01-01")) / pd.Timedelta(seconds=1)
    return epoch.astype(float) - cfg.utc_offset_hours * 3600.0, res, "string", has_ampm


def _protocol(txt: pd.Series) -> pd.Series:
    num = pd.to_numeric(txt, errors="coerce")
    as_int = num.where(num.notna() & (num == num.round()))
    name = txt.str.lower().map(PROTO_NAMES)
    out = as_int.map({6.0: 6, 17.0: 17})
    return out.fillna(name)


def parse_label_frame(raw: pd.DataFrame, cfg: LabelConfig, source_file: str = "",
                      row_offset: int = 0, source_row_offset: int = 0) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Parse a frame whose columns are internal field names. Returns (valid, invalid).

    Accepts string columns (CSV) and native Parquet types (int/float ports, datetime timestamps).
    ``row_id`` is global across all loaded files; ``source_row`` is the 0-based data-row position
    inside ``source_file`` (provenance).
    """
    n = len(raw)
    raw = raw.reset_index(drop=True)
    row_id = np.arange(row_offset, row_offset + n)
    source_row = np.arange(source_row_offset, source_row_offset + n)
    df = raw.astype(str).apply(lambda s: s.str.strip()) if n else raw.astype(str)
    reason = pd.Series("", index=df.index, dtype=object)

    def flag(mask, why):
        nonlocal reason
        reason = reason.mask(mask & (reason == ""), why)

    missing = {fld: (df[fld].isin(MISSING_TOKENS) | raw[fld].isna()) for fld in REQUIRED_FIELDS}
    # A row in which EVERY required field is empty carries no label record at all (e.g. trailing blank
    # rows in a CSV export). It is reported as 'empty_row', separately from malformed records.
    all_empty = pd.concat(missing.values(), axis=1).all(axis=1) if n else pd.Series(dtype=bool)
    flag(all_empty, "empty_row")
    for fld in REQUIRED_FIELDS:
        flag(missing[fld], f"missing_{fld}")
    proto = _protocol(df["protocol"])
    flag(proto.isna(), "unsupported_protocol")
    epoch, res, kind, has_ampm = _timestamps(raw["timestamp"], df["timestamp"], cfg)
    flag(epoch.isna(), "malformed_timestamp")
    dur = pd.to_numeric(df["duration"], errors="coerce")
    flag(dur.isna() | (dur < 0) | ~np.isfinite(dur.fillna(0)), "invalid_duration")
    sport = pd.to_numeric(df["src_port"], errors="coerce")
    dport = pd.to_numeric(df["dst_port"], errors="coerce")
    bad_port = lambda p: p.isna() | (p < 0) | (p > 65535) | (p != p.round())
    flag(bad_port(sport) | bad_port(dport), "invalid_port")
    src_hex = df["src_ip"].map(_ip_hex)
    dst_hex = df["dst_ip"].map(_ip_hex)
    flag(src_hex.isna() | dst_hex.isna(), "invalid_ip")

    bad = (reason != "").to_numpy()
    invalid = pd.DataFrame({"row_id": row_id[bad], "source_file": source_file, "source_row": source_row[bad],
                            "reason": reason[bad].to_numpy()})
    good = ~bad
    g = df[good]
    start = epoch[good].to_numpy(dtype=float)
    start_alt = np.full(len(g), np.nan)
    if cfg.ambiguous_12h and kind == "string":
        hours = pd.to_datetime(start + cfg.utc_offset_hours * 3600.0, unit="s").hour
        amb = (~has_ampm[good].to_numpy()) & (np.asarray(hours) < 12)
        start_alt[amb] = start[amb] + 12 * 3600.0
    scale = {"us": 1e6, "ms": 1e3, "s": 1.0}[cfg.duration_unit]
    src_ep = endpoint_strings(g["src_ip"], sport[good])
    dst_ep = endpoint_strings(g["dst_ip"], dport[good])
    valid = pd.DataFrame({
        "row_id": row_id[good],
        "source_file": source_file,
        "source_row": source_row[good],
        "key": canonical_keys(proto[good].astype(int), src_ep, dst_ep).to_numpy(),
        "csv_src_ep": src_ep.to_numpy(),
        "csv_start": start,
        "csv_start_alt": start_alt,
        "csv_resolution": res[good].to_numpy(dtype=float),
        "csv_duration": (dur[good] / scale).to_numpy(dtype=float),
        "csv_label": g["label"].map(normalize_label).to_numpy(),
        "timestamp_kind": kind,
    })
    if "flow_id" in raw.columns:
        valid["csv_flow_id"] = g["flow_id"].to_numpy()
    for fld in ("fwd_packets", "bwd_packets"):
        if fld in raw.columns:
            valid[f"csv_{fld}"] = pd.to_numeric(g[fld], errors="coerce").to_numpy(dtype=float)
    return valid, invalid


def _empty_valid(cfg: LabelConfig) -> pd.DataFrame:
    return parse_label_frame(pd.DataFrame({f: pd.Series(dtype=str) for f in REQUIRED_FIELDS}), cfg)[0]


SUPPORTED_SUFFIXES = (".csv", ".parquet")


def column_mapping(cols: Iterable[str], cfg: LabelConfig) -> Dict[str, str]:
    """Required columns (strict) plus optional ones (flow id, packet counts) when present."""
    cols = list(cols)
    mapping = resolve_columns(cols, cfg)
    norm: Dict[str, List[str]] = {}
    for c in cols:
        norm.setdefault(normalize_header(c), []).append(c)
    for fld, want in (cfg.optional_columns or {}).items():
        raws = norm.get(want, [])
        if len(raws) == 1 and raws[0] not in mapping and fld not in mapping.values():
            mapping[raws[0]] = fld
    return mapping


def label_file_columns(path: Path, encoding: str = "latin-1") -> List[str]:
    path = Path(path)
    if path.suffix.lower() == ".parquet":
        import pyarrow.parquet as pq
        return list(pq.ParquetFile(path).schema_arrow.names)
    return list(pd.read_csv(path, nrows=0, encoding=encoding).columns)


def iter_label_chunks(path: Path, cfg: LabelConfig):
    """Yield (chunk with internal field names, mapping) in bounded memory for CSV or Parquet."""
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix not in SUPPORTED_SUFFIXES:
        raise LabelSchemaError(f"{path.name}: unsupported label file type {suffix!r}; use .csv or .parquet")
    cols = label_file_columns(path, cfg.encoding)
    mapping = column_mapping(cols, cfg)
    if suffix == ".parquet":
        import pyarrow.parquet as pq
        pf = pq.ParquetFile(path)
        for batch in pf.iter_batches(batch_size=cfg.chunksize, columns=list(mapping)):
            yield batch.to_pandas().rename(columns=mapping)
    else:
        for chunk in pd.read_csv(path, usecols=list(mapping), chunksize=cfg.chunksize,
                                 encoding=cfg.encoding, dtype=str, keep_default_na=False):
            yield chunk.rename(columns=mapping)


def load_label_files(paths: Sequence[Path], cfg: LabelConfig) -> Tuple[pd.DataFrame, pd.DataFrame, dict]:
    """Chunked load of CSV and/or Parquet label files into one shared internal schema.

    Returns (valid rows, invalid rows, per-file stats). Raw files are only read.
    """
    cfg.validate()
    valids, invalids, stats = [], [], {}
    offset = 0
    for path in paths:
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(f"label file not found: {path}")
        n_file = 0
        kinds = set()
        for chunk in iter_label_chunks(path, cfg):
            v, inv = parse_label_frame(chunk, cfg, path.name, offset, n_file)
            valids.append(v)
            invalids.append(inv)
            kinds.update(v["timestamp_kind"].unique().tolist())
            offset += len(chunk)
            n_file += len(chunk)
        stats[path.name] = {"rows": n_file, "format": path.suffix.lower().lstrip("."),
                            "timestamp_kinds": sorted(kinds)}
    valid = pd.concat(valids, ignore_index=True) if valids else _empty_valid(cfg)
    invalid = (pd.concat(invalids, ignore_index=True) if invalids
               else pd.DataFrame(columns=["row_id", "source_file", "source_row", "reason"]))
    for name in stats:
        stats[name]["invalid"] = int((invalid["source_file"] == name).sum())
    return valid, invalid, stats


load_label_csvs = load_label_files  # backward-compatible name (v4.1)


def label_frame_from_records(records: List[dict], cfg: LabelConfig, source_file: str = "test") -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Convenience for tests: records use the configured (normalised) CSV header names."""
    cfg.validate()
    raw = pd.DataFrame(records)
    mapping = column_mapping(raw.columns, cfg)
    return parse_label_frame(raw[list(mapping)].rename(columns=mapping), cfg, source_file)


def label_frame_from_file(path: Path, cfg: LabelConfig) -> Tuple[pd.DataFrame, pd.DataFrame]:
    v, inv, _ = load_label_files([path], cfg)
    return v, inv


# ----------------------------------------------------------------- matching
EVIDENCE_COLUMNS = ("match_status", "match_reason", "label", "binary_label", "matched_row_id",
                    "n_key_rows", "n_overlap_rows", "n_start_aligned", "n_consistent",
                    "start_offset_s", "duration_diff_s", "orientation", "used_12h_shift",
                    "candidate_row_ids", "candidate_labels",
                    # v4.3 identity evidence and traceability
                    "matching_mode", "n_strict", "identity_basis", "matched_source_file", "matched_source_row",
                    "expected_duration_s", "expected_duration_exact", "duration_censored",
                    "selected_duration_residual_s", "selected_packet_residual",
                    "runner_up_row_id", "runner_up_duration_residual_s", "runner_up_miss_ratio")


def _flow_keys(flows: pd.DataFrame) -> Tuple[pd.Series, pd.Series, pd.Series]:
    proto = pd.to_numeric(flows["protocol"], errors="coerce")
    sport = pd.to_numeric(flows["src_port"], errors="coerce")
    dport = pd.to_numeric(flows["dst_port"], errors="coerce")
    src_ep = endpoint_strings(flows["src_ip"].astype(str), sport)
    dst_ep = endpoint_strings(flows["dst_ip"].astype(str), dport)
    keys = canonical_keys(proto, src_ep, dst_ep)
    ok = (proto.isin([6, 17]) & sport.notna() & dport.notna() & src_ep.notna() & dst_ep.notna()
          & pd.to_numeric(flows["start_time"], errors="coerce").notna()
          & pd.to_numeric(flows["end_time"], errors="coerce").notna())
    return keys.where(ok & keys.notna(), None), src_ep, (ok & keys.notna())


def match_flows(flows: pd.DataFrame, labels: pd.DataFrame, cfg: LabelConfig,
                chunk_size: int = 250_000) -> pd.DataFrame:
    """Return a DataFrame (index aligned with ``flows``) of match evidence columns.

    Flows are matched in chunks to bound the size of the key merge. Row-sharing checks and
    binary labels are applied globally afterwards. Output is deterministic for identical inputs.
    """
    cfg.validate()
    starts = range(0, len(flows), chunk_size) if len(flows) else [0]
    parts, pairs = [], []
    for i in starts:
        o, pr = _match_chunk(flows.iloc[i:i + chunk_size], labels, cfg)
        parts.append(o)
        pairs.append(pr)
    out = pd.concat(parts) if len(parts) > 1 else parts[0]
    cons_pairs = pd.concat(pairs, ignore_index=True) if pairs else pd.DataFrame(columns=["fidx", "row_id"])
    # (1) A CSV row may be the unique match of only one PCAP flow.
    uq = out["match_status"] == "unique"
    shared = out.loc[uq, "matched_row_id"].duplicated(keep=False)
    sidx = shared[shared].index
    out.loc[sidx, ["match_status", "match_reason"]] = ["ambiguous_shared_row", "csv_row_matches_multiple_pcap_flows"]
    # (2) v4.3: the selected row must not also be a consistent candidate of ANOTHER flow
    #     (label rows reused across sessions on the same 5-tuple).
    if cfg.matching_mode == "evidence_v43" and len(cons_pairs):
        uq = out["match_status"] == "unique"
        sel = out.loc[uq, ["matched_row_id"]].reset_index().rename(columns={"index": "fidx_sel"})
        sel.columns = ["fidx_sel", "row_id"]
        sel["row_id"] = sel["row_id"].astype("int64")
        cp = cons_pairs.astype({"row_id": "int64"})
        j = sel.merge(cp, on="row_id")
        reused = j.loc[j["fidx"] != j["fidx_sel"], "fidx_sel"].unique()
        out.loc[reused, ["match_status", "match_reason"]] = ["ambiguous_shared_row",
                                                             "selected_row_is_candidate_of_other_flow"]
        sidx = sidx.union(pd.Index(reused))
    out.loc[sidx, ["matched_row_id", "label", "matched_source_file", "matched_source_row"]] = None
    uq = out["match_status"] == "unique"
    out.loc[uq, "binary_label"] = np.where(out.loc[uq, "label"].isin(set(cfg.benign_labels)), "BENIGN", "ATTACK")
    return out


def _num_col(flows: pd.DataFrame, name: str, mask) -> np.ndarray:
    if name not in flows.columns:
        return np.full(int(np.asarray(mask).sum()), np.nan)
    return pd.to_numeric(flows.loc[mask, name], errors="coerce").to_numpy(dtype=float)


def _match_chunk(flows: pd.DataFrame, labels: pd.DataFrame, cfg: LabelConfig, return_candidates: bool = False):
    n = len(flows)
    out = pd.DataFrame({c: None for c in EVIDENCE_COLUMNS}, index=flows.index)
    for c in ("n_key_rows", "n_overlap_rows", "n_start_aligned", "n_consistent", "n_strict"):
        out[c] = 0
    out["used_12h_shift"] = False
    out["matching_mode"] = cfg.matching_mode
    no_pairs = pd.DataFrame({"fidx": pd.Series(dtype=object), "row_id": pd.Series(dtype="int64")})
    keys, src_ep, ok = _flow_keys(flows)
    out.loc[~ok, ["match_status", "match_reason"]] = ["invalid_flow", "missing_or_invalid_flow_fields"]
    out.loc[ok, ["match_status", "match_reason"]] = ["unmatched", "no_csv_row_with_same_key"]
    if n == 0 or labels.empty or not ok.any():
        return (out, no_pairs, pd.DataFrame()) if return_candidates else (out, no_pairs)

    okm = ok.to_numpy()
    f = pd.DataFrame({"fidx": flows.index[okm], "key": keys[ok].to_numpy(),
                      "f_src_ep": src_ep[ok].to_numpy(),
                      "f_start": pd.to_numeric(flows.loc[ok, "start_time"]).to_numpy(float),
                      "f_end": pd.to_numeric(flows.loc[ok, "end_time"]).to_numpy(float),
                      "f_eof": (flows.loc[ok, "end_reason"].astype(str).to_numpy() == "eof")
                      if "end_reason" in flows.columns else np.zeros(int(okm.sum()), bool),
                      "f_window_s": _num_col(flows, "window_s", ok),
                      "f_win_last": _num_col(flows, "window_last_rel_ts", ok),
                      "f_nfwd": _num_col(flows, "n_fwd_packets", ok), "f_nbwd": _num_col(flows, "n_bwd_packets", ok),
                      "f_wfwd": _num_col(flows, "window_fwd_packets", ok),
                      "f_wbwd": _num_col(flows, "window_bwd_packets", ok)})
    want = ["key", "row_id", "source_file", "source_row", "csv_src_ep", "csv_start", "csv_start_alt",
            "csv_resolution", "csv_duration", "csv_label", "csv_fwd_packets", "csv_bwd_packets"]
    lab = labels.reindex(columns=want)
    alt = lab[lab["csv_start_alt"].notna()].copy()
    lab0 = lab.assign(alt=False)
    if len(alt):
        alt = alt.assign(csv_start=alt["csv_start_alt"], alt=True)
        lab0 = pd.concat([lab0, alt], ignore_index=True)
    m = f.merge(lab0, on="key", how="inner")
    if m.empty:
        return (out, no_pairs, m) if return_candidates else (out, no_pairs)
    m = m.sort_values(["fidx", "row_id", "alt"], kind="mergesort").reset_index(drop=True)  # deterministic
    tol = cfg.start_tolerance_s + m["csv_resolution"]
    m["dt"] = m["csv_start"] - m["f_start"]  # signed: CSV start minus PCAP flow start
    m["overlap"] = (m["csv_start"] - tol <= m["f_end"]) & (m["f_start"] <= m["csv_start"] + m["csv_duration"] + tol)
    m["aligned"] = m["dt"].abs() <= tol
    f_dur = (m["f_end"] - m["f_start"]).clip(lower=0)
    if cfg.matching_mode == "legacy_v41":
        # v4.1/v4.2 behaviour, kept for reproducibility. NOTE (defect D43-2): with csv_active_timeout_s
        # set, min(duration, T) is not the duration of the first CSV segment.
        expected = f_dur if cfg.csv_active_timeout_s is None else np.minimum(f_dur, cfg.csv_active_timeout_s)
        exact = pd.Series(True, index=m.index)
        censored = pd.Series(False, index=m.index)
        m["dur_diff"] = m["csv_duration"] - expected
        resid = m["dur_diff"].abs()
    else:
        T = cfg.csv_active_timeout_s
        expected = f_dur.copy()
        exact = pd.Series(True, index=m.index)
        if T is not None:
            longer = f_dur > T
            win_ok = (m["f_window_s"] == T) & m["f_win_last"].notna()
            expected = expected.where(~longer, np.where(win_ok, m["f_win_last"], T))
            exact = ~longer | win_ok  # exact when the extractor recorded the same window
        censored = m["f_eof"].astype(bool) & cfg.eof_censoring
        m["dur_diff"] = m["csv_duration"] - expected
        # right-censored flows (cut by end of capture): only a CSV row SHORTER than observed contradicts
        resid = m["dur_diff"].abs().where(~censored, (-m["dur_diff"]).clip(lower=0))
    m["expected"] = expected
    m["exact"] = exact
    m["censored"] = censored
    m["resid"] = resid
    dur_tol = cfg.duration_abs_tolerance_s + cfg.duration_rel_tolerance * np.maximum(m["csv_duration"], expected)
    m["dur_ok"] = (resid <= dur_tol) if cfg.check_duration else True
    m["consistent"] = m["aligned"] & m["dur_ok"]
    # ---- v4.3 strict identity evidence (never uses the label) ----
    strict_tol = cfg.strict_duration_abs_s + cfg.strict_duration_rel * np.maximum(m["csv_duration"], expected)
    m["miss_ratio"] = resid / strict_tol
    same = m["csv_src_ep"] == m["f_src_ep"]
    use_win = cfg.csv_active_timeout_s is not None
    our_f = np.where(use_win, m["f_wfwd"], m["f_nfwd"])
    our_b = np.where(use_win, m["f_wbwd"], m["f_nbwd"])
    o_fwd = np.where(same, our_f, our_b)
    o_bwd = np.where(same, our_b, our_f)
    d_f = m["csv_fwd_packets"] - o_fwd
    d_b = m["csv_bwd_packets"] - o_bwd
    pk = np.where(censored, np.clip(-d_f, 0, None) + np.clip(-d_b, 0, None), np.abs(d_f) + np.abs(d_b))
    m["pkt_resid"] = pk  # NaN when either side lacks packet counts
    pkt_ok = (m["pkt_resid"] <= cfg.packet_tolerance) if cfg.packet_check == "require" else True
    m["strict"] = m["consistent"] & (m["miss_ratio"] <= 1.0) & pkt_ok
    # A candidate that fails a REQUIRED packet-count check is categorically separated (infinite miss).
    if cfg.packet_check == "require":
        m["miss_ratio"] = m["miss_ratio"].where(pkt_ok, np.inf)

    key_rows = m.groupby("fidx")["row_id"].nunique()
    out.loc[key_rows.index, "n_key_rows"] = key_rows.to_numpy()
    for col, name in (("overlap", "n_overlap_rows"), ("aligned", "n_start_aligned"), ("consistent", "n_consistent"),
                      ("strict", "n_strict")):
        cnt = m[m[col]].groupby("fidx")["row_id"].nunique()
        out.loc[cnt.index, name] = cnt.to_numpy()

    has_key = out["n_key_rows"] > 0
    out.loc[has_key & ok, ["match_status", "match_reason"]] = ["unmatched", "no_csv_row_overlapping_flow_time"]
    ov = has_key & (out["n_overlap_rows"] > 0)
    out.loc[ov, ["match_status", "match_reason"]] = ["time_inconsistent", "start_misaligned"]
    al = has_key & (out["n_start_aligned"] > 0)
    out.loc[al, ["match_status", "match_reason"]] = ["time_inconsistent", "duration_mismatch"]

    # Evidence of the best (closest-start) candidate within the decisive set.
    def best(rows: pd.DataFrame) -> pd.DataFrame:
        r = rows.assign(absdt=rows["dt"].abs()).sort_values(["fidx", "absdt", "row_id"])
        return r.drop_duplicates("fidx").set_index("fidx")

    for subset in (m[m["overlap"]], m[m["aligned"]], m[m["consistent"]]):  # later subsets overwrite
        if len(subset):
            b = best(subset)
            out.loc[b.index, "start_offset_s"] = b["dt"].to_numpy()
            out.loc[b.index, "duration_diff_s"] = b["dur_diff"].to_numpy()
            out.loc[b.index, "expected_duration_s"] = b["expected"].to_numpy()
            out.loc[b.index, "expected_duration_exact"] = b["exact"].to_numpy()
            out.loc[b.index, "duration_censored"] = b["censored"].to_numpy()
            out.loc[b.index, "orientation"] = np.where(b["csv_src_ep"] == b["f_src_ep"], "same", "reversed")
            out.loc[b.index, "used_12h_shift"] = b["alt"].to_numpy()

    aligned = m[m["aligned"]]
    cons = m[m["consistent"]]
    if len(aligned):
        g = aligned.groupby("fidx")
        n_lab_aligned = g["csv_label"].nunique()
        # Candidate lists are only materialised where they matter (>1 aligned row);
        # building strings for every flow dominated v4.1 run time in benchmarks.
        multi = g["row_id"].nunique()
        many = aligned[aligned["fidx"].isin(multi[multi > 1].index)]
        if len(many):
            gm = many.drop_duplicates(["fidx", "row_id"]).sort_values(["fidx", "row_id"]).groupby("fidx")
            out.loc[gm.size().index, "candidate_row_ids"] = gm["row_id"].agg(
                lambda s: ";".join(map(str, s.iloc[:20]))).to_numpy()
            out.loc[gm.size().index, "candidate_labels"] = many.groupby("fidx")["csv_label"].agg(
                lambda s: "|".join(sorted(set(s)))).to_numpy()
        single = multi[multi == 1].index
        if len(single):
            one = aligned[aligned["fidx"].isin(single)].drop_duplicates("fidx").set_index("fidx")
            out.loc[one.index, "candidate_row_ids"] = one["row_id"].astype(str).to_numpy()
            out.loc[one.index, "candidate_labels"] = one["csv_label"].to_numpy()
    else:
        n_lab_aligned = pd.Series(dtype=int)
    if len(cons) and cfg.matching_mode == "legacy_v41":
            gc = cons.groupby("fidx")
            n_cons = gc["row_id"].nunique()
            if cfg.collapse_exact_duplicate_rows:
                uniq = cons.drop_duplicates(["fidx", "csv_start", "csv_duration", "csv_label", "csv_src_ep"])
                n_cons = uniq.groupby("fidx")["row_id"].nunique()
            n_rows = gc["row_id"].nunique()
            n_distinct = cons.drop_duplicates(["fidx", "csv_start", "csv_duration", "csv_label"]).groupby("fidx").size()
            dup_exact = (n_distinct.reindex(n_rows.index) == 1) & (n_rows > 1)
            first_row = gc["row_id"].min()
            first_label = cons.sort_values("row_id").groupby("fidx")["csv_label"].first()
            lab_al = n_lab_aligned.reindex(n_cons.index).fillna(1)
            conflict = lab_al > 1
            amb = (~conflict) & (n_cons > 1)
            uniq = (~conflict) & (n_cons == 1)
            idx = n_cons.index
            out.loc[idx[conflict.to_numpy()], ["match_status", "match_reason"]] = ["conflict", "start_aligned_rows_with_different_labels"]
            amb_idx = idx[amb.to_numpy()]
            out.loc[amb_idx, "match_status"] = "ambiguous_same_label"
            out.loc[amb_idx, "match_reason"] = np.where(dup_exact.reindex(amb_idx).fillna(False).to_numpy(bool),
                                                        "exact_duplicate_csv_rows", "multiple_consistent_rows_same_label")
            u_idx = idx[uniq.to_numpy()]
            out.loc[u_idx, ["match_status", "match_reason"]] = ["unique", "single_consistent_row"]
            out.loc[u_idx, "matched_row_id"] = first_row.reindex(u_idx).astype(int).to_numpy()
            out.loc[u_idx, "label"] = first_label.reindex(u_idx).to_numpy()
            _trace(out, m, u_idx)
    elif len(cons):
        _evidence_decision(out, m, cons, n_lab_aligned, cfg)
    # conflicts among aligned rows even if none is duration-consistent
    if len(n_lab_aligned):
        conf_idx = n_lab_aligned[n_lab_aligned > 1].index
        out.loc[conf_idx, ["match_status", "match_reason"]] = ["conflict", "start_aligned_rows_with_different_labels"]
        out.loc[conf_idx, ["matched_row_id", "label", "matched_source_file", "matched_source_row"]] = None

    pairs = cons[["fidx", "row_id"]].drop_duplicates() if len(cons) else no_pairs
    if return_candidates:
        return out, pairs, m
    return out, pairs


def _trace(out: pd.DataFrame, m: pd.DataFrame, idx) -> None:
    """Fill traceability/evidence columns for flows whose matched_row_id is set."""
    if len(idx) == 0:
        return
    sel = out.loc[idx, ["matched_row_id"]].reset_index().rename(columns={"index": "fidx", "matched_row_id": "row_id"})
    sel["row_id"] = sel["row_id"].astype("int64")
    pick = m[m["consistent"]].merge(sel, on=["fidx", "row_id"])
    pick = pick.assign(absdt=pick["dt"].abs()).sort_values(["fidx", "absdt"]).drop_duplicates("fidx").set_index("fidx")
    out.loc[pick.index, "matched_source_file"] = pick["source_file"].to_numpy()
    out.loc[pick.index, "matched_source_row"] = pick["source_row"].to_numpy()
    out.loc[pick.index, "selected_duration_residual_s"] = pick["resid"].to_numpy()
    out.loc[pick.index, "selected_packet_residual"] = pick["pkt_resid"].to_numpy()
    out.loc[pick.index, "start_offset_s"] = pick["dt"].to_numpy()
    out.loc[pick.index, "duration_diff_s"] = pick["dur_diff"].to_numpy()
    out.loc[pick.index, "orientation"] = np.where(pick["csv_src_ep"] == pick["f_src_ep"], "same", "reversed")
    out.loc[pick.index, "used_12h_shift"] = pick["alt"].to_numpy()


def _evidence_decision(out, m, cons, n_lab_aligned, cfg) -> None:
    """v4.3 decision. Labels are only used to DETECT conflicts, never to choose a candidate."""
    if cfg.collapse_exact_duplicate_rows:
        cons = cons.drop_duplicates(["fidx", "csv_start", "csv_duration", "csv_label", "csv_src_ep"])
    # one row per (flow, label row): keep its best start alternative
    c = (cons.assign(absdt=cons["dt"].abs()).sort_values(["fidx", "row_id", "absdt"], kind="mergesort")
         .drop_duplicates(["fidx", "row_id"]))
    c = c.sort_values(["fidx", "miss_ratio", "absdt", "row_id"], kind="mergesort")
    g = c.groupby("fidx", sort=True)
    n_cons = g.size()
    n_str = c[c["strict"]].groupby("fidx").size().reindex(n_cons.index, fill_value=0)
    first = g.head(1).set_index("fidx")
    second = g.nth(1).set_index("fidx") if (n_cons > 1).any() else pd.DataFrame(columns=c.columns).set_index("fidx")
    n_distinct = c[c["strict"]].drop_duplicates(["fidx", "csv_start", "csv_duration", "csv_src_ep"]).groupby("fidx").size()
    lab_al = n_lab_aligned.reindex(n_cons.index).fillna(1)
    idx = n_cons.index
    conflict = (lab_al > 1).to_numpy()
    single = (n_cons == 1).to_numpy()
    s1 = (n_str == 1).to_numpy()
    runner_ratio = second["miss_ratio"].reindex(idx).to_numpy(dtype=float) if len(second) else np.full(len(idx), np.inf)
    margin_ok = ~(runner_ratio < cfg.identity_margin)  # NaN (no runner-up) counts as ok
    status = np.full(len(idx), "ambiguous_same_label", dtype=object)
    reason = np.full(len(idx), "multiple_strict_candidates", dtype=object)
    basis = np.full(len(idx), None, dtype=object)
    uniq_single = ~conflict & single
    uniq_strict = ~conflict & ~single & s1 & margin_ok
    status[uniq_single | uniq_strict] = "unique"
    reason[uniq_single] = "single_consistent_row"
    basis[uniq_single] = np.where(first["strict"].reindex(idx).to_numpy(bool)[uniq_single],
                                  "single_candidate_strict", "single_candidate_loose")
    reason[uniq_strict] = "disambiguated_by_duration_residual"
    basis[uniq_strict] = "strict_unique_with_margin"
    amb = ~conflict & ~single & ~(s1 & margin_ok)
    reason[amb & s1] = "insufficient_identity_margin"
    reason[amb & (n_str.to_numpy() == 0)] = "no_candidate_meets_strict_identity"
    dup = (n_distinct.reindex(idx).to_numpy() == 1) & (n_str.to_numpy() >= 2)
    reason[amb & dup] = "exact_duplicate_csv_rows"
    status[conflict] = "conflict"
    reason[conflict] = "start_aligned_rows_with_different_labels"
    out.loc[idx, "match_status"] = status
    out.loc[idx, "match_reason"] = reason
    out.loc[idx, "identity_basis"] = basis
    out.loc[idx, "runner_up_row_id"] = second["row_id"].reindex(idx).to_numpy() if len(second) else None
    out.loc[idx, "runner_up_duration_residual_s"] = second["resid"].reindex(idx).to_numpy() if len(second) else None
    out.loc[idx, "runner_up_miss_ratio"] = runner_ratio
    u = idx[status == "unique"]
    out.loc[u, "matched_row_id"] = first["row_id"].reindex(u).astype("int64").to_numpy()
    out.loc[u, "label"] = first["csv_label"].reindex(u).to_numpy()
    _trace(out, m, u)


def label_flows(flows: pd.DataFrame, labels: pd.DataFrame, cfg: LabelConfig,
                chunk_size: Optional[int] = None) -> pd.DataFrame:
    ev = match_flows(flows, labels, cfg, chunk_size=chunk_size or cfg.match_chunk_size)
    res = pd.concat([flows.drop(columns=[c for c in EVIDENCE_COLUMNS if c in flows.columns]), ev], axis=1)
    valid_prefix = res["valid_early_prefix"].astype(bool) if "valid_early_prefix" in res else True
    res["trusted"] = (res["match_status"] == TRUSTED_STATUS) & valid_prefix
    reason = pd.Series("", index=res.index, dtype=object)
    if "valid_early_prefix" in res:
        reason = reason.mask(~res["valid_early_prefix"].astype(bool),
                             "not_valid_early_prefix:" + res.get("start_reason", pd.Series("?", index=res.index)).astype(str))
    reason = reason.mask((reason == "") & (res["match_status"] != TRUSTED_STATUS),
                         "label:" + res["match_status"].astype(str) + ":" + res["match_reason"].astype(str))
    res["exclusion_reason"] = reason.where(~res["trusted"], "")
    # Backwards-compatible alias used by v4 scripts.
    res["supervised_eligible"] = res["trusted"]
    return res


def time_offset_diagnostics(flows: pd.DataFrame, labels_utc0: pd.DataFrame, max_hours: int = 14) -> dict:
    """Histogram of (CSV start - PCAP start) rounded to whole hours over key-matched pairs.

    Use with labels parsed at ``utc_offset_hours=0`` to see which offset aligns the
    data. Diagnostic only: the chosen offset must also be justified by documentation.
    """
    keys, _, ok = _flow_keys(flows)
    f = pd.DataFrame({"key": keys[ok].to_numpy(), "f_start": pd.to_numeric(flows.loc[ok, "start_time"]).to_numpy(float)})
    m = f.merge(labels_utc0[["key", "csv_start"]], on="key")
    if m.empty:
        return {"pairs": 0, "hour_histogram": {}}
    h = ((m["csv_start"] - m["f_start"]) / 3600.0).round()
    h = h[h.abs() <= max_hours]
    return {"pairs": int(len(m)), "hour_histogram": {str(int(k)): int(v) for k, v in h.value_counts().sort_index().items()},
            "note": "A dominant bucket +k means CSV local time = UTC + k hours (i.e. utc_offset_hours = k)."}


def offset_evidence(flows: pd.DataFrame, labels_utc0: pd.DataFrame, cfg: LabelConfig,
                    candidates: Optional[Sequence[float]] = None, max_flows: int = 200_000,
                    seed: int = 0) -> dict:
    """Score candidate UTC offsets on endpoint-matched flow/label pairs (v4.2).

    ``labels_utc0`` must be parsed with ``utc_offset_hours = 0`` (local clock read as UTC), so
    for a candidate offset h the UTC start is ``csv_start - h*3600``. For each h we count flows
    with exactly one / at least one start-aligned row (|dt| <= start_tolerance_s + resolution).
    The function never selects an offset for matching: it returns evidence and flags only.
    """
    cand = list(candidates) if candidates is not None else [x / 2 for x in range(-28, 29)]
    keys, _, ok = _flow_keys(flows)
    f = pd.DataFrame({"fidx": flows.index[ok.to_numpy()], "key": keys[ok].to_numpy(),
                      "f_start": pd.to_numeric(flows.loc[ok, "start_time"]).to_numpy(float)})
    if len(f) > max_flows:
        f = f.sample(n=max_flows, random_state=seed)
    lab = labels_utc0[["key", "csv_start", "csv_resolution"]]
    m = f.merge(lab, on="key")
    m = m[(m["csv_start"] - m["f_start"]).abs() <= 27 * 3600]  # wide enough for best +/- 12 h checks
    out: dict = {"flows_considered": int(len(f)), "flows_with_endpoint_match_within_27h": int(m["fidx"].nunique()),
                 "pairs": int(len(m)), "candidates": []}
    pc = pd.to_numeric(flows["start_time"], errors="coerce")
    out["pcap_time_range_utc"] = [float(pc.min()), float(pc.max())] if pc.notna().any() else None
    out["label_rows"] = int(len(labels_utc0))
    out["label_timestamp_kinds"] = (sorted(labels_utc0["timestamp_kind"].unique().tolist())
                                    if "timestamp_kind" in labels_utc0 and len(labels_utc0) else [])
    res_counts = labels_utc0["csv_resolution"].round(6).value_counts().to_dict() if len(labels_utc0) else {}
    out["label_timestamp_resolution_s"] = {str(k): int(v) for k, v in res_counts.items()}
    hours = pd.to_datetime(labels_utc0["csv_start"], unit="s", errors="coerce").dt.hour if len(labels_utc0) else pd.Series(dtype=int)
    out["label_local_hour_histogram"] = {str(int(k)): int(v) for k, v in hours.value_counts().sort_index().items()}
    flags: List[str] = []
    if m.empty:
        out["flags"] = ["no_endpoint_matches: check that PCAP and label files belong to the same capture day"]
        out["evidence_best_offset_hours"] = None
        out["ranking"] = []
        out["note"] = ("Evidence only. No offset is applied automatically: set labeling.utc_offset_hours explicitly, "
                       "justified by this report and the dataset documentation.")
        return out
    tol = cfg.start_tolerance_s + m["csv_resolution"].to_numpy()
    base = (m["csv_start"] - m["f_start"]).to_numpy()
    nkey = m["fidx"].nunique()
    for h in cand:
        dt = base - h * 3600.0
        al = np.abs(dt) <= tol
        if not al.any():
            out["candidates"].append({"offset_hours": h, "flows_aligned": 0, "flows_uniquely_aligned": 0,
                                      "support": 0.0, "median_abs_dt_s": None})
            continue
        sub = m.loc[al, ["fidx"]].assign(adt=np.abs(dt[al]))
        per = sub.groupby("fidx").size()
        out["candidates"].append({"offset_hours": h, "flows_aligned": int(len(per)),
                                  "flows_uniquely_aligned": int((per == 1).sum()),
                                  "support": float(len(per) / nkey),
                                  "median_abs_dt_s": float(sub["adt"].median())})
    ranked = sorted(out["candidates"], key=lambda c: (-c["flows_aligned"], abs(c["offset_hours"])))
    out["ranking"] = [{"offset_hours": c["offset_hours"], "flows_aligned": c["flows_aligned"],
                       "support": c["support"]} for c in ranked[:5]]
    best, second = ranked[0], ranked[1] if len(ranked) > 1 else None
    if best["flows_aligned"] == 0:
        flags.append("no_candidate_aligns_any_flow")
    else:
        if best["support"] < 0.5:
            flags.append(f"low_support: best candidate aligns only {best['support']:.1%} of endpoint-matched flows")
        if second and second["flows_aligned"] >= 0.8 * best["flows_aligned"]:
            flags.append(f"no_clear_winner: {second['offset_hours']} h aligns {second['flows_aligned']} vs "
                         f"{best['flows_aligned']} for {best['offset_hours']} h")
        twelve = {}
        for d in (12.0, -12.0):  # evaluated explicitly, even outside the candidate range
            h2 = best["offset_hours"] + d
            al2 = np.abs(base - h2 * 3600.0) <= tol
            n2 = int(m.loc[al2, "fidx"].nunique())
            twelve[str(h2)] = n2
            if n2 >= 0.2 * best["flows_aligned"]:
                flags.append(f"possible_12h_ambiguity: offset {h2} h also aligns {n2} flows "
                             "(AM/PM missing in label timestamps?) -- inspect the hour histogram; consider ambiguous_12h")
        out["best_plus_minus_12h_aligned_flows"] = twelve
        if out["pcap_time_range_utc"]:
            lo, hi = out["pcap_time_range_utc"]
            starts = labels_utc0["csv_start"] - best["offset_hours"] * 3600.0
            outside = float(((starts < lo - 3600) | (starts > hi + 3600)).mean())
            out["label_rows_outside_pcap_range_at_best"] = outside
            if outside > 0.05:
                flags.append(f"label_rows_outside_pcap_time_range: {outside:.1%} at the best candidate")
        if any(k not in ("string",) for k in out["label_timestamp_kinds"]):
            flags.append("non_string_timestamps: datetime/epoch values; confirm whether they are local time or UTC")
    out["evidence_best_offset_hours"] = best["offset_hours"] if best["flows_aligned"] else None
    out["flags"] = flags
    out["note"] = ("Evidence only. No offset is applied automatically: set labeling.utc_offset_hours explicitly, "
                   "justified by this report and the dataset documentation.")
    return out


CANDIDATE_COLUMNS = ("flow_uid", "row_id", "source_file", "source_row", "csv_label", "orientation", "alt",
                     "dt", "csv_duration", "expected", "exact", "censored", "resid", "miss_ratio", "pkt_resid",
                     "aligned", "consistent", "strict")


def candidate_evidence(flows: pd.DataFrame, labels: pd.DataFrame, cfg: LabelConfig) -> pd.DataFrame:
    """Every (flow, label-row) candidate with its evidence, for manual identity review (diagnostic)."""
    cfg.validate()
    _, _, m = _match_chunk(flows, labels, cfg, return_candidates=True)
    if m.empty:
        return pd.DataFrame(columns=CANDIDATE_COLUMNS)
    m = m.assign(flow_uid=flows.loc[m["fidx"], "flow_uid"].to_numpy() if "flow_uid" in flows else m["fidx"],
                 orientation=np.where(m["csv_src_ep"] == m["f_src_ep"], "same", "reversed"))
    return m.reindex(columns=CANDIDATE_COLUMNS).sort_values(["flow_uid", "miss_ratio", "row_id"], kind="mergesort")
