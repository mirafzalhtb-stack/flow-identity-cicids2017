"""Flow record writers (Parquet preferred, CSV for v3 compatibility)."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import List, Optional

LIST_COLUMNS = ("pkt_rel_ts", "pkt_iat", "pkt_direction", "pkt_ip_len",
                "pkt_payload_len", "pkt_tcp_flags", "pkt_ttl", "pkt_retrans")

# Causal per-packet prefix inputs that a Phase-2 model MAY use (truncated to the first k packets).
PREFIX_FEATURE_COLUMNS = LIST_COLUMNS
# Whole-flow metadata. Known only after the flow ends (or used for labelling/auditing).
# These MUST NOT be used as packet-prefix model inputs.
FULL_FLOW_METADATA_COLUMNS = ("end_time", "duration", "observed_packets", "observed_bytes", "end_reason",
                              "prefix_complete", "packet_count", "n_retrans_prefix", "n_out_of_order",
                              "match_status", "match_reason", "label", "binary_label", "trusted",
                              "start_offset_s", "duration_diff_s", "matched_row_id", "exclusion_reason")


def assert_prefix_only(columns) -> None:
    """Raise if any whole-flow metadata column is requested as a model input."""
    bad = sorted(set(columns) & set(FULL_FLOW_METADATA_COLUMNS))
    if bad:
        raise ValueError(f"full-flow / label columns must not be packet-prefix inputs: {bad}")


class FlowWriter:
    """Batching writer. ``fmt='parquet'`` needs pyarrow; ``fmt='csv'`` also writes
    the v3 ``features_json`` column ([ip_len, iat, direction] per packet) and a
    ``label`` column so ``src.gru_baseline`` can consume the output after labeling."""

    def __init__(self, path: Path, fmt: str = "parquet", batch_size: int = 50_000):
        self.path = Path(path)
        self.fmt = fmt
        self.batch_size = batch_size
        self.buffer: List[dict] = []
        self.n_written = 0
        self._pq_writer = None
        self._csv_file = None
        self._csv_writer = None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if fmt not in ("parquet", "csv"):
            raise ValueError("fmt must be 'parquet' or 'csv'")

    def __call__(self, record: dict) -> None:
        self.buffer.append(record)
        if len(self.buffer) >= self.batch_size:
            self._flush_buffer()

    def _flush_buffer(self) -> None:
        if not self.buffer:
            return
        if self.fmt == "parquet":
            import pyarrow as pa
            import pyarrow.parquet as pq
            table = pa.Table.from_pylist(self.buffer)
            if self._pq_writer is None:
                self._pq_writer = pq.ParquetWriter(str(self.path), table.schema)
            else:
                table = table.cast(self._pq_writer.schema)
            self._pq_writer.write_table(table)
        else:
            if self._csv_writer is None:
                self._csv_file = open(self.path, "w", newline="", encoding="utf-8")
                fields = [k for k in self.buffer[0] if k not in LIST_COLUMNS]
                fields += ["packets_json", "features_json", "label"]
                self._csv_writer = csv.DictWriter(self._csv_file, fieldnames=fields)
                self._csv_writer.writeheader()
            for rec in self.buffer:
                row = {k: v for k, v in rec.items() if k not in LIST_COLUMNS}
                row["packets_json"] = json.dumps({k: rec[k] for k in LIST_COLUMNS}, separators=(",", ":"))
                row["features_json"] = json.dumps(
                    [[l, round(t, 6), d] for l, t, d in zip(rec["pkt_ip_len"], rec["pkt_iat"], rec["pkt_direction"])],
                    separators=(",", ":"))
                row["label"] = rec.get("label", "UNLABELED")
                self._csv_writer.writerow(row)
        self.n_written += len(self.buffer)
        self.buffer = []

    def close(self) -> None:
        self._flush_buffer()
        if self._pq_writer is not None:
            self._pq_writer.close()
        if self._csv_file is not None:
            self._csv_file.close()
        if self.n_written == 0 and self.fmt == "parquet":
            # Write an empty file with no rows so downstream steps fail loudly but cleanly.
            import pyarrow as pa
            import pyarrow.parquet as pq
            pq.write_table(pa.table({"flow_uid": pa.array([], pa.string())}), str(self.path))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def read_flows(path: Path):
    """Load a flow table (Parquet or v4 CSV) into a pandas DataFrame."""
    import pandas as pd
    path = Path(path)
    if path.suffix.lower() == ".parquet":
        return pd.read_parquet(path)
    df = pd.read_csv(path)
    if "packets_json" in df.columns:
        lists = df["packets_json"].map(json.loads)
        for col in LIST_COLUMNS:
            df[col] = lists.map(lambda d, c=col: d[c])
    return df
