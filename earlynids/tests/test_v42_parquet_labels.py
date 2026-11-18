"""v4.2: native Parquet label files share the CSV schema and the conservative policy."""
import numpy as np
import pandas as pd
import pytest

from src.labeling.cicids2017 import (LabelConfig, LabelSchemaError, label_flows, load_label_files)

T0 = 1499086800.0  # 2017-07-03 13:00:00 UTC
COLS = [" Flow ID", " Source IP", " Source Port", " Destination IP", " Destination Port", " Protocol",
        " Timestamp", " Flow Duration", " Label"]


def rows(spec):
    out = []
    for ts, dur, label, *rest in spec:
        src = rest[0] if rest else "10.0.0.1"
        out.append({" Flow ID": f"id-{len(out)}", " Source IP": src, " Source Port": 40000,
                    " Destination IP": "10.0.0.2", " Destination Port": 80, " Protocol": 6,
                    " Timestamp": ts, " Flow Duration": dur, " Label": label})
    return pd.DataFrame(out, columns=COLS)


def flow(uid="f1", start=T0, end=T0 + 1.0, src="10.0.0.1", sport=40000, dst="10.0.0.2", dport=80):
    return {"flow_uid": uid, "capture_id": "mon", "protocol": 6, "src_ip": src, "src_port": sport,
            "dst_ip": dst, "dst_port": dport, "start_time": start, "end_time": end,
            "valid_early_prefix": True, "start_reason": "syn"}


def write_both(df, tmp_path, name="Monday-WorkingHours.pcap_ISCX.csv"):
    csv = tmp_path / name
    df.to_csv(csv, index=False)
    pq = tmp_path / (name + ".parquet")
    df.to_parquet(pq, index=False)
    return csv, pq


def cfg(**kw):
    return LabelConfig(**{"utc_offset_hours": 0.0, **kw})


def run_file(path, flows, **kw):
    c = cfg(**kw)
    labels, invalid, stats = load_label_files([path], c)
    return label_flows(pd.DataFrame(flows), labels, c), labels, invalid, stats


def test_csv_parquet_schema_equivalence(tmp_path):
    df = rows([("03/07/2017 13:00:00", 1_000_000, "BENIGN"), ("03/07/2017 13:00:30", 1_000_000, "DoS Hulk"),
               ("bad time", 5, "BENIGN")])
    csv, pq = write_both(df, tmp_path)
    flows = [flow("a"), flow("b", T0 + 30, T0 + 31), flow("c", T0 + 999, T0 + 1000)]
    rc, lc, ic, sc = run_file(csv, flows)
    rp, lp, ip, sp = run_file(pq, flows)
    cols = ["key", "csv_src_ep", "csv_start", "csv_duration", "csv_label", "source_row", "csv_flow_id"]
    pd.testing.assert_frame_equal(lc[cols].reset_index(drop=True), lp[cols].reset_index(drop=True), check_dtype=False)
    assert list(ic.reason) == list(ip.reason) == ["malformed_timestamp"]
    ev = ["match_status", "match_reason", "binary_label", "matched_row_id"]
    pd.testing.assert_frame_equal(rc[ev], rp[ev])
    assert sp[pq.name]["format"] == "parquet" and sc[csv.name]["format"] == "csv"


def test_parquet_native_types_equivalent_to_strings(tmp_path):
    """Parquet with float protocol/ports and datetime64 timestamps parses like the string CSV."""
    df = rows([("03/07/2017 13:00:00", 1_000_000, "PortScan")])
    native = df.copy()
    native[" Protocol"] = 6.0
    native[" Source Port"] = 40000.0
    native[" Timestamp"] = pd.to_datetime(["2017-07-03 13:00:00"])
    p = tmp_path / "Tuesday-x.parquet"; native.to_parquet(p, index=False)
    res, labels, invalid, _ = run_file(p, [flow()])
    assert invalid.empty and labels["timestamp_kind"].tolist() == ["datetime_naive"]
    assert res.iloc[0].match_status == "unique" and res.iloc[0].binary_label == "ATTACK"


def test_parquet_tz_aware_timestamps_ignore_offset(tmp_path):
    df = rows([("x", 1_000_000, "BENIGN")])
    df[" Timestamp"] = pd.to_datetime(["2017-07-03 10:00:00"]).tz_localize("America/Halifax")  # = 13:00 UTC
    p = tmp_path / "Monday-tz.parquet"; df.to_parquet(p, index=False)
    res, labels, _, _ = run_file(p, [flow()], utc_offset_hours=-3.0)
    assert labels["timestamp_kind"].tolist() == ["datetime_tz"]
    assert labels["csv_start"].iloc[0] == pytest.approx(T0)
    assert res.iloc[0].match_status == "unique"


def test_parquet_missing_required_column(tmp_path):
    df = rows([("03/07/2017 13:00:00", 1, "BENIGN")]).drop(columns=[" Timestamp"])
    p = tmp_path / "Monday.parquet"; df.to_parquet(p, index=False)
    with pytest.raises(LabelSchemaError):
        load_label_files([p], cfg())


def test_parquet_duplicate_required_column(tmp_path):
    df = rows([("03/07/2017 13:00:00", 1, "BENIGN")])
    df["Label"] = "BENIGN"  # normalises to the same name as ' Label'
    p = tmp_path / "Monday.parquet"; df.to_parquet(p, index=False)
    with pytest.raises(LabelSchemaError, match="duplicated"):
        load_label_files([p], cfg())


def test_parquet_malformed_and_null_values(tmp_path):
    df = rows([("03/07/2017 13:00:00", 1_000_000, "BENIGN"), ("31/31/2017 99:00:00", 1, "BENIGN"),
               ("03/07/2017 13:00:00", 1, None), ("03/07/2017 13:00:00", float("inf"), "BENIGN"),
               ("03/07/2017 13:00:00", 1, "BENIGN", None)])
    df[" Protocol"] = [6, 6, 6, 6, 6]
    p = tmp_path / "Monday.parquet"; df.to_parquet(p, index=False)
    labels, invalid, stats = load_label_files([p], cfg())
    assert len(labels) == 1
    assert sorted(invalid.reason) == sorted(["malformed_timestamp", "missing_label", "invalid_duration", "missing_src_ip"])
    assert sorted(invalid.source_row) == [1, 2, 3, 4]  # provenance: row position inside the file
    assert stats[p.name]["invalid"] == 4


def test_unsupported_protocol_and_extension(tmp_path):
    df = rows([("03/07/2017 13:00:00", 1, "BENIGN")]); df[" Protocol"] = 1
    p = tmp_path / "Monday.parquet"; df.to_parquet(p, index=False)
    _, invalid, _ = load_label_files([p], cfg())
    assert invalid.reason.tolist() == ["unsupported_protocol"]
    bad = tmp_path / "labels.json"; bad.write_text("{}")
    with pytest.raises(LabelSchemaError):
        load_label_files([bad], cfg())


@pytest.mark.parametrize("spec,flows,expected", [
    # duplicate label rows -> ambiguous (exact duplicates)
    ([("03/07/2017 13:00:00", 1_000_000, "DDoS"), ("03/07/2017 13:00:00", 1_000_000, "DDoS")],
     [flow()], ["ambiguous_same_label"]),
    # conflicting labels
    ([("03/07/2017 13:00:00", 1_000_000, "BENIGN"), ("03/07/2017 13:00:01", 1_000_000, "PortScan")],
     [flow(start=T0 + 0.5, end=T0 + 1.5)], ["conflict"]),
    # one label row shared by two PCAP flows
    ([("03/07/2017 13:00:00", 10_000_000, "DDoS")], [flow("a", T0, T0 + 10), flow("b", T0 + 0.5, T0 + 10)],
     ["ambiguous_shared_row", "ambiguous_shared_row"]),
    # reused five-tuple: two sessions, two flows -> unique each
    ([("03/07/2017 13:00:00", 1_000_000, "BENIGN"), ("03/07/2017 13:00:30", 1_000_000, "FTP-Patator")],
     [flow("a"), flow("b", T0 + 30, T0 + 31)], ["unique", "unique"]),
])
def test_parquet_policy_cases(tmp_path, spec, flows, expected):
    p = tmp_path / "Monday.parquet"; rows(spec).to_parquet(p, index=False)
    res, _, _, _ = run_file(p, flows)
    assert list(res.match_status) == expected
    assert res.loc[res.match_status != "unique", "binary_label"].isna().all()


def test_parquet_reversed_direction(tmp_path):
    p = tmp_path / "Monday.parquet"; rows([("03/07/2017 13:00:00", 1_000_000, "BENIGN")]).to_parquet(p, index=False)
    res, _, _, _ = run_file(p, [flow(src="10.0.0.2", sport=80, dst="10.0.0.1", dport=40000)])
    assert res.iloc[0].match_status == "unique" and res.iloc[0].orientation == "reversed"


def test_parquet_streamed_in_small_batches(tmp_path):
    spec = [(f"03/07/2017 13:{m:02d}:00", 1_000_000, "BENIGN") for m in range(50)]
    p = tmp_path / "Monday.parquet"; rows(spec).to_parquet(p, index=False, row_group_size=7)
    labels, _, stats = load_label_files([p], cfg(chunksize=5))
    assert len(labels) == 50 and stats[p.name]["rows"] == 50
    assert list(labels["source_row"]) == list(range(50)) and labels["row_id"].is_unique


def test_multiple_files_keep_provenance(tmp_path):
    a = tmp_path / "Friday-A.parquet"; rows([("03/07/2017 13:00:00", 1, "BENIGN")]).to_parquet(a, index=False)
    b = tmp_path / "Friday-B.csv"; rows([("03/07/2017 14:00:00", 1, "BENIGN")]).to_csv(b, index=False)
    labels, _, stats = load_label_files([a, b], cfg())
    assert list(labels.source_file) == [a.name, b.name] and list(labels.row_id) == [0, 1]
    assert list(labels.source_row) == [0, 0]


def test_fully_empty_rows_are_reported_separately(tmp_path):
    df = rows([("03/07/2017 13:00:00", 1_000_000, "BENIGN")])
    blank = pd.DataFrame({c: [None] * 3 for c in df.columns})
    p = tmp_path / "Thursday.parquet"; pd.concat([df, blank], ignore_index=True).to_parquet(p, index=False)
    labels, invalid, _ = load_label_files([p], cfg())
    assert len(labels) == 1 and invalid.reason.tolist() == ["empty_row"] * 3


def test_gate_separates_empty_rows_from_malformed_records():
    from src.datasets.quality_gate import GateConfig, evaluate
    import sys
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))
    from test_v41_cli_and_gate import labelled_df
    stats = {"total_csv_records": 1000, "invalid_csv_records": 600, "invalid_by_reason": {"empty_row": 600}}
    rep = evaluate(labelled_df(), stats, GateConfig())
    assert rep["passed"] and rep["rates"]["invalid_csv_rate"] == 0.0 and rep["rates"]["empty_row_rate"] == 0.6
    assert rep["totals"]["empty_csv_records"] == 600 and rep["threshold_status"]["max_empty_row_rate"] == "provisional"
    stats["invalid_by_reason"] = {"empty_row": 590, "malformed_timestamp": 10}
    assert not evaluate(labelled_df(), stats, GateConfig())["passed"]  # 10/410 malformed > 1 %
    assert not evaluate(labelled_df(), stats, GateConfig(max_empty_row_rate=0.5))["passed"]
