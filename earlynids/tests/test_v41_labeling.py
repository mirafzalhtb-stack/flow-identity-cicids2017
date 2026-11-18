"""v4.1 conservative label matching. Covers the 10 required regression cases
plus the intents of the superseded v4 tests (tests/test_v4_labeling.py)."""
import pandas as pd
import pytest

from src.labeling.cicids2017 import (LabelConfig, LabelSchemaError, config_from_dict, label_flows,
                                     label_frame_from_records, match_flows, normalize_header,
                                     normalize_label, resolve_columns, time_offset_diagnostics)

T0 = 1499086800.0  # 2017-07-03 13:00:00 UTC


def csv_row(ts="03/07/2017 13:00:00", dur_us=1_000_000, label="BENIGN", **over):
    r = {"source ip": "10.0.0.1", "source port": "40000", "destination ip": "10.0.0.2",
         "destination port": "80", "protocol": "6", "timestamp": ts, "flow duration": str(dur_us), "label": label}
    r.update(over)
    return r


def flow(uid="f1", start=T0, end=T0 + 1.0, src="10.0.0.1", sport=40000, dst="10.0.0.2", dport=80, proto=6, valid=True):
    return {"flow_uid": uid, "capture_id": "mon", "protocol": proto, "src_ip": src, "src_port": sport,
            "dst_ip": dst, "dst_port": dport, "start_time": start, "end_time": end,
            "valid_early_prefix": valid, "start_reason": "syn" if valid else "midstream"}


def run(rows, flows, **cfg_kw):
    cfg = LabelConfig(**{"utc_offset_hours": 0.0, **cfg_kw})
    labels, invalid = label_frame_from_records(rows, cfg)
    res = label_flows(pd.DataFrame(flows), labels, cfg)
    return res, labels, invalid


# 1 exact unique match
def test_exact_unique_match():
    res, _, _ = run([csv_row(label="DoS Hulk")], [flow(start=T0 + 0.3, end=T0 + 1.2)])
    r = res.iloc[0]
    assert r.match_status == "unique" and r.match_reason == "single_consistent_row"
    assert r.binary_label == "ATTACK" and r.trusted and r.label == "DoS Hulk"
    assert r.orientation == "same" and r.start_offset_s == pytest.approx(-0.3)
    assert r.matched_row_id == 0


# 2 reversed direction
def test_reversed_direction():
    res, _, _ = run([csv_row()], [flow(src="10.0.0.2", sport=80, dst="10.0.0.1", dport=40000)])
    assert res.iloc[0].match_status == "unique" and res.iloc[0].orientation == "reversed"


# 3 reused five-tuple: two CSV sessions, two PCAP flows -> each matched to its own row
def test_reused_five_tuple_two_sessions():
    rows = [csv_row(label="BENIGN"), csv_row(ts="03/07/2017 13:00:30", label="FTP-Patator")]
    flows = [flow("a", T0, T0 + 1), flow("b", T0 + 30, T0 + 31)]
    res, _, _ = run(rows, flows)
    assert list(res.match_status) == ["unique", "unique"]
    assert list(res.label) == ["BENIGN", "FTP-Patator"]
    assert list(res.matched_row_id) == [0, 1]


def test_reused_tuple_merged_pcap_flow_is_not_trusted():
    """v4 accepted this (overlap + same label). A PCAP flow spanning two CSV sessions
    is start-aligned with only the first row but its duration does not match it."""
    rows = [csv_row(), csv_row(ts="03/07/2017 13:00:05")]
    res, _, _ = run(rows, [flow(start=T0, end=T0 + 6.0)])
    r = res.iloc[0]
    assert r.match_status == "time_inconsistent" and r.match_reason == "duration_mismatch"
    assert r.binary_label is None and not r.trusted


# 4 two CSV rows with the same label -> ambiguous, NOT trusted (v4 accepted it)
def test_two_rows_same_label_is_ambiguous():
    rows = [csv_row(label="DDoS"), csv_row(ts="03/07/2017 13:00:01", label="DDoS")]
    res, _, _ = run(rows, [flow(start=T0 + 0.5, end=T0 + 1.5)])
    r = res.iloc[0]
    assert r.match_status == "ambiguous_same_label" and not r.trusted and r.binary_label is None
    assert r.n_consistent == 2


def test_exact_duplicate_rows_flagged():
    rows = [csv_row(label="DDoS"), csv_row(label="DDoS")]
    res, _, _ = run(rows, [flow()])
    assert res.iloc[0].match_reason == "exact_duplicate_csv_rows" and not res.iloc[0].trusted
    res2, _, _ = run(rows, [flow()], collapse_exact_duplicate_rows=True)
    assert res2.iloc[0].match_status == "unique"


# 5 conflicting labels
def test_conflicting_labels():
    rows = [csv_row(label="BENIGN"), csv_row(ts="03/07/2017 13:00:01", label="PortScan")]
    res, _, _ = run(rows, [flow(start=T0 + 0.5, end=T0 + 1.5)])
    r = res.iloc[0]
    assert r.match_status == "conflict" and r.binary_label is None and not r.trusted
    assert r.candidate_labels == "BENIGN|PortScan"


def test_conflict_with_duration_inconsistent_candidate():
    rows = [csv_row(label="BENIGN"), csv_row(dur_us=500_000_000, label="DoS Slowloris")]
    res, _, _ = run(rows, [flow()])
    assert res.iloc[0].match_status == "conflict"


# 6 timestamp offset: wrong / right time zone; start misalignment
def test_timestamp_offset():
    rows = [csv_row(ts="03/07/2017 10:00:00")]  # local time UTC-3
    wrong, _, _ = run(rows, [flow()])
    assert wrong.iloc[0].match_status == "unmatched"
    right, _, _ = run(rows, [flow()], utc_offset_hours=-3.0)
    assert right.iloc[0].match_status == "unique"


def test_start_misaligned_is_not_trusted():
    """v4 accepted a flow starting 100 s into a long CSV row."""
    res, _, _ = run([csv_row(dur_us=600_000_000, label="DoS Hulk")], [flow(start=T0 + 100, end=T0 + 101)])
    r = res.iloc[0]
    assert r.match_status == "time_inconsistent" and r.match_reason == "start_misaligned"
    assert r.start_offset_s == pytest.approx(-100.0)


def test_minute_resolution_widens_start_tolerance():
    res, _, _ = run([csv_row(ts="03/07/2017 13:00", dur_us=1_000_000)], [flow(start=T0 + 45, end=T0 + 46)])
    assert res.iloc[0].match_status == "unique"


def test_ambiguous_12h_option():
    rows = [csv_row(ts="03/07/2017 01:00:00")]
    plain, _, _ = run(rows, [flow()])
    assert plain.iloc[0].match_status == "unmatched"
    shifted, _, _ = run(rows, [flow()], ambiguous_12h=True)
    assert shifted.iloc[0].match_status == "unique" and shifted.iloc[0].used_12h_shift


# 7 duration mismatch
def test_duration_mismatch():
    res, _, _ = run([csv_row(dur_us=1_000_000, label="PortScan")], [flow(end=T0 + 300)])
    r = res.iloc[0]
    assert r.match_status == "time_inconsistent" and r.match_reason == "duration_mismatch"
    assert r.duration_diff_s == pytest.approx(-299.0)


def test_csv_active_timeout_allows_split_rows():
    res, _, _ = run([csv_row(dur_us=120_000_000)], [flow(end=T0 + 300)], csv_active_timeout_s=120.0)
    assert res.iloc[0].match_status == "unique"


# 8 missing fields
def test_missing_fields_are_invalid_records():
    rows = [csv_row(**{"source port": ""}), csv_row(label=""), csv_row()]
    _, labels, invalid = run(rows, [flow()])
    assert len(labels) == 1
    assert sorted(invalid.reason) == ["missing_label", "missing_src_port"]


def test_missing_column_is_schema_error():
    cfg = LabelConfig(utc_offset_hours=0.0)
    rec = csv_row(); rec.pop("timestamp")
    with pytest.raises(LabelSchemaError):
        label_frame_from_records([rec], cfg)


def test_duplicated_required_header_is_schema_error():
    with pytest.raises(LabelSchemaError):
        resolve_columns([" Source IP", "Source IP", " Source Port", " Destination IP", " Destination Port",
                         " Protocol", " Timestamp", " Flow Duration", " Label"], LabelConfig(utc_offset_hours=0))


# 9 malformed timestamps and other invalid values
def test_malformed_values():
    rows = [csv_row(ts="yesterday"), csv_row(**{"source ip": "999.1.1.1"}), csv_row(protocol="1"),
            csv_row(**{"destination port": "70000"}), csv_row(dur_us=-5)]
    _, labels, invalid = run(rows, [flow()])
    assert labels.empty
    assert sorted(invalid.reason) == sorted(["malformed_timestamp", "invalid_ip", "unsupported_protocol",
                                             "invalid_port", "invalid_duration"])


# 10 unmatched PCAP flow -> never BENIGN
def test_unmatched_flow_not_benign():
    res, _, _ = run([csv_row()], [flow("x", T0 + 3600, T0 + 3601), flow("y", src="9.9.9.9", proto=17)])
    assert list(res.match_status) == ["unmatched", "unmatched"]
    assert list(res.match_reason) == ["no_csv_row_overlapping_flow_time", "no_csv_row_with_same_key"]
    assert res.binary_label.isna().all() and not res.trusted.any()


# additional policy checks
def test_shared_csv_row_is_ambiguous():
    rows = [csv_row(dur_us=10_000_000, label="DDoS")]
    flows = [flow("a", T0, T0 + 10), flow("b", T0 + 0.5, T0 + 10)]
    res, _, _ = run(rows, flows)
    assert list(res.match_status) == ["ambiguous_shared_row", "ambiguous_shared_row"]
    assert not res.trusted.any()


def test_invalid_early_prefix_not_trusted_even_if_unique():
    res, _, _ = run([csv_row()], [flow(valid=False)])
    r = res.iloc[0]
    assert r.match_status == "unique" and not r.trusted
    assert r.exclusion_reason.startswith("not_valid_early_prefix")


def test_invalid_flow_record():
    res, _, _ = run([csv_row()], [flow(src="not-an-ip")])
    assert res.iloc[0].match_status == "invalid_flow"


def test_requires_explicit_timezone_and_rejects_removed_option():
    with pytest.raises(ValueError):
        LabelConfig().validate()
    with pytest.raises(ValueError):
        config_from_dict({"utc_offset_hours": 0, "accepted_statuses": ["matched"]})


def test_every_flow_has_status_and_reason():
    rows = [csv_row(), csv_row(ts="03/07/2017 14:00:00", label="X")]
    flows = [flow("a"), flow("b", T0 + 99999, T0 + 99999), flow("c", src="9.9.9.9")]
    res, _, _ = run(rows, flows)
    assert res.match_status.notna().all() and res.match_reason.notna().all()
    assert set(res.match_status) <= {"unique", "unmatched"}


def test_time_offset_diagnostics_detects_offset():
    cfg = LabelConfig(utc_offset_hours=0.0)
    labels, _ = label_frame_from_records([csv_row(ts="03/07/2017 10:00:00")], cfg)
    d = time_offset_diagnostics(pd.DataFrame([flow()]), labels)
    assert d["hour_histogram"] == {"-3": 1}


def test_label_and_header_normalization():
    assert normalize_label("Web Attack \x96 Brute Force") == "Web Attack - Brute Force"
    assert normalize_label(" benign ") == "BENIGN"
    assert normalize_header(" Source IP") == "source ip"


def test_chunked_matching_equals_single_pass_and_detects_cross_chunk_sharing():
    rows = [csv_row(label="BENIGN"), csv_row(ts="03/07/2017 13:00:30", label="PortScan"),
            csv_row(ts="03/07/2017 13:01:00", dur_us=10_000_000, label="DDoS")]
    flows = [flow("a", T0, T0 + 1), flow("b", T0 + 30, T0 + 31), flow("c", T0 + 60, T0 + 70),
             flow("d", T0 + 60.5, T0 + 70)]  # c and d share row 2 but sit in different chunks
    cfg = LabelConfig(utc_offset_hours=0.0)
    labels, _ = label_frame_from_records(rows, cfg)
    df = pd.DataFrame(flows)
    one = label_flows(df, labels, cfg, chunk_size=1000)
    many = label_flows(df, labels, cfg, chunk_size=1)
    cols = ["match_status", "match_reason", "binary_label", "matched_row_id"]
    pd.testing.assert_frame_equal(one[cols], many[cols])
    assert list(many.match_status) == ["unique", "unique", "ambiguous_shared_row", "ambiguous_shared_row"]
