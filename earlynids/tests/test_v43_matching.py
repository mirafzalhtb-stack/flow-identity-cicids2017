"""v4.3 identity-evidence matching (evidence_v43) vs legacy_v41. Synthetic fixtures only:
they demonstrate the algorithm's behaviour, not real-world correctness."""
import numpy as np
import pandas as pd
import pytest
from scapy.all import IP, UDP, Ether, Raw

from src.labeling.cicids2017 import (LabelConfig, candidate_evidence, label_flows, label_frame_from_records,
                                     load_label_files)
from src.preprocessing.flows import FlowConfig, extract_flows

T0 = 1499086800.0
A, B = "192.168.10.12", "192.168.10.50"


def row(src=A, sp=47006, dst=B, dp=63652, dur_us=1_000_000, label="BENIGN", ts="03/07/2017 13:00:00", proto="6", **extra):
    r = {"source ip": src, "source port": str(sp), "destination ip": dst, "destination port": str(dp),
         "protocol": proto, "timestamp": ts, "flow duration": str(dur_us), "label": label}
    r.update(extra)
    return r


def flow(uid="f", start=T0 + 0.3, dur=0.020719, src=A, sp=47006, dst=B, dp=63652, proto=6, end_reason="fin", **extra):
    d = {"flow_uid": uid, "capture_id": "monday", "protocol": proto, "src_ip": src, "src_port": sp, "dst_ip": dst,
         "dst_port": dp, "start_time": start, "end_time": start + dur, "valid_early_prefix": True,
         "start_reason": "syn", "end_reason": end_reason}
    d.update(extra)
    return d


def run(rows, flows, **kw):
    cfg = LabelConfig(**{"utc_offset_hours": 0.0, **kw})
    labels, _ = label_frame_from_records(rows, cfg)
    return label_flows(pd.DataFrame(flows), labels, cfg), labels, cfg


CASE_5370 = [row(dur_us=20655), row(dur_us=1), row(src=B, sp=63652, dst=A, dp=47006, dur_us=4),
             row(src=B, sp=63652, dst=A, dp=47006, dur_us=240)]


def test_very_short_tcp_flow_disambiguated_by_duration_residual():
    """Reconstruction of the reported monday-000005370 case (4 same-label candidates)."""
    res, _, _ = run(CASE_5370, [flow("monday-000005370")])
    r = res.iloc[0]
    assert r.match_status == "unique" and r.match_reason == "disambiguated_by_duration_residual"
    assert r.matched_row_id == 0 and r.identity_basis == "strict_unique_with_margin"
    assert r.n_consistent == 4 and r.n_strict == 1
    assert r.selected_duration_residual_s == pytest.approx(64e-6, abs=1e-6)  # float epoch precision
    assert r.runner_up_miss_ratio >= 2.0
    assert r.matched_source_file == "test" and r.matched_source_row == 0


def test_legacy_mode_reproduces_v42_ambiguity():
    res, _, _ = run(CASE_5370, [flow()], matching_mode="legacy_v41")
    assert res.iloc[0].match_status == "ambiguous_same_label" and res.iloc[0].matching_mode == "legacy_v41"


def test_label_is_never_used_to_choose_conflict_wins():
    rows = [row(dur_us=20655, label="BENIGN"), row(dur_us=1, label="DoS Hulk")]
    res, _, _ = run(rows, [flow()])
    assert res.iloc[0].match_status == "conflict" and res.iloc[0].binary_label is None


def test_insufficient_margin_stays_ambiguous():
    # residuals 0.2 ms and 1.6 ms; strict tol about 1.2 ms -> runner-up misses by < 2x
    rows = [row(dur_us=20919), row(dur_us=22319)]
    res, _, _ = run(rows, [flow()])
    assert res.iloc[0].match_status == "ambiguous_same_label"
    assert res.iloc[0].match_reason == "insufficient_identity_margin"


def test_same_label_non_identical_both_strict_is_ambiguous():
    rows = [row(dur_us=20719), row(dur_us=20720)]
    res, _, _ = run(rows, [flow()])
    assert res.iloc[0].match_reason == "multiple_strict_candidates" and not res.iloc[0].trusted


def test_exact_duplicates_stay_ambiguous_unless_collapsed():
    rows = [row(dur_us=20700), row(dur_us=20700)]
    res, _, _ = run(rows, [flow()])
    assert res.iloc[0].match_reason == "exact_duplicate_csv_rows"
    res2, _, _ = run(rows, [flow()], collapse_exact_duplicate_rows=True)
    assert res2.iloc[0].match_status == "unique"


def test_no_strict_candidate_is_ambiguous():
    rows = [row(dur_us=500_000), row(dur_us=700_000)]
    res, _, _ = run(rows, [flow(dur=0.6)])
    assert res.iloc[0].match_reason == "no_candidate_meets_strict_identity"


def test_reverse_orientation_candidate_can_be_selected():
    rows = [row(src=B, sp=63652, dst=A, dp=47006, dur_us=20700), row(dur_us=3)]
    res, _, _ = run(rows, [flow()])
    r = res.iloc[0]
    assert r.match_status == "unique" and r.orientation == "reversed" and r.matched_row_id == 0


def test_reused_label_row_across_flows_is_shared():
    """Two PCAP sessions on one 5-tuple, 0.5 s apart; only one CSV row. The row is a consistent
    candidate of both flows, so neither may claim it."""
    rows = [row(dur_us=20700)]
    res, _, _ = run(rows, [flow("a"), flow("b", start=T0 + 0.8, dur=0.0207)])
    assert set(res.match_status) == {"ambiguous_shared_row"}
    assert res.matched_row_id.isna().all() and not res.trusted.any()


def test_reused_five_tuple_two_sessions_resolved_independently():
    rows = [row(dur_us=20700), row(dur_us=40000, ts="03/07/2017 13:00:30", label="FTP-Patator")]
    res, _, _ = run(rows, [flow("a"), flow("b", start=T0 + 30.2, dur=0.04)])
    assert list(res.match_status) == ["unique", "unique"] and list(res.label) == ["BENIGN", "FTP-Patator"]


def test_long_udp_flow_with_csv_active_timeout_uses_window_duration():
    """Reported NTP case: PCAP flow 684.019431 s (idle-timeout segmentation), CSV row 72.018466 s.
    With the extractor's 120 s window statistic the expected duration is exact."""
    rows = [row(src="192.168.10.3", sp=123, dst="192.168.10.1", dp=123, proto="17", dur_us=72018466)]
    fl = flow("monday-000000224", start=T0, dur=684.019431, src="192.168.10.3", sp=123, dst="192.168.10.1",
              dp=123, proto=17, end_reason="idle_timeout", window_s=120.0, window_last_rel_ts=72.018466)
    legacy, _, _ = run(rows, [fl], matching_mode="legacy_v41", csv_active_timeout_s=120.0)
    assert legacy.iloc[0].match_status == "time_inconsistent"           # defect D43-2 reproduced
    without, _, _ = run(rows, [fl])                                       # no active timeout configured
    assert without.iloc[0].match_status == "time_inconsistent"
    ev, _, _ = run(rows, [fl], csv_active_timeout_s=120.0)
    r = ev.iloc[0]
    assert r.match_status == "unique" and r.expected_duration_exact
    assert r.expected_duration_s == pytest.approx(72.018466)


def test_active_timeout_without_window_stats_is_flagged_approximate():
    rows = [row(proto="17", dur_us=120_000_000)]
    res, _, _ = run(rows, [flow(dur=684.0, proto=17)], csv_active_timeout_s=120.0)
    assert res.iloc[0].expected_duration_exact is False or res.iloc[0].expected_duration_exact == False  # noqa: E712


def test_eof_truncated_flow_is_right_censored():
    """Partial capture: the PCAP flow is cut by end of file, the CSV row is longer."""
    rows = [row(dur_us=50_000_000)]
    res, _, _ = run(rows, [flow(dur=3.0, end_reason="eof")])
    assert res.iloc[0].match_status == "unique" and res.iloc[0].duration_censored
    legacy, _, _ = run(rows, [flow(dur=3.0, end_reason="eof")], matching_mode="legacy_v41")
    assert legacy.iloc[0].match_status == "time_inconsistent"
    short_csv, _, _ = run([row(dur_us=1_000_000)], [flow(dur=3.0, end_reason="eof")])
    assert short_csv.iloc[0].match_status == "time_inconsistent"  # CSV shorter than observed: contradiction


def test_packet_evidence_report_and_require():
    rows = [row(dur_us=20700, **{"total fwd packets": "5", "total backward packets": "4"}),
            row(dur_us=20705, **{"total fwd packets": "1", "total backward packets": "0"})]
    fl = flow(n_fwd_packets=5, n_bwd_packets=4)
    rep, _, _ = run(rows, [fl])                       # report mode: both strict on duration -> ambiguous
    assert rep.iloc[0].match_reason == "multiple_strict_candidates"
    req, _, _ = run(rows, [fl], packet_check="require")
    r = req.iloc[0]
    assert r.match_status == "unique" and r.matched_row_id == 0 and r.selected_packet_residual == 0


def test_packet_counts_orientation_aware():
    rows = [row(src=B, sp=63652, dst=A, dp=47006, dur_us=20700, **{"total fwd packets": "4", "total backward packets": "5"})]
    res, _, _ = run(rows, [flow(n_fwd_packets=5, n_bwd_packets=4)], packet_check="require")
    assert res.iloc[0].match_status == "unique" and res.iloc[0].selected_packet_residual == 0


def test_malformed_packet_columns_do_not_crash():
    rows = [row(dur_us=20700, **{"total fwd packets": "x", "total backward packets": ""})]
    res, labels, _ = run(rows, [flow(n_fwd_packets=5, n_bwd_packets=4)])
    assert res.iloc[0].match_status == "unique" and np.isnan(labels["csv_fwd_packets"].iloc[0])


def test_deterministic_and_order_invariant():
    rows = CASE_5370 + [row(sp=50000, dur_us=1000), row(sp=50000, dur_us=900)]
    flows = [flow("x"), flow("y", sp=50000, dur=0.001), flow("z", sp=1, dur=1)]
    r1, _, _ = run(rows, flows)
    r2, _, _ = run(rows, flows)
    r3, _, _ = run(rows, list(reversed(flows)))
    cols = ["flow_uid", "match_status", "match_reason", "matched_row_id", "runner_up_row_id"]
    pd.testing.assert_frame_equal(r1[cols], r2[cols])
    pd.testing.assert_frame_equal(r1[cols].sort_values("flow_uid").reset_index(drop=True),
                                  r3[cols].sort_values("flow_uid").reset_index(drop=True))


def test_timestamp_offset_with_evidence_mode():
    rows = [row(dur_us=20700, ts="03/07/2017 10:00:00")]
    assert run(rows, [flow()])[0].iloc[0].match_status == "unmatched"
    assert run(rows, [flow()], utc_offset_hours=-3.0)[0].iloc[0].match_status == "unique"


@pytest.mark.parametrize("unit,value", [("us", "20700"), ("ms", "20.7"), ("s", "0.0207")])
def test_duration_unit_conversions(tmp_path, unit, value):
    df = pd.DataFrame([{" Source IP": A, " Source Port": 47006, " Destination IP": B, " Destination Port": 63652,
                        " Protocol": 6, " Timestamp": "03/07/2017 13:00:00", " Flow Duration": value,
                        " Label": "BENIGN"}] + [{" Source IP": A, " Source Port": 47006, " Destination IP": B,
                        " Destination Port": 63652, " Protocol": 6, " Timestamp": "03/07/2017 13:00:00",
                        " Flow Duration": {"us": "1", "ms": "0.001", "s": "0.000001"}[unit], " Label": "BENIGN"}])
    p = tmp_path / "Monday.parquet"; df.to_parquet(p, index=False)
    cfg = LabelConfig(utc_offset_hours=0.0, duration_unit=unit)
    labels, _, _ = load_label_files([p], cfg)
    assert labels["csv_duration"].iloc[0] == pytest.approx(0.0207)
    res = label_flows(pd.DataFrame([flow()]), labels, cfg)
    assert res.iloc[0].match_status == "unique" and res.iloc[0].matched_row_id == 0


def test_candidate_evidence_table():
    _, labels, cfg = run(CASE_5370, [flow("monday-000005370")])
    ce = candidate_evidence(pd.DataFrame([flow("monday-000005370")]), labels, cfg)
    assert len(ce) == 4 and ce.iloc[0]["row_id"] == 0 and bool(ce.iloc[0]["strict"])
    assert set(ce["orientation"]) == {"same", "reversed"}


def test_invalid_config_values():
    for kw in ({"matching_mode": "x"}, {"packet_check": "maybe"}, {"identity_margin": 0.5}, {"strict_duration_abs_s": -1}):
        with pytest.raises(ValueError):
            LabelConfig(utc_offset_hours=0.0, **kw).validate()


# ---------------------------------------------------------------- extractor window statistics
def _udp(t, src="10.1.1.1", dst="10.1.1.2"):
    p = Ether() / IP(src=src, dst=dst) / UDP(sport=123, dport=123) / Raw(b"n")
    p.time = t
    return p


def test_extractor_window_statistics_and_segmentation_before_after():
    times = [0.0, 8.0, 72.018466] + [72.018466 + 64 * k for k in range(1, 10)] + [684.019431]
    frames = [_udp(t) for t in times]
    out = []
    extract_flows(frames, FlowConfig(), out.append)               # default: idle timeout only
    assert len(out) == 1
    f = out[0]
    assert f["duration"] == pytest.approx(684.019431) and f["end_reason"] == "eof"
    assert f["window_s"] == 120.0 and f["window_last_rel_ts"] == pytest.approx(72.018466)
    assert f["window_fwd_packets"] == 3 and f["n_fwd_packets"] == len(times) and f["n_bwd_packets"] == 0
    out2 = []
    extract_flows(frames, FlowConfig(active_timeout=120.0), out2.append)  # optional CIC-like cut
    assert out2[0]["duration"] == pytest.approx(72.018466) and out2[0]["end_reason"] == "active_timeout"
    assert all(not f["valid_early_prefix"] for f in out2[1:])     # continuation segments are not early samples


def test_extractor_bidirectional_counts():
    frames = [_udp(0.0), _udp(0.1, "10.1.1.2", "10.1.1.1"), _udp(0.2)]
    out = []
    extract_flows(frames, FlowConfig(window_s=None), out.append)
    assert (out[0]["n_fwd_packets"], out[0]["n_bwd_packets"]) == (2, 1)
    assert out[0]["window_last_rel_ts"] is None
