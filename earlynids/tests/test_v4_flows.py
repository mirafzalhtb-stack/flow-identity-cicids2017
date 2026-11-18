"""Unit tests for v4 packet parsing and flow reconstruction (synthetic fixtures)."""
import pytest

from src.preprocessing.flows import FlowConfig, extract_flows
from src.preprocessing.packet import PacketRecord, SkipReason, parse_packet
from src.preprocessing.synthetic import EXPECTED, _tcp, _udp, build_scenarios, handshake_session

SC = build_scenarios()


def run(frames, **kw):
    out = []
    cfg = FlowConfig(**{"max_packets": 20, **kw})
    stats = extract_flows(sorted(frames, key=lambda p: float(p.time)), cfg, out.append)
    return stats, out


# ---------------------------------------------------------------- parsing
def test_ip_length_not_frame_length():
    p = _tcp("10.0.0.1", "10.0.0.2", 1, 2, "S", 0.0)
    r = parse_packet(p)
    assert isinstance(r, PacketRecord)
    assert r.ip_len == 40 and len(p) == 54  # 14-byte Ethernet header excluded
    assert r.payload_len == 0


def test_payload_length():
    r = parse_packet(_tcp("10.0.0.1", "10.0.0.2", 1, 2, "PA", 0.0, payload=b"x" * 7))
    assert r.payload_len == 7 and r.ip_len == 47


def test_udp_and_ipv6_parse():
    assert parse_packet(_udp("1.1.1.1", "2.2.2.2", 1, 53, 0.0)).proto == 17
    r = parse_packet(_tcp("2001:db8::1", "2001:db8::2", 1, 2, "S", 0.0, v6=True))
    assert r.ip_version == 6 and r.ip_len == 60


def test_skip_reasons():
    arp, frag, icmp = SC["skipped"]
    assert parse_packet(arp) == SkipReason.NOT_IP
    assert parse_packet(frag) == SkipReason.FRAGMENT
    assert parse_packet(icmp) == SkipReason.NOT_TCP_UDP


def test_malformed_input_does_not_raise():
    class Broken:
        time = 0.0
        def __contains__(self, item):
            raise RuntimeError("corrupt frame")
    assert parse_packet(Broken()) == SkipReason.MALFORMED


def test_bad_timestamp():
    p = _tcp("10.0.0.1", "10.0.0.2", 1, 2, "S", 0.0)
    p.time = float("nan")
    assert parse_packet(p) == SkipReason.BAD_TIMESTAMP


# ---------------------------------------------------------------- flows
def test_tuple_reuse_after_fin_gives_two_flows():
    stats, flows = run(SC["tuple_reuse_fin"])
    exp = EXPECTED["tuple_reuse_fin"]
    assert len(flows) == exp["flows"]
    assert sorted(f["end_reason"] for f in flows) == exp["end_reasons"]
    assert stats["post_close_packets"] == exp["post_close"]
    assert all(f["start_reason"] == "syn" and f["valid_early_prefix"] for f in flows)


def test_bidirectional_direction_and_iat():
    _, flows = run(SC["tuple_reuse_fin"])
    f = flows[0]
    assert f["pkt_direction"][:3] == [1, -1, 1]  # SYN, SYN-ACK, ACK
    assert f["pkt_iat"][0] == 0.0
    assert f["pkt_iat"][1] == pytest.approx(0.01)
    assert f["src_port"] == 40000 and f["dst_port"] == 80


def test_rst_termination():
    _, flows = run(SC["rst"])
    assert [f["end_reason"] for f in flows] == ["rst"]


def test_long_flow_prefix_cap_without_duplicates():
    stats, flows = run(SC["long"])
    assert len(flows) == 1
    f = flows[0]
    assert f["observed_packets"] == EXPECTED["long"]["observed_packets"]
    assert f["packet_count"] == 20 and f["prefix_complete"]
    assert stats["packets_after_prefix"] == 13
    assert f["end_reason"] == "eof"


def test_short_flow_and_configurable_horizon():
    _, flows = run(SC["rst"], max_packets=3)
    assert flows[0]["packet_count"] == 3 and flows[0]["observed_packets"] == 8


def test_udp_idle_timeout_restart():
    _, flows = run(SC["udp_timeout"])
    assert len(flows) == 2
    reasons = sorted(f["end_reason"] for f in flows)
    assert reasons == ["eof", "idle_timeout"]
    assert sorted(f["observed_packets"] for f in flows) == [1, 2]


def test_syn_retransmission_is_same_flow():
    stats, flows = run(SC["syn_retrans"])
    assert len(flows) == 1 and stats["syn_retransmissions"] == 1


def test_data_retransmission_flagged():
    stats, flows = run(SC["data_retrans"])
    assert len(flows) == 1
    assert flows[0]["n_retrans_prefix"] == 1 and sum(flows[0]["pkt_retrans"]) == 1


def test_midstream_flagged_invalid():
    _, flows = run(SC["midstream"])
    assert flows[0]["start_reason"] == "midstream" and not flows[0]["valid_early_prefix"]


def test_synack_first_sets_initiator_to_client():
    frames = handshake_session("10.1.0.1", "10.1.0.2", 41000, 80, 0.0)[1:]
    _, flows = run(frames)
    f = flows[0]
    assert f["src_ip"] == "10.1.0.1" and f["pkt_direction"][0] == -1
    assert f["start_reason"] == "midstream"


def test_ipv6_flow():
    _, flows = run(SC["ipv6"])
    assert len(flows) == 1 and flows[0]["ip_version"] == 6


def test_session_restart_on_new_syn():
    _, flows = run(SC["restart"])
    assert sorted(f["end_reason"] for f in flows) == sorted(EXPECTED["restart"]["end_reasons"])


def test_capacity_eviction_marks_continuation_not_new_session():
    a = handshake_session("10.2.0.1", "10.2.0.2", 42000, 80, 0.0, n_data=6, close=None)
    b = handshake_session("10.2.0.3", "10.2.0.4", 42001, 80, 0.005, n_data=6, close=None)
    stats, flows = run(a + b, max_active=1)
    assert stats["peak_active_flows"] == 1
    assert stats["end_capacity"] > 0
    starts = [f["start_reason"] for f in flows]
    assert starts.count("syn") == 2  # exactly one genuine start per connection
    assert all(s in ("syn", "continuation") for s in starts)
    assert sum(f["valid_early_prefix"] for f in flows) == 2
    assert sum(f["observed_packets"] for f in flows) == len(a) + len(b)


def test_timestamp_regression_counted_and_iat_clamped():
    frames = handshake_session("10.3.0.1", "10.3.0.2", 43000, 80, 0.0, close=None)
    frames[3].time = 0.001  # earlier than previous packet of the flow
    out = []
    stats = extract_flows(frames, FlowConfig(), out.append)  # keep capture order
    assert stats["global_timestamp_regressions"] >= 1
    assert stats["flow_out_of_order_packets"] >= 1
    assert min(out[0]["pkt_iat"]) >= 0.0


def test_active_timeout_splits_long_lived_flow():
    frames = [_udp("10.4.0.1", "10.4.0.2", 1000, 2000, float(t)) for t in range(0, 50, 10)]
    _, flows = run(frames, active_timeout=25.0)
    assert len(flows) == 2
    assert flows[0]["end_reason"] == "active_timeout"
    assert flows[1]["start_reason"] == "continuation" and not flows[1]["valid_early_prefix"]


def test_packet_conservation_all_scenarios():
    frames = [f for fr in SC.values() for f in fr]
    stats, flows = run(frames)
    assert stats["conservation_ok"]
    assert stats["eligible_packets"] == sum(f["observed_packets"] for f in flows) + stats["post_close_packets"]
    assert len({f["flow_uid"] for f in flows}) == len(flows)
    expected_flows = sum(v["flows"] for v in EXPECTED.values())
    assert len(flows) == expected_flows


def test_invalid_config_rejected():
    with pytest.raises(ValueError):
        FlowConfig(max_packets=0).validate()
    with pytest.raises(ValueError):
        FlowConfig(idle_timeout=-1).validate()
