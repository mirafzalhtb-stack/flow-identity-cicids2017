"""v4.1 preprocessing regression tests."""
from scapy.all import ICMP, IP, TCP, UDP, Ether, IPv6, Raw

from src.preprocessing.flows import FlowConfig, extract_flows
from src.preprocessing.packet import SkipReason, parse_packet
from src.preprocessing.synthetic import _tcp, handshake_session


def built(p, t=1.0):
    q = Ether(bytes(p))  # dissect from wire bytes, like PcapReader does
    q.time = t
    return q


def test_tso_zero_length_falls_back_to_captured_length():
    """v4 returned ip_len=0 for frames whose IPv4 total-length field is 0."""
    p = built(Ether() / IP(src="10.0.0.1", dst="10.0.0.2", len=0) / TCP(sport=1, dport=2, flags="PA") / Raw(b"x" * 100))
    r = parse_packet(p)
    assert r.ip_len == 140 and r.payload_len == 100 and r.ip_len_from_capture


def test_normal_length_from_header():
    r = parse_packet(built(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2) / Raw(b"x" * 10)))
    assert r.ip_len == 50 and not r.ip_len_from_capture and not r.truncated


def test_ip_in_ip_is_skipped_as_nested():
    """v4 combined outer IPs with inner ports."""
    p = built(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=3, dport=4))
    assert parse_packet(p) == SkipReason.NESTED


def test_icmp_error_quoting_udp_is_not_a_udp_packet():
    """Verified NOT a defect in v4; kept as a regression guard."""
    inner = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=53) / Raw(b"q")
    p = built(Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / ICMP(type=3, code=3) / bytes(inner))
    assert parse_packet(p) == SkipReason.NOT_TCP_UDP


def test_ipv6_wire_parsing():
    r = parse_packet(built(Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=1, dport=53) / Raw(b"abcd")))
    assert r.ip_version == 6 and r.ip_len == 52 and r.payload_len == 4


def test_truncated_frame_flagged():
    p = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2) / Raw(b"x" * 100)
    raw = bytes(p)[:60]  # snaplen-truncated capture
    q = Ether(raw); q.time = 1.0
    r = parse_packet(q)
    assert r.truncated and r.ip_len == 140


def _run(frames, **kw):
    out = []
    stats = extract_flows(sorted(frames, key=lambda p: float(p.time)), FlowConfig(**kw), out.append)
    return stats, out


def test_prefix_limit_does_not_create_new_flow():
    frames = handshake_session("10.5.0.1", "10.5.0.2", 45000, 80, 0.0, n_data=50, close="fin")
    stats, flows = _run(frames, max_packets=3)
    assert len(flows) == 1
    f = flows[0]
    assert f["packet_count"] == 3 and f["prefix_complete"] and f["end_reason"] == "fin"
    assert f["observed_packets"] == len(frames) - 1  # final ACK is post-close
    assert stats["packets_after_prefix"] == len(frames) - 1 - 3


def test_end_reason_categories_are_distinct():
    done = handshake_session("10.6.0.1", "10.6.0.2", 46000, 80, 0.0)                     # completed (fin)
    idle = [_tcp("10.6.1.1", "10.6.1.2", 46001, 80, "S", 0.0)]                          # timed out
    long_ = handshake_session("10.6.2.1", "10.6.2.2", 46002, 80, 0.0, n_data=30, close=None)  # prefix reached, eof
    later = [_tcp("10.6.3.1", "10.6.3.2", 46003, 80, "S", 500.0)]
    stats, flows = _run(done + idle + long_ + later)
    by = {f["src_port"]: f for f in flows}
    assert by[46000]["end_reason"] == "fin"
    assert by[46001]["end_reason"] == "idle_timeout"
    assert by[46002]["end_reason"] == "idle_timeout" and by[46002]["prefix_complete"]
    assert by[46003]["end_reason"] == "eof"
    s2, f2 = _run(done + idle, max_active=1)
    assert any(f["end_reason"] == "capacity" for f in f2)


def test_new_counters_present_and_conservation():
    frames = handshake_session("10.7.0.1", "10.7.0.2", 47000, 80, 0.0)
    frames.append(built(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / IP(src="3.3.3.3", dst="4.4.4.4") / UDP(), 1.0))
    stats, flows = _run(frames)
    assert stats["skipped_nested"] == 1 and stats["conservation_ok"]
    for k in ("ip_len_from_capture", "truncated_frames", "suspicious_forward_jumps"):
        assert k in stats


def test_suspicious_forward_jump_counted():
    frames = [_tcp("10.8.0.1", "10.8.0.2", 48000, 80, "S", 0.0), _tcp("10.8.0.3", "10.8.0.4", 48001, 80, "S", 10_000.0)]
    stats, _ = _run(frames, forward_jump_warn_s=3600.0)
    assert stats["suspicious_forward_jumps"] == 1
