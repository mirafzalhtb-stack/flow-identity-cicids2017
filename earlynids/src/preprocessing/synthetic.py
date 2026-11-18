"""Synthetic PCAP fixtures with KNOWN expected flow-reconstruction outcomes.

These fixtures test engineering correctness only. They contain no attack
traffic and say nothing about detection performance on real data.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List


def _tcp(src, dst, sport, dport, flags, t, seq=0, payload=b"", v6=False):
    from scapy.layers.inet import IP, TCP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw
    net = IPv6(src=src, dst=dst) if v6 else IP(src=src, dst=dst)
    p = Ether() / net / TCP(sport=sport, dport=dport, flags=flags, seq=seq)
    if payload:
        p = p / Raw(load=payload)
    p.time = t
    return p


def _udp(src, dst, sport, dport, t, payload=b"x"):
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw
    p = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(load=payload)
    p.time = t
    return p


def handshake_session(c, s, cp, sp, t0, n_data=4, close="fin", v6=False, gap=0.01):
    """Complete TCP session: 3-way handshake, data, and FIN/FIN/ACK or RST."""
    pk = [_tcp(c, s, cp, sp, "S", t0, seq=100, v6=v6),
          _tcp(s, c, sp, cp, "SA", t0 + gap, seq=500, v6=v6),
          _tcp(c, s, cp, sp, "A", t0 + 2 * gap, seq=101, v6=v6)]
    t = t0 + 3 * gap
    for i in range(n_data):
        fwd = i % 2 == 0
        pk.append(_tcp(c if fwd else s, s if fwd else c, cp if fwd else sp, sp if fwd else cp,
                       "PA", t, seq=101 + i * 10, payload=b"d" * (10 + i), v6=v6))
        t += gap
    if close == "fin":
        pk += [_tcp(c, s, cp, sp, "FA", t, seq=999, v6=v6),
               _tcp(s, c, sp, cp, "FA", t + gap, seq=1999, v6=v6),
               _tcp(c, s, cp, sp, "A", t + 2 * gap, seq=1000, v6=v6)]  # final ACK -> post_close
    elif close == "rst":
        pk.append(_tcp(c, s, cp, sp, "R", t, seq=999, v6=v6))
    return pk


def build_scenarios() -> Dict[str, List]:
    """Each scenario lists frames and the documented expected outcome."""
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw
    sc: Dict[str, List] = {}
    # 1. Two sessions on the same 5-tuple 5 s apart (< idle timeout) -> 2 flows
    sc["tuple_reuse_fin"] = handshake_session("10.0.0.1", "10.0.0.2", 40000, 80, 0.0) + \
        handshake_session("10.0.0.1", "10.0.0.2", 40000, 80, 5.0)
    # 2. RST termination -> 1 flow end_reason=rst
    sc["rst"] = handshake_session("10.0.1.1", "10.0.1.2", 40001, 443, 10.0, close="rst")
    # 3. Long flow (30 data packets) without close -> 1 flow, prefix capped, eof
    sc["long"] = handshake_session("10.0.2.1", "10.0.2.2", 40002, 22, 20.0, n_data=30, close=None)
    # 4. Short UDP flow (2 pkts) + same tuple after 200 s (> timeout) -> 2 flows
    sc["udp_timeout"] = [_udp("10.0.3.1", "10.0.3.2", 5353, 53, 30.0),
                         _udp("10.0.3.2", "10.0.3.1", 53, 5353, 30.1),
                         _udp("10.0.3.1", "10.0.3.2", 5353, 53, 230.0)]
    # 5. SYN retransmission then normal session -> 1 flow, syn_retransmissions=1
    s5 = handshake_session("10.0.4.1", "10.0.4.2", 40004, 80, 40.0)
    sc["syn_retrans"] = [s5[0], _tcp("10.0.4.1", "10.0.4.2", 40004, 80, "S", 40.005, seq=100)] + s5[1:]
    # 6. Data retransmission inside prefix (same seq & length, same direction)
    s6 = handshake_session("10.0.5.1", "10.0.5.2", 40005, 80, 50.0, n_data=2)
    dup = _tcp("10.0.5.1", "10.0.5.2", 40005, 80, "PA", 50.045, seq=101, payload=b"d" * 10)
    sc["data_retrans"] = s6[:4] + [dup] + s6[4:]
    # 7. Mid-stream start (first packet is ACK/data) -> start_reason=midstream
    sc["midstream"] = [_tcp("10.0.6.1", "10.0.6.2", 40006, 80, "PA", 60.0, seq=5, payload=b"zz"),
                       _tcp("10.0.6.2", "10.0.6.1", 80, 40006, "A", 60.01, seq=9)]
    # 8. IPv6 session
    sc["ipv6"] = handshake_session("2001:db8::1", "2001:db8::2", 40007, 443, 70.0, v6=True)
    # 9. Non-IP frame, non-first IPv4 fragment, ICMP -> skipped & counted
    from scapy.layers.inet import ICMP
    from scapy.layers.l2 import ARP
    arp = Ether() / ARP(); arp.time = 80.0
    frag = Ether() / IP(src="10.0.8.1", dst="10.0.8.2", frag=10, proto=17) / Raw(load=b"f" * 20); frag.time = 80.1
    icmp = Ether() / IP(src="10.0.8.1", dst="10.0.8.2") / ICMP(); icmp.time = 80.2
    sc["skipped"] = [arp, frag, icmp]
    # 10. Session restart: established session, then fresh SYN without closing
    s10 = handshake_session("10.0.9.1", "10.0.9.2", 40009, 80, 90.0, n_data=2, close=None)
    sc["restart"] = s10 + handshake_session("10.0.9.1", "10.0.9.2", 40009, 80, 91.0, n_data=2)
    return sc


EXPECTED = {
    "tuple_reuse_fin": {"flows": 2, "end_reasons": ["fin", "fin"], "post_close": 2},
    "rst": {"flows": 1, "end_reasons": ["rst"]},
    "long": {"flows": 1, "observed_packets": 33},
    "udp_timeout": {"flows": 2},
    "syn_retrans": {"flows": 1, "syn_retransmissions": 1},
    "data_retrans": {"flows": 1, "retrans_in_prefix": 1},
    "midstream": {"flows": 1, "start_reason": "midstream"},
    "ipv6": {"flows": 1},
    "skipped": {"flows": 0, "skipped": 3},
    "restart": {"flows": 2, "end_reasons": ["restart", "fin"]},
}


def write_all(path: Path) -> int:
    from scapy.utils import wrpcap
    frames = [f for fr in build_scenarios().values() for f in fr]
    frames.sort(key=lambda p: float(p.time))
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), frames)
    return len(frames)
