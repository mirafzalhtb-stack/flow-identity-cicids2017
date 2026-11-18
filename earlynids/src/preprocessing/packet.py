"""Packet parsing for EarlyNIDS v4.

Design decisions (see docs/methodology.md, section "Packet features"):

* Packet length is the **IP-layer length** (IPv4 total length / IPv6 payload
  length + 40), not ``len(frame)``. v3 used the frame length, which includes the
  link-layer header and therefore differs between capture setups (Ethernet,
  Linux cooked capture, VLAN tags). That is a capture artefact, not traffic
  behaviour.
* Only TCP and UDP over IPv4/IPv6 are eligible. Everything else is counted and
  skipped, never silently dropped.
* Non-first IPv4 fragments carry no transport header, so they cannot be
  assigned to a 5-tuple. They are counted separately.
* Parsing failures are reported as ``malformed`` instead of raising, so that a
  single broken frame cannot abort a multi-gigabyte capture.

v4.1 changes (regression tests in tests/test_v41_preprocessing.py):

* If the IPv4 total-length field is 0 or smaller than the headers (TCP
  segmentation offload captures), the captured IP length is used instead and
  ``ip_len_from_capture`` is set. v4 produced ``ip_len = 0``.
* Tunnelled/nested packets (e.g. IP-in-IP, GRE) are skipped as ``nested``.
  v4 combined the outer IP addresses with the inner transport ports.
* ``truncated`` marks frames whose captured bytes are fewer than the IP length
  (snaplen); the header length is kept as the semantic packet length.
* Endpoints are packed once at parse time (v4 re-parsed the IP string on
  every access, a measurable cost).
"""
from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple, Union

# TCP flag bit masks (RFC 793 / RFC 3168)
FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80


class SkipReason(str, Enum):
    NOT_IP = "not_ip"
    NOT_TCP_UDP = "not_tcp_udp"
    FRAGMENT = "non_first_fragment"
    MALFORMED = "malformed"
    BAD_TIMESTAMP = "bad_timestamp"
    NESTED = "nested"


Endpoint = Tuple[bytes, int]  # (packed IP address, port)


@dataclass(frozen=True, slots=True)
class PacketRecord:
    """Minimal, causal per-packet information extracted from one frame."""

    ts: float
    ip_version: int
    proto: int  # 6 = TCP, 17 = UDP
    src_ip: str
    dst_ip: str
    sport: int
    dport: int
    ip_len: int
    payload_len: int
    ttl: int  # IPv4 TTL or IPv6 hop limit
    tcp_flags: int  # 0 for UDP
    tcp_seq: int  # 0 for UDP
    src: Endpoint = (b"", 0)  # (packed IP, port), filled by parse_packet / make_record
    dst: Endpoint = (b"", 0)
    ip_len_from_capture: bool = False
    truncated: bool = False

    def canonical_key(self) -> tuple:
        """Direction-independent 5-tuple key (ip_version, proto, low endpoint, high endpoint)."""
        a, b = self.src, self.dst
        return (self.ip_version, self.proto, min(a, b), max(a, b))

    def has(self, flag: int) -> bool:
        return bool(self.tcp_flags & flag)


ParseResult = Union[PacketRecord, SkipReason]

_IPV6_EXT = {0, 43, 44, 60, 51, 50, 135, 139, 140, 253, 254}  # hop-by-hop, routing, fragment, dest-opts, AH, ESP, ...


def make_record(**kw) -> PacketRecord:
    """Build a PacketRecord and fill the packed endpoints (used by tests and parse_packet)."""
    kw.setdefault("src", (ipaddress.ip_address(kw["src_ip"]).packed, int(kw["sport"])))
    kw.setdefault("dst", (ipaddress.ip_address(kw["dst_ip"]).packed, int(kw["dport"])))
    return PacketRecord(**kw)


def _timestamp(pkt) -> Optional[float]:
    try:
        ts = float(pkt.time)
    except (TypeError, ValueError, AttributeError):
        return None
    return ts if math.isfinite(ts) else None


def parse_packet(pkt) -> ParseResult:
    """Convert a Scapy packet into a :class:`PacketRecord` or a :class:`SkipReason`."""
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    try:
        if IP in pkt:
            net = pkt[IP]
            if int(net.frag) > 0:  # fragment offset > 0 -> no L4 header
                return SkipReason.FRAGMENT
            ip_version = 4
            hdr_len = int(net.ihl) * 4 if net.ihl is not None else 20
            next_proto = int(net.proto)
            captured = len(net)
            header_len = int(net.len) if net.len is not None else captured
            ttl = int(net.ttl)
        elif IPv6 in pkt:
            net = pkt[IPv6]
            ip_version = 6
            hdr_len = 40  # extension headers are counted as payload (documented limitation)
            next_proto = int(net.nh)
            captured = len(net)
            plen = int(net.plen) if net.plen is not None else captured - 40
            header_len = plen + 40
            ttl = int(net.hlim)
        else:
            return SkipReason.NOT_IP

        # The transport header must belong to THIS network header (no tunnels).
        if ip_version == 4 and next_proto not in (6, 17):
            return SkipReason.NESTED if (TCP in net.payload or UDP in net.payload) else SkipReason.NOT_TCP_UDP
        if ip_version == 6 and next_proto not in (6, 17) and next_proto not in _IPV6_EXT:
            return SkipReason.NESTED if (TCP in net.payload or UDP in net.payload) else SkipReason.NOT_TCP_UDP

        if TCP in pkt:
            tr = pkt[TCP]
            proto = 6
            flags = int(tr.flags)
            seq = int(tr.seq)
            l4_hdr = int(tr.dataofs) * 4 if tr.dataofs is not None else 20
        elif UDP in pkt:
            tr = pkt[UDP]
            proto, flags, seq, l4_hdr = 17, 0, 0, 8
        else:
            return SkipReason.NOT_TCP_UDP

        ts = _timestamp(pkt)
        if ts is None:
            return SkipReason.BAD_TIMESTAMP

        from_capture = False
        ip_len = header_len
        if ip_len < hdr_len + l4_hdr:  # length field 0 (TSO) or inconsistent
            ip_len = captured
            from_capture = True
        truncated = captured < ip_len
        payload_len = max(0, ip_len - hdr_len - l4_hdr)
        src_ip, dst_ip = str(net.src), str(net.dst)
        sport, dport = int(tr.sport), int(tr.dport)
        return PacketRecord(ts=ts, ip_version=ip_version, proto=proto,
                            src_ip=src_ip, dst_ip=dst_ip, sport=sport, dport=dport,
                            ip_len=ip_len, payload_len=payload_len, ttl=ttl,
                            tcp_flags=flags, tcp_seq=seq,
                            src=(ipaddress.ip_address(src_ip).packed, sport),
                            dst=(ipaddress.ip_address(dst_ip).packed, dport),
                            ip_len_from_capture=from_capture, truncated=truncated)
    except Exception:  # noqa: BLE001 - any dissection failure is "malformed"
        return SkipReason.MALFORMED
