"""Streaming bidirectional flow reconstruction with causal packet prefixes.

EarlyNIDS v4 replacement for the v3 ``src/preprocess.py`` extractor. The v3
module is kept unchanged for backward compatibility.

Fixes relative to v3 (each confirmed by a probe, see docs/repository_audit.md):

* TCP FIN/RST termination: a 5-tuple reused for a new TCP session within the
  idle timeout is no longer merged into one flow.
* Session restart: a fresh SYN on a flow that is already past its handshake
  closes the old flow (``end_reason='restart'``) and opens a new one.
* Capacity eviction no longer fragments one live connection into many
  "new" flows that start mid-stream. Packets of an evicted flow create a flow
  marked ``start_reason='continuation'`` which is excluded from early-
  detection samples by ``valid_early_prefix=False``.
* Packet length is the IP-layer length (see packet.py).
* Flows whose first observed packet is not the opening packet
  (``start_reason='midstream'``) are flagged: their "prefix" is not the start
  of the connection and must not be used as an early-detection sample.

Causality: every per-packet feature in the prefix is computed only from the
packet itself and the packets before it in the same flow.
"""
from __future__ import annotations

import heapq
import logging
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, Iterator, List, Optional

from .packet import ACK, FIN, RST, SYN, PacketRecord, SkipReason, parse_packet

log = logging.getLogger(__name__)

VALID_START_REASONS = ("syn", "udp")


@dataclass
class FlowConfig:
    max_packets: int = 20
    idle_timeout: float = 120.0
    active_timeout: Optional[float] = None  # None = never split long-lived flows
    max_active: int = 200_000
    post_close_grace: float = 5.0  # late ACK/RST after a closed TCP flow is not a new flow
    closed_memory: int = 400_000  # bounded memory of recently closed / evicted keys
    forward_jump_warn_s: float = 3600.0
    # v4.3: reporting window (does NOT change segmentation). For each flow the extractor records the
    # last packet time and fwd/bwd packet counts within [start, start + window_s]. This lets the label
    # matcher compare against tools that cut flows at a fixed duration (e.g. a 120 s flow timeout).
    window_s: Optional[float] = 120.0  # diagnostic only: count packets jumping far ahead in time
    capture_id: str = "capture"
    source_file: str = ""

    def validate(self) -> None:
        if self.max_packets < 1:
            raise ValueError("max_packets must be >= 1")
        if self.idle_timeout <= 0:
            raise ValueError("idle_timeout must be > 0")
        if self.active_timeout is not None and self.active_timeout <= 0:
            raise ValueError("active_timeout must be > 0 or None")
        if self.max_active < 1 or self.closed_memory < 1:
            raise ValueError("max_active and closed_memory must be >= 1")
        if self.window_s is not None and self.window_s <= 0:
            raise ValueError("window_s must be > 0 or None")
        if self.post_close_grace < 0:
            raise ValueError("post_close_grace must be >= 0")


@dataclass(slots=True)
class _Flow:
    uid: str
    key: tuple
    ip_version: int
    proto: int
    init_ip: str
    init_port: int
    resp_ip: str
    resp_port: int
    initiator: tuple
    start: float
    last: float
    start_reason: str
    n_seen: int = 0
    bytes_seen: int = 0
    only_syns: bool = True
    first_syn_seq: Optional[int] = None
    fin_fwd: bool = False
    fin_bwd: bool = False
    n_retrans_prefix: int = 0
    n_out_of_order: int = 0
    n_fwd: int = 0
    n_bwd: int = 0
    win_fwd: int = 0
    win_bwd: int = 0
    win_last_rel: float = 0.0
    data_sigs: set = field(default_factory=set)
    rel_ts: List[float] = field(default_factory=list)
    iat: List[float] = field(default_factory=list)
    direction: List[int] = field(default_factory=list)
    ip_len: List[int] = field(default_factory=list)
    payload_len: List[int] = field(default_factory=list)
    tcp_flags: List[int] = field(default_factory=list)
    ttl: List[int] = field(default_factory=list)
    retrans: List[int] = field(default_factory=list)


COUNTER_KEYS = (
    "frames_seen", "eligible_packets", "skipped_not_ip", "skipped_not_tcp_udp",
    "skipped_non_first_fragment", "skipped_malformed", "skipped_bad_timestamp", "skipped_nested",
    "ip_len_from_capture", "truncated_frames", "suspicious_forward_jumps",
    "flows_emitted", "complete_prefixes", "valid_early_prefix_flows",
    "end_fin", "end_rst", "end_restart", "end_idle_timeout", "end_active_timeout",
    "end_capacity", "end_eof",
    "start_syn", "start_udp", "start_midstream", "start_continuation",
    "global_timestamp_regressions", "flow_out_of_order_packets",
    "packets_after_prefix", "post_close_packets", "syn_retransmissions",
    "data_retransmissions_in_prefix", "peak_active_flows",
)


class FlowExtractor:
    """Stateful streaming extractor. Feed packets, receive finished flow records."""

    def __init__(self, config: FlowConfig, sink: Callable[[dict], None]):
        config.validate()
        self.cfg = config
        self.sink = sink
        self.active: "OrderedDict[tuple, _Flow]" = OrderedDict()
        self.heap: list = []
        self.recently_closed: "OrderedDict[tuple, float]" = OrderedDict()
        self.evicted: "OrderedDict[tuple, float]" = OrderedDict()
        self.counters: Dict[str, int] = {k: 0 for k in COUNTER_KEYS}
        self._next = 0
        self._last_global: Optional[float] = None

    # ------------------------------------------------------------------ utils
    def _remember(self, store: OrderedDict, key: tuple, ts: float) -> None:
        store[key] = ts
        store.move_to_end(key)
        while len(store) > self.cfg.closed_memory:
            store.popitem(last=False)

    def _new_uid(self) -> str:
        self._next += 1
        return f"{self.cfg.capture_id}-{self._next:09d}"

    def _emit(self, flow: _Flow, reason: str) -> None:
        self.active.pop(flow.key, None)
        c = self.counters
        c["flows_emitted"] += 1
        c[f"end_{reason}"] += 1
        complete = len(flow.direction) == self.cfg.max_packets
        c["complete_prefixes"] += int(complete)
        valid = flow.start_reason in VALID_START_REASONS
        c["valid_early_prefix_flows"] += int(valid)
        if reason in ("fin", "rst", "restart"):
            self._remember(self.recently_closed, flow.key, flow.last)
        if reason == "capacity":
            self._remember(self.evicted, flow.key, flow.last)
        self.sink({
            "flow_uid": flow.uid,
            "capture_id": self.cfg.capture_id,
            "source_file": self.cfg.source_file,
            "ip_version": flow.ip_version,
            "protocol": flow.proto,
            "src_ip": flow.init_ip, "src_port": flow.init_port,
            "dst_ip": flow.resp_ip, "dst_port": flow.resp_port,
            "start_time": flow.start, "end_time": flow.last,
            "duration": max(0.0, flow.last - flow.start),
            "observed_packets": flow.n_seen,
            "observed_bytes": flow.bytes_seen,
            "packet_count": len(flow.direction),  # == prefix length actually stored
            "prefix_complete": complete,
            "start_reason": flow.start_reason,
            "end_reason": reason,
            "valid_early_prefix": valid,
            "n_retrans_prefix": flow.n_retrans_prefix,
            "n_out_of_order": flow.n_out_of_order,
            "n_fwd_packets": flow.n_fwd,
            "n_bwd_packets": flow.n_bwd,
            "window_s": self.cfg.window_s,
            "window_last_rel_ts": flow.win_last_rel if self.cfg.window_s is not None else None,
            "window_fwd_packets": flow.win_fwd if self.cfg.window_s is not None else None,
            "window_bwd_packets": flow.win_bwd if self.cfg.window_s is not None else None,
            "pkt_rel_ts": list(flow.rel_ts),
            "pkt_iat": list(flow.iat),
            "pkt_direction": list(flow.direction),
            "pkt_ip_len": list(flow.ip_len),
            "pkt_payload_len": list(flow.payload_len),
            "pkt_tcp_flags": list(flow.tcp_flags),
            "pkt_ttl": list(flow.ttl),
            "pkt_retrans": list(flow.retrans),
        })

    def _create(self, r: PacketRecord, key: tuple, start_reason: str) -> _Flow:
        while len(self.active) >= self.cfg.max_active:
            _, victim = next(iter(self.active.items()))
            self._emit(victim, "capacity")
        # Initiator: SYN sender. If the first seen packet is a SYN-ACK, the
        # initiator is its destination. Otherwise the first sender (heuristic,
        # flagged by start_reason='midstream').
        if r.proto == 6 and r.has(SYN) and r.has(ACK):
            init, resp = (r.dst_ip, r.dport, r.dst), (r.src_ip, r.sport)
        else:
            init, resp = (r.src_ip, r.sport, r.src), (r.dst_ip, r.dport)
        flow = _Flow(uid=self._new_uid(), key=key, ip_version=r.ip_version, proto=r.proto,
                     init_ip=init[0], init_port=init[1], resp_ip=resp[0], resp_port=resp[1],
                     initiator=init[2], start=r.ts, last=r.ts, start_reason=start_reason)
        self.active[key] = flow
        self.counters[f"start_{start_reason}"] += 1
        heapq.heappush(self.heap, (r.ts + self.cfg.idle_timeout, flow.uid, key))
        self.counters["peak_active_flows"] = max(self.counters["peak_active_flows"], len(self.active))
        return flow

    def _sweep(self, now: float) -> None:
        """Lazily expire idle flows. Each live flow has at most one heap entry."""
        while self.heap and self.heap[0][0] < now:
            _, uid, key = heapq.heappop(self.heap)
            flow = self.active.get(key)
            if flow is None or flow.uid != uid:
                continue  # stale entry of an already emitted flow
            if now - flow.last > self.cfg.idle_timeout:
                self._emit(flow, "idle_timeout")
            else:
                heapq.heappush(self.heap, (flow.last + self.cfg.idle_timeout, uid, key))

    # --------------------------------------------------------------- main API
    def process_frame(self, pkt) -> None:
        self.counters["frames_seen"] += 1
        res = parse_packet(pkt)
        if isinstance(res, SkipReason):
            self.counters[f"skipped_{res.value}"] += 1
            return
        self.process_record(res)

    def process_record(self, r: PacketRecord) -> None:
        c = self.counters
        c["eligible_packets"] += 1
        c["ip_len_from_capture"] += int(r.ip_len_from_capture)
        c["truncated_frames"] += int(r.truncated)
        if self._last_global is not None and r.ts < self._last_global:
            c["global_timestamp_regressions"] += 1
        if self._last_global is not None and r.ts - self._last_global > self.cfg.forward_jump_warn_s:
            # Unverified risk: one bogus future timestamp would idle-expire every
            # active flow. Counted, not corrected (see docs/v4_1_defect_audit.md).
            c["suspicious_forward_jumps"] += 1
        self._last_global = r.ts if self._last_global is None else max(self._last_global, r.ts)
        self._sweep(r.ts)

        key = r.canonical_key()
        is_tcp = r.proto == 6
        pure_syn = is_tcp and r.has(SYN) and not r.has(ACK)
        flow = self.active.get(key)

        if flow is not None and r.ts - flow.last > self.cfg.idle_timeout:
            self._emit(flow, "idle_timeout")
            flow = None
        if (flow is not None and self.cfg.active_timeout is not None
                and r.ts - flow.start > self.cfg.active_timeout):
            self._emit(flow, "active_timeout")
            self._remember(self.evicted, key, r.ts)
            flow = None
        if flow is not None and pure_syn and not flow.only_syns:
            # New connection attempt on a tuple whose previous session is past the handshake.
            self._emit(flow, "restart")
            flow = None

        if flow is None:
            closed_at = self.recently_closed.get(key)
            if (closed_at is not None and not pure_syn
                    and r.ts - closed_at <= self.cfg.post_close_grace):
                c["post_close_packets"] += 1  # e.g. final ACK after FIN/FIN
                return
            if key in self.evicted and not pure_syn:
                reason = "continuation"
                self.evicted.pop(key, None)
            elif not is_tcp:
                reason = "udp"
            elif pure_syn:
                reason = "syn"
            else:
                reason = "midstream"
            flow = self._create(r, key, reason)

        # ---- append causal per-packet features
        sign = 1 if r.src == flow.initiator else -1
        if is_tcp:
            if pure_syn and flow.only_syns and flow.n_seen > 0 and sign == 1:
                c["syn_retransmissions"] += 1
            if not (r.has(SYN) and not r.has(ACK)):
                flow.only_syns = False
        if len(flow.direction) < self.cfg.max_packets:
            if flow.n_seen == 0:
                iat = 0.0
            else:
                iat = r.ts - flow.last
                if iat < 0:
                    flow.n_out_of_order += 1
                    c["flow_out_of_order_packets"] += 1
                    iat = 0.0
            is_re = 0
            if is_tcp and r.payload_len > 0:
                sig = (sign, r.tcp_seq, r.payload_len)
                if sig in flow.data_sigs:
                    is_re = 1
                    flow.n_retrans_prefix += 1
                    c["data_retransmissions_in_prefix"] += 1
                else:
                    flow.data_sigs.add(sig)
            flow.rel_ts.append(max(0.0, r.ts - flow.start))
            flow.iat.append(iat)
            flow.direction.append(sign)
            flow.ip_len.append(r.ip_len)
            flow.payload_len.append(r.payload_len)
            flow.tcp_flags.append(r.tcp_flags)
            flow.ttl.append(r.ttl)
            flow.retrans.append(is_re)
        else:
            c["packets_after_prefix"] += 1
            if flow.data_sigs:
                flow.data_sigs = set()  # free memory, no longer needed
        flow.n_seen += 1
        flow.bytes_seen += r.ip_len
        if sign == 1:
            flow.n_fwd += 1
        else:
            flow.n_bwd += 1
        rel = r.ts - flow.start
        if self.cfg.window_s is not None and 0 <= rel <= self.cfg.window_s:
            flow.win_last_rel = max(flow.win_last_rel, rel)
            if sign == 1:
                flow.win_fwd += 1
            else:
                flow.win_bwd += 1
        flow.last = max(flow.last, r.ts)
        self.active.move_to_end(key)

        if is_tcp:
            if r.has(RST):
                self._emit(flow, "rst")
                return
            if r.has(FIN):
                if sign == 1:
                    flow.fin_fwd = True
                else:
                    flow.fin_bwd = True
                if flow.fin_fwd and flow.fin_bwd:
                    self._emit(flow, "fin")

    def flush(self) -> None:
        for flow in list(self.active.values()):
            self._emit(flow, "eof")
        self.heap.clear()


def iter_pcap(path: Path) -> Iterator:
    """Yield frames from a pcap/pcapng file without loading it into memory.

    ``scapy.all`` is imported on purpose: it registers every link-layer
    dissector (Ethernet, Linux cooked capture, 802.1Q, ...). Importing only
    ``scapy.utils`` makes PcapReader return Raw frames in a fresh interpreter,
    which silently turns every packet into "not_ip" (bug found by benchmark,
    covered by tests/test_v4_integration.py::test_fresh_interpreter_parses_ethernet).
    """
    from scapy.all import PcapReader  # noqa: F401  (registers all layers)
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            yield pkt


def extract_flows(frames: Iterable, config: FlowConfig, sink: Callable[[dict], None]) -> Dict[str, int]:
    ex = FlowExtractor(config, sink)
    for pkt in frames:
        ex.process_frame(pkt)
    ex.flush()
    stats = dict(ex.counters)
    stats["no_eligible_packets_warning"] = stats["frames_seen"] > 0 and stats["eligible_packets"] == 0
    stats["conservation_ok"] = (
        stats["frames_seen"] == stats["eligible_packets"] + sum(
            stats[k] for k in stats if k.startswith("skipped_")))
    return stats
