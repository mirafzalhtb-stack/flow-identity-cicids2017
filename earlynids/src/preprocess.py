"""Streaming packet-prefix extractor. Unlabeled research preprocessing, not an IDS."""
import argparse
import csv
import heapq
import ipaddress
import json
import math
from collections import OrderedDict
from pathlib import Path
from scapy.all import PcapReader, IP, IPv6, TCP, UDP

FIELDS = ['flow_id','ip_version','protocol','src_ip','src_port','dst_ip','dst_port',
          'start_time','end_time','observed_packets','packet_count','prefix_complete',
          'end_reason','features_json','label']

def packet_info(pkt):
    if IP in pkt:
        net = pkt[IP]
    elif IPv6 in pkt:
        net = pkt[IPv6]
    else:
        return None
    if TCP in pkt:
        tr, proto = pkt[TCP], 6
    elif UDP in pkt:
        tr, proto = pkt[UDP], 17
    else:
        return None
    a = (ipaddress.ip_address(net.src).packed, int(tr.sport))
    b = (ipaddress.ip_address(net.dst).packed, int(tr.dport))
    key = (net.version, proto, min(a,b), max(a,b))
    return key, (a,b), float(pkt.time), len(pkt), net.src, net.dst, int(tr.sport), int(tr.dport)

def extract(pcap, output, max_packets=20, timeout=120.0, max_active=100000,
            stats_path=None, cleanup_interval=10000):
    if max_packets < 1 or timeout <= 0 or max_active < 1 or cleanup_interval < 1:
        raise ValueError('max_packets, max_active, cleanup_interval must be positive; timeout > 0')
    active = OrderedDict()
    expiry_heap = []
    counters = dict(packets_seen=0, eligible_packets=0, ignored_packets=0,
                    emitted=0, complete_prefixes=0, timeout_evictions=0,
                    capacity_evictions=0, end_of_file_flushes=0,
                    timestamp_regressions=0, peak_active_flows=0,
                    packets_after_prefix=0, out_of_order_flow_packets=0)
    next_id = 0
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    def emit(writer, flow, reason):
        counters['emitted'] += 1
        counters[{'timeout':'timeout_evictions','capacity':'capacity_evictions',
                  'eof':'end_of_file_flushes'}[reason]] += 1
        if len(flow['features']) == max_packets:
            counters['complete_prefixes'] += 1
        writer.writerow(dict(flow_id=flow['id'], ip_version=flow['key'][0], protocol=flow['key'][1],
             src_ip=flow['src_ip'],src_port=flow['src_port'],dst_ip=flow['dst_ip'],dst_port=flow['dst_port'],
             start_time=f"{flow['start']:.6f}",end_time=f"{flow['last']:.6f}",
             observed_packets=flow['seen'],packet_count=len(flow['features']),
             prefix_complete=int(len(flow['features']) == max_packets),end_reason=reason,
             features_json=json.dumps(flow['features'],separators=(',',':')),label='UNLABELED'))
    with open(output,'w',newline='',encoding='utf-8') as out, PcapReader(str(pcap)) as reader:
        writer=csv.DictWriter(out,fieldnames=FIELDS)
        writer.writeheader()
        last_global = None
        for pkt in reader:
            counters['packets_seen'] += 1
            info=packet_info(pkt)
            if info is None or not math.isfinite(info[2]):
                counters['ignored_packets'] += 1
                continue
            key, direction, ts, length, sip, dip, sport, dport = info
            counters['eligible_packets'] += 1
            if last_global is not None and ts < last_global:
                counters['timestamp_regressions'] += 1
            last_global=ts
            # Expiry heap avoids O(active_flows) scan for each packet. Out-of-order
            # captures may not have strict timeout semantics; regressions are counted.
            if counters['eligible_packets'] % cleanup_interval == 0:
                while expiry_heap and expiry_heap[0][0] < ts:
                    _, fid, old_key = heapq.heappop(expiry_heap)
                    old = active.get(old_key)
                    if old is not None and old['id'] == fid and ts-old['last'] > timeout:
                        emit(writer, active.pop(old_key), 'timeout')
            old=active.get(key)
            if old is not None and ts-old['last'] > timeout:
                emit(writer,active.pop(key),'timeout')
                old=None
            if old is None:
                while len(active)>=max_active:
                    _, evicted=active.popitem(last=False)
                    emit(writer,evicted,'capacity')
                next_id += 1
                old=dict(id=next_id,key=key,direction=direction,src_ip=sip,dst_ip=dip,
                         src_port=sport,dst_port=dport,start=ts,last=ts,
                         seen=0,features=[])
                active[key]=old
                heapq.heappush(expiry_heap,(ts+timeout,next_id,key))
            sign=1 if direction==old['direction'] else -1
            if ts < old['last']:
                counters['out_of_order_flow_packets'] += 1
            if len(old['features']) < max_packets:
                dt=max(0.0,ts-old['last']) if old['seen'] else 0.0
                old['features'].append([length,round(dt,6),sign])
            else:
                counters['packets_after_prefix'] += 1
            old['seen'] += 1
            old['last']=max(ts,old['last'])
            active.move_to_end(key)
            # Only one pending expiry entry per flow; refresh lazily on cleanup.
            # Rebuild periodically to keep heap bounded by active flow count.
            if counters['eligible_packets'] % cleanup_interval == 0:
                expiry_heap=[(f['last']+timeout,f['id'],k) for k,f in active.items()]
                heapq.heapify(expiry_heap)
            counters['peak_active_flows']=max(counters['peak_active_flows'],len(active))
        for flow in active.values():
            emit(writer,flow,'eof')
    if stats_path:
        Path(stats_path).parent.mkdir(parents=True,exist_ok=True)
        Path(stats_path).write_text(json.dumps(counters,indent=2),encoding='utf-8')
    return counters

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pcap',required=True)
    p.add_argument('--output',required=True)
    p.add_argument('--max-packets',type=int,default=20)
    p.add_argument('--timeout',type=float,default=120)
    p.add_argument('--max-active',type=int,default=100000)
    p.add_argument('--cleanup-interval',type=int,default=10000)
    p.add_argument('--stats')
    a=p.parse_args()
    print(json.dumps(extract(a.pcap,a.output,a.max_packets,a.timeout,a.max_active,a.stats,a.cleanup_interval),indent=2))
if __name__=='__main__': main()
