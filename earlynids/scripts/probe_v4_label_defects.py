"""Reproduces the v4 label-matching defects L1-L4 (run against a v4 checkout). Not used by v4.1."""
import sys; sys.path.insert(0, sys.argv[1] if len(sys.argv) > 1 else '.')  # path to a v4 checkout (shows v4 behaviour)
from src.labeling.cicids2017 import LabelConfig, LabelIndex
def row(ts,dur,label='BENIGN'):
    return {'source ip':'10.0.0.1','source port':'40000','destination ip':'10.0.0.2','destination port':'80','protocol':'6','timestamp':ts,'flow duration':str(dur),'label':label}
cfg=LabelConfig(utc_offset_hours=0.0); 
# A: two CSV sessions on same tuple, same label; PCAP flow spans both
idx=LabelIndex(cfg); idx.add_row(0,row('03/07/2017 13:00:00',1_000_000)); idx.add_row(1,row('03/07/2017 13:00:05',1_000_000)); idx.finalize()
t=idx.parse_timestamp('03/07/2017 13:00:00')[0][0]
m=idx.match(6,'10.0.0.1',40000,'10.0.0.2',80,t,t+6); print('A same-label reuse:',m['label_status'], m['binary_label'])
# B: PCAP flow starts 100 s after a long CSV row started (start misaligned)
idx=LabelIndex(cfg); idx.add_row(0,row('03/07/2017 13:00:00',600_000_000,'DoS Hulk')); idx.finalize()
m=idx.match(6,'10.0.0.1',40000,'10.0.0.2',80,t+100,t+101); print('B start misaligned by 100s:',m['label_status'],m['binary_label'],m['match_dt_s'])
# C: duration mismatch: CSV 1s, PCAP flow 300s
idx=LabelIndex(cfg); idx.add_row(0,row('03/07/2017 13:00:00',1_000_000,'PortScan')); idx.finalize()
m=idx.match(6,'10.0.0.1',40000,'10.0.0.2',80,t,t+300); print('C duration 1s vs 300s:',m['label_status'],m['binary_label'])
# D: one CSV row claimed by two PCAP flows
idx=LabelIndex(cfg); idx.add_row(0,row('03/07/2017 13:00:00',10_000_000,'DDoS')); idx.finalize()
a=idx.match(6,'10.0.0.1',40000,'10.0.0.2',80,t,t+2); b=idx.match(6,'10.0.0.1',40000,'10.0.0.2',80,t+4,t+6)
print('D row claimed twice:',a['label_status'],a['label_row_ids'],'|',b['label_status'],b['label_row_ids'])
# E: missing field value
idx=LabelIndex(cfg); r=row('03/07/2017 13:00:00',1); r['source port']=''; idx.add_row(0,r); print('E empty port ->',dict(idx.stats))
print('default accepted_statuses:',cfg.accepted_statuses)
