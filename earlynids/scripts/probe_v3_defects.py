import sys, csv, tempfile, json
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parents[1]))
from pathlib import Path
from scapy.all import Ether, IP, TCP, wrpcap, Raw
from src.preprocess import extract
d=Path(tempfile.mkdtemp())
# Probe 1: two TCP sessions on same 5-tuple separated by FIN/RST, 5 s apart (< timeout)
pk=[]
def a(src,dst,sp,dp,fl,t,pl=b''):
    p=Ether()/IP(src=src,dst=dst)/TCP(sport=sp,dport=dp,flags=fl)/Raw(pl) if pl else Ether()/IP(src=src,dst=dst)/TCP(sport=sp,dport=dp,flags=fl); p.time=t; pk.append(p)
for base in (0,5):
    a('10.0.0.1','10.0.0.2',40000,80,'S',base); a('10.0.0.2','10.0.0.1',80,40000,'SA',base+.01)
    a('10.0.0.1','10.0.0.2',40000,80,'A',base+.02); a('10.0.0.1','10.0.0.2',40000,80,'FA',base+.03)
    a('10.0.0.2','10.0.0.1',80,40000,'FA',base+.04)
wrpcap(str(d/'p1.pcap'),pk); extract(d/'p1.pcap',d/'o1.csv')
r=list(csv.DictReader(open(d/'o1.csv')))
print('P1 sessions-in-pcap=2, flows emitted=',len(r),'observed=',[x['observed_packets'] for x in r])
print('P1 first packet length feature =',json.loads(r[0]['features_json'])[0][0],'(IP total len would be 40; includes 14B Ethernet header)')
# Probe 2: capacity eviction fragments a live flow
pk=[]
for i in range(6):
    a('10.0.0.1','10.0.0.2',40001,80,'PA',i*.1,b'x')
    a('10.0.0.3','10.0.0.4',40002,80,'PA',i*.1+.05,b'y')
wrpcap(str(d/'p2.pcap'),pk); s=extract(d/'p2.pcap',d/'o2.csv',max_active=1)
r=list(csv.DictReader(open(d/'o2.csv')))
print('P2 real flows=2, emitted rows=',len(r),'capacity_evictions=',s['capacity_evictions'])
