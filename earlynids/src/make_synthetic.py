"""Create deterministic synthetic test traffic. No real attack labels."""
import argparse
from pathlib import Path
from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap

def generate(path):
    packets=[]
    def add(src,dst,sport,dport,proto,t,payload):
        tr=TCP(sport=sport,dport=dport,flags='PA') if proto=='tcp' else UDP(sport=sport,dport=dport)
        p=Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IP(src=src,dst=dst)/tr/Raw(load=payload)
        p.time=t
        packets.append(p)
    # 30 packets in one bidirectional TCP session.
    for i in range(30):
        forward=i%2==0
        add('10.0.0.1' if forward else '10.0.0.2',
            '10.0.0.2' if forward else '10.0.0.1',
            50000 if forward else 443,443 if forward else 50000,'tcp',1000+i*.1,b'A'*(10+i))
    # Short UDP flow.
    for i in range(3):
        add('10.0.0.3','10.0.0.4',53000,53,'udp',1005+i*.1,b'DNS')
    # Same 5-tuple after timeout; should become a new flow.
    for i in range(4):
        add('10.0.0.3','10.0.0.4',53000,53,'udp',1400+i*.1,b'NEW')
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    wrpcap(str(path),packets)
    return len(packets)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',default='data/synthetic.pcap')
    a=p.parse_args();print(f'Created {generate(a.output)} packets in {a.output}')
