"""Generate artificial labeled sequences for pipeline smoke testing only; not scientific evidence."""
import argparse,csv,json,random
from pathlib import Path
from .preprocess import FIELDS

def generate(path,n=240,seed=42):
    rng=random.Random(seed);Path(path).parent.mkdir(parents=True,exist_ok=True)
    with open(path,'w',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f,fieldnames=FIELDS);writer.writeheader()
        for i in range(n):
            attack=i%2==1;length=rng.randint(3,20)
            seq=[[rng.randint(700,1400) if attack else rng.randint(60,300),round(rng.uniform(.001,.03),5),1 if j%2==0 else -1] for j in range(length)]
            row={k:'' for k in FIELDS};row.update(flow_id=i+1,packet_count=length,observed_packets=length,prefix_complete=int(length==20),features_json=json.dumps(seq),label='ATTACK' if attack else 'BENIGN')
            writer.writerow(row)
    print(f'Created {n} ARTIFICIAL labeled rows (smoke test ONLY): {path}')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',default='data/smoke_labeled.csv');p.add_argument('--rows',type=int,default=240)
    a=p.parse_args();generate(a.output,a.rows)
