"""CPU-friendly GRU baseline. Only trains on explicitly labeled flows."""
import argparse, csv, json, random
from pathlib import Path
import numpy as np

def load_rows(path, max_packets=20):
    X, y, groups = [], [], []
    with open(path, newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            label = row['label'].strip().upper()
            if label not in ('BENIGN', 'ATTACK'):
                continue
            seq = np.asarray(json.loads(row['features_json']), dtype=np.float32)
            if seq.ndim != 2 or seq.shape[1] != 3 or len(seq) == 0 or not np.isfinite(seq).all():
                continue
            # Transform raw length and inter-arrival time; do not learn scaling from test data.
            seq[:, 0] = np.log1p(np.maximum(seq[:, 0], 0))
            seq[:, 1] = np.log1p(np.maximum(seq[:, 1], 0))
            padded = np.zeros((max_packets, 3), dtype=np.float32)
            n = min(len(seq), max_packets)
            padded[:n] = seq[:n]
            X.append(padded); y.append(int(label == 'ATTACK'))
            # Source filename or capture/day should be provided in future real-data split.
            groups.append(row.get('capture_id', 'unknown'))
    if not X:
        raise ValueError('No BENIGN/ATTACK labeled rows. UNLABELED synthetic data cannot train an IDS.')
    return np.stack(X), np.asarray(y, dtype=np.int64), groups

def metrics(y, pred):
    from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, confusion_matrix
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {'accuracy':float(accuracy_score(y,pred)), 'macro_f1':float(f1_score(y,pred,average='macro',zero_division=0)),
            'attack_precision':float(precision_score(y,pred,zero_division=0)),
            'attack_recall':float(recall_score(y,pred,zero_division=0)),
            'fpr':float(fp/(fp+tn)) if fp+tn else None,
            'tn':int(tn),'fp':int(fp),'fn':int(fn),'tp':int(tp)}

def run(args):
    import torch
    from torch import nn
    from sklearn.model_selection import train_test_split
    torch.manual_seed(args.seed); np.random.seed(args.seed); random.seed(args.seed)
    torch.set_num_threads(max(1,args.threads))
    X,y,groups=load_rows(args.input,args.max_packets)
    if len(set(y.tolist())) != 2:
        raise ValueError('Need both BENIGN and ATTACK labels')
    if len(X) < 20 or min(np.bincount(y)) < 4:
        raise ValueError('At least 20 samples and >=4 per class required for smoke training')
    if args.real_data and len(set(groups)) < 3:
        raise ValueError('Real-data evaluation requires >=3 capture_id groups for held-out group split. No random flow split.')
    if args.real_data:
        from sklearn.model_selection import GroupShuffleSplit
        splitter=GroupShuffleSplit(n_splits=1,test_size=.2,random_state=args.seed)
        tr,te=next(splitter.split(X,y,groups))
        # Separate validation groups from train groups; do not tune on test.
        remaining=np.asarray(groups)[tr]
        if len(set(remaining))<2: raise ValueError('Need >=2 training groups for separate validation')
        tr_rel,va_rel=next(GroupShuffleSplit(n_splits=1,test_size=.2,random_state=args.seed+1).split(X[tr],y[tr],remaining))
        va=tr[va_rel];tr=tr[tr_rel]
    else:
        tr,te=train_test_split(np.arange(len(y)),test_size=.2,stratify=y,random_state=args.seed)
        tr,va=train_test_split(tr,test_size=.25,stratify=y[tr],random_state=args.seed)
    if len(set(y[tr]))<2 or len(set(y[va]))<2 or len(set(y[te]))<2:
        raise ValueError('Each split needs both classes; provide more diverse capture groups')
    # All 3/5/10/20 evaluations use a single 20-prefix-trained GRU; shorter prefixes are truncated.
    class GRU(nn.Module):
        def __init__(self):
            super().__init__();self.rnn=nn.GRU(3,args.hidden,batch_first=True);self.head=nn.Linear(args.hidden,2)
        def forward(self,x,lengths):
            from torch.nn.utils.rnn import pack_padded_sequence
            packed=pack_padded_sequence(x,lengths.cpu(),batch_first=True,enforce_sorted=False)
            _,h=self.rnn(packed);return self.head(h[-1])
    model=GRU(); opt=torch.optim.Adam(model.parameters(),lr=args.lr); lossfn=nn.CrossEntropyLoss()
    def batches(indices,shuffle=False):
        indices=np.asarray(indices).copy()
        if shuffle: np.random.shuffle(indices)
        for ids in np.array_split(indices,max(1,int(np.ceil(len(indices)/args.batch_size)))):
            yield ids
    def inputs(ids,k):
        x=torch.tensor(X[ids,:k,:],dtype=torch.float32)
        # Determine actual length from original padding (direction is +/-1).
        lengths=torch.tensor(np.maximum(1,np.count_nonzero(X[ids,:k,2],axis=1)),dtype=torch.long)
        return x,lengths,torch.tensor(y[ids],dtype=torch.long)
    best=float('inf');best_state=None
    for epoch in range(args.epochs):
        model.train()
        for ids in batches(tr,True):
            x,l,labels=inputs(ids,args.max_packets)
            opt.zero_grad();loss=lossfn(model(x,l),labels);loss.backward();opt.step()
        model.eval(); losses=[]
        with torch.no_grad():
            for ids in batches(va):
                x,l,labels=inputs(ids,args.max_packets)
                losses.append((lossfn(model(x,l),labels).item(),len(ids)))
        val=sum(v*n for v,n in losses)/sum(n for _,n in losses)
        if val<best:
            best=val;best_state={k:v.detach().clone() for k,v in model.state_dict().items()}
        print(f'epoch={epoch+1} val_loss={val:.4f}')
    model.load_state_dict(best_state);model.eval()
    results={}
    for k in [3,5,10,20]:
        if k>args.max_packets:continue
        preds=[]
        with torch.no_grad():
            for ids in batches(te):
                x,l,_=inputs(ids,k)
                preds.extend(model(x,l).argmax(1).tolist())
        results[str(k)]=metrics(y[te],np.asarray(preds))
    output={'mode':'real_group_split' if args.real_data else 'smoke_only_random_split',
            'warning':'NOT PUBLISHABLE: synthetic or randomly split data' if not args.real_data else 'Preliminary: group-held-out; labeling and leakage audit required',
            'n_samples':len(y),'split_sizes':{'train':len(tr),'val':len(va),'test':len(te)},'seed':args.seed,'metrics_by_prefix':results}
    Path(args.output).parent.mkdir(parents=True,exist_ok=True)
    Path(args.output).write_text(json.dumps(output,indent=2),encoding='utf-8')
    print(json.dumps(output,indent=2))

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--input',required=True);p.add_argument('--output',default='results/gru_metrics.json')
    p.add_argument('--real-data',action='store_true',help='Enforce group-held-out split using capture_id column')
    p.add_argument('--max-packets',type=int,default=20);p.add_argument('--hidden',type=int,default=32)
    p.add_argument('--epochs',type=int,default=5);p.add_argument('--batch-size',type=int,default=64)
    p.add_argument('--lr',type=float,default=.001);p.add_argument('--seed',type=int,default=42);p.add_argument('--threads',type=int,default=2)
    args=p.parse_args()
    if args.max_packets<1: p.error('--max-packets must be positive')
    run(args)
if __name__=='__main__':main()
