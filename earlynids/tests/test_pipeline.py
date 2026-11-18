import csv
import json
import tempfile
import unittest
from pathlib import Path
from src.make_synthetic import generate
from src.preprocess import extract

class TestExtractor(unittest.TestCase):
    def run_case(self, prefix=20, max_active=100):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'in.pcap';out=Path(d)/'out.csv'
            generate(p)
            stats=extract(p,out,max_packets=prefix,max_active=max_active,cleanup_interval=2)
            with out.open(newline='',encoding='utf-8') as fh:
                rows=list(csv.DictReader(fh))
            return stats,rows

    def test_bidirectional_and_no_duplicate_after_prefix(self):
        stats,rows=self.run_case()
        self.assertEqual(stats['packets_seen'],37)
        tcp=[r for r in rows if r['protocol']=='6']
        self.assertEqual(len(tcp),1)
        self.assertEqual(tcp[0]['observed_packets'],'30')
        self.assertEqual(tcp[0]['packet_count'],'20')
        self.assertEqual(tcp[0]['prefix_complete'],'1')
        self.assertEqual(stats['packets_after_prefix'],10)
        feats=json.loads(tcp[0]['features_json'])
        self.assertEqual([f[2] for f in feats[:5]],[1,-1,1,-1,1])
        self.assertTrue(all(f[0]>0 for f in feats))
        self.assertAlmostEqual(feats[1][1],.1)

    def test_timeout_restarts_same_tuple(self):
        _,rows=self.run_case()
        udp=[r for r in rows if r['protocol']=='17']
        self.assertEqual(len(udp),2)
        self.assertEqual(sorted(int(r['observed_packets']) for r in udp),[3,4])
        self.assertIn('timeout',[r['end_reason'] for r in udp])

    def test_short_flow_and_complete_prefix(self):
        stats,rows=self.run_case(prefix=5)
        tcp=next(r for r in rows if r['protocol']=='6')
        self.assertEqual(tcp['packet_count'],'5')
        self.assertEqual(tcp['observed_packets'],'30')
        udp=[r for r in rows if r['protocol']=='17']
        self.assertTrue(all(r['prefix_complete']=='0' for r in udp))
        self.assertEqual(stats['complete_prefixes'],1)

    def test_capacity_eviction(self):
        stats,rows=self.run_case(max_active=1)
        self.assertGreaterEqual(stats['capacity_evictions'],0)
        self.assertLessEqual(stats['peak_active_flows'],1)
        self.assertEqual(sum(int(r['observed_packets']) for r in rows),37)

    def test_stats_conservation(self):
        stats,rows=self.run_case()
        self.assertEqual(stats['packets_seen'],stats['eligible_packets']+stats['ignored_packets'])
        self.assertEqual(stats['emitted'],len(rows))
        self.assertEqual(stats['timestamp_regressions'],0)

if __name__=='__main__': unittest.main()
