import csv,json,tempfile,unittest
from pathlib import Path
from src.make_smoke_data import generate
from src.gru_baseline import load_rows,metrics
class TestV3(unittest.TestCase):
    def test_unlabeled_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'test.csv';p.write_text('label,features_json\nUNLABELED,"[[1, 0, 1]]"\n')
            with self.assertRaises(ValueError):load_rows(p)
    def test_smoke_shapes(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'test.csv';generate(p,40)
            X,y,_=load_rows(p)
            self.assertEqual(X.shape,(40,20,3));self.assertEqual(set(y.tolist()),{0,1})
    def test_metrics(self):
        m=metrics([0,0,1,1],[0,1,1,1]);self.assertAlmostEqual(m['fpr'],.5)
if __name__=='__main__':unittest.main()
