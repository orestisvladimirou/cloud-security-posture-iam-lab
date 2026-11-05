import csv
from datetime import date
from pathlib import Path
import tempfile
import unittest
from cloudguard.exceptions import load_exceptions

ROOT=Path(__file__).resolve().parents[1]
FILE=ROOT/'phase3/data/exception_requests.csv'

class ExceptionWorkflowTests(unittest.TestCase):
    def test_no_exception_suppresses_any_finding(self):
        rows=load_exceptions(FILE,date(2026,11,5))
        self.assertEqual(len(rows),3)
        self.assertEqual([r['effective_status'] for r in rows],['Proposed','Rejected','Expired'])
        self.assertTrue(all(not r['suppresses_finding'] for r in rows))

    def test_expired_proposed_exception_is_not_accepted(self):
        rows=load_exceptions(FILE,date(2027,1,1))
        self.assertTrue(all(r['effective_status']=='Expired' for r in rows))

    def test_forged_fictional_approval_has_no_provenance(self):
        with FILE.open(newline='',encoding='utf-8') as f:
            original=list(csv.DictReader(f))
            heads=list(original[0])
        original[0]['decision']='Approved in fictional scenario'
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)/'try.csv'
            with out.open('w',newline='',encoding='utf-8') as f:
                w=csv.DictWriter(f,fieldnames=heads);w.writeheader();w.writerows(original)
            with self.assertRaises(ValueError):load_exceptions(out,date(2026,11,5))

if __name__=='__main__':unittest.main()
