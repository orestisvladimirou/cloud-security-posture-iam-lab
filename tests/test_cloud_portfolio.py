import json
import unittest
from pathlib import Path
from scripts_validate_cloud_portfolio import validate,ROOT

class PortfolioCloudReviewTests(unittest.TestCase):
    def test_cross_phase_portfolio_integrity(self):
        self.assertTrue(validate())

    def test_comparison_is_explicitly_offline(self):
        report=json.loads((ROOT/'reports/terraform/comparison.json').read_text(encoding='utf-8'))
        self.assertTrue(report['synthetic'])
        self.assertIn('no production changes',report['assurance'])
        self.assertEqual(report['hardened']['manual_reviews'],3)

    def test_sarif_does_not_claim_real_source_line_or_live_cloud(self):
        sarif=json.loads((ROOT/'reports/terraform/vulnerable.sarif').read_text(encoding='utf-8'))
        self.assertFalse(sarif['runs'][0]['properties']['liveAwsInspected'])
        self.assertTrue(all(x['locations'][0]['physicalLocation']['region']['startLine']==1 for x in sarif['runs'][0]['results']))

if __name__=='__main__':unittest.main()
