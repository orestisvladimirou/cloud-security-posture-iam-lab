import unittest
from scripts_validate_reports import validate_reports


class ReportIntegrityTests(unittest.TestCase):
    def test_generated_artifacts_match_fixtures(self):
        self.assertTrue(validate_reports())
