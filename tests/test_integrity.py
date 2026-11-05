import unittest
from scripts_validate_integrity import validate_integrity

class IntegrityTests(unittest.TestCase):
    def test_documentation_and_crosswalk(self):
        self.assertTrue(validate_integrity())
