import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def run(*args):
    return subprocess.run([sys.executable,'-m','cloudguard',*map(str,args)],cwd=ROOT,text=True,capture_output=True)


class CliTests(unittest.TestCase):
    def test_json_output(self):
        p=run('scan','fixtures/vulnerable.json','--format','json')
        self.assertEqual(p.returncode,0,p.stderr)
        obj=json.loads(p.stdout)
        self.assertTrue(obj['synthetic'])
        self.assertEqual(len(obj['findings']),15)

    def test_markdown_output(self):
        p=run('scan','fixtures/vulnerable.json')
        self.assertEqual(p.returncode,0)
        self.assertIn('15 pattern-level findings',p.stdout)
        self.assertIn('Fictional AWS-style snapshot',p.stdout)

    def test_fail_on_critical(self):
        self.assertEqual(run('scan','fixtures/vulnerable.json','--fail-on','Critical').returncode,2)
        self.assertEqual(run('scan','fixtures/hardened.json','--fail-on','Critical').returncode,0)

    def test_compare(self):
        p=run('compare','fixtures/vulnerable.json','fixtures/hardened.json')
        self.assertEqual(p.returncode,0,p.stderr)
        obj=json.loads(p.stdout)
        self.assertEqual(len(obj['resolved']),15)
        self.assertEqual(obj['remediated_findings'],0)

    def test_missing_file_is_input_error(self):
        p=run('scan','fixtures/does-not-exist.json')
        self.assertEqual(p.returncode,3)
        self.assertIn('Input error:',p.stderr)

    def test_output_file(self):
        with tempfile.TemporaryDirectory() as d:
            dest=Path(d)/'scan.json'
            p=run('scan','fixtures/hardened.json','--format','json','--output',dest)
            self.assertEqual(p.returncode,0)
            self.assertTrue(dest.exists())
            self.assertEqual(json.loads(dest.read_text())['findings'],[])


if __name__=='__main__':unittest.main()
