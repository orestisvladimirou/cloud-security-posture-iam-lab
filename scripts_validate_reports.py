"""Check that published JSON/Markdown reports match the documented source snapshots."""
import json
from pathlib import Path
from cloudguard.engine import compare,load_snapshot,scan,summarize
from cloudguard.cli import markdown

ROOT=Path(__file__).resolve().parent


def validate_reports():
    a=scan(load_snapshot(ROOT/'fixtures/vulnerable.json'))
    b=scan(load_snapshot(ROOT/'fixtures/hardened.json'))
    for name,records in [('vulnerable',a),('hardened',b)]:
        expected={"synthetic":True,"scope":"pattern-detection-only","findings":[f.to_dict() for f in records],"counts":summarize(records)}
        assert json.loads((ROOT/f'reports/{name}.json').read_text(encoding='utf-8'))==expected
        assert (ROOT/f'reports/{name}.md').read_text(encoding='utf-8')==markdown(records,f'fixtures/{name}.json')
    diff=json.loads((ROOT/'reports/comparison.json').read_text(encoding='utf-8'))
    assert diff=={'synthetic':True,'baseline_findings':len(a),'remediated_findings':len(b),**compare(a,b)}
    assert len(a)==15 and not b
    print('PASS: 15 vulnerable-pattern findings, 0 hardened-pattern findings, identical reports and comparison')
    return True


if __name__=='__main__':validate_reports()
