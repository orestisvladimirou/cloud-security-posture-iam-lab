"""Validate versioned cloud-rule output without claiming production security."""
from __future__ import annotations
import csv
import json
from datetime import date
from pathlib import Path
from cloudguard.engine import load_snapshot,scan
from cloudguard.terraform_plan import load_plan,scan_plan
from cloudguard.sarif import from_plan
from cloudguard.exceptions import load_exceptions

ROOT=Path(__file__).resolve().parent


def readcsv(path):
    with (ROOT/path).open(encoding='utf-8',newline='') as f:
        return list(csv.DictReader(f))


def validate():
    old=scan(load_snapshot(ROOT/'fixtures/vulnerable.json'))
    fixed=scan(load_snapshot(ROOT/'fixtures/hardened.json'))
    assert len(old)==15 and not fixed
    raw=scan_plan(load_plan(ROOT/'terraform/vulnerable.plan.json'))
    hardened=scan_plan(load_plan(ROOT/'terraform/hardened.plan.json'))
    assert raw['resource_count']==12 and hardened['resource_count']==12
    assert raw['counts']=={'Critical':1,'High':6,'Medium':3,'Low':0}
    assert hardened['counts']=={'Critical':0,'High':0,'Medium':0,'Low':0}
    assert len(raw['manual_reviews'])==len(hardened['manual_reviews'])==3
    records=readcsv('phase2/data/terraform_findings.csv')
    crosswalk=readcsv('phase3/data/verification_matrix.csv')
    requests=load_exceptions(ROOT/'phase3/data/exception_requests.csv',date(2026,11,5))
    assert len(records)==len(crosswalk)==10
    assert len({r['finding_id'] for r in records})==10
    assert {r['finding_id'] for r in crosswalk}=={r['finding_id'] for r in records}
    matches={(x.address,x.rule_id):x for x in raw['findings']}
    assert len(matches)==10
    for row in records:
        obs=matches[(row['terraform_resource'],row['rule_id'])]
        assert row['severity']==obs.severity and row['observed_pattern']==obs.evidence
        assert row['proposed_remediation']==obs.remediation
        assert row['fixture']=='terraform/vulnerable.plan.json' and 'pattern' in row['confidence'].lower()
    for row in crosswalk:
        assert (row['terraform_resource'],row['rule_id']) in matches
        assert row['outcome']=='RESOLVED ONLY IN SYNTHETIC PLAN'
        assert row['real_aws_verification']=='NOT PERFORMED' and row['approval']=='NOT OBTAINED'
    assert len(requests)==3 and all(not r['suppresses_finding'] for r in requests)
    assert {r['effective_status'] for r in requests}=={'Proposed','Rejected','Expired'}
    for label,report in [('vulnerable',raw),('hardened',hardened)]:
        expected=json.dumps(from_plan(report,f'terraform/{label}.plan.json'),indent=2,sort_keys=True)+'\n'
        assert (ROOT/f'reports/terraform/{label}.sarif').read_text(encoding='utf-8')==expected
    comparison=json.loads((ROOT/'reports/terraform/comparison.json').read_text(encoding='utf-8'))
    assert comparison['vulnerable']['findings']==10 and comparison['hardened']['findings']==0
    assert comparison['vulnerable']['manual_reviews']==3 and comparison['hardened']['manual_reviews']==3
    assert len(comparison['resolved_patterns'])==10
    assert not comparison['introduced_patterns'] and not comparison['persistent_patterns']
    for p in ('phase4/dashboard.md','phase4/quality-review.md','README.md'):
        text=(ROOT/p).read_text(encoding='utf-8')
        assert 'synthetic' in text.lower() or 'fictional' in text.lower()
        assert ('AWS' in text or 'cloud' in text.lower())
    print('PASS cloud portfolio: 15 original and 10 Terraform planted patterns, 0 fixture findings after modeled mitigation, '+
          '3 reviews on each Terraform plan, 10 plan-only action crosswalks, 3 unsigned exceptions, reproducible SARIF.')
    return True


if __name__=='__main__':validate()
