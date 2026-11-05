"""Validate fictional findings, action crosswalk, documentation links and manifest."""
from __future__ import annotations
import csv
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import unquote
from cloudguard.engine import load_snapshot,scan
from scripts_validate_reports import validate_reports

ROOT=Path(__file__).resolve().parent
SKIP={'__pycache__','.git','.pytest_cache','.venv'}


def files_inventory():
    output={}
    for p in ROOT.rglob('*'):
        if not p.is_file() or any(part in SKIP for part in p.relative_to(ROOT).parts):continue
        if p.name=='SOURCE_MANIFEST.json' or p.suffix in ('.pyc','.pyo'):continue
        rel=p.relative_to(ROOT).as_posix()
        raw=p.read_bytes()
        output[rel]={'sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw)}
    return output


def validate_integrity():
    validate_reports()
    f={x.finding_id:x for x in scan(load_snapshot(ROOT/'fixtures/vulnerable.json'))}
    with (ROOT/'data/findings.csv').open(newline='',encoding='utf-8') as h:
        findings=list(csv.DictReader(h))
    with (ROOT/'data/remediation_plan.csv').open(newline='',encoding='utf-8') as h:
        actions=list(csv.DictReader(h))
    assert len(f)==len(findings)==len(actions)==15
    assert {x['finding_id'] for x in findings}=={x['finding_id'] for x in actions}==set(f)
    assert len({x['action_id'] for x in actions})==15
    for r in findings:
        ff=f[r['finding_id']]
        assert (r['rule_id'],r['severity'],r['account'],r['resource'],r['finding'],r['snapshot_evidence'],r['proposed_mitigation'],r['confidence']) == (
            ff.rule_id,ff.severity,ff.account,ff.resource,ff.title,ff.evidence,ff.recommendation,ff.confidence)
        assert r['source_snapshot']=='fixtures/vulnerable.json'
    for a in actions:
        assert a['severity']==f[a['finding_id']].severity
        assert a['proposed_action']==f[a['finding_id']].recommendation
        assert a['priority_order']==str({'Critical':1,'High':2,'Medium':3,'Low':4}[a['severity']])
        assert a['status']=='Proposed - scenario' and a['approval']=='Not obtained - simulation'
        assert a['proposed_owner'] and a['required_verification']
    broken=[]
    link=re.compile(r'\[[^\]]*\]\(([^)]+)\)')
    for md in ROOT.rglob('*.md'):
        for url in link.findall(md.read_text(encoding='utf-8')):
            url=url.strip().split(' ',1)[0].strip('<>')
            if not url or url.startswith(('#','https://','http://','mailto:')):continue
            rel=unquote(url.split('#',1)[0])
            if rel and not (md.parent/rel).exists():broken.append(f'{md.relative_to(ROOT)} -> {rel}')
    assert not broken, 'Broken internal links: '+', '.join(broken)
    manifest=json.loads((ROOT/'SOURCE_MANIFEST.json').read_text(encoding='utf-8'))
    assert manifest['version']=='0.4'
    assert manifest['purpose']=='Entirely synthetic offline cloud-security portfolio exercise'
    assert manifest['files']==files_inventory(), 'Files changed; deliberately regenerate manifest after QA'
    print(f'PASS integrity: 15 findings and 15 open fictional actions; links valid; {len(manifest["files"])} source files match SHA-256 manifest')
    return True


if __name__=='__main__':validate_integrity()
