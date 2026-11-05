"""Reproduce synthetic Terraform finding CSV, SARIF and portfolio crosswalks."""
import csv
import json
from pathlib import Path
from cloudguard.terraform_plan import load_plan, scan_plan
from cloudguard.sarif import from_plan

ROOT=Path(__file__).resolve().parent


def csv_out(path,headers,rows):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',encoding='utf-8',newline='') as f:
        w=csv.writer(f,lineterminator='\n'); w.writerow(headers); w.writerows(rows)


def main():
    before=scan_plan(load_plan(ROOT/'terraform/vulnerable.plan.json'))
    after=scan_plan(load_plan(ROOT/'terraform/hardened.plan.json'))
    a={(x.address,x.rule_id) for x in before['findings']}
    b={(x.address,x.rule_id) for x in after['findings']}
    assert len(a)==len(before['findings']), 'duplicate resource/rule patterns not supported by crosswalk'
    assert not b and len(a)==10
    columns=['finding_id','rule_id','severity','terraform_resource','observed_pattern','proposed_remediation','fixture','confidence']
    rows=[]
    for idx,x in enumerate(before['findings'],1):
        rows.append([f'TF-F{idx:03d}',x.rule_id,x.severity,x.address,x.evidence,x.remediation,
            'terraform/vulnerable.plan.json',x.confidence])
    csv_out(ROOT/'phase2/data/terraform_findings.csv',columns,rows)
    headers=['finding_id','terraform_resource','rule_id','review_owner','proposed_test','vulnerable_fixture','hardened_fixture','outcome','real_aws_verification','approval']
    verify=[]
    for r in rows:
        fid,rule,sev,address,evidence,fix,fixture,confidence=r
        verify.append([fid,address,rule,'Fictional Cloud Security Lead',
            'Compare rule result on both fictional plan snapshots; then seek actual AWS config, IAM policy simulation and ownership evidence',
            'Pattern detected','Pattern absent','RESOLVED ONLY IN SYNTHETIC PLAN','NOT PERFORMED','NOT OBTAINED'])
    csv_out(ROOT/'phase3/data/verification_matrix.csv',headers,verify)
    for label,obj in [('vulnerable',before),('hardened',after)]:
        (ROOT/f'reports/terraform/{label}.sarif').write_text(
            json.dumps(from_plan(obj,f'terraform/{label}.plan.json'),indent=2,sort_keys=True)+'\n',encoding='utf-8')
    comparison={
        'synthetic':True,'assurance':'Offline Terraform plan pattern checks only; no production changes',
        'vulnerable':{'findings':len(a),'counts':before['counts'],'manual_reviews':len(before['manual_reviews'])},
        'hardened':{'findings':len(b),'counts':after['counts'],'manual_reviews':len(after['manual_reviews'])},
        'resolved_patterns':[f'{address}::{rule}' for address,rule in sorted(a-b)],
        'persistent_patterns':[f'{address}::{rule}' for address,rule in sorted(a&b)],
        'introduced_patterns':[f'{address}::{rule}' for address,rule in sorted(b-a)],
    }
    (ROOT/'reports/terraform/comparison.json').write_text(json.dumps(comparison,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print('Generated ten Terraform-pattern findings, verification matrix and reproducible SARIF artifacts.')

if __name__=='__main__':main()
