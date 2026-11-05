"""Command-line front end for offline lab snapshots."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from .engine import InvalidSnapshot, compare, load_snapshot, scan, summarize, SEVERITIES
from .terraform_plan import InvalidPlan, load_plan, scan_plan
from .sarif import from_plan


def markdown(findings, path):
    counts=summarize(findings)
    lines=[f'# Offline cloud posture: {Path(path).name}', '',
           '> Fictional AWS-style snapshot; no live AWS access or compliance determination.', '',
           f'**{len(findings)} pattern-level findings:** '+', '.join(f'{n} {v}' for n,v in counts.items()), '',
           '| ID | Severity | Issue | Evidence |', '|---|---|---|---|']
    for f in findings:
        def cell(s): return s.replace('|','\\|').replace('\n',' ')
        lines.append(f'| `{cell(f.finding_id)}` | {f.severity} | {cell(f.title)} | {cell(f.evidence)} |')
    lines += ['', '## Recommendations', '']
    for f in findings:
        lines.append(f'- **{f.finding_id}**: {f.recommendation}')
    lines+=['','**Limitations:** Snapshot may omit account/organization policies, SCPs, permission boundaries, data-plane tests, role conditions, assets, network routing, IAM evaluation order, identity federation and actual log delivery. A clean scan is not proof of security.','']
    return '\n'.join(lines)


def plan_markdown(report, filename):
    lines=[f'# Synthetic Terraform plan review: {Path(filename).name}', '',
           '> Hand-authored, offline Terraform JSON-shaped example only. No AWS account queried or change applied.', '',
           f'**{len(report["findings"])} pattern findings; {len(report["manual_reviews"])} additional manual-review notes.**', '',
           '| Rule | Severity | Resource | Pattern |', '|---|---|---|---|']
    def safe(s): return str(s).replace('|', '\\|').replace('\n',' ')
    for f in report['findings']:
        lines.append(f'| {safe(f.rule_id)} | {f.severity} | `{safe(f.address)}` | {safe(f.issue)} |')
    lines.extend(['', '## Unknowns and manual review', ''])
    for x in report['manual_reviews']:
        lines.append(f'- **{x.address}** — {x.issue}. {x.evidence}')
    lines.extend(['', '**Assurance boundary:** Terraform planned values are not effective IAM access, deployed state, network reachability, organization policy, data access, audit log delivery, or compliance evidence.', ''])
    return '\n'.join(lines)


def main(argv=None):
    ap=argparse.ArgumentParser(description='Scan synthetic AWS-style snapshots without cloud credentials')
    sub=ap.add_subparsers(dest='command',required=True)
    p=sub.add_parser('scan',help='Scan a synthetic snapshot')
    p.add_argument('snapshot')
    p.add_argument('--format',choices=['json','markdown'],default='markdown')
    p.add_argument('--output',help='Save report to path instead of stdout')
    p.add_argument('--fail-on',choices=['none','Critical','High','Medium','Low'],default='none',help='Exit 2 if finding at or above threshold')
    t=sub.add_parser('plan',help='Inspect a SYNTHETIC Terraform show -json plan shaped fixture')
    t.add_argument('planfile')
    t.add_argument('--format',choices=['markdown','json','sarif'],default='markdown')
    t.add_argument('--output')
    t.add_argument('--fail-on',choices=['none','Critical','High','Medium','Low'],default='none')
    t.add_argument('--fail-on-review',action='store_true',help='Exit 4 for unresolved unknowns or manual-review items')
    c=sub.add_parser('compare',help='Compare finding IDs between two synthetic snapshots')
    c.add_argument('before')
    c.add_argument('after')
    c.add_argument('--output')
    args=ap.parse_args(argv)
    try:
        if args.command=='plan':
            report=scan_plan(load_plan(args.planfile))
            if args.format=='sarif':
                result=json.dumps(from_plan(report,args.planfile),indent=2,sort_keys=True)+'\n'
            elif args.format=='json':
                result=json.dumps({'synthetic':True,'scope':report['scope'],
                    'resource_count':report['resource_count'],'counts':report['counts'],
                    'findings':[x.to_dict() for x in report['findings']],
                    'manual_reviews':[x.to_dict() for x in report['manual_reviews']]},indent=2,sort_keys=True)+'\n'
            else:
                result=plan_markdown(report,args.planfile)
            fail=args.fail_on!='none' and any(SEVERITIES[x.severity]>=SEVERITIES[args.fail_on] for x in report['findings'])
            exit_code=2 if fail else 4 if args.fail_on_review and report['manual_reviews'] else 0
        elif args.command=='scan':
            findings=scan(load_snapshot(args.snapshot))
            result=(json.dumps({'synthetic':True,'scope':'pattern-detection-only','findings':[x.to_dict() for x in findings],
                                'counts':summarize(findings)},indent=2)+'\n') if args.format=='json' else markdown(findings,args.snapshot)
            fail=args.fail_on!='none' and any(['Critical','High','Medium','Low'].index(x.severity) <=
                                                ['Critical','High','Medium','Low'].index(args.fail_on) for x in findings)
            exit_code=2 if fail else 0
        else:
            before=scan(load_snapshot(args.before))
            after=scan(load_snapshot(args.after))
            result=json.dumps({'synthetic':True,'baseline_findings':len(before),'remediated_findings':len(after),
                               **compare(before,after)},indent=2)+'\n'
            exit_code=0
        if args.output:
            Path(args.output).write_text(result,encoding='utf-8')
        else:
            sys.stdout.write(result)
        return exit_code
    except (OSError,json.JSONDecodeError,InvalidSnapshot,InvalidPlan) as exc:
        print(f'Input error: {exc}',file=sys.stderr)
        return 3

if __name__=='__main__':
    raise SystemExit(main())
