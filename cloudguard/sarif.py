"""Generate SARIF 2.1.0 for offline synthetic Terraform-plan findings.

SARIF here is an artifact for code review, not a GitHub security alert or proof
of effective AWS permissions. The file itself is the location, not HCL source.
"""
from __future__ import annotations
import hashlib
from pathlib import Path


def from_plan(result, filename: str) -> dict:
    rules = {}
    emitted = []
    severity_level = {'Critical':'error','High':'error','Medium':'warning','Low':'note'}
    for finding in result['findings']:
        rules.setdefault(finding.rule_id, {
            'id':finding.rule_id,
            'shortDescription':{'text':finding.issue},
            'fullDescription':{'text':finding.remediation},
            'properties':{'tags':['security','synthetic','terraform-plan-pattern']},
        })
        fingerprint = hashlib.sha256((finding.address+'|'+finding.rule_id+'|'+finding.evidence).encode('utf-8')).hexdigest()
        emitted.append({
            'ruleId':finding.rule_id,
            'level':severity_level[finding.severity],
            'message':{'text':f'{finding.address}: {finding.issue}. {finding.evidence}. '+
                      'Offline synthetic fixture; effective AWS exposure unverified.'},
            'locations':[{'physicalLocation':{
                'artifactLocation':{'uri':Path(filename).as_posix()},
                # We cannot resolve resource line positions from Terraform JSON.
                'region':{'startLine':1},
            }}],
            'partialFingerprints':{'resourceRuleHash':fingerprint},
            'properties':{'trainingSeverity':finding.severity,'resourceAddress':finding.address}
        })
    return {'version':'2.1.0', '$schema':
            'https://json.schemastore.org/sarif-2.1.0.json',
            'runs':[{'tool':{'driver':{
                'name':'CloudGuard-Synthetic-Terraform',
                'semanticVersion':'0.4.0',
                'informationUri':'https://developer.hashicorp.com/terraform/internals/json-format',
                'rules':list(rules.values())}},
                'invocations':[{'executionSuccessful':True}],
                'results':emitted,
                'properties':{'synthetic':True,'liveAwsInspected':False,
                              'manualReviewCount':len(result['manual_reviews'])}}]}
