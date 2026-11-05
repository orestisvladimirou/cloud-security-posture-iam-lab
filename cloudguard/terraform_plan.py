"""Offline *synthetic* Terraform JSON plan pattern scanner.

Accepts representative `terraform show -json` planned_values subset with an
additional lab_metadata.synthetic=true marker. It does not parse HCL or query
AWS. Not a complete Terraform/provider graph or AWS permission evaluator.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from ipaddress import ip_network
from pathlib import Path
import json
from typing import Any

from .engine import SEVERITIES
BPA_PLAN_FIELDS = ("block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets")


class InvalidPlan(ValueError):
    """Invalid / non-fictional / unsupported plan."""


@dataclass(frozen=True)
class PlanObservation:
    address: str
    rule_id: str
    severity: str
    issue: str
    evidence: str
    remediation: str
    kind: str = 'Finding'
    confidence: str = 'Configuration pattern only; cloud effectiveness unverified'

    def to_dict(self):
        return asdict(self)


def parse_policy(value: Any, label: str) -> list[dict]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError) as exc:
            raise InvalidPlan(f'{label}: invalid policy JSON') from exc
    if not isinstance(value, dict):
        raise InvalidPlan(f'{label}: policy must be a JSON policy object')
    clauses = value.get('Statement')
    if isinstance(clauses, dict):
        clauses = [clauses]
    if not isinstance(clauses, list) or not all(isinstance(x, dict) for x in clauses):
        raise InvalidPlan(f'{label}: missing or invalid Statement')
    return clauses


def _values(val):
    if isinstance(val, str):
        return [val]
    if isinstance(val, list) and all(isinstance(x, str) for x in val):
        return val
    return []


def _any_unknown(value):
    if value is True:
        return True
    if isinstance(value, dict):
        return any(_any_unknown(x) for x in value.values())
    if isinstance(value, list):
        return any(_any_unknown(x) for x in value)
    return False


def _known_bool(value, field, address, notices):
    if type(value) is bool:
        return value
    notices.append(PlanObservation(address, 'TF-UNKNOWN', 'Info',
        f'{field} not known from synthetic planned values',
        f'{field}={value!r}', 'Review provider defaults and authoritative AWS state.', 'Review'))
    return None


def _resource_items(module):
    if not isinstance(module, dict):
        raise InvalidPlan('planned_values.root_module must be an object')
    resources = module.get('resources', [])
    children = module.get('child_modules', [])
    if not isinstance(resources, list) or not isinstance(children, list):
        raise InvalidPlan('module resources / child_modules must be lists')
    for r in resources:
        if not isinstance(r, dict):
            raise InvalidPlan('resource must be an object')
        yield r
    for child in children:
        yield from _resource_items(child)


def load_plan(path: str | Path) -> dict:
    try:
        plan = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise InvalidPlan(f'Could not parse plan: {exc}') from exc
    validate_plan(plan)
    return plan


def validate_plan(plan):
    if not isinstance(plan, dict) or not isinstance(plan.get('lab_metadata'), dict) or plan['lab_metadata'].get('synthetic') is not True:
        raise InvalidPlan('Only synthetic lab plans with lab_metadata.synthetic=true are accepted')
    v = plan.get('format_version')
    if not isinstance(v, str) or not v.startswith('1.'):
        raise InvalidPlan('Requires known Terraform JSON plan format_version 1.x')
    values = plan.get('planned_values')
    if not isinstance(values, dict) or 'root_module' not in values:
        raise InvalidPlan('planned_values.root_module is required; state-only JSON not supported')
    addresses = set()
    for r in _resource_items(values['root_module']):
        addr = r.get('address')
        if not isinstance(addr, str) or not addr or addr in addresses:
            raise InvalidPlan('resource address must be unique and nonempty')
        addresses.add(addr)
        if not isinstance(r.get('type'), str):
            raise InvalidPlan(f'{addr}: missing type')
        if r.get('values') is not None and not isinstance(r['values'], dict):
            raise InvalidPlan(f'{addr}: values must be an object or null')
    changes = plan.get('resource_changes', [])
    if not isinstance(changes, list):
        raise InvalidPlan('resource_changes must be an array')
    for c in changes:
        if not isinstance(c, dict) or not isinstance(c.get('address'), str):
            raise InvalidPlan('resource_changes entry missing address')
        change = c.get('change')
        if not isinstance(change, dict) or not isinstance(change.get('actions'), list):
            raise InvalidPlan('resource_changes entry has invalid change.actions')
    return plan


def scan_plan(plan: dict) -> dict:
    validate_plan(plan)
    findings: list[PlanObservation] = []
    notices: list[PlanObservation] = []
    resources = list(_resource_items(plan['planned_values']['root_module']))
    changes = {c['address']:c['change'] for c in plan.get('resource_changes', [])}
    bucket_blocks: dict[str, dict] = {}
    def add(address, rule, severity, title, evidence, fix):
        findings.append(PlanObservation(address, rule, severity, title, evidence, fix))
    def review(address, title, evidence):
        notices.append(PlanObservation(address, 'TF-REVIEW', 'Info', title, evidence,
            'Confirm effective state and conditions using approved account evidence.', 'Review'))

    # Look up scoped bucket-public-access configuration first. Missing linkage is unknown.
    for r in resources:
        if r['type'] != 'aws_s3_bucket_public_access_block':
            continue
        v = r.get('values') or {}
        bucket = v.get('bucket')
        if isinstance(bucket, str):
            bucket_blocks[bucket] = v
        else:
            review(r['address'], 'Bucket BPA association unknown', 'Provider bucket ID unresolved')

    for r in resources:
        addr, typ, v = r['address'], r['type'], r.get('values')
        lifecycle = changes.get(addr, {}).get('actions', ['no-op'])
        if lifecycle == ['delete']:
            continue
        if v is None:
            review(addr, 'Resource planned values unresolved', 'values=null')
            continue
        unknown = changes.get(addr, {}).get('after_unknown', {})
        if _any_unknown(unknown):
            review(addr, 'Unknown planned attributes; rule evaluation skipped',
                   'after_unknown contains unknown values for resource')
            continue
        if typ == 'aws_iam_role':
            policy = v.get('assume_role_policy')
            if policy is None:
                review(addr, 'Role trust document unresolved', 'assume_role_policy missing')
                continue
            for p in parse_policy(policy, addr):
                if p.get('Effect') != 'Allow':
                    continue
                principal = p.get('Principal')
                values = _values(principal) if not isinstance(principal, dict) else [x for vs in principal.values() for x in _values(vs)]
                if '*' in values:
                    if p.get('Condition'):
                        review(addr, 'Wildcard trust principal is conditioned',
                               'Principal=* with Condition; review exact condition evaluation and external IDs')
                    else:
                        add(addr, 'TF-IAM-001', 'Critical', 'Wildcard role trust with no recorded Condition',
                            'Allow Principal=* in trust statement; no Condition',
                            'Limit trusted principals and verify role assumption conditions.')
        elif typ in ('aws_iam_policy', 'aws_iam_role_policy'):
            policy = v.get('policy')
            if policy is None:
                review(addr, 'IAM permission policy unresolved', 'policy missing or unknown')
                continue
            clauses = parse_policy(policy, addr)
            conditional_deny = any(s.get('Effect') == 'Deny' and s.get('Condition') for s in clauses)
            unconditional_global_deny = any(s.get('Effect') == 'Deny' and
                '*' in _values(s.get('Action')) and '*' in _values(s.get('Resource')) and not s.get('Condition') for s in clauses)
            if unconditional_global_deny:
                review(addr, 'Unconditional global Deny in same policy',
                       'Explicit deny may override other allows in this policy; other policies still unknown')
            for p in clauses:
                if p.get('Effect') != 'Allow':
                    continue
                if 'NotAction' in p or 'NotResource' in p or p.get('Condition'):
                    review(addr, 'Conditional or NotAction IAM statement needs review',
                           'NotAction/NotResource/Condition cannot be reduced to this pattern model')
                    continue
                acts, targets = _values(p.get('Action')), _values(p.get('Resource'))
                if unconditional_global_deny:
                    # This same policy has an unconditional Deny * on *;
                    # explicit Deny overrides its broad Allow. Record review,
                    # never declare other policies or effective grants safe.
                    continue
                if '*' not in targets:
                    continue
                if '*' in acts:
                    add(addr, 'TF-IAM-002', 'High', 'Administrative wildcard Allow pattern',
                        'Allow Action=* Resource=*; not effective permission confirmation',
                        'Apply least privilege; review boundaries, SCPs, RCPs, session policies and Deny rules.')
                elif any(a.endswith(':*') for a in acts):
                    add(addr, 'TF-IAM-003', 'Medium', 'Service-wide wildcard Allow pattern',
                        'Allow service:* Resource=*; effective permissions unknown',
                        'Scope actions and resources to the role business purpose.')
            if conditional_deny:
                review(addr, 'Conditional Deny requires contextual evaluation',
                       'Do not assume all administrative actions are denied from conditional statement')
        elif typ == 'aws_s3_bucket':
            bucket = v.get('bucket') or v.get('id')
            if not isinstance(bucket, str):
                review(addr, 'S3 bucket name unknown', 'Unable to join BPA with bucket')
                continue
            block = bucket_blocks.get(bucket)
            if block is None:
                review(addr, 'Bucket BPA resource not represented in synthetic plan',
                       'No matching aws_s3_bucket_public_access_block; account-level BPA unknown')
            else:
                missing = [k for k in BPA_PLAN_FIELDS if block.get(k) is False]
                if missing:
                    add(addr, 'TF-S3-001', 'High', 'Bucket public-access-block flags explicitly disabled',
                        'Disabled: '+', '.join(missing),
                        'Review account-level BPA and configure appropriate protection for private buckets.')
                elif any(k not in block for k in BPA_PLAN_FIELDS):
                    review(addr, 'Bucket public-access-block settings incomplete', 'Missing one or more BPA flag values')
        elif typ == 'aws_security_group':
            ingress = v.get('ingress')
            if ingress is None:
                review(addr, 'Security group ingress unresolved', 'ingress missing')
                continue
            if not isinstance(ingress, list):
                raise InvalidPlan(f'{addr}: ingress must be list')
            for item in ingress:
                if not isinstance(item, dict):
                    raise InvalidPlan(f'{addr}: malformed ingress')
                for cidr in (item.get('cidr_blocks') or []) + (item.get('ipv6_cidr_blocks') or []):
                    _network_rule(addr, item.get('protocol'), item.get('from_port'), item.get('to_port'), cidr, add, review)
        elif typ == 'aws_vpc_security_group_ingress_rule':
            cidr = v.get('cidr_ipv4') or v.get('cidr_ipv6')
            if cidr:
                _network_rule(addr, v.get('ip_protocol'), v.get('from_port'), v.get('to_port'), cidr, add, review)
            elif v.get('referenced_security_group_id'):
                pass  # reference to a group, not a public CIDR
            else:
                review(addr, 'Ingress source unknown', 'No CIDR or security group reference in planned values')
        elif typ == 'aws_cloudtrail':
            for field, rule, sev, title in (
                ('is_multi_region_trail','TF-MON-001','High','CloudTrail multi-region disabled'),
                ('enable_log_file_validation','TF-MON-002','Medium','CloudTrail log validation disabled')):
                value = _known_bool(v.get(field), field, addr, notices)
                if value is False:
                    add(addr, rule, sev, title, field+'=false', 'Enable and verify appropriate logging controls.')
        elif typ == 'aws_config_configuration_recorder':
            settings = v.get('recording_group')
            if not isinstance(settings, list) or not settings or not isinstance(settings[0], dict):
                review(addr, 'AWS Config recorder scope unresolved', 'recording_group missing')
            else:
                enabled = _known_bool(settings[0].get('all_supported'),'recording_group.all_supported',addr,notices)
                if enabled is False:
                    add(addr,'TF-MON-003','Medium','Config recorder does not specify all supported resources',
                        'all_supported=false','Inspect recording scope and coverage for required resource types.')
    findings.sort(key=lambda o:(-SEVERITIES.get(o.severity,0),o.address,o.rule_id))
    notices.sort(key=lambda o:(o.address,o.rule_id,o.issue))
    return {'synthetic':True,'scope':'limited-terraform-json-plan-patterns',
            'resource_count':len(resources),'findings':findings,'manual_reviews':notices,
            'counts':{key:sum(x.severity==key for x in findings) for key in SEVERITIES}}


def _network_rule(addr, protocol, start, end, cidr, add, review):
    try:
        net = ip_network(cidr, strict=False)
    except (TypeError, ValueError):
        raise InvalidPlan(f'{addr}: invalid CIDR {cidr!r}')
    if net.prefixlen != 0:
        return
    if protocol not in ('tcp', '-1', 'all'):
        return
    if protocol in ('-1','all'):
        start,end = 0,65535
    if type(start) is not int or type(end) is not int or not 0 <= start <= end <= 65535:
        review(addr, 'Public ingress ports unknown', f'protocol={protocol}, ports={start}..{end}')
        return
    if start <= 22 <= end or start <= 3389 <= end:
        add(addr,'TF-NET-001','High','Administrative ingress from all IPv4/IPv6 addresses',
            f'{cidr}: ports {start}-{end}', 'Restrict privileged ingress and confirm actual routing and exposure.')
    if any(start <= p <= end for p in (3306,5432,6379,27017)):
        add(addr,'TF-NET-002','High','Data-service ingress from all IPv4/IPv6 addresses',
            f'{cidr}: ports {start}-{end}', 'Limit database ports to private workloads and confirm actual routing.')
