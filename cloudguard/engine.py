"""Static assessment of deliberately synthetic AWS-style configuration snapshots.

Important: this is NOT a fully faithful IAM, S3, or network policy evaluator.
It detects documented configuration patterns, not effective cloud permissions.
"""
from __future__ import annotations
import ipaddress
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

SEVERITIES = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
ADMIN_PORTS = {22: 'SSH', 3389: 'RDP'}
DATA_PORTS = {3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB'}
BLOCK_FLAGS = ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets')


class InvalidSnapshot(ValueError):
    """Input is missing required information or has invalid structure."""


@dataclass(frozen=True)
class Finding:
    finding_id: str
    rule_id: str
    severity: str
    account: str
    resource: str
    title: str
    evidence: str
    recommendation: str
    confidence: str = 'Pattern-level: verify effective access and scope'

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def _expect(obj: Any, kind: type, field: str) -> None:
    if not isinstance(obj, kind):
        raise InvalidSnapshot(f'{field} must be a {kind.__name__}')


def _bool(obj: dict, field: str, scope: str) -> None:
    if type(obj.get(field)) is not bool:
        raise InvalidSnapshot(f'{scope}.{field} must be true/false (not missing)')


def validate(snapshot: dict) -> dict:
    _expect(snapshot, dict, 'root')
    if snapshot.get('synthetic') is not True:
        raise InvalidSnapshot('synthetic must be true; this tool accepts lab snapshots only')
    if snapshot.get('schema_version') != '1.0':
        raise InvalidSnapshot('schema_version must be 1.0')
    accounts = snapshot.get('accounts')
    _expect(accounts, list, 'accounts')
    if not accounts:
        raise InvalidSnapshot('accounts must not be empty')
    ids = set()
    for account in accounts:
        _expect(account, dict, 'account')
        aid = account.get('account_id')
        if not isinstance(aid, str) or not aid or aid in ids:
            raise InvalidSnapshot('account_id must be unique nonempty string')
        ids.add(aid)
        for name in ('root', 'logging'):
            _expect(account.get(name), dict, f'{aid}.{name}')
        for name in ('mfa_enabled', 'access_keys_active'):
            _bool(account['root'], name, f'{aid}.root')
        logging = account['logging']
        for name in ('cloudtrail_enabled', 'cloudtrail_multi_region',
                     'cloudtrail_log_validation', 'config_recorder_enabled'):
            _bool(logging, name, f'{aid}.logging')
        for collection in ('roles', 'buckets', 'security_groups'):
            _expect(account.get(collection), list, f'{aid}.{collection}')
            names = set()
            for item in account[collection]:
                _expect(item, dict, f'{aid}.{collection}[]')
                name = item.get('name')
                if not isinstance(name, str) or not name or name in names:
                    raise InvalidSnapshot(f'{aid}.{collection} names must be unique and nonempty')
                names.add(name)
                if collection == 'roles':
                    _expect(item.get('trust_principals'), list, f'{name}.trust_principals')
                    if not all(isinstance(v, str) for v in item['trust_principals']):
                        raise InvalidSnapshot('trust principals must be strings')
                    _expect(item.get('policies'), list, f'{name}.policies')
                    for policy in item['policies']:
                        _expect(policy, dict, f'{name}.policies[]')
                        if policy.get('Effect') not in ('Allow', 'Deny'):
                            raise InvalidSnapshot('Policy Effect must be Allow or Deny')
                        for field in ('Action', 'Resource'):
                            v = policy.get(field)
                            if not isinstance(v, (str, list)) or (isinstance(v, list) and (not v or not all(isinstance(s,str) for s in v))):
                                raise InvalidSnapshot(f'Policy {field} must be string or nonempty string list')
                elif collection == 'buckets':
                    _expect(item.get('block_public_access'), dict, f'{name}.block_public_access')
                    for flag in BLOCK_FLAGS:
                        _bool(item['block_public_access'], flag, f'{name}.block_public_access')
                    if item.get('encryption') not in ('AES256', 'aws:kms', 'none'):
                        raise InvalidSnapshot(f'{name}.encryption must be AES256, aws:kms or none')
                    _bool(item, 'versioning', name)
                    _expect(item.get('policy'), list, f'{name}.policy')
                    for policy in item['policy']:
                        _expect(policy, dict, f'{name}.policy[]')
                        if policy.get('Effect') not in ('Allow','Deny'):
                            raise InvalidSnapshot('S3 policy Effect invalid')
                        if not isinstance(policy.get('Principal'), str):
                            raise InvalidSnapshot('Simplified bucket policy Principal must be a string')
                else:
                    _expect(item.get('inbound'), list, f'{name}.inbound')
                    for rule in item['inbound']:
                        _expect(rule, dict, f'{name}.inbound[]')
                        if type(rule.get('from_port')) is not int or type(rule.get('to_port')) is not int:
                            raise InvalidSnapshot(f'{name} port ranges must be integers')
                        if not (0 <= rule['from_port'] <= rule['to_port'] <= 65535):
                            raise InvalidSnapshot(f'{name} port range invalid')
                        if rule.get('protocol') not in ('tcp', 'udp', 'all'):
                            raise InvalidSnapshot(f'{name} protocol must be tcp, udp or all')
                        try:
                            ipaddress.ip_network(rule['cidr'], strict=False)
                        except (KeyError, TypeError, ValueError) as exc:
                            raise InvalidSnapshot(f'{name} CIDR invalid') from exc
    return snapshot


def _values(v: str | list[str]) -> list[str]:
    return [v] if isinstance(v, str) else v


def _finding(aid: str, resource: str, rule: str, severity: str,
             title: str, evidence: str, recommendation: str) -> Finding:
    return Finding(f'{aid}/{resource}/{rule}', rule, severity, aid, resource,
                   title, evidence, recommendation)


def scan(snapshot: dict) -> list[Finding]:
    validate(snapshot)
    results: list[Finding] = []
    for account in snapshot['accounts']:
        aid = account['account_id']
        root = account['root']
        logging = account['logging']
        if not root['mfa_enabled']:
            results.append(_finding(aid, 'root', 'IAM-001', 'Critical', 'Root MFA not enabled',
                'root.mfa_enabled=false', 'Enable protected root MFA; confirm organization-level root access posture.'))
        if root['access_keys_active']:
            results.append(_finding(aid, 'root', 'IAM-002', 'Critical', 'Root access key is active',
                'root.access_keys_active=true', 'Remove root access keys and migrate automation to roles.'))
        for role in account['roles']:
            name = role['name']
            if '*' in role['trust_principals']:
                results.append(_finding(aid, name, 'IAM-003', 'Critical', 'Unrestricted role trust principal',
                    'Role trust_principals includes *', 'Restrict trust to specific appropriate principals and examine conditions.'))
            admin = service_wildcard = False
            for policy in role['policies']:
                if policy['Effect'] != 'Allow':
                    continue
                actions = _values(policy['Action'])
                resources = _values(policy['Resource'])
                if '*' in resources:
                    if '*' in actions:
                        admin = True
                    elif any(action.endswith(':*') for action in actions):
                        service_wildcard = True
            if admin:
                results.append(_finding(aid, name, 'IAM-004', 'Critical', 'Broad administrative Allow statement',
                    'Allow Action=* and Resource=* in same statement', 'Replace with task-specific least-privilege permissions; verify effective access.'))
            elif service_wildcard:
                results.append(_finding(aid, name, 'IAM-005', 'High', 'Broad service wildcard permission',
                    'Allow service:* and Resource=* in same statement', 'Narrow actions and resources after reviewing the application access needs.'))
        for bucket in account['buckets']:
            name = bucket['name']
            blocks = bucket['block_public_access']
            missing = [flag for flag in BLOCK_FLAGS if not blocks[flag]]
            if missing:
                results.append(_finding(aid, name, 'S3-001', 'High', 'Bucket public-access safeguards not all enabled',
                    'Disabled: ' + ', '.join(missing), 'Enable all four Block Public Access settings for private buckets; verify account-level policies.'))
            if any(p['Effect']=='Allow' and p['Principal']=='*' for p in bucket['policy']):
                level = 'Critical' if missing else 'Medium'
                results.append(_finding(aid, name, 'S3-002', level, 'Bucket policy has wildcard Allow principal',
                    'At least one Allow policy uses Principal=*', 'Review intent, constraints and effective account/organization BPA; remove unintended public grants.'))
            if bucket['encryption'] == 'none':
                results.append(_finding(aid, name, 'S3-003', 'High', 'Bucket lacks recorded default encryption',
                    'encryption=none in snapshot', 'Configure appropriate SSE default; assess KMS/key policy and other exposure paths.'))
            if not bucket['versioning']:
                results.append(_finding(aid, name, 'S3-004', 'Medium', 'Bucket versioning is disabled',
                    'versioning=false in snapshot', 'Consider enabling versioning where data recovery requirements justify it.'))
        for sg in account['security_groups']:
            name = sg['name']
            exposed_admin, exposed_data = set(), set()
            for rule in sg['inbound']:
                network = ipaddress.ip_network(rule['cidr'], strict=False)
                # Only the exact world route is treated as public by this narrow lab rule.
                if network.prefixlen != 0 or rule['protocol'] not in ('tcp','all'):
                    continue
                exposed_admin |= {f'{desc}:{port}/{rule["cidr"]}' for port,desc in ADMIN_PORTS.items()
                                  if rule['from_port']<=port<=rule['to_port']}
                exposed_data |= {f'{desc}:{port}/{rule["cidr"]}' for port,desc in DATA_PORTS.items()
                                 if rule['from_port']<=port<=rule['to_port']}
            if exposed_admin:
                results.append(_finding(aid, name, 'NET-001', 'Critical', 'Administrative ports reachable from any IPv4/IPv6 source',
                    ', '.join(sorted(exposed_admin)), 'Remove world-open administrative ingress; use private access and scoped administrative controls.'))
            if exposed_data:
                results.append(_finding(aid, name, 'NET-002', 'Critical', 'Data-service ports reachable from any IPv4/IPv6 source',
                    ', '.join(sorted(exposed_data)), 'Restrict database access to specific trusted workloads or security groups.'))
        if not logging['cloudtrail_enabled']:
            results.append(_finding(aid, 'logging', 'MON-001', 'Critical', 'No ongoing CloudTrail trail in snapshot',
                'cloudtrail_enabled=false', 'Enable a verified trail or equivalent organization-wide trail and check event coverage.'))
        elif not logging['cloudtrail_multi_region']:
            results.append(_finding(aid, 'logging', 'MON-002', 'High', 'CloudTrail trail is not multi-Region',
                'cloudtrail_multi_region=false', 'Enable a multi-Region trail and verify all relevant event classes.'))
        if not logging['cloudtrail_log_validation']:
            results.append(_finding(aid, 'logging', 'MON-003', 'Medium', 'CloudTrail log-file validation not enabled',
                'cloudtrail_log_validation=false', 'Enable log-file integrity validation and verify delivery and storage protection.'))
        if not logging['config_recorder_enabled']:
            results.append(_finding(aid, 'logging', 'MON-004', 'High', 'AWS Config recording disabled',
                'config_recorder_enabled=false', 'Enable appropriate resource configuration recording and monitoring.'))
    return sorted(results, key=lambda r:(-SEVERITIES[r.severity],r.account,r.rule_id,r.resource))


def load_snapshot(path: str | Path) -> dict:
    with Path(path).open(encoding='utf-8') as handle:
        data = json.load(handle)
    return validate(data)


def summarize(findings: list[Finding]) -> dict[str, int]:
    return {name:sum(f.severity==name for f in findings) for name in SEVERITIES}


def compare(before: list[Finding], after: list[Finding]) -> dict[str,list[str]]:
    old={x.finding_id for x in before}
    new={x.finding_id for x in after}
    return {'resolved':sorted(old-new),'persistent':sorted(old&new),'introduced':sorted(new-old)}
