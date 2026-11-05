# 02 — Detection rule library and methodology

This intentionally small scanner has **15 rule identifiers**. A rule may produce one finding per account/resource; the baseline fixture happens to generate **15 total findings**. Neither the number of rules nor the absence of matches is an assessment of all AWS services or compliance.

| Rule | Severity for base case | Pattern detected | Example evidence request |
|---|---|---|---|
| IAM-001 | Critical | Root MFA is false | Root account protection status and delegated root access model |
| IAM-002 | Critical | Root access key active | IAM credential report and process-owner signoff |
| IAM-003 | Critical | Role trust lists wildcard principal | Verified trust policy, conditions and external principals |
| IAM-004 | Critical | `Allow Action=* Resource=*` in same role statement | Effective permissions review and permissions boundaries |
| IAM-005 | High | `Allow service:* Resource=*` in same role statement | Service action usage, scoped ARN and least privilege review |
| S3-001 | High | Some bucket-level public-access block flags false | Account/org/bucket Block Public Access and access point checks |
| S3-002 | Critical/Medium | Bucket policy wildcard `Allow` principal | Effective public-access analysis and request-context conditions |
| S3-003 | High | Default bucket encryption marked `none` | S3 encryption configuration, keys and sample objects |
| S3-004 | Medium | Bucket versioning false | Business recovery and deletion/ransomware protection requirements |
| NET-001 | Critical | World-open ingress to 22 or 3389 | Routes, listeners, access paths, IPv4/IPv6 ingress |
| NET-002 | Critical | World-open ingress to selected database ports | VPC flow, routes, attached instances, DB endpoints |
| MON-001 | Critical | No ongoing CloudTrail trail in snapshot | Organization/account trail proof and management event sample |
| MON-002 | High | Enabled CloudTrail trail not multi-region | All enabled-region coverage and exceptions |
| MON-003 | Medium | CloudTrail log validation false | Real delivery, hash integrity and storage protections |
| MON-004 | High | AWS Config recorder off | Recorder configuration and captured-resource types |

**Rule behavior:** S3-002 is Critical when at least one bucket Block Public Access flag is disabled, Medium otherwise. Only `Principal="*"` in a simplified Allow statement is detected, without evaluating conditions. Network rules flag the exact `0.0.0.0/0` or `::/0` CIDR and TCP/all protocols. World-open HTTPS 443 is not automatically flagged; ordinary private CIDRs for administration are not treated as internet-wide. No service availability or business exposure is inferred solely from the CIDR.

## Evidence confidence

All observations are **synthetic input facts**, not authentic AWS exports. The scanner can assert that a supplied field has a specified value but cannot demonstrate that the resource exists, an IAM permission is effective, data is accessible, encryption works, or an attacker can reach a port. JSON schema rejects missing required fields rather than silently treating them as secure. No actual end-to-end security verification occurred.

## Reproducibility

`python -m cloudguard scan fixtures/vulnerable.json --format json` emits deterministic IDs and evidence. `python -m cloudguard compare fixtures/vulnerable.json fixtures/hardened.json` identifies changes without editing source data. `python scripts_validate_reports.py` checks that committed reports match scanner output exactly. The 15 IDs are stable within the snapshot naming scheme: `account/resource/rule`.

## False negatives and false positives

This implementation covers only explicit rules and fields, not the full AWS IAM policy language. In particular, a wildcard Allow can be neutralized by explicit Deny/condition/SCP/boundary; a wildcard Principal may be constrained by policy conditions or public-access blocks; the input does not describe all account/org controls. Also, a policy may have significant access without using literal wildcard `*`. A finding must be reviewed by a human before action. The clean fixture is **not** evidence of real account security.
