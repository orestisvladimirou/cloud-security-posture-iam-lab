# Cloud Security Posture & IAM — Executive Engineering Dashboard

> **SIMULATED OFFLINE LAB • NOT AWS ACCOUNT SCANNING, NOT COMPLIANCE ATTESTATION.** All configurations, account references, findings and remediation evidence are fictitious. Terraform plan examples were **hand-authored** in the structure of `terraform show -json`, not generated or applied through the Terraform CLI.

## Two separate synthetic datasets

| Measurement | Vulnerable | Hardened | Assurance boundary |
|---|---:|---:|---|
| **v0.1 AWS-style account snapshots:** finding patterns | **15** | **0** | Two fictional accounts; rule-specific patterns only |
| v0.1 Critical / High / Medium | 8 / 5 / 2 | 0 / 0 / 0 | Initial risk labels are illustrative |
| **v0.2 Terraform-shaped plan snapshots:** finding patterns | **10** | **0** | 12 modeled resources; does not parse HCL or inspect AWS |
| v0.2 Critical / High / Medium | 1 / 6 / 3 | 0 / 0 / 0 | A clean plan is not proof of deployed security |
| Terraform manual-review notes | **3** | **3** | Conditional trust, global Deny and unknown planned value |
| Synthetic exception requests | 3 | 3 | Proposed, Rejected, Expired; none suppress a finding |
| Terraform findings independently verified on AWS | **0** | **0** | No cloud credentials or live tests |

Do **not** add 15 and 10 to imply 25 distinct problems across a real estate. They are **two intentionally different training fixtures**, exploring different data models and tests.

## Main attack surfaces and limitations

| Theme | Examples of patterns | Effective security requires |
|---|---|---|
| Identity / IAM | Unconditioned wildcard trust, broad `Allow` | Actual IAM simulator and access logs; SCP/RCP/boundary/context review |
| S3 data protection | Explicitly disabled bucket Block Public Access | Account/organization BPA, bucket policy/ACL and access testing |
| Network | World-open admin/data-service ports | Routing, ENIs, NACLs, live service configuration and reachability |
| Monitoring | Single-region trail, no log validation, incomplete Config recording | Event selection, actual delivery/retention and central monitoring tests |

## Findings and change process

- [v0.1 prioritized findings](../data/findings.csv) — original synthetic account model
- [v0.1 remediation owner/action plan](../data/remediation_plan.csv) — all proposed and unapproved
- [Terraform review findings](../phase2/data/terraform_findings.csv) — 10 distinct synthetic plan patterns
- [Terraform mitigation verification matrix](../phase3/data/verification_matrix.csv) — **all 10 marked plan-only**; no real AWS change
- [Exception requests](../phase3/data/exception_requests.csv) — **none approved**
- [SARIF artifacts and comparison report](../reports/terraform/comparison.json) — code-review artifacts, not real GitHub Security alerts

## Engineering design decisions

1. Explicit `lab_metadata.synthetic=true` gate prevents accidental use on ordinary Terraform plan/state JSON; no AWS SDK and no credentials.
2. Unknown Terraform attributes produce visible manual-review entries, not successful findings; effective policy evaluation is out of scope.
3. Global unconditional Deny inside the same IAM policy prevents falsely reporting its broad Allow as necessarily effective, while still prompting review.
4. Conditional role trust is flagged for **manual review**, not conflated with unconditioned wildcard trust.
5. Permission-risk and remediation fields represent **suggested engineering priorities**, not confirmed exposure or risk acceptance.
6. CI reports expected detector outputs, reproducible SARIF and source integrity rather than running Terraform apply.

## Remaining operational gates

To adapt to a genuine organization, obtain authorized access, secure collection/storage of Terraform plans, provider-version/schema checks, IAM policy simulator decisions, resource inventory, AWS Config/CloudTrail proof, authenticated network exposure testing and signed remediation/exception governance. Nothing in this case establishes that those activities occurred.

**Conclusion:** the portfolio demonstrates Python security rule implementation, negative testing, Terraform plan interpretation, secure CI reporting, evidence mapping and remediation validation **in a completely synthetic environment**. It must not be described as having hardened real AWS infrastructure.
