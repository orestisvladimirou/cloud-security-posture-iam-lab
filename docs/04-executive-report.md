# 04 — Executive cloud posture report (fictional)

**Subject:** Aster Finch Commerce imaginary two-account AWS environment  
**Review date:** 5 November 2026  
**Deliverable:** Static synthetic configuration review — not a real penetration test, audit, incident investigation or cloud certification.

## Executive view

The training scanner identifies **15 flagged patterns** in the initial deliberately insecure fixture: **8 Critical, 5 High, 2 Medium**. A second, fictional hardened fixture produces **zero results under the same 15 defined rules**. This shows deterministic testable improvements **in a model only**, not demonstrated security of a live environment.

The highest-risk themes are root-account protection, over-broad IAM and vendor trust, potential public object storage policies, internet-wide administrative/database ingress, and incomplete cloud audit trails. These themes are consistent with public AWS best practice recommendations but are not evidence that a real firm has a security weakness.

## Dashboard

| Area | Baseline finding count | Illustrated next step |
|---|---:|---|
| Identity and permissions | 5 | Enforce root protections and role least privilege |
| S3 storage | 4 | Verify public access status, encryption and versioning |
| Network ingress | 2 | Restrict world-open admin and database ports |
| Logging and change monitoring | 4 | Establish CloudTrail and AWS Config coverage |
| **Total** | **15** | Independently validate before any real-world closure |

The code-backed numbers are available in [vulnerable scan JSON](../reports/vulnerable.json) and [baseline vs. hardened comparison](../reports/comparison.json). Source account IDs and all resources use fictitious `lab-` names.

## Suggested management questions

- Who owns the AWS accounts and is all AWS Organizations infrastructure in scope?
- Can the team show privileged account and trust relationships **after evaluating** permission boundaries, conditions and SCPs?
- Do account-level, organization-level or access point controls already mitigate bucket-level public exposure?
- Can source-authenticated security telemetry confirm every enabled Region and event class?
- What negative tests and rollback approvals are needed before a production remediation can be marked closed?

## Recommendation

Use this as a **portfolio demonstration of cloud-security reasoning and Python engineering**, not a compliance percentage or proof of a real environment's hardening. Future work can add Terraform examples, additional rule families, rule configuration, SARIF exports, and safe CI checks without ever requiring production credentials.
