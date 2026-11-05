# Final Code, Security and Portfolio Quality Review

**Date: 5 November 2026 · Fictional/offline lab only.** A passing validator proves source consistency, not AWS security, live infrastructure changes, or certification.

| Review item | Evidence | Outcome |
|---|---|---|
| v0.1 independent snapshot scanner | 15 planted patterns, zero on hardened example | Passed narrow-rule regression |
| Terraform plan model | Synthetic JSON format 1.x, root and child module resources | Parsed/validated, no HCL interpretation |
| Unknown and provider-computed attributes | `after_unknown` and missing trust/BPA values | Manual review, not hidden or falsely compliant |
| IAM policy treatment | Explicit global Deny, conditional trust and IAM wildcards | Tested conservative heuristic distinctions |
| Network scope | IPv4/IPv6 world CIDR and sensitive ports | Pattern detection only; no routing verification |
| Remediation and exceptions | 10 plan-only mitigations; 3 unapproved exception requests | No actual AWS action claimed |
| SARIF 2.1.0 | Stable rule and resource references; synthetic warnings | Reproducible artifact, not source-level HCL precision |
| CI and source integrity | Unit tests, deterministic reports, local Markdown links, SHA-256 manifest | Reproducible offline validation |
| Privacy and safety | Only invented identities, no credentials, no network/cloud calls | No real security data disclosed |

## Deliberate gaps and false-positive boundaries

- IAM `Allow` statements are **not effective permissions**; permissions boundaries, SCPs/RCPs, explicit Deny, service-specific evaluation, identity context, session policies and resource-based grants may alter the result.
- A wildcard principal with a Condition may or may not be appropriately constrained; the condition's semantics are **not interpreted**. Therefore a note remains even on the hardened fixture.
- A disabled S3 bucket BPA flag is not proof of public data access; account/organization-level settings may override it. New objects are encrypted by default in modern Amazon S3; absence of explicit SSE config alone is not proof of unencrypted objects.
- Terraform planned values omit some computed values. This scanner intentionally skips resources with unknown changes rather than asserting controls passed.
- Planned resource values are not deployed state; the hand-authored fixtures are examples rather than verified Terraform output, and their fields may diverge from provider schema versions.
- SARIF attaches to the JSON plan file, not precise source HCL lines. We do not upload results to a code-scanning service and do not claim actual GitHub alerts.
- No external exception request was approved; no live verification, remediation or real production security assessment occurred.

## Publication / CV gate

- [x] Distinct technical scope from GRC and SOC portfolio projects.
- [x] All findings traceable to synthetic fixture, rule, evidence and remediation.
- [x] Negative tests and CI preserve important uncertainty rather than burying it.
- [x] v0.1 baseline retained intact; Terraform upgrade is additive and versioned.
- [x] All internal links and versioned SHA-256 manifest validate.
- [ ] Owner personally reviews and can explain design decisions.
- [ ] Owner explicitly decides whether to make the repository public. Keep private until then.

Appropriate CV language: **Independent Python-based offline cloud security posture and IAM hardening lab; developed configuration heuristics for synthetic AWS-style snapshots and Terraform plan JSON, tested vulnerable/hardened baselines, documented uncertainty and automated SARIF/CI reporting.** Never present as AWS employment, cloud penetration testing or deployed remediation.

Official references: [HashiCorp JSON format](https://developer.hashicorp.com/terraform/internals/json-format) · [IAM evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html) · [AWS IAM best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html).
