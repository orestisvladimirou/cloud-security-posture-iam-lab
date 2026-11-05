# Synthetic Terraform plan review: vulnerable.plan.json

> Hand-authored, offline Terraform JSON-shaped example only. No AWS account queried or change applied.

**10 pattern findings; 3 additional manual-review notes.**

| Rule | Severity | Resource | Pattern |
|---|---|---|---|
| TF-IAM-001 | Critical | `aws_iam_role.support_access` | Wildcard role trust with no recorded Condition |
| TF-MON-001 | High | `aws_cloudtrail.organization_audit` | CloudTrail multi-region disabled |
| TF-IAM-002 | High | `aws_iam_policy.build_permissions` | Administrative wildcard Allow pattern |
| TF-S3-001 | High | `aws_s3_bucket.records` | Bucket public-access-block flags explicitly disabled |
| TF-NET-001 | High | `aws_security_group.web` | Administrative ingress from all IPv4/IPv6 addresses |
| TF-NET-002 | High | `aws_security_group.web` | Data-service ingress from all IPv4/IPv6 addresses |
| TF-NET-002 | High | `module.application.aws_vpc_security_group_ingress_rule.database` | Data-service ingress from all IPv4/IPv6 addresses |
| TF-MON-002 | Medium | `aws_cloudtrail.organization_audit` | CloudTrail log validation disabled |
| TF-MON-003 | Medium | `aws_config_configuration_recorder.recorder` | Config recorder does not specify all supported resources |
| TF-IAM-003 | Medium | `aws_iam_role_policy.reporting_permissions` | Service-wide wildcard Allow pattern |

## Unknowns and manual review

- **aws_iam_policy.explicit_deny_context** — Unconditional global Deny in same policy. Explicit deny may override other allows in this policy; other policies still unknown
- **aws_iam_role.conditional_partner** — Wildcard trust principal is conditioned. Principal=* with Condition; review exact condition evaluation and external IDs
- **module.application.aws_iam_role.future_partner** — Unknown planned attributes; rule evaluation skipped. after_unknown contains unknown values for resource

**Assurance boundary:** Terraform planned values are not effective IAM access, deployed state, network reachability, organization policy, data access, audit log delivery, or compliance evidence.
