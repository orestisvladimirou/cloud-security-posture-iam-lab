# Synthetic Terraform plan review: hardened.plan.json

> Hand-authored, offline Terraform JSON-shaped example only. No AWS account queried or change applied.

**0 pattern findings; 3 additional manual-review notes.**

| Rule | Severity | Resource | Pattern |
|---|---|---|---|

## Unknowns and manual review

- **aws_iam_policy.explicit_deny_context** — Unconditional global Deny in same policy. Explicit deny may override other allows in this policy; other policies still unknown
- **aws_iam_role.conditional_partner** — Wildcard trust principal is conditioned. Principal=* with Condition; review exact condition evaluation and external IDs
- **module.application.aws_iam_role.future_partner** — Unknown planned attributes; rule evaluation skipped. after_unknown contains unknown values for resource

**Assurance boundary:** Terraform planned values are not effective IAM access, deployed state, network reachability, organization policy, data access, audit log delivery, or compliance evidence.
