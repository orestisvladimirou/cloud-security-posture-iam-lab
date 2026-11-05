# 03 — Fictional remediation and verification plan

The [treatment register](../data/remediation_plan.csv) maps every baseline finding to a proposed owner, an acceptance-evidence check and an open/unapproved status. The [comparison report](../reports/comparison.json) documents how many supported patterns disappear after switching the input to the independently written hardened example.

## Treatment sequence (proposed only)

1. **Critical identity controls:** investigate root credentials, enforce MFA via an appropriate root-user protection model, remove root access keys, restrict wildcard trust and eliminate unnecessary full admin permissions. Confirm access workflows won't be broken.
2. **Critical network/storage exposure:** examine what is reachable and whether any S3 policy grants effective public access, taking account of all AWS policy layers. Restrict administrative and database ingress; implement least privilege and verified bucket-level safeguards.
3. **Monitoring foundation:** verify organization-wide/account-specific CloudTrail coverage and evidence integrity; enable configuration recording with appropriate resource/region scope.
4. **Hardening:** implement scoped service-level roles, storage encryption, and appropriate versioning after business owner signoff.
5. **Follow-up:** capture independently obtained AWS configuration evidence, link change records, test authorized access/denied access and business workflows, then determine whether the actual finding can close.

## Change control

The `fixtures/hardened.json` file represents a **modeled target state**, not a change applied in AWS. For a real implementation, obtain the account owner, maintenance window, permissions, rollback, monitoring and security exceptions. Tests must inspect effective access rather than trust this scanner's `0 findings` headline. Each priority is a training assumption subject to owner risk appetite.

## Example evidence acceptance tests

| Workstream | What would constitute stronger evidence in a real assessment? |
|---|---|
| IAM | Dated IAM root/role configuration, Access Analyzer findings, authorized use-case and negative permission tests |
| S3 | Account/organization/bucket/access point BPA evidence and owner-approved object-access tests |
| Network | Security-group rules **plus** route/access-path inspection and rejected unauthorized connection attempt |
| Logging | Multi-region trail and Config resource coverage with actual event delivery and tamper-detection sample |
| Verification | Independent reviewer, dated change record, owner acceptance, and regression monitoring |

**No such genuine evidence was collected in this exercise.** All CSV rows remain `Proposed - scenario` and `Not obtained - simulation`; no real risk was accepted or finding independently closed.
