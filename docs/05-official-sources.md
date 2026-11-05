# 05 — Official technical references and limitations

The following primary AWS documentation informed the educational rules and proposed evidence checks. **Always follow current AWS documentation and validate scope for real workloads.** These are reference patterns, not a verbatim standard or a certification mapping.

- [AWS IAM security best practices — least privilege](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html): task-specific actions, resources and conditions.
- [AWS root-user best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html): secure root credentials, MFA and avoiding root access keys.
- [AWS S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html): four settings and inherited account/organization protections.
- [AWS S3 access-control overview](https://docs.aws.amazon.com/AmazonS3/latest/user-guide/access-control-overview.html): bucket controls, encryption considerations and versioning.
- [AWS VPC security-group rules](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html): interpreting ingress sources and resource relationships.
- [AWS CloudTrail best practices](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html): multi-Region trails and log-file integrity validation.
- [AWS Config overview](https://docs.aws.amazon.com/config/latest/developerguide/WhatIsConfig.html): resource configuration inventory and change tracking.

## Critical scope limitations

This is *not* an AWS API integration, an IAM policy simulator, a comprehensive security configuration audit, a complete implementation of Security Hub/CIS benchmarks, or a certification claim. It cannot test AWS organization rules, permission boundaries, policy evaluation order, resource-based permission conditions, encryption-key grants, effective network paths or actual log reception. It rejects incomplete synthetic snapshots for the fields it checks, but the schema itself omits vast parts of AWS.

The test data and account numbers are fictitious placeholders. No keys, secrets, personal data, real access attempts or client information are included. Zero findings **only** means these defined patterns were not found in the supplied modeled fields. False negatives are expected outside rule scope; false positives can arise from compensating controls.
