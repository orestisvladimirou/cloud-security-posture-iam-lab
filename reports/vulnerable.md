# Offline cloud posture: vulnerable.json

> Fictional AWS-style snapshot; no live AWS access or compliance determination.

**15 pattern-level findings:** Critical 8, High 5, Medium 2, Low 0

| ID | Severity | Issue | Evidence |
|---|---|---|---|
| `lab-prod-111111111111/root/IAM-001` | Critical | Root MFA not enabled | root.mfa_enabled=false |
| `lab-prod-111111111111/root/IAM-002` | Critical | Root access key is active | root.access_keys_active=true |
| `lab-prod-111111111111/external-support/IAM-003` | Critical | Unrestricted role trust principal | Role trust_principals includes * |
| `lab-prod-111111111111/payment-platform-admin/IAM-004` | Critical | Broad administrative Allow statement | Allow Action=* and Resource=* in same statement |
| `lab-prod-111111111111/logging/MON-001` | Critical | No ongoing CloudTrail trail in snapshot | cloudtrail_enabled=false |
| `lab-prod-111111111111/lab-app-public/NET-001` | Critical | Administrative ports reachable from any IPv4/IPv6 source | RDP:3389/::/0, SSH:22/0.0.0.0/0 |
| `lab-prod-111111111111/lab-database/NET-002` | Critical | Data-service ports reachable from any IPv4/IPv6 source | PostgreSQL:5432/0.0.0.0/0 |
| `lab-prod-111111111111/lab-customer-records/S3-002` | Critical | Bucket policy has wildcard Allow principal | At least one Allow policy uses Principal=* |
| `lab-dev-222222222222/dev-build-role/IAM-005` | High | Broad service wildcard permission | Allow service:* and Resource=* in same statement |
| `lab-dev-222222222222/logging/MON-002` | High | CloudTrail trail is not multi-Region | cloudtrail_multi_region=false |
| `lab-prod-111111111111/logging/MON-004` | High | AWS Config recording disabled | config_recorder_enabled=false |
| `lab-prod-111111111111/lab-customer-records/S3-001` | High | Bucket public-access safeguards not all enabled | Disabled: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets |
| `lab-prod-111111111111/lab-customer-records/S3-003` | High | Bucket lacks recorded default encryption | encryption=none in snapshot |
| `lab-prod-111111111111/logging/MON-003` | Medium | CloudTrail log-file validation not enabled | cloudtrail_log_validation=false |
| `lab-prod-111111111111/lab-customer-records/S3-004` | Medium | Bucket versioning is disabled | versioning=false in snapshot |

## Recommendations

- **lab-prod-111111111111/root/IAM-001**: Enable protected root MFA; confirm organization-level root access posture.
- **lab-prod-111111111111/root/IAM-002**: Remove root access keys and migrate automation to roles.
- **lab-prod-111111111111/external-support/IAM-003**: Restrict trust to specific appropriate principals and examine conditions.
- **lab-prod-111111111111/payment-platform-admin/IAM-004**: Replace with task-specific least-privilege permissions; verify effective access.
- **lab-prod-111111111111/logging/MON-001**: Enable a verified trail or equivalent organization-wide trail and check event coverage.
- **lab-prod-111111111111/lab-app-public/NET-001**: Remove world-open administrative ingress; use private access and scoped administrative controls.
- **lab-prod-111111111111/lab-database/NET-002**: Restrict database access to specific trusted workloads or security groups.
- **lab-prod-111111111111/lab-customer-records/S3-002**: Review intent, constraints and effective account/organization BPA; remove unintended public grants.
- **lab-dev-222222222222/dev-build-role/IAM-005**: Narrow actions and resources after reviewing the application access needs.
- **lab-dev-222222222222/logging/MON-002**: Enable a multi-Region trail and verify all relevant event classes.
- **lab-prod-111111111111/logging/MON-004**: Enable appropriate resource configuration recording and monitoring.
- **lab-prod-111111111111/lab-customer-records/S3-001**: Enable all four Block Public Access settings for private buckets; verify account-level policies.
- **lab-prod-111111111111/lab-customer-records/S3-003**: Configure appropriate SSE default; assess KMS/key policy and other exposure paths.
- **lab-prod-111111111111/logging/MON-003**: Enable log-file integrity validation and verify delivery and storage protection.
- **lab-prod-111111111111/lab-customer-records/S3-004**: Consider enabling versioning where data recovery requirements justify it.

**Limitations:** Snapshot may omit account/organization policies, SCPs, permission boundaries, data-plane tests, role conditions, assets, network routing, IAM evaluation order, identity federation and actual log delivery. A clean scan is not proof of security.
