# 01 — Scope and threat model (synthetic)

**Training business:** Aster Finch Commerce, an invented medium-sized e-commerce platform with two imaginary AWS-style accounts, `lab-prod-111111111111` and `lab-dev-222222222222`. Neither account exists or is accessible by this project. The snapshots are not AWS Config, CloudTrail, IAM Access Analyzer or an actual API export: their schema is expressly constructed for the local teaching scanner.

## Assumed assets and trust boundaries

- Production: payment-platform management role, vendor-support cross-account role, customer-records bucket, audit-logs bucket, application and database security groups, root credentials, service logging.
- Development: build role, artifact bucket, administrative security group, root credentials and logging.
- Threats: privileged identity misuse, accidental over-permission, public customer data exposure, remote administration/data-service access from untrusted networks, undetected cloud changes and weak evidence preservation.
- Business objective: limit unauthorized access and maintain investigation evidence while preserving required service access; actual asset criticality, data sensitivity and regulatory scope would need confirmed owners.

## What is in and out of scope

**In:** deterministic static checks of the limited JSON schema, remediation proposals, baseline/hardened comparison, automated quality assurance, and an internal management-style report.

**Out:** live account discovery, boto3, AWS API calls, handling real credentials, AWS Organizations/SCP evaluation, identity federation, IAM permissions boundaries, IAM policy variables/conditions, ABAC, effective S3 public exposure, VPC routing, KMS grants, security services, cross-region completeness, production change execution, and ISO/CIS/PCI certification.

## Risk prioritization

An educational Critical/High/Medium severity is assigned to detected patterns, not to confirmed incidents. Priorities are defensible hypotheses given the fictional payment workload. A real assessment would validate architecture, attack paths, compensating controls, existing owner approvals and acceptance criteria before scoring residual risk or committing to a change.

The response approach is **observe → verify effective risk → agree owner and treatment → change with rollback plan → independently verify → monitor**. The second JSON fixture illustrates possible design improvements; it does not establish that those steps were actually executed.
