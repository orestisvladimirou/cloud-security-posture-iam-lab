# 06 — Historical development roadmap (original v0.1 planning)

## v0.1 — Completed foundation

- Python standard-library scanner with strict synthetic snapshot validation, stable rule/resource identifiers, CLI exit codes and two report formats.
- Two hypothetical AWS-style accounts and deliberately vulnerable/hardened configurations.
- Fifteen detection rules spanning root and role permissions, S3 safeguards, sensitive security-group ingress, CloudTrail and AWS Config.
- Documented finding register, treatment proposal and modeled comparison report.
- Automated negative tests for unsupported inputs, benign HTTPS, private management traffic, explicit Deny and inherited S3 protections; GitHub Actions on push/PR.

## v0.2 — Terraform plan JSON review (completed)

- Evaluate selected **Terraform HCL configuration fixtures**, using a parser with transparent supported subset and a documented non-goal for full Terraform semantics; or support verified AWS Config-style JSON. Do not falsely represent the synthetic schema as a real AWS export.
- Add practical remediation patches and expected findings per sample.
- Capture selected attack-path and effective-permission limitations with explicit uncertainty labels.

## v0.3 — Evidence and CI usability (completed)

- SARIF output with CI annotations, rules metadata, signed exception review and expiration.
- Control mapping and richer dashboards; assess false-positive behavior on varied synthetic cases.
- Automated test coverage for schema version migrations and regression stability.

## v0.4 — Portfolio quality review (completed)

- Full consistency, documentation and safety review; independent model limitations analysis.
- Explain architecture and nonfunctional requirements, benchmark scan runtime, and verify reproducible outputs.
- Keep GitHub private until the project is reviewed and publication explicitly authorized by its owner.

The later phases are implemented in [Phase 2](../phase2/README.md), [Phase 3](../phase3/README.md) and [Phase 4](../phase4/README.md). This file preserves original intentions for traceability; not all planned ideas (such as a general HCL parser) were adopted. A feature is useful only when accurate, testable and honest about limits.
