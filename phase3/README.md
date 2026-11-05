# Phase 3 — Remediation Verification, Exceptions and SARIF for CI

**All records and cloud resources are fictional. No AWS account was configured or tested.**

The baseline v0.1 source JSON scans 15 pattern issues across two synthetic AWS-style accounts. The additional v0.2 Terraform-shaped plan snapshots trigger **10** pattern findings; the hardened Terraform example triggers **zero under these narrow rules, with three manual-review notes remaining**. They are different synthetic datasets and **must not be summed as independent findings in the same estate**.

## Verification matrix

The [verification matrix](data/verification_matrix.csv) tracks every Terraform finding from [the Phase 2 catalogue](../phase2/data/terraform_findings.csv): corresponding hardened-fixture pattern no longer appears, but `real_aws_verification=NOT PERFORMED` and `approval=NOT OBTAINED` throughout. A corrected code example is not evidence that the real cloud state changed.

## Security exception lifecycle

The [fictional exception requests](data/exception_requests.csv) illustrate `Proposed`, `Rejected`, and `Expired` decisions. The Python workflow in `cloudguard/exceptions.py` validates decision state, review expiration, and fictional approval provenance. No exception suppresses a detection—especially one pending, expired, or lacking real organizational sign-off. Even a fictional approved exception is not automatically proof of risk acceptability.

## SARIF output

`python -m cloudguard plan terraform/vulnerable.plan.json --format sarif` emits **SARIF 2.1.0** with rule metadata, stable resource/rule fingerprints, and synthetic evidence warnings. Findings are intentionally attached to line 1 of the **JSON plan file**, not purported HCL source-line numbers (mapping Terraform resource addresses to HCL source positions is not implemented). A GitHub Actions artifact is available for code review; this project does **not** claim the repository's GitHub Code Scanning service created real security alerts.

CI validates both the intentionally failing detection threshold and the intentionally nonfailing hardened threshold through unit tests, checks generated reports for stable output, and uploads SARIF as an artifact without any AWS credentials. See [GitHub workflow](../.github/workflows/verify.yml).
