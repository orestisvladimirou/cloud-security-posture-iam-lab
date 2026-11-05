# Phase 4 — Integrated Technical Portfolio Review

This phase closes the technical build with a source-linked [executive dashboard](dashboard.md), a [quality/release checklist](quality-review.md), validation of Terraform plan findings, an exception gate and reproducible SARIF output.

**Scope:** only locally invented cloud-configurations and hand-authored Terraform-JSON-shaped examples. No cloud scanning, penetration testing, Terraform apply, employee access or security remediation actually occurred. The old AWS-style snapshot scanner and its original 15 findings are retained as v0.1 historical evidence; the Terraform plan scanner is a separately scoped v0.2 addition.

Run `python scripts_validate_cloud_portfolio.py` plus the complete workflow described in the [root README](../README.md).
