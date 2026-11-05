# Cloud Security Posture & IAM Hardening Lab

**Independent cybersecurity portfolio project · v0.4 · 5 November 2026**

> **Entirely offline / fictional.** Aster Finch Commerce, its AWS-style accounts, resources, policies, threats, findings, and remediations are invented. This repository makes **no AWS API calls**, stores **no credentials**, and has not scanned, changed or secured any actual cloud resources. A clean lab scan is **not** an AWS, CIS, ISO 27001 or regulatory compliance finding.

## Phase 4 integrated technical results

The [latest technical dashboard](phase4/dashboard.md) consolidates **two different fictional models** (do not sum their findings): the original AWS-style snapshot scanner identifies 15 planted patterns, while the new **Terraform JSON plan scanner** identifies 10 deliberately planted patterns in a separate hand-authored Terraform-shaped fixture. Both hardened examples have **zero findings under the limited rules**. The hardened Terraform example **still has three manual-review notes**, and neither scanner contacts AWS or applies fixes.

[Terraform plan approach](phase2/README.md) · [SARIF, remediation and exception review](phase3/README.md) · [Final quality review](phase4/quality-review.md)

## Why this project exists

Build and test a small, transparent **Python cloud-configuration scanner** that identifies selected security posture and identity-access management patterns in intentionally vulnerable configuration fixtures, then verifies the same rules against a separately hardened fixture. Unlike a compliance spreadsheet-only project, this includes executable detection rules, strict input validation, tests, repeatable command-line reports and a remediation crosswalk.

**Technical areas:** IAM least privilege and role trust, root-account protections, S3 Block Public Access, default storage encryption, versioning, VPC security-group ingress, CloudTrail coverage and AWS Config recording. The scanner deliberately implements a **limited pattern library**, not AWS's effective policy evaluation or a complete cloud security posture management product.

## Executive results (all synthetic)

| Measurement | Vulnerable model | Hardened model |
|---|---:|---:|
| AWS-style accounts | 2 | 2 |
| Critical findings | **8** | 0 |
| High findings | **5** | 0 |
| Medium findings | **2** | 0 |
| Total supported-pattern findings | **15** | **0** |
| Actual cloud tests or changes | 0 | 0 |

**Zero detected patterns** in the deliberately hardened fixture means only that these fifteen **defined checks** find no flagged configuration there. It does not prove security or conformance. No production remediation is claimed.

## Quick start (Python 3.10+; standard library only)

```bash
python -m unittest discover -s tests -v
python scripts_validate_reports.py
python -m cloudguard scan fixtures/vulnerable.json
python -m cloudguard scan fixtures/vulnerable.json --format json
python -m cloudguard compare fixtures/vulnerable.json fixtures/hardened.json
python -m cloudguard scan fixtures/hardened.json --fail-on Critical
```

`scan` prints readable Markdown or machine-readable JSON; `--output path` writes a report, while `--fail-on Critical|High|Medium|Low` returns **2** if the rule threshold is met, or **3** on invalid input. `compare` reports persistent, resolved and new **rule IDs per resource**, comparing two snapshots without contacting AWS. It never applies remediation.

## Project structure

| Path | Function |
|---|---|
| [`cloudguard/engine.py`](cloudguard/engine.py) | Input validation and 15 pattern detectors across IAM, S3, network and monitoring |
| [`cloudguard/cli.py`](cloudguard/cli.py) | Scan/compare CLI, JSON and Markdown output, CI-friendly status codes |
| [`fixtures/vulnerable.json`](fixtures/vulnerable.json) | Two deliberately misconfigured synthetic account snapshots |
| [`fixtures/hardened.json`](fixtures/hardened.json) | Independently reviewed illustrative corrected configuration |
| [`reports/vulnerable.md`](reports/vulnerable.md) | Baseline human-readable security findings |
| [`reports/comparison.json`](reports/comparison.json) | Explicit modeled finding-resolution delta |
| [`data/findings.csv`](data/findings.csv) | Per-resource prioritized evidence and remediation list |
| [`data/remediation_plan.csv`](data/remediation_plan.csv) | Proposed owners, verification tests and unapproved states |
| [`docs/`](docs/) | Scope, rule catalogue, remediation strategy, evidence limits and executive report |
| [`tests/`](tests/) | Regression, negative, schema, CLI and artifact-integrity tests |
| [`.github/workflows/verify.yml`](.github/workflows/verify.yml) | GitHub Actions verification, without any AWS secret or account access |

## Findings are evidence-led, not definitive vulnerabilities

- A wildcard IAM `Allow` can be narrowed by permission boundaries, service control policies, conditions or explicit denies. **The lab cannot calculate effective permissions**.
- A bucket `Principal="*"` does not necessarily mean that data is publicly accessible: organizational/account-level Block Public Access can override local policies. **The lab flags a configuration pattern, not proven exposure**.
- Security group world-open ingress flags a possible network exposure; actual route tables, NACLs, instance listeners and reachability are not evaluated.
- CloudTrail `enabled=true` in the fixture is not proof log ingestion, event coverage, retention or integrity.
- Risk levels are **training priorities**, not validated business risk scores, external severity standards or a certification score.

## Terraform plan scanner and SARIF workflow (offline only)

The new `plan` command accepts marked **synthetic Terraform-JSON-shaped plan examples**, not arbitrary live plan exports. It reads a subset of `planned_values` and `resource_changes` with `after_unknown`, supports nested modules, treats unresolved configuration as **manual review**, and never interprets runtime effective access. Fixture JSON was hand-authored to resemble `terraform show -json` structure; it has **not been generated or applied with Terraform**.

```bash
python -m cloudguard plan terraform/vulnerable.plan.json --format markdown
python -m cloudguard plan terraform/vulnerable.plan.json --format sarif --output /tmp/findings.sarif
python -m cloudguard plan terraform/hardened.plan.json --fail-on High
python -m cloudguard plan terraform/hardened.plan.json --fail-on-review  # intentionally exits 4
python scripts_validate_cloud_portfolio.py
python scripts_validate_integrity.py
```

CI publishes a synthetic SARIF artifact for inspection but makes **no claim of real code-scanning alerts**. Exceptions are proposal-only and never hide findings. All actions are explicitly unapproved and no cloud remediation was executed.

## Read the case study

1. [Scope and threat model](docs/01-scope-and-threat-model.md)
2. [Detection rules and methodology](docs/02-rules-and-method.md)
3. [Remediation and verification plan](docs/03-treatment-and-verification.md)
4. [Executive report](docs/04-executive-report.md)
5. [Official AWS references and important limitations](docs/05-official-sources.md)
6. [Historical original development roadmap](docs/06-roadmap.md)
7. [Phase 2 — Terraform plan JSON pattern checks](phase2/README.md)
8. [Phase 3 — SARIF, mitigation verification and exception review](phase3/README.md)
9. [Phase 4 — Integrated dashboard and quality report](phase4/README.md)

**Privacy and publication:** Keep this repository **private** until its owner explicitly decides to publish it. Every identity, bucket and security group is invented; no actual tokens or credentials are required. A passing test or zero finding count **does not establish security of an actual AWS account**.
