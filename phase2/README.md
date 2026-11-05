# Phase 2 — Terraform Plan JSON Configuration Review

**Fictional AWS cloud accounts, hand-authored JSON-shaped Terraform plans and no real cloud access.**

This phase adds a separate scanner for a deliberately supported subset of the structured JSON representation emitted by `terraform show -json`. It does **not parse HCL** or claim that these example files were created by a Terraform run. The fixtures include a `lab_metadata.synthetic=true` marker and are **not** actual Terraform-exported plans. Real credentials, real plan files and state are outside this project.

## What is assessed

| Rule | Resource class | Pattern detected | Important uncertainty |
|---|---|---|---|
| TF-IAM-001 | `aws_iam_role` | Wildcard trust `Principal=*` with no condition | Actual STS assume-role permission/context unknown |
| TF-IAM-002 | IAM policy / inline role policy | `Allow Action=* Resource=*` | Explicit denies, SCPs, RCPs, permission boundary and sessions may restrict |
| TF-IAM-003 | IAM policy / inline role policy | `Allow service:* Resource=*` | Effective permissions not evaluated |
| TF-S3-001 | Bucket plus Public Access Block | At least one explicitly disabled block flag | Account-level BPA and effective public access unknown |
| TF-NET-001 | Security group or ingress rule | World-open admin port | Routing, listeners and NACLs untested |
| TF-NET-002 | Security group or ingress rule | World-open database port | Actual reachability untested |
| TF-MON-001 | CloudTrail trail | Multi-region setting false | Organization-wide logging not resolved |
| TF-MON-002 | CloudTrail trail | Log-file validation false | Delivered data, retention, log integrity untested |
| TF-MON-003 | Config recorder | `all_supported=false` | Resource-type-specific selection may be appropriate |

The scanner produces **10 pattern findings** on the vulnerable plan (1 Critical, 6 High, 3 Medium) and **0** under its defined checks on the hardened example. Both models retain **3 manual-review items**: conditional wildcard role trust, an unconditional global-Deny policy context, and an unresolved future role policy. The hardened snapshot is **not** an AWS security or ISO compliance verdict.

## Data flow

`terraform/vulnerable.plan.json` / `terraform/hardened.plan.json` → `cloudguard/terraform_plan.py` → `cloudguard/cli.py` → human JSON/Markdown, SARIF 2.1.0 and a [per-finding remediation crosswalk](data/terraform_findings.csv).

The `resource_changes[].change.after_unknown` values are treated conservatively: resource-level unknowns become **manual-review notes**, not a clean pass. Deleted-only resources are skipped. Supported nested modules are traversed; omitted unrelated resources and account-wide settings cannot be inferred.

Run:

```sh
python -m cloudguard plan terraform/vulnerable.plan.json --format markdown
python -m cloudguard plan terraform/vulnerable.plan.json --format json --fail-on High
python -m cloudguard plan terraform/hardened.plan.json --format sarif --output /tmp/hardened.sarif
python -m cloudguard plan terraform/hardened.plan.json --fail-on-review
```

Expected return codes: `0` no selected finding threshold met; `2` selected threshold met; `3` input error; `4` manual review required with `--fail-on-review`. The vulnerable example intentionally exits `2`, while the hardened example intentionally exits `4` with `--fail-on-review`.

> **Caution:** Terraform JSON plan files can contain sensitive values in clear text and are not inherently safe to commit or share. This project accepts only marked synthetic lab fixtures, but do not publish or upload real plan/state files. Never run `terraform apply` on these examples; no infrastructure is provisioned.

Official references: [Terraform JSON output format](https://developer.hashicorp.com/terraform/internals/json-format) and [AWS IAM policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html). These lab detectors cover only a small subset of their semantics.
