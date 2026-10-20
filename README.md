<p align="center">
  <img src="docs/kam.png" alt="kam mascot" width="180">
</p>

<h1 align="center">kam</h1>

<p align="center"><b>Know what your Terraform plan grants before you apply it.</b></p>

`kam diff` reads a Terraform plan and works out how every IAM role, user and group's
**effective access** changes, then flags the changes that matter: privilege escalation
paths, admin grants, roles that anyone on GitHub can assume, account-wide secret reads.

Linters like Checkov and tfsec check a resource against fixed rules ("this policy uses `*`").
kam answers a different question: **who can now do what, and how did they get it?** It
follows attachments, group memberships and trust policies across the whole plan, so a
one-line change to a group membership shows up as "alice is now an administrator".

```text
$ kam diff plan.json
kam diff · terraform 1.9.8 · 13 IAM resources in plan

4 principals with access changes: 2 critical · 1 high · 1 info

CRITICAL  role/ci-deploy (aws_iam_role.ci)  changed
    ▲ critical Any GitHub repository can assume this role
      The GitHub Actions OIDC trust has no token.actions.githubusercontent.com:sub condition, ...
    ▲ critical Privilege escalation: iam:PassRole plus lambda:CreateFunction
      Can start compute with any role it can pass and run code with that role's permissions, ...
    new permissions
      policy/ci-deploy (aws_iam_policy.ci), attached by aws_iam_role_policy_attachment.ci
        + iam:PassRole           on *    [high]
        + lambda:CreateFunction  on *    [low]

CRITICAL  user/alice (aws_iam_user.alice)  changed
    ▲ critical Full administrator access
    new permissions
      via group/admins: AWS managed AdministratorAccess, attached by aws_iam_group_policy_attachment.admins
        + *  on *    [critical]
```

## Install

**Homebrew** (macOS, Linux and WSL):

```sh
brew install kamllistos/tap/kam
```

**WSL / Linux without Homebrew:**

```sh
curl -fsSL https://github.com/kamllistos/kam/releases/latest/download/kam_linux_amd64.tar.gz | tar -xz kam
sudo mv kam /usr/local/bin/
```

**Go:**

```sh
go install github.com/kamllistos/kam@latest
```

kam is a single static binary with no dependencies. It never calls AWS: it only reads the plan.

## Use

```sh
terraform plan -out tfplan
terraform show -json tfplan > plan.json
kam diff plan.json
```

kam also accepts the binary `tfplan` directly (it runs `terraform show -json` for you) or JSON on stdin:

```sh
terraform show -json tfplan | kam diff
```

| Flag | Default | What it does |
|---|---|---|
| `-f, --format` | `text` | `text`, `markdown` (PR comments) or `json` |
| `--fail-on` | `none` | Exit 1 when any principal reaches `low`, `medium`, `high` or `critical` |
| `--account` | | Your AWS account IDs, comma-separated. Trust from other accounts is flagged as external |
| `--min-severity` | `info` | Hide principals below this severity |
| `--show-removed` | off | Also list access the plan takes away |
| `--no-color` | off | Plain output (also honours `NO_COLOR`) |

Exit codes: `0` ok, `1` the `--fail-on` threshold was reached, `2` usage or input error.

## In pull requests

```yaml
# .github/workflows/iam-review.yml
on: pull_request
permissions:
  contents: read
  pull-requests: write
  id-token: write
jobs:
  kam:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      # ... configure AWS credentials ...
      - run: terraform init && terraform plan -out tfplan && terraform show -json tfplan > plan.json
      - id: kam
        uses: kamllistos/kam@v0
        with:
          plan: plan.json
          accounts: "111122223333"
          fail-on: critical
      - if: always()
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          header: kam
          path: ${{ steps.kam.outputs.report }}
```

The markdown report starts with `<!-- kam-diff -->` so bots can update one comment instead of piling up new ones.

## What kam checks

| Rule | Severity | Triggers on |
|---|---|---|
| `admin` | critical | `*` on `*` |
| `notaction-admin` | critical | `Allow` + `NotAction` that does not exclude IAM |
| `privesc` | critical / high | Actions that rewrite IAM: `iam:PutRolePolicy`, `iam:AttachUserPolicy`, `iam:CreatePolicyVersion`, `iam:CreateAccessKey`, `iam:UpdateAssumeRolePolicy`, ... |
| `passrole-compute` | critical | `iam:PassRole` on a wildcard **plus** something that launches compute with it (Lambda, EC2, ECS, Glue, CloudFormation, ...) |
| `github-oidc-unscoped` | critical | GitHub Actions OIDC trust without a `sub` condition, or with `repo:*` |
| `public-trust` | critical / high | Trust policy with `Principal: "*"` |
| `external-trust` | high | Trust from an account not passed to `--account` |
| `data-read-broad` | high | `secretsmanager:GetSecretValue`, `ssm:GetParameter*`, `kms:Decrypt`, `s3:GetObject` on a wildcard |
| `defense-evasion` | high | Stopping CloudTrail, GuardDuty, Config, Security Hub; deleting log groups |
| `code-exec` | high / medium | `lambda:UpdateFunctionCode`, `ssm:SendCommand`, `ecs:ExecuteCommand`, ... |
| `destructive-broad` | high | Deleting buckets, databases, snapshots, KMS keys on a wildcard |
| `wildcard-broad` | medium | Any other wildcard action on all resources |
| `opaque-policy` | medium / low | An attached policy kam cannot see into |

### How it works

1. Rebuild every principal's grants **before** and **after** the plan from `aws_iam_role`, `aws_iam_policy`,
   inline and attached policies, `aws_iam_policy_attachment` and group memberships. Values only known after
   apply (`role = aws_iam_role.app.id`) are resolved through the plan's configuration references.
2. Expand statements into (action, resource) pairs, drop pairs cancelled by an unconditional `Deny`, and keep
   the pairs the old access did not already cover, with IAM wildcard semantics (`s3:*` covers `s3:Get*`).
3. Score each new pair and each new trust relationship, and look for dangerous combinations across the
   principal's full access.

### Limits (proof of concept)

- AWS only. Azure RBAC and GCP IAM are on the roadmap.
- Static: kam does not evaluate SCPs, permission boundaries, session policies or resource-based policies
  (bucket, key and queue policies).
- AWS managed policies are resolved from a small built-in catalog (`AdministratorAccess`, `PowerUserAccess`,
  `IAMFullAccess`, `AmazonS3FullAccess`, `AmazonS3ReadOnlyAccess`). Others are reported as "contents not visible".
- Policies and principals defined outside the plan (existing ARNs) are identified by name only.

## Development

```sh
go test ./...
go run . diff testdata/plan.json
```

Releases are cut by pushing a `v*` tag; GoReleaser builds the binaries and updates the
[Homebrew tap](https://github.com/kamllistos/homebrew-tap).

## License

MIT
