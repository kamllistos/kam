# Try kam in 5 minutes

This example shows what `kam diff` catches, using a real Terraform plan against your own AWS account.
**Nothing risky is ever deployed.** You create a few harmless IAM resources, then *plan* (not apply)
a set of dangerous changes and let kam explain them.

Use a **test or sandbox AWS account**, not production.

## What you need

- [Terraform](https://developer.hashicorp.com/terraform/install) 1.5 or newer
- AWS credentials for a test account (`aws sso login --profile <name>` or access keys)
- kam: `brew install kamllistos/tap/kam` or `go install github.com/kamllistos/kam@latest`

## Steps

```sh
cd examples/smoke
export AWS_PROFILE=<your-test-profile>
terraform init
```

**1. Create the safe starting point.** This adds 2 roles and policies, 1 user with no password or
keys, and 2 groups. All names start with `kam-smoke-`.

```sh
terraform apply -var stage=baseline
```

**2. Plan the risky changes. Do not apply them.**

```sh
terraform plan -var stage=risky -out tfplan
```

**3. Ask kam what that plan would do.**

```sh
kam diff tfplan --account "$(terraform output -raw account_id)"
```

**4. Clean up.**

```sh
terraform destroy -var stage=baseline
```

## What kam should tell you

The risky plan hides three real-world mistakes. Each looks small in a code review:

| What changed in the code | What kam reports |
|---|---|
| The CI role's trust policy switches to GitHub Actions but leaves out the `sub` condition | **Critical:** any GitHub repository can assume `role/kam-smoke-ci-deploy` |
| The CI policy gains `iam:PassRole` and `lambda:CreateFunction` on `*` | **Critical:** the role can create a Lambda that runs as any other role, including admin |
| `kam-smoke-alice` is added to one more group | **Critical:** alice becomes a full administrator through `group/kam-smoke-admins` |
| A new vendor role trusts account `444455556666` and reads secrets | **High:** an external account can assume it. **High:** it can read every secret in the account |

`terraform plan` shows all of these as ordinary in-place updates. kam shows who gains which access.

## More to try

```sh
kam diff tfplan -f markdown > report.md      # the comment kam would post on a pull request
kam diff tfplan --fail-on critical; echo $?  # prints 1: this is how kam fails a CI check
kam diff tfplan -f json | jq .max_severity   # machine-readable output
```

## Good to know

- kam only reads the plan file. It never calls AWS.
- Baseline creates an **empty** group with `AdministratorAccess` attached. Security tools in your
  account (GuardDuty, Security Hub, Config) may flag it until you run the destroy step.
- The GitHub OIDC provider and account `444455556666` are only referenced in the risky plan, which you
  never apply, so neither needs to exist.
