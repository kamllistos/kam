# kam smoke test

A two-stage Terraform config for a **throwaway test AWS account**. Stage `baseline` creates a few
harmless IAM resources. Stage `risky` is only ever *planned*: kam explains what it would grant.

```sh
export AWS_PROFILE=your-test-profile        # aws sso login --profile your-test-profile first
terraform init
terraform apply -var stage=baseline         # creates 2 roles/policies, 1 user, 2 groups
terraform plan  -var stage=risky -out tfplan
kam diff tfplan --account "$(terraform output -raw account_id)"
kam diff tfplan -f markdown > report.md     # what a PR comment would look like
terraform destroy -var stage=baseline       # clean up
```

kam should report:

| Principal | Expected |
|---|---|
| `role/kam-smoke-ci-deploy` | critical: any GitHub repository can assume it; critical: iam:PassRole plus lambda:CreateFunction |
| `user/kam-smoke-alice` | critical: full administrator access via `group/kam-smoke-admins` |
| `role/kam-smoke-vendor-reader` | high: external account 444455556666 can assume it; high: reads every secret |

What baseline creates: an IAM user with no credentials, an empty group with `AdministratorAccess`
attached, a group with `AmazonS3ReadOnlyAccess`, and a role only Lambda can assume. Security tooling
in your test account (GuardDuty, Security Hub, Config) may still flag the admin group.
