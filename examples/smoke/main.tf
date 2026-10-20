# kam smoke test: a two-stage config for a throwaway AWS account.
#
#   1. terraform apply -var stage=baseline     creates harmless IAM resources
#   2. terraform plan  -var stage=risky -out tfplan
#      kam diff tfplan                          explains what stage 2 WOULD grant
#   3. terraform destroy -var stage=baseline
#
# Never apply stage=risky: it is meant to be planned, not deployed.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "stage" {
  description = "baseline (apply this) or risky (only plan this)"
  type        = string
  default     = "baseline"
  validation {
    condition     = contains(["baseline", "risky"], var.stage)
    error_message = "stage must be baseline or risky."
  }
}

variable "prefix" {
  type    = string
  default = "kam-smoke"
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { purpose = "kam-smoke-test" }
  }
}

data "aws_caller_identity" "current" {}

locals {
  risky   = var.stage == "risky"
  account = data.aws_caller_identity.current.account_id
}

# --- Scenario 1: a CI role whose trust and permissions get loosened ----------

data "aws_iam_policy_document" "ci_trust" {
  # baseline: only Lambda can assume the role
  dynamic "statement" {
    for_each = local.risky ? [] : [1]
    content {
      actions = ["sts:AssumeRole"]
      principals {
        type        = "Service"
        identifiers = ["lambda.amazonaws.com"]
      }
    }
  }
  # risky: GitHub Actions OIDC with no :sub condition, so any repository on GitHub can assume it
  dynamic "statement" {
    for_each = local.risky ? [1] : []
    content {
      actions = ["sts:AssumeRoleWithWebIdentity"]
      principals {
        type        = "Federated"
        identifiers = ["arn:aws:iam::${local.account}:oidc-provider/token.actions.githubusercontent.com"]
      }
      condition {
        test     = "StringEquals"
        variable = "token.actions.githubusercontent.com:aud"
        values   = ["sts.amazonaws.com"]
      }
    }
  }
}

resource "aws_iam_role" "ci" {
  name               = "${var.prefix}-ci-deploy"
  assume_role_policy = data.aws_iam_policy_document.ci_trust.json
}

data "aws_iam_policy_document" "ci" {
  statement {
    sid       = "ReadArtifacts"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::${var.prefix}-artifacts-${local.account}/*"]
  }
  # risky: PassRole on * plus lambda:CreateFunction is a privilege-escalation path
  dynamic "statement" {
    for_each = local.risky ? [1] : []
    content {
      sid       = "DeployLambdas"
      actions   = ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]
      resources = ["*"]
    }
  }
}

resource "aws_iam_policy" "ci" {
  name   = "${var.prefix}-ci-deploy"
  policy = data.aws_iam_policy_document.ci.json
}

resource "aws_iam_role_policy_attachment" "ci" {
  role       = aws_iam_role.ci.name
  policy_arn = aws_iam_policy.ci.arn
}

# --- Scenario 2: a one-line group membership change that makes a user admin --

resource "aws_iam_user" "alice" {
  name = "${var.prefix}-alice" # no access keys or password: it cannot sign in
}

resource "aws_iam_group" "readers" {
  name = "${var.prefix}-readers"
}

resource "aws_iam_group_policy_attachment" "readers" {
  group      = aws_iam_group.readers.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

resource "aws_iam_group" "admins" {
  name = "${var.prefix}-admins" # empty in baseline; only the risky plan adds a member
}

resource "aws_iam_group_policy_attachment" "admins" {
  group      = aws_iam_group.admins.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user_group_membership" "alice" {
  user   = aws_iam_user.alice.name
  groups = local.risky ? [aws_iam_group.readers.name, aws_iam_group.admins.name] : [aws_iam_group.readers.name]
}

# --- Scenario 3: a brand-new role trusted by an outside account --------------

resource "aws_iam_role" "vendor" {
  count = local.risky ? 1 : 0
  name  = "${var.prefix}-vendor-reader"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "arn:aws:iam::444455556666:root" } # example vendor account
    }]
  })
}

resource "aws_iam_role_policy" "vendor" {
  count = local.risky ? 1 : 0
  name  = "read-everything"
  role  = aws_iam_role.vendor[0].id # unknown until apply: kam resolves it through the reference
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue", "ssm:GetParameter"]
      Resource = "*"
    }]
  })
}

output "account_id" {
  value = local.account
}
