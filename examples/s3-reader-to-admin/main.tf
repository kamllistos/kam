# kam example: a user who can only read S3 is quietly made a superadmin.
#
#   terraform apply -var access=s3-read          # bob can read S3, nothing else
#   terraform plan  -var access=admin -out tfplan
#   kam diff tfplan                              # explains what the plan grants
#   terraform destroy -var access=s3-read
#
# In terraform plan the change is a single policy ARN being replaced.
# kam shows what it means: bob goes from S3 reader to full administrator.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "access" {
  description = "s3-read (apply this) or admin (only plan this)"
  type        = string
  default     = "s3-read"
  validation {
    condition     = contains(["s3-read", "admin"], var.access)
    error_message = "access must be s3-read or admin."
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { purpose = "kam-example" }
  }
}

locals {
  policies = {
    "s3-read" = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
    "admin"   = "arn:aws:iam::aws:policy/AdministratorAccess"
  }
}

# No password or access keys, so the user cannot actually sign in.
resource "aws_iam_user" "bob" {
  name = "kam-example-bob"
}

resource "aws_iam_user_policy_attachment" "bob" {
  user       = aws_iam_user.bob.name
  policy_arn = local.policies[var.access]
}
