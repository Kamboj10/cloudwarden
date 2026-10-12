# SANDBOX ONLY. Creates deliberately weak resources so CloudWarden has something to find.
# Use a throwaway AWS account with a billing alert. Run `terraform destroy` when done.
# Not validated in the authoring environment: run `terraform init && terraform validate` first.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "region" {
  default = "ap-south-1"
}

variable "bucket_name" {
  description = "Globally unique bucket name, for example cloudwarden-lab-<yourname>-123"
  type        = string
}

provider "aws" {
  region = var.region
}

# 1. Security group open to the world on SSH (not attached to any instance)
resource "aws_security_group" "weak_ssh" {
  name        = "cloudwarden-lab-weak-ssh"
  description = "CloudWarden lab: SSH open to the internet"

  ingress {
    description = "SSH from anywhere (intentionally weak)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 2. Unencrypted 1 GiB volume (unattached)
resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "${var.region}a"
  size              = 1
  encrypted         = false

  tags = { Name = "cloudwarden-lab-unencrypted" }
}

# 3. Bucket with the public access block switched off.
#    The bucket stays private (no public policy or ACL); it only lacks the safety net.
resource "aws_s3_bucket" "no_block" {
  bucket = var.bucket_name
}

resource "aws_s3_bucket_public_access_block" "no_block" {
  bucket                  = aws_s3_bucket.no_block.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
