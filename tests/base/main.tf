locals {
  test_prefix   = "tf-vault-${random_string.this.result}"
  key_pair_name = "${var.key_pair_name == "" ? aws_key_pair.this.0.id : var.key_pair_name}"
  kms_key_id    = "${var.kms_key_id == "" ? aws_kms_key.this.0.id : var.kms_key_id}"
}

resource "random_string" "this" {
  length  = 6
  upper   = false
  special = false
}
resource "tls_private_key" "this" {
  count     = "${var.key_pair_name == "" ? 1 : 0}"
  algorithm = "RSA"
  rsa_bits  = "4096"
}

resource "aws_key_pair" "this" {
  count      = "${var.key_pair_name == "" ? 1 : 0}"
  key_name   = "${local.test_prefix}-rsa"
  public_key = "${tls_private_key.this.0.public_key_openssh}"
}
resource "aws_kms_alias" "this" {
  count         = "${var.key_pair_name == "" ? 1 : 0}"
  name          = "alias/${local.test_prefix}"
  target_key_id = "${aws_kms_key.this.0.key_id}"
}
resource "aws_kms_key" "this" {
  count                   = "${var.kms_key_id == "" ? 1 : 0}"
  description             = "KSM Key for vault tests"
  deletion_window_in_days = 10
  tags = {
    Environment = "${var.environment}"
    Name        = "${local.test_prefix}"
  }
}

module "vault-py3" {
  source           = "../../"
  environment      = "${var.environment}"
  desired_capacity = 1
  ami_owner        = "${var.ami_owner}"

  name           = "${local.test_prefix}-py3"
  key_pair_name  = "${local.key_pair_name}"
  kms_key_id     = "${local.kms_key_id}"
  ec2_subnet_ids = "${var.ec2_subnet_ids}"
  lb_subnet_ids  = "${var.lb_subnet_ids}"

  cloudwatch_agent_url = "${var.cloudwatch_agent_url}"

  domain_name    = "${var.domain_name}"
  vault_version  = "${var.vault_version}"
  dynamodb_table = "${var.dynamodb_table}"

  watchmaker_config = "${var.watchmaker_config}"

  toggle_update = "B"
}


data "aws_route53_zone" "this" {
  name         = "${var.domain_name}"
  private_zone = false
}

data "aws_acm_certificate" "this" {
  domain      = "*.${var.domain_name}"
  types       = ["AMAZON_ISSUED"]
  most_recent = true
}
