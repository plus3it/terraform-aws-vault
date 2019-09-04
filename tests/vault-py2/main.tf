terraform {
  required_version = ">= 0.12"
}

resource "random_id" "name" {
  byte_length = 6
  prefix      = "tf-vault-"
}

module "base" {
  source = "../../"

  environment      = var.environment
  desired_capacity = 1
  ami_owner        = var.ami_owner

  name           = "${random_id.name.hex}-py2"
  key_pair_name  = var.key_pair_name
  kms_key_id     = var.kms_key_id
  ec2_subnet_ids = var.ec2_subnet_ids
  lb_subnet_ids  = var.lb_subnet_ids

  cloudwatch_agent_url = var.cloudwatch_agent_url

  domain_name     = var.domain_name
  route53_zone_id = var.route53_zone_id

  # Vault settings
  vault_version      = var.vault_version
  vault_configs_path = "${path.module}/.configs"
  dynamodb_table     = var.dynamodb_table

  # Watchmaker settings
  watchmaker_config = var.watchmaker_config

  toggle_update = "B"
}

output "cluster_url" {
  value = module.base.vault_url
}
