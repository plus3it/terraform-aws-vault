variable "environment" {
  description = "Type of environment -- must be one of: dev, test, prod"
  type        = string
  default     = "test"
}

variable "key_pair_name" {
  description = "Keypair to associate to launched instances"
  type        = string
}

variable "ami_owner" {
  description = "Account id/alias of the AMI owner"
  type        = string
}

variable "ec2_subnet_ids" {
  description = "List of subnets where EC2 instances will be launched"
  type        = list(string)
}

variable "lb_subnet_ids" {
  description = "List of subnets to associate to the Load Balancer"
  type        = list(string)
}

variable "vault_version" {
  description = "Version of Vault to be installed on servers"
  type        = string
}

variable "kms_key_id" {
  description = "Id of an AWS KMS key use for auto unseal operation when vault is intialize"
  type        = string
  default     = ""
}

variable "domain_name" {
  type        = string
  description = "Domain to provision test vault cluster"
}

variable "route53_zone_id" {
  type        = string
  description = "Hosted zone ID Route 53 hosted zone"
}

variable "dynamodb_table" {
  description = "Name of the Dynamodb to be used as storage backend for Vault"
  type        = string
  default     = ""
}

variable "cloudwatch_agent_url" {
  type        = string
  description = "(Optional) S3 URL to CloudWatch Agent installer. Example: s3://amazoncloudwatch-agent/linux/amd64/latest/AmazonCloudWatchAgent.zip"
  default     = ""
}

variable "watchmaker_config" {
  type        = string
  description = "(Optional) URL to a Watchmaker config file"
  default     = ""
}

