variable "environment" {
  description = "Type of environment -- must be one of: dev, test, prod"
  type        = string
  default     = "test"
}

variable "key_pair_name" {
  description = "Keypair to associate to launched instances"
  type        = string
}

variable "ami_owners" {
  description = "Account id/alias of the AMI owner"
  type        = list(string)
}

variable "ec2_subnet_ids" {
  description = "List of subnets where EC2 instances will be launched"
  type        = list(string)
}

variable "lb_subnet_ids" {
  description = "List of subnets to associate to the Load Balancer"
  type        = list(string)
}

variable "domain_name" {
  type        = string
  description = "Domain to provision test vault cluster"
}

variable "route53_zone_id" {
  type        = string
  description = "Hosted zone ID Route 53 hosted zone"
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

variable "toggle_update" {
  type        = string
  default     = "A"
  description = "(Optional) Toggle that triggers a stack update by modifying the launch config, resulting in new instances; must be one of: A or B"
}

variable "vault_version" {
  description = "Version of Vault to be installed on servers"
  type        = string
}

variable "vault_pillar_path" {
  type        = string
  description = "Specify the path to vault pillar"
}

variable "dynamodb_table" {
  description = "Name of the Dynamodb to be used as storage backend for Vault"
  type        = string
  default     = null
}

variable "certificate_arn" {
  type        = string
  description = "The ARN of the default SSL server certificate to be use for HTTPS lb listener."
  default     = null
}

variable "ec2_extra_security_group_ids" {
  type        = list(string)
  description = "List of additional security groups to add to EC2 instances"
  default     = []
}

variable "vault_pillar_extra_config" {
  description = "(Optional) List extra configurations to be referenced in the pillar"
  default     = []
}

variable "scale_down_schedule" {
  type        = string
  description = "(Optional) Scheduled Action in cron-format (UTC) to scale down to MinCapacity; ignored if empty or ScaleUpSchedule is unset (E.g. \"0 0 * * *\")"
  default     = null
}

variable "scale_up_schedule" {
  type        = string
  description = "(Optional) Scheduled Action in cron-format (UTC) to scale up to MaxCapacity; ignored if empty or ScaleDownSchedule is unset (E.g. \"0 10 * * Mon-Fri\")"
  default     = null
}
