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
