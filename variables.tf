###
### REQUIRED VARIABLES
###
variable "name" {
  description = "Name of the vault stack, will be use to prefix resources"
  type        = "string"
}

variable "environment" {
  description = "Type of environment -- must be one of: dev, test, prod"
  type        = "string"
}

variable "bucket_name" {
  description = "The name of the bucket will be use to store app scripts and vault's salt formula."
  type        = "string"
}

variable "key_pair_name" {
  description = "Keypair to associate to launched instances"
  type        = "string"
}

variable "ami_owner" {
  description = "Account id/alias of the AMI owner"
  type        = "string"
}

variable "additional_ips_allow_inbound" {
  description = "List of ip address that allow to have access to resources"
  type        = "list"
}

variable "ec2_extra_security_group_ids" {
  description = "List of additional security groups to add to EC2 instances"
  type        = "list"
}

variable "ec2_subnet_ids" {
  description = "List of subnets where EC2 instances will be launched"
  type        = "list"
}

variable "lb_certificate_arn" {
  type        = "string"
  description = "Arn of a created certificate to be use for the load balancer"
}

variable "lb_subnet_ids" {
  description = "List of subnets to associate to the Load Balancer"
  type        = "list"
}

variable "vault_version" {
  description = "Version of Vault to be installed on servers"
  type        = "string"
}

variable "vault_url" {
  type        = "string"
  description = "The DNS address that vault will be accessible at. Example: vault.domain.net"
}

variable "kms_key_id" {
  description = "Id of an AWS KMS key use for auto unseal operation when vault is intialize"
  type        = "string"
}

variable "dynamodb_table" {
  description = "Name of the Dynamodb to be used as storage backend for Vault"
  type        = "string"
}

variable "route53_zone_id" {
  type        = "string"
  description = "Zone ID for domain"
}

###
### OPTIONAL VARIABLES
###
variable "ami_name_filter" {
  description = "Will be use to filter out AMI"
  type        = "string"
  default     = "spel-minimal-centos-7-hvm-*.x86_64-gp2"
}

variable "ami_name_regex" {
  description = "Regex to help fine-grain filtering AMI"
  type        = "string"
  default     = "spel-minimal-centos-7-hvm-\\d{4}\\.\\d{2}\\.\\d{1}\\.x86_64-gp2"
}

variable "instance_type" {
  default     = "t2.medium"
  description = "Amazon EC2 instance type"
  type        = "string"
}

variable "lb_internal" {
  description = "Boolean indicating whether the load balancer is internal or external"
  type        = "string"
  default     = false
}

variable "ingress_cidr_blocks" {
  description = "(Optional) List of CIDR block."
  type        = "list"
  default     = ["0.0.0.0/0"]
}

variable "lb_ssl_policy" {
  description = "The name of the SSL Policy for the listener"
  type        = "string"
  default     = "ELBSecurityPolicy-FS-2018-06"
}

variable "min_capacity" {
  type        = "string"
  description = "(Optional) Minimum number of instances in the Autoscaling Group"
  default     = "1"
}

variable "max_capacity" {
  type        = "string"
  description = "(Optional) Maximum number of instances in the Autoscaling Group"
  default     = "2"
}

variable "desired_capacity" {
  type        = "string"
  description = "(Optional) Desired number of instances in the Autoscaling Group"
  default     = "2"
}

variable "pypi_index_url" {
  type        = "string"
  description = "(Optional) URL to the PyPi Index"
  default     = "https://pypi.org/simple"
}

variable "cfn_endpoint_url" {
  type        = "string"
  description = "(Optional) URL to the CloudFormation Endpoint. e.g. https://cloudformation.us-east-1.amazonaws.com"
  default     = "https://cloudformation.us-east-1.amazonaws.com"
}

variable "cfn_bootstrap_utils_url" {
  type        = "string"
  description = "(Optional) URL to aws-cfn-bootstrap-latest.tar.gz"
  default     = "https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.tar.gz"
}

variable "cloudwatch_agent_url" {
  type        = "string"
  description = "(Optional) S3 URL to CloudWatch Agent installer. Example: s3://amazoncloudwatch-agent/linux/amd64/latest/AmazonCloudWatchAgent.zip"
  default     = ""
}

variable "watchmaker_config" {
  type        = "string"
  description = "(Optional) URL to a Watchmaker config file"
  default     = ""
}

variable "watchmaker_ou_path" {
  type        = "string"
  description = "(Optional) DN of the OU to place the instance when joining a domain. If blank and WatchmakerEnvironment enforces a domain join, the instance will be placed in a default container. Leave blank if not joining a domain, or if WatchmakerEnvironment is false"
  default     = ""
}

variable "watchmaker_admin_groups" {
  type        = "string"
  description = "(Optional) Colon-separated list of domain groups that should have admin permissions on the EC2 instance"
  default     = ""
}

variable "watchmaker_admin_users" {
  type        = "string"
  description = "(Optional) Colon-separated list of domain users that should have admin permissions on the EC2 instance"
  default     = ""
}

variable "toggle_update" {
  default     = "A"
  description = "(Optional) Toggle that triggers a stack update by modifying the launch config, resulting in new instances; must be one of: A or B"
  type        = "string"
}

variable "route53_enabled" {
  description = "Creates Route53 DNS entries for Vault automatically"
  default     = false
}

variable "tags" {
  description = "(Optional) list of tags to include with resource"
  type        = "map"
  default     = {}
}

variable "ip_data_url" {
  description = "URL to get ip address of the current user"
  type        = "string"
  default     = "http://ipv4.icanhazip.com"
}
