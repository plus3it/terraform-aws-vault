# ---------------------------------------------------------------------------------------------------------------------
# REQUIRED PARAMETERS
# You must provide a value for each of these parameters.
# ---------------------------------------------------------------------------------------------------------------------

variable "name" {
  type        = string
  description = "Name of the vault stack, will be use to prefix resources"
}

variable "environment" {
  type        = string
  description = "Type of environment -- must be one of: dev, test, prod"
}

variable "key_pair_name" {
  type        = string
  description = "Keypair to associate to launched instances"
}

variable "ami_owners" {
  type        = list(string)
  description = "Account id/alias of the AMI owners"
}

variable "ec2_extra_security_group_ids" {
  type        = list(string)
  description = "List of additional security groups to add to EC2 instances"
  default     = []
}

variable "ec2_subnet_ids" {
  type        = list(string)
  description = "List of subnets where EC2 instances will be launched"
}

variable "lb_subnet_ids" {
  type        = list(string)
  description = "List of subnets to associate to the Load Balancer"
}

variable "vault_version" {
  type        = string
  description = "Version of Vault to be installed on servers"
}

variable "vault_pillar_path" {
  type        = string
  description = "Specify the path to vault pillar"
}

variable "vault_url" {
  type        = string
  description = "The DNS address that vault will be accessible at. Stack name will be used as the url when value is set to empty. Example: vault.domain.net"
  default     = null
}

variable "domain_name" {
  type        = string
  description = "The domain name where vault url will be registered to. Example: domain.net"
}

variable "route53_zone_id" {
  type        = string
  description = "Hosted zone ID Route 53 hosted zone"
}

# ---------------------------------------------------------------------------------------------------------------------
# OPTIONAL PARAMETERS
# These parameters have reasonable defaults.
# ---------------------------------------------------------------------------------------------------------------------
variable "kms_key_id" {
  type        = string
  description = "Id of an AWS KMS key use for auto unseal operation when vault is intialize"
  default     = null
}

variable "dynamodb_table" {
  type        = string
  description = "Name of the Dynamodb to be used as storage backend for Vault"
  default     = null
}

variable "ami_name_filters" {
  type        = list(string)
  description = "Will be use to filter out AMI"
  default     = ["spel-minimal-centos-7-hvm-*.x86_64-gp2"]
}

variable "ami_name_regex" {
  type        = string
  description = "Regex to help fine-grain filtering AMI"
  default     = "spel-minimal-centos-7-hvm-\\d{4}\\.\\d{2}\\.\\d{1}\\.x86_64-gp2"
}

variable "instance_type" {
  type        = string
  description = "Amazon EC2 instance type"
  default     = "t2.medium"
}

variable "lb_internal" {
  type        = bool
  description = "Boolean indicating whether the load balancer is internal or external"
  default     = true
}

variable "certificate_arn" {
  type        = string
  description = "The ARN of the default SSL server certificate to be use for HTTPS lb listener."
  default     = null
}

variable "inbound_cidrs" {
  type        = list(string)
  description = "(Optional) IP address or range of addresses to be allowed to Firewall Zone."
  default     = []
}

variable "ingress_cidr_blocks" {
  type        = list(string)
  description = "(Optional) List of CIDR block."
  default     = ["0.0.0.0/0"]
}

variable "lb_ssl_policy" {
  type        = string
  description = "The name of the SSL Policy for the listener"
  default     = "ELBSecurityPolicy-FS-2018-06"
}

variable "api_port" {
  description = "The port to use for Vault API calls"
  default     = 8200
}

variable "cluster_port" {
  description = "The port to use for Vault server-to-server communication."
  default     = 8201
}

variable "min_capacity" {
  type        = string
  description = "(Optional) Minimum number of instances in the Autoscaling Group"
  default     = "1"
}

variable "max_capacity" {
  type        = string
  description = "(Optional) Maximum number of instances in the Autoscaling Group"
  default     = "2"
}

variable "desired_capacity" {
  type        = string
  description = "(Optional) Desired number of instances in the Autoscaling Group"
  default     = "2"
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

variable "dynamodb_max_read_capacity" {
  type        = number
  description = "(Optional) The max capacity of the scalable target for DynamoDb table autoscaling."
  default     = 100
}

variable "dynamodb_min_read_capacity" {
  type        = number
  description = "(Optional) The min capacity of the scalable target for DynamoDb table autoscaling."
  default     = 5
}

variable "dynamodb_target_value" {
  type        = number
  description = "(Optional) The target value for the metric of the scaling policy configuration."
  default     = 70
}

variable "point_in_time_recovery" {
  type        = bool
  description = "(Optional) Enabling Amazon DynamoDB point-in-time recovery (PITR) provides automatic backups of your DynamoDB table data."
  default     = true
}

variable "enabled_repos" {
  type        = list(string)
  description = "(Optional) List of repos to be enabled with yum-config-manager. Epel repo will be enabled by default."
  default     = []
}

variable "pypi_index_url" {
  type        = string
  description = "(Optional) URL to the PyPi Index"
  default     = "https://pypi.org/simple"
}

variable "cfn_endpoint_url" {
  type        = string
  description = "(Optional) URL to the CloudFormation Endpoint. e.g. https://cloudformation.us-east-1.amazonaws.com"
  default     = "https://cloudformation.us-east-1.amazonaws.com"
}

variable "cfn_bootstrap_utils_url" {
  type        = string
  description = "(Optional) URL to aws-cfn-bootstrap-latest.tar.gz"
  default     = "https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.tar.gz"
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

variable "watchmaker_ou_path" {
  type        = string
  description = "(Optional) DN of the OU to place the instance when joining a domain. If blank and WatchmakerEnvironment enforces a domain join, the instance will be placed in a default container. Leave blank if not joining a domain, or if WatchmakerEnvironment is false"
  default     = ""
}

variable "watchmaker_admin_groups" {
  type        = string
  description = "(Optional) Colon-separated list of domain groups that should have admin permissions on the EC2 instance"
  default     = ""
}

variable "watchmaker_admin_users" {
  type        = string
  description = "(Optional) Colon-separated list of domain users that should have admin permissions on the EC2 instance"
  default     = ""
}

variable "toggle_update" {
  type        = string
  default     = "A"
  description = "(Optional) Toggle that triggers a stack update by modifying the launch config, resulting in new instances; must be one of: A or B"
}

variable "tags" {
  type        = map(string)
  description = "(Optional) List of tags to include with resource"
  default     = {}
}

variable "pillar_template_vars" {
  description = "(Optional) List extra configurations to be referenced in the pillar"
  default     = {}
}
