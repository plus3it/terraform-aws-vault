# ----------------------------------------------------------------------------------------------------------------------
# REQUIRE A SPECIFIC TERRAFORM VERSION OR HIGHER
# This module has been updated with 0.12 syntax, which means it is no longer compatible with any versions below 0.12.
# ----------------------------------------------------------------------------------------------------------------------
terraform {
  required_version = ">= 0.12"
}

###
### LOCALS
###

locals {
  vpc_id                 = element(data.aws_subnet.lb.*.vpc_id, 0)
  archive_file_name      = "salt.zip"
  configs_file_name      = "configs.zip"
  appscript_file_name    = "appscript.sh"
  config_dir_path        = "/etc/vault/configs"
  logs_path              = "/var/log/vault"
  default_enabled_repos  = ["epel"]
  default_inbound_cdirs  = ["10.0.0.0/16", "10.0.0.0/8"]
  appscript_url          = join("/", [module.s3_bucket.id, random_string.this.result, local.appscript_file_name])
  archive_dir_path       = join("/", [path.module, ".files"])
  appscript_dir_path     = join("/", [path.module, "scripts"])
  role_name              = join("-", [upper(var.name), "INSTANCE", data.aws_caller_identity.current.account_id])
  ssm_root_path          = join("/", ["vault", var.environment, data.aws_caller_identity.current.account_id, var.name])
  s3_salt_vault_content  = join("/", [module.s3_bucket.id, random_string.this.result, local.archive_file_name])
  s3_vault_configuration = var.vault_configs_path == null ? "" : join("/", [module.s3_bucket.id, random_string.this.result, local.configs_file_name])
  dynamodb_table         = var.dynamodb_table == null ? join("", aws_dynamodb_table.this.*.id) : var.dynamodb_table
  kms_key_id             = var.kms_key_id == null ? join("", aws_kms_key.this.*.id) : var.kms_key_id
  vault_url              = var.vault_url == null ? join(".", [var.name, var.domain_name]) : var.vault_url

  # Logs files to be streamed to CloudWatch Logs
  logs = [
    join("/", [local.logs_path, "salt_call.log"]),
    join("/", [local.logs_path, "initialize.log"]),
    join("/", [local.logs_path, "sync_config.log"])
  ]

  tags = merge(var.tags,
    {
      Environment = var.environment
    }
  )
}

###
### DATA SOURCES
###

data "aws_partition" "current" {
}

data "aws_caller_identity" "current" {
}

data "aws_region" "current" {
}

data "aws_ami" "this" {
  most_recent = "true"

  owners     = [var.ami_owner]
  name_regex = var.ami_name_regex
  filter {
    name   = "name"
    values = [var.ami_name_filter]
  }
}

data "aws_subnet" "lb" {
  count = length(var.lb_subnet_ids)

  id = var.lb_subnet_ids[count.index]
}

data "archive_file" "salt" {
  type        = "zip"
  source_dir  = join("/", [path.module, "salt"])
  output_path = join("/", [local.archive_dir_path, local.archive_file_name])
}

data "archive_file" "configs" {
  count       = var.vault_configs_path == null ? 0 : 1
  type        = "zip"
  source_dir  = var.vault_configs_path
  output_path = join("/", [local.archive_dir_path, local.configs_file_name])
}

data "aws_acm_certificate" "this" {
  domain      = join(".", ["*", var.domain_name])
  types       = ["AMAZON_ISSUED"]
  most_recent = true
}

data "template_file" "appscript" {
  template = file(join("/", [local.appscript_dir_path, local.appscript_file_name]))

  vars = {
    salt_content_archive = local.s3_salt_vault_content

    salt_grains_json = join("", ["'", jsonencode({
      api_port        = var.api_port
      cluster_port    = var.cluster_port
      dynamodb_table  = local.dynamodb_table
      inbound_cidrs   = concat(var.inbound_cidrs, local.default_inbound_cdirs)
      kms_key_id      = local.kms_key_id
      logs_path       = local.logs_path
      region          = data.aws_region.current.name
      ssm_path        = local.ssm_root_path
      version         = var.vault_version
    }), "'"])
  }
}

# Manage S3 bucket module
module "s3_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "0.0.1"

  bucket = var.name
}


resource "aws_s3_bucket_policy" "this" {
  bucket = module.s3_bucket.id
  policy = templatefile("${path.module}/policies/bucket_policy.json", { bucket_arn = module.s3_bucket.arn })
}

# Manage IAM module
module "iam" {
  source = "./modules/iam"

  role_name = local.role_name
  policy_vars = {
    bucket_name    = var.name
    dynamodb_table = local.dynamodb_table
    kms_key_id     = local.kms_key_id
    stack_name     = var.name
    ssm_path       = local.ssm_root_path
  }
}

# Generate a random id for each deployment
resource "random_string" "this" {
  length  = 8
  special = "false"
}

# Manage archive and appscript files
resource "aws_s3_bucket_object" "salt_zip" {
  bucket = module.s3_bucket.id
  key    = join("/", [random_string.this.result, local.archive_file_name])
  source = join("/", [local.archive_dir_path, local.archive_file_name])
  etag   = data.archive_file.salt.output_md5
}

resource "aws_s3_bucket_object" "configs_zip" {
  count  = var.vault_configs_path == null ? 0 : 1
  bucket = module.s3_bucket.id
  key    = join("/", [random_string.this.result, local.configs_file_name])
  source = join("/", [local.archive_dir_path, local.configs_file_name])
  etag   = data.archive_file.configs[count.index].output_md5
}

resource "aws_s3_bucket_object" "app_script" {
  bucket  = module.s3_bucket.id
  key     = join("/", [random_string.this.result, local.appscript_file_name])
  content = data.template_file.appscript.rendered
  etag    = md5(data.template_file.appscript.rendered)
}
# Manage domain record
resource "aws_route53_record" "this" {
  zone_id = var.route53_zone_id
  name    = local.vault_url
  type    = "A"

  alias {
    name                   = aws_lb.this.dns_name
    zone_id                = aws_lb.this.zone_id
    evaluate_target_health = false
  }
}

# Manage KMS key
resource "aws_kms_alias" "this" {
  count         = var.kms_key_id == null ? 1 : 0
  name          = "alias/${var.name}"
  target_key_id = join("", aws_kms_key.this.*.key_id)
}

resource "aws_kms_key" "this" {
  count                   = var.kms_key_id == null ? 1 : 0
  description             = "KSM Key for ${var.name}"
  deletion_window_in_days = 10

  tags = merge({ Name = var.name }, local.tags)
}

# Manage load balancer
resource "aws_lb" "this" {
  name            = var.name
  internal        = "false"
  security_groups = [aws_security_group.lb.id]
  subnets         = var.lb_subnet_ids

  access_logs {
    enabled = var.enable_access_logs
    bucket  = module.s3_bucket.id
    prefix  = "ALBLogs"
  }

  tags = merge({ Name = var.name }, local.tags)
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = var.lb_ssl_policy
  certificate_arn   = data.aws_acm_certificate.this.arn

  default_action {
    target_group_arn = aws_lb_target_group.this.arn
    type             = "forward"
  }
}

resource "aws_lb_target_group" "this" {
  name     = var.name
  port     = var.api_port
  protocol = "HTTP"
  vpc_id   = local.vpc_id

  deregistration_delay = "10"

  # /sys/health will return 200 only if the vault instance
  # is the leader. Meaning there will only ever be one healthy
  # instance, but a failure will cause a new instance to
  # be healthy automatically. This healthceck path prevents
  # unnecessary redirect loops by not sending traffic to
  # followers, which always just route traffic to the master
  health_check {
    path                = "/v1/sys/health?standbyok=true"
    port                = var.api_port
    interval            = "5"
    timeout             = "3"
    healthy_threshold   = "2"
    unhealthy_threshold = "2"
  }

  tags = merge({ Name = var.name }, local.tags)
}

# Manage security groups
resource "aws_security_group" "lb" {
  name        = "${var.name}-lb"
  description = "Allow web traffic to the load balancer"
  vpc_id      = local.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.ingress_cidr_blocks
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.ingress_cidr_blocks
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge({ Name = "${var.name}-lb" }, local.tags)
}

resource "aws_security_group" "ec2" {
  name        = "${var.name}-ec2"
  description = "Allow vault traffic between ALB and EC2 instances"
  vpc_id      = local.vpc_id

  ingress {
    from_port       = var.api_port
    to_port         = var.api_port
    description     = "Allows traffics to come to vault"
    protocol        = "tcp"
    security_groups = [aws_security_group.lb.id]
  }

  ingress {
    from_port   = var.cluster_port
    to_port     = var.cluster_port
    description = "Allows traffics to route between vault nodes"
    protocol    = "tcp"
    self        = true
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge({ Name = "${var.name}-ec2" }, local.tags)
}

# Manage Dynamodb Tables
resource "aws_dynamodb_table" "this" {
  count = var.dynamodb_table == null ? 1 : 0

  name           = var.name
  read_capacity  = 5
  write_capacity = 5
  hash_key       = "Path"
  range_key      = "Key"

  attribute {
    name = "Path"
    type = "S"
  }

  attribute {
    name = "Key"
    type = "S"
  }

  tags = merge({ Name = var.name }, local.tags)
}

resource "aws_appautoscaling_target" "this" {
  count = var.dynamodb_table == null ? 1 : 0

  max_capacity       = var.dynamodb_max_read_capacity
  min_capacity       = var.dynamodb_min_read_capacity
  resource_id        = join("/", ["table", local.dynamodb_table])
  scalable_dimension = "dynamodb:table:ReadCapacityUnits"
  service_namespace  = "dynamodb"
}

resource "aws_appautoscaling_policy" "this" {
  count = var.dynamodb_table == null ? 1 : 0

  name               = join(":", ["DynamoDBReadCapacityUtilization", join("", aws_appautoscaling_target.this.*.resource_id)])
  policy_type        = "TargetTrackingScaling"
  resource_id        = join("", aws_appautoscaling_target.this.*.resource_id)
  scalable_dimension = join("", aws_appautoscaling_target.this.*.scalable_dimension)
  service_namespace  = join("", aws_appautoscaling_target.this.*.service_namespace)

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "DynamoDBReadCapacityUtilization"
    }

    target_value = var.dynamodb_target_value
  }
}

# Manage autoscaling group
module "autoscaling_group" {
  source = "git::https://github.com/plus3it/terraform-aws-watchmaker//modules/lx-autoscale?ref=1.15.7"

  Name            = var.name
  OnFailureAction = ""
  DisableRollback = "true"

  AmiId                = data.aws_ami.this.id
  AmiDistro            = "CentOS"
  AppScriptUrl         = join("", ["s3://", local.appscript_url])
  CfnBootstrapUtilsUrl = var.cfn_bootstrap_utils_url

  CfnEndpointUrl     = var.cfn_endpoint_url
  CloudWatchAgentUrl = var.cloudwatch_agent_url
  CloudWatchAppLogs  = local.logs
  KeyPairName        = var.key_pair_name
  InstanceRole       = module.iam.profile_name
  InstanceType       = var.instance_type
  NoReboot           = "true"
  NoPublicIp         = "false"
  PypiIndexUrl       = var.pypi_index_url
  SecurityGroupIds   = join(",", compact(concat([aws_security_group.ec2.id], var.ec2_extra_security_group_ids)))
  SubnetIds          = join(",", var.ec2_subnet_ids)
  TargetGroupArns    = aws_lb_target_group.this.arn
  ToggleNewInstances = var.toggle_update
  TimeoutInMinutes   = "20"

  WatchmakerEnvironment = var.environment
  WatchmakerConfig      = var.watchmaker_config
  WatchmakerAdminGroups = var.watchmaker_admin_groups
  WatchmakerAdminUsers  = var.watchmaker_admin_users
  WatchmakerOuPath      = var.watchmaker_ou_path

  DesiredCapacity = var.desired_capacity
  MinCapacity     = var.min_capacity
  MaxCapacity     = var.max_capacity

  EnableRepos = join(" ", concat(var.enabled_repos, local.default_enabled_repos))

}
