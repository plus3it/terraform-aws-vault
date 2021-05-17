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
  vpc_id                = data.aws_subnet.lb[0].vpc_id
  bucket_name           = "${var.name}-${random_string.this.result}"
  vault_url             = var.vault_url == null ? join(".", [var.name, var.domain_name]) : var.vault_url
  archive_file_name     = "salt.zip"
  configs_file_name     = "configs.zip"
  appscript_file_name   = "appscript.sh"
  pillar_file_name      = "pillar.zip"
  logs_dir              = "/var/log/vault"
  logs_path             = "${local.logs_dir}/state.vault"
  enabled_repos         = "epel"
  default_inbound_cdirs = ["10.0.0.0/16"]
  s3_appscript_url      = "s3://${aws_s3_bucket.this.id}/${local.appscript_file_name}"
  s3_salt_vault_content = "s3://${aws_s3_bucket.this.id}/${local.archive_file_name}"
  s3_pillar_url         = "s3://${aws_s3_bucket.this.id}/${local.pillar_file_name}"
  archive_path          = join("/", [path.module, ".files", local.archive_file_name])
  pillar_path           = join("/", [path.module, ".files", local.pillar_file_name])
  appscript_path        = join("/", [path.module, "scripts", local.appscript_file_name])
  ssm_root_path         = join("/", ["vault", var.environment, data.aws_caller_identity.current.account_id, var.name])
  role_name             = join("-", [upper(var.name), "INSTANCE", data.aws_caller_identity.current.account_id])
  dynamodb_table        = var.dynamodb_table == null ? aws_dynamodb_table.this[0].id : var.dynamodb_table
  kms_key_id            = var.kms_key_id == null ? aws_kms_key.this[0].id : var.kms_key_id
  certificate_arn       = var.certificate_arn == null ? module.certificate.acm_certificate_validation[local.vault_url].certificate_arn : var.certificate_arn

  template_vars = { for key, value in var.template_vars : key => jsonencode(value) }

  # Logs files to be streamed to CloudWatch Logs
  logs = [
    "${local.logs_path}.log",
    "${local.logs_path}.initialize.log",
    "${local.logs_path}.sync.log",
  ]

  tags = merge(
    {
      Name        = var.name,
      Environment = var.environment
    },
    var.tags
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

  owners     = var.ami_owners
  name_regex = var.ami_name_regex
  filter {
    name   = "name"
    values = var.ami_name_filters
  }
}

data "aws_subnet" "lb" {
  count = length(var.lb_subnet_ids)

  id = var.lb_subnet_ids[count.index]
}

# Resorting to alernative means of creating the directory due to
# https://github.com/gruntwork-io/terragrunt/issues/829
resource "local_file" "pillar" {
  for_each = fileset(var.vault_pillar_path, "[^.]*")
  filename = "${path.module}/.files/pillar/${each.value}"

  content = templatefile("${var.vault_pillar_path}/${each.value}", merge({
    api_port       = var.api_port
    cluster_port   = var.cluster_port
    dynamodb_table = local.dynamodb_table
    inbound_cidrs  = jsonencode(concat(var.inbound_cidrs, local.default_inbound_cdirs))
    kms_key_id     = local.kms_key_id
    logs_dir       = local.logs_dir
    logs_path      = local.logs_path
    region         = data.aws_region.current.name
    ssm_path       = local.ssm_root_path
    vault_version  = var.vault_version
  }, local.template_vars))
}

# Using a second local_file resource due to
# https://github.com/hashicorp/terraform/issues/24220
resource "local_file" "pillar_data" {
  for_each = fileset("${var.vault_pillar_path}/vault", "[^.]*")
  filename = "${path.module}/.files/pillar/vault/${each.value}"

  content = templatefile("${var.vault_pillar_path}/vault/${each.value}", merge({
    api_port       = var.api_port
    cluster_port   = var.cluster_port
    dynamodb_table = local.dynamodb_table
    inbound_cidrs  = jsonencode(concat(var.inbound_cidrs, local.default_inbound_cdirs))
    kms_key_id     = local.kms_key_id
    logs_dir       = local.logs_dir
    logs_path      = local.logs_path
    region         = data.aws_region.current.name
    ssm_path       = local.ssm_root_path
    vault_version  = var.vault_version
  }, local.template_vars))
}

data "archive_file" "pillar" {
  type        = "zip"
  source_dir  = "${path.module}/.files/pillar/"
  output_path = local.pillar_path
  depends_on  = [local_file.pillar, local_file.pillar_data]
}

resource "aws_s3_bucket_object" "pillar" {
  bucket = aws_s3_bucket.this.id
  key    = local.pillar_file_name
  source = local.pillar_path
  etag   = data.archive_file.pillar.output_md5
}

# Manage S3 bucket
resource "aws_s3_bucket" "this" {
  bucket = local.bucket_name

  tags = local.tags
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = templatefile("${path.module}/policies/bucket_policy.json", { bucket_arn = aws_s3_bucket.this.arn })
}

# Manage IAM module
module "iam" {
  source = "./modules/iam"

  role_name     = local.role_name
  override_json = var.override_json
  policy_vars = {
    bucket_name    = aws_s3_bucket.this.id
    dynamodb_table = local.dynamodb_table
    kms_key_id     = local.kms_key_id
    stack_name     = var.name
    ssm_path       = local.ssm_root_path
  }
}

# Generate a random id for each deployment
resource "random_string" "this" {
  length  = 8
  special = false
  upper   = false
}

# Manage archive, appscript, pillar files

data "archive_file" "salt" {
  type        = "zip"
  source_dir  = "${path.module}/salt"
  output_path = local.archive_path
}

resource "aws_s3_bucket_object" "salt_zip" {
  bucket = aws_s3_bucket.this.id
  key    = local.archive_file_name
  source = local.archive_path
  etag   = data.archive_file.salt.output_md5
}

data "template_file" "appscript" {
  template = file(local.appscript_path)

  vars = {
    salt_content_archive = local.s3_salt_vault_content
    pillar_archive       = local.s3_pillar_url
  }
}

resource "aws_s3_bucket_object" "app_script" {
  bucket  = aws_s3_bucket.this.id
  key     = local.appscript_file_name
  content = data.template_file.appscript.rendered
  etag    = md5(data.template_file.appscript.rendered)
}

# Manage KMS key
resource "aws_kms_alias" "this" {
  count         = var.kms_key_id == null ? 1 : 0
  name          = "alias/${var.name}"
  target_key_id = aws_kms_key.this[0].key_id
}

resource "aws_kms_key" "this" {
  count       = var.kms_key_id == null ? 1 : 0
  description = "KMS Key for ${var.name}"

  tags = local.tags
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

# Manage certificate
data "aws_route53_zone" "this" {
  name         = var.domain_name
  private_zone = false
}

module "certificate" {
  source = "git::https://github.com/plus3it/terraform-aws-tardigrade-acm.git?ref=1.0.0"

  create_acm_certificate = var.certificate_arn == null

  domain_name = local.vault_url
  zone_id     = data.aws_route53_zone.this.zone_id

  subject_alternative_names = [
    "*.${local.vault_url}"
  ]
}

# Manage load balancer
resource "aws_lb" "this" {
  name            = var.name
  internal        = var.lb_internal
  security_groups = [aws_security_group.lb.id]
  subnets         = var.lb_subnet_ids

  tags = local.tags
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
  certificate_arn   = local.certificate_arn

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
  # be healthy automatically. This healthcheck path prevents
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

  tags = local.tags
}

# Manage security groups
resource "aws_security_group" "lb" {
  name        = "${var.name}-lb"
  description = "Allow web traffic to the ${var.name} load balancer"
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
  description = "Allow vault traffic between ${var.name} ALB and EC2 instances"
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

  # Amazon DynamoDB point-in-time recovery (PITR) provides automatic backups of your DynamoDB table data.
  # By enabling this feature, Vault's dynamodb table can be recover to any point in time during the last 35 days.
  point_in_time_recovery {
    enabled = var.point_in_time_recovery
  }

  tags = local.tags
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

  name               = join(":", ["DynamoDBReadCapacityUtilization", aws_appautoscaling_target.this[0].resource_id])
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.this[0].resource_id
  scalable_dimension = aws_appautoscaling_target.this[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.this[0].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "DynamoDBReadCapacityUtilization"
    }

    target_value = var.dynamodb_target_value
  }
}

# Manage autoscaling group
module "autoscaling_group" {
  source = "git::https://github.com/plus3it/terraform-aws-watchmaker//modules/lx-autoscale?ref=2.0.0"

  Name            = var.name
  OnFailureAction = ""
  DisableRollback = "true"

  AmiId        = data.aws_ami.this.id
  AmiDistro    = "CentOS"
  AppScriptUrl = local.s3_appscript_url

  CfnEndpointUrl     = var.cfn_endpoint_url
  CloudWatchAgentUrl = var.cloudwatch_agent_url
  CloudWatchAppLogs  = local.logs
  KeyPairName        = var.key_pair_name
  InstanceRole       = module.iam.profile_name
  InstanceType       = var.instance_type
  NoReboot           = true
  NoPublicIp         = true
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

  DesiredCapacity   = var.desired_capacity
  MinCapacity       = var.min_capacity
  MaxCapacity       = var.max_capacity
  ScaleDownSchedule = var.scale_down_schedule
  ScaleUpSchedule   = var.scale_up_schedule

  EnableRepos = local.enabled_repos
}
