terraform {
  required_version = ">= 0.12"
}

###
### LOCALS
###

locals {
  vpc_id              = "${data.aws_subnet.lb.0.vpc_id}"
  role_name           = "${upper(var.name)}-INSTANCE-${data.aws_caller_identity.current.account_id}"
  ssm_root_path       = "vault/${var.environment}/${data.aws_caller_identity.current.account_id}/${var.name}"
  public_ip           = "${chomp(data.http.ip.body)}/32"
  allow_inbound       = "${compact(distinct(concat(list(local.public_ip), var.additional_ips_allow_inbound)))}"
  archive_file_name   = "salt.zip"
  configs_file_name   = "configs.zip"
  appscript_file_name = "appscript.sh"
  archive_dir_path    = "${path.module}/.files"
  appscript_dir_path  = "${path.module}/scripts"
  dynamodb_table      = "${var.dynamodb_table == "" ? aws_dynamodb_table.this.id : var.dynamodb_table}"
  url                 = "${var.name}.${var.domain_name}"
  vault_url           = "${var.vault_url == "" ? local.url : var.vault_url}"
  stack_name          = "${var.name}-${var.environment}"
  tags = {
    Environment = "${var.environment}"
  }
}

###
### DATA SOURCES
###

data "aws_partition" "current" {}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "aws_ami" "this" {
  most_recent = "true"

  owners = ["${var.ami_owner}"]

  name_regex = "${var.ami_name_regex}"

  filter {
    name   = "name"
    values = ["${var.ami_name_filter}"]
  }
}

data "http" "ip" {
  url = "${var.ip_data_url}"
}

data "aws_subnet" "lb" {
  count = "${length(var.lb_subnet_ids)}"

  id = "${var.lb_subnet_ids[count.index]}"
}

data "aws_kms_key" "this" {
  key_id = "${var.kms_key_id}"
}

data "archive_file" "salt" {
  type        = "zip"
  source_dir  = "${path.module}/salt"
  output_path = "${local.archive_dir_path}/${local.archive_file_name}"
}

data "archive_file" "configs" {
  count       = "${var.configs_path == "" ? 0 : 1}"
  type        = "zip"
  source_dir  = "${var.configs_path}"
  output_path = "${local.archive_dir_path}/${local.configs_file_name}"
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

# Manage S3 bucket module
module "s3_bucket" {
  source = "./modules/bucket"

  bucket_name = "${var.name}-appscript"
}

# Manage IAM module
module "iam" {
  source = "./modules/iam"

  bucket_name    = "${module.s3_bucket.bucket_name}"
  dynamodb_table = "${local.dynamodb_table}"
  kms_key_id     = "${data.aws_kms_key.this.key_id}"
  stack_name     = "${local.stack_name}"
  role_name      = "${local.role_name}"
  ssm_root_path  = "${local.ssm_root_path}"
}

# Generate a random id for each deployment
resource "random_string" "this" {
  length  = 8
  special = "false"
}

# Manage archive and appscript files
resource "aws_s3_bucket_object" "salt_zip" {
  bucket = "${module.s3_bucket.bucket_name}"
  key    = "${random_string.this.result}/${local.archive_file_name}"
  source = "${local.archive_dir_path}/${local.archive_file_name}"
  etag   = "${data.archive_file.salt.output_md5}"
}

resource "aws_s3_bucket_object" "configs_zip" {
  count  = "${var.configs_path == "" ? 0 : 1}"
  bucket = "${module.s3_bucket.bucket_name}"
  key    = "${random_string.this.result}/${local.configs_file_name}"
  source = "${local.archive_dir_path}/${local.configs_file_name}"
  etag   = "${data.archive_file.configs.*.output_md5[count.index]}"
}

resource "aws_s3_bucket_object" "app_script" {
  bucket = "${module.s3_bucket.bucket_name}"
  key    = "${random_string.this.result}/${local.appscript_file_name}"
  source = "${local.appscript_dir_path}/${local.appscript_file_name}"
  etag   = "${filemd5("${local.appscript_dir_path}/${local.appscript_file_name}")}"
}

# Manage domain record
resource "aws_route53_record" "this" {
  zone_id = "${data.aws_route53_zone.this.zone_id}"
  name    = "${local.vault_url}"
  type    = "A"

  alias {
    name                   = "${aws_lb.this.dns_name}"
    zone_id                = "${aws_lb.this.zone_id}"
    evaluate_target_health = false
  }
}

# Manage load balancer
resource "aws_lb" "this" {
  name            = "${var.name}-lb-${var.environment}"
  internal        = "false"
  security_groups = ["${aws_security_group.lb.id}"]
  subnets         = "${var.lb_subnet_ids}"

  # access_logs {
  #   enabled = true
  #   bucket  = "${module.bucket.bucket_name}"
  #   prefix  = "logs/lb_access_logs"
  # }

  tags = "${merge(map("Name", "${var.name}-lb"), local.tags)}"
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = "${aws_lb.this.arn}"
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
  load_balancer_arn = "${aws_lb.this.arn}"
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "${var.lb_ssl_policy}"
  certificate_arn   = "${data.aws_acm_certificate.this.arn}"

  default_action {
    target_group_arn = "${aws_lb_target_group.this.arn}"
    type             = "forward"
  }
}

resource "aws_lb_target_group" "this" {
  name     = "${var.name}-tg-${var.environment}"
  port     = "8200"
  protocol = "HTTP"
  vpc_id   = "${local.vpc_id}"

  deregistration_delay = "10"

  # /sys/health will return 200 only if the vault instance
  # is the leader. Meaning there will only ever be one healthy
  # instance, but a failure will cause a new instance to
  # be healthy automatically. This healthceck path prevents
  # unnecessary redirect loops by not sending traffic to
  # followers, which always just route traffic to the master
  health_check {
    path                = "/v1/sys/health?standbyok=true"
    port                = "8200"
    interval            = "5"
    timeout             = "3"
    healthy_threshold   = "2"
    unhealthy_threshold = "2"
  }

  tags = "${merge(map("Name", "${var.name}-tg"), local.tags)}"
}

# Manage security groups
resource "aws_security_group" "lb" {
  name        = "${var.name}-lb-sg-${var.environment}"
  description = "Rules required for operation of ${var.name}"
  vpc_id      = "${local.vpc_id}"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = "${var.ingress_cidr_blocks}"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = "${var.ingress_cidr_blocks}"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = "${merge(map("Name", "${var.name}-lb-${var.environment}"), local.tags)}"
}

resource "aws_security_group" "ec2" {
  name        = "${var.name}-ec2-sg-${var.environment}"
  description = "Rules required for operation of ${var.name}"
  vpc_id      = "${local.vpc_id}"

  ingress {
    from_port       = 8200
    to_port         = 8200
    description     = "Allows traffics to come to vault"
    protocol        = "tcp"
    security_groups = ["${aws_security_group.lb.id}"]
  }

  ingress {
    from_port   = 8201
    to_port     = 8201
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

  tags = "${merge(map("Name", "${var.name}-ec2-sg-${var.environment}"), local.tags)}"
}

resource "aws_security_group_rule" "ssh" {
  count       = "${var.environment == "dev" ? 1 : 0}"
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = "${local.allow_inbound}"

  security_group_id = "${aws_security_group.ec2.id}"
}

# Prepare appscript parameters
locals {
  # combine key to configs s3 object, otherwise pass 'n/a' to appscript
  s3_configs_key = "${var.configs_path == "" ? "n/a" : "${module.s3_bucket.bucket_name}/${random_string.this.result}/${local.configs_file_name}"}"
  params_for_appscript = [
    "${module.s3_bucket.bucket_name}/${random_string.this.result}/${local.archive_file_name}",
    "${local.s3_configs_key}",
    "${var.vault_version}",
    "${local.dynamodb_table}",
    "${data.aws_kms_key.this.key_id}",
    "${local.ssm_root_path}"
  ]

  appscript_url    = "s3://${module.s3_bucket.bucket_name}/${random_string.this.result}/${local.appscript_file_name}"
  appscript_params = "${join(" ", local.params_for_appscript)}"
}


# Manage Dynamodb Tables
resource "aws_dynamodb_table" "this" {
  name           = "${var.name}-data"
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

  tags = {
    Name        = "${var.name}-data"
    Environment = "${var.environment}"
  }
}


# Manage autoscaling group
module "autoscaling_group" {
  source = "git::https://github.com/plus3it/terraform-aws-watchmaker//modules/lx-autoscale?ref=1.15.7"

  Name            = "${local.stack_name}"
  OnFailureAction = ""
  DisableRollback = "true"

  AmiId                = "${data.aws_ami.this.id}"
  AmiDistro            = "CentOS"
  AppScriptUrl         = "${local.appscript_url}"
  AppScriptParams      = "${local.appscript_params}"
  CfnBootstrapUtilsUrl = "${var.cfn_bootstrap_utils_url}"

  CfnEndpointUrl     = "${var.cfn_endpoint_url}"
  CloudWatchAgentUrl = "${var.cloudwatch_agent_url}"
  CloudWatchAppLogs  = ["/var/log/salt_vault.log", "/var/log/salt_vault_initialize.log", "/var/log/salt_vault_sync.log"]
  KeyPairName        = "${var.key_pair_name}"
  InstanceRole       = "${module.iam.profile_name}"
  InstanceType       = "${var.instance_type}"
  NoReboot           = "true"
  NoPublicIp         = "false"
  PypiIndexUrl       = "${var.pypi_index_url}"
  SecurityGroupIds   = "${join(",", compact(concat(list(aws_security_group.ec2.id), var.ec2_extra_security_group_ids)))}"
  SubnetIds          = "${join(",", var.ec2_subnet_ids)}"
  TargetGroupArns    = "${aws_lb_target_group.this.arn}"
  ToggleNewInstances = "${var.toggle_update}"
  TimeoutInMinutes   = "20"

  WatchmakerEnvironment = "${var.environment}"
  WatchmakerConfig      = "${var.watchmaker_config}"
  WatchmakerAdminGroups = "${var.watchmaker_admin_groups}"
  WatchmakerAdminUsers  = "${var.watchmaker_admin_users}"
  WatchmakerOuPath      = "${var.watchmaker_ou_path}"

  DesiredCapacity = "${var.desired_capacity}"
  MinCapacity     = "${var.min_capacity}"
  MaxCapacity     = "${var.max_capacity}"

  EnableRepos = "epel"
}
