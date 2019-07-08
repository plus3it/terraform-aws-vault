terraform {
  required_version = ">= 0.12"
}

###
### LOCALS
###

locals {
  name_id             = "${var.name}-${random_string.this.result}"
  vpc_id              = "${data.aws_subnet.lb.0.vpc_id}"
  role_name           = "INSTANCE_VAULT_${data.aws_caller_identity.current.account_id}"
  ssm_root_path       = "vault/${var.environment}/${data.aws_caller_identity.current.account_id}/${var.name}"
  public_ip           = "${chomp(data.http.ip.body)}/32"
  allow_inbound       = "${compact(distinct(concat(list(local.public_ip), var.additional_ips_allow_inbound)))}"
  archive_file_name   = "salt.zip"
  appscript_file_name = "appscript.sh"
  archive_file_path   = "${path.module}/.files/${local.archive_file_name}"
  appscript_file_path = "${path.module}/scripts/${local.appscript_file_name}"

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
  source_dir  = "salt"
  output_path = "${local.archive_file_path}"
}

# Manage Bucket module
module "s3_bucket" {
  source = "./modules/bucket"

  bucket_name = "${var.bucket_name}"
}

# Manage IAM module
module "iam" {
  source = "./modules/iam"

  bucket_name    = "${module.s3_bucket.bucket_name}"
  dynamodb_table = "${var.dynamodb_table}"
  environment    = "${var.environment}"
  kms_key_id     = "${data.aws_kms_key.this.key_id}"
  name           = "${var.name}"
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
  source = "${local.archive_file_path}"
  etag   = "${data.archive_file.salt.output_md5}"
}

resource "aws_s3_bucket_object" "app_script" {
  bucket = "${module.s3_bucket.bucket_name}"
  key    = "${random_string.this.result}/${local.appscript_file_name}"
  source = "${local.appscript_file_path}"
  etag   = "${filemd5("${local.appscript_file_path}")}"
}

# Manage domain record
resource "aws_route53_record" "this" {
  count   = "${var.route53_zone_id == "" || var.vault_url == "" ? 0 : 1}"
  zone_id = "${var.route53_zone_id}"
  name    = "${var.vault_url}"
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
  certificate_arn   = "${var.lb_certificate_arn}"

  default_action {
    target_group_arn = "${aws_lb_target_group.this.arn}"
    type             = "forward"
  }
}

resource "aws_lb_target_group" "this" {
  name     = "${var.name}-${var.environment}"
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

  tags = "${merge(
    map("Name", "${var.name}-tg"),
  local.tags)}"
}

# Manage security groups
resource "aws_security_group" "lb" {
  name        = "${var.name}-${var.environment}"
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
  params_for_appscript = [
    "${module.s3_bucket.bucket_name}/${random_string.this.result}/${local.archive_file_name}",
    "${var.vault_version}",
    "${var.dynamodb_table}",
    "${data.aws_kms_key.this.key_id}",
    "${local.ssm_root_path}",
  ]

  appscript_url    = "s3://${module.s3_bucket.bucket_name}/${random_string.this.result}/${local.appscript_file_name}"
  appscript_params = "${join(" ", local.params_for_appscript)}"
}

# Manage autoscaling group
module "autoscaling_group" {
  source = "git::https://github.com/plus3it/terraform-aws-watchmaker//modules/lx-autoscale?ref=1.15.2"

  Name            = "${var.name}-${var.environment}"
  OnFailureAction = ""
  DisableRollback = "true"

  AmiId                = "${data.aws_ami.this.id}"
  AmiDistro            = "CentOS"
  AppScriptUrl         = "${local.appscript_url}"
  AppScriptParams      = "${local.appscript_params}"
  CfnBootstrapUtilsUrl = "${var.cfn_bootstrap_utils_url}"

  CfnEndpointUrl     = "${var.cfn_endpoint_url}"
  CloudWatchAgentUrl = "${var.cloudwatch_agent_url}"
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
}
