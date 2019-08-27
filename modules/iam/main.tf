###
### REQUIRED VARIABLES
###
variable "stack_name" {
  description = "Name of the stack"
  type        = "string"
}

variable "kms_key_id" {
  description = "Id of an AWS KMS key use for auto unseal operation when vault is intialize"
  type        = "string"
}

variable "dynamodb_table" {
  description = "Name of the Dynamodb to be used as storage backend for Vault"
  type        = "string"
}

variable "bucket_name" {
  description = "The name of the bucket will be use to store app scripts and vault's salt formula."
  type        = "string"
}

variable "role_name" {
  description = "Name of the role to be create for vault"
  type        = "string"
}

variable "ssm_root_path" {
  description = "SSM parameter path. Initialize scripts will create tokens and store them as parameter at this path."
  type        = "string"
}

###
### OPTIONAL VARIABLES
###
variable "url_suffix" {
  default     = "amazonaws.com"
  description = "URL suffix associated with the current partition"
  type        = "string"
}

###
### DATA
###
data "aws_partition" "current" {}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

###
### RESOURCES
###
data "template_file" "instance_policy" {
  template = "${file("${path.module}/iam_policy.json")}"

  vars = {
    partition  = "${data.aws_partition.current.partition}"
    region     = "${data.aws_region.current.name}"
    account_id = "${data.aws_caller_identity.current.account_id}"

    stack_name     = "${var.stack_name}"
    key_id         = "${var.kms_key_id}"
    dynamodb_table = "${var.dynamodb_table}"
    bucket_name    = "${var.bucket_name}"
    ssm_path       = "${var.ssm_root_path}"
  }
}

data "aws_iam_policy_document" "instance_trust_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.${var.url_suffix}"]
    }
  }
}

resource "aws_iam_role" "instance" {
  name               = "${var.role_name}"
  assume_role_policy = "${data.aws_iam_policy_document.instance_trust_policy.json}"
}

resource "aws_iam_role_policy" "instance" {
  name_prefix = "${var.role_name}_"
  policy      = "${data.template_file.instance_policy.rendered}"
  role        = "${aws_iam_role.instance.id}"
}

resource "aws_iam_instance_profile" "instance" {
  name = "${var.role_name}"
  role = "${aws_iam_role.instance.name}"
}

###
### OUTPUTS
###

output "profile_name" {
  value = "${aws_iam_instance_profile.instance.name}"
}
