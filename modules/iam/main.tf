###
### REQUIRED VARIABLES
###
variable "policy_vars" {
  description = "Variables for interpolation within the template. Must include the following vars: bucket_name, dynamodb_table, kms_key_id, stack_name, ssm_path"
  type        = map(string)
}

variable "role_name" {
  description = "Name of the role to be create for vault"
  type        = string
}
###
### OPTIONAL VARIABLES
###
variable "url_suffix" {
  default     = "amazonaws.com"
  description = "URL suffix associated with the current partition"
  type        = string
}

###
### DATA
###
data "aws_partition" "current" {
}

data "aws_caller_identity" "current" {
}

data "aws_region" "current" {
}

###
### RESOURCES
###
data "template_file" "instance_policy" {
  template = file("${path.module}/iam_policy.json")

  vars = merge(var.policy_vars,
    {
      partition  = data.aws_partition.current.partition
      region     = data.aws_region.current.name
      account_id = data.aws_caller_identity.current.account_id
    }
  )
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
  name               = var.role_name
  assume_role_policy = data.aws_iam_policy_document.instance_trust_policy.json
}

resource "aws_iam_role_policy" "instance" {
  name_prefix = "${var.role_name}_"
  policy      = data.template_file.instance_policy.rendered
  role        = aws_iam_role.instance.id
}

resource "aws_iam_instance_profile" "instance" {
  name = var.role_name
  role = aws_iam_role.instance.name
}

###
### OUTPUTS
###

output "profile_name" {
  value = aws_iam_instance_profile.instance.name
}

