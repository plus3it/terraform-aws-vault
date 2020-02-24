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

data "aws_iam_policy_document" "instance_policy" {
  source_json   = data.template_file.instance_policy.rendered
  override_json = var.override_json
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
  policy      = data.aws_iam_policy_document.instance_policy.json
  role        = aws_iam_role.instance.id
}

resource "aws_iam_instance_profile" "instance" {
  name = var.role_name
  role = aws_iam_role.instance.name
}
