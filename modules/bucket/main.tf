###
### VARIABLES
###

variable "bucket_name" {
  description = "The name of the bucket will be use to store app scripts and vault's salt formula."
  type        = "string"
  default     = "vault-salt-formula"
}

###
### DATA SOURCES
###

data "aws_partition" "current" {}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "template_file" "bucket_policy" {
  template = "${file("${path.module}/bucket_policy.json")}"

  vars = {
    bucket_arn = "${aws_s3_bucket.this.arn}"
  }
}

###
### RESOURCES
###

resource "aws_s3_bucket" "this" {
  bucket = "${var.bucket_name}"
}

resource "aws_s3_bucket_policy" "this" {
  bucket = "${aws_s3_bucket.this.id}"
  policy = "${data.template_file.bucket_policy.rendered}"
}

###
### OUTPUTS
###
output "bucket_name" {
  description = "Name of the S3 bucket"
  value       = "${aws_s3_bucket.this.id}"
}

output "bucket_arn" {
  description = "ARN of the S3 bucket"
  value       = "${aws_s3_bucket.this.arn}"
}
