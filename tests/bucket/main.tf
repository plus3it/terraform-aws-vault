provider aws {
  region = "us-east-1"
}

resource "random_id" "name" {
  byte_length = 6
  prefix      = "terraform-aws-vault-"
}

module "bucket" {
  source = "../../modules/bucket"

  providers = {
    aws = "aws"
  }

  bucket_name = "${random_id.name}"
}
