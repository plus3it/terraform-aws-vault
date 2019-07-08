## terraform-aws-vault

Terraform module that installs and configures Hashicorp Vault cluster with HA DyanamoDb storage backend.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|:----:|:-----:|:-----:|
| additional\_ips\_allow\_inbound | List of ip address that allow to have access to resources | list | n/a | yes |
| ami\_name\_filter | Will be use to filter out AMI | string | `"spel-minimal-centos-7-hvm-*.x86_64-gp2"` | no |
| ami\_name\_regex | Regex to help fine-grain filtering AMI | string | `"spel-minimal-centos-7-hvm-\\d{4}\\.\\d{2}\\.\\d{1}\\.x86_64-gp2"` | no |
| ami\_owner | Account id/alias of the AMI owner | string | n/a | yes |
| bucket\_name | The name of the bucket will be use to store app scripts and vault's salt formula. | string | n/a | yes |
| cfn\_bootstrap\_utils\_url | (Optional) URL to aws-cfn-bootstrap-latest.tar.gz | string | `"https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.tar.gz"` | no |
| cfn\_endpoint\_url | (Optional) URL to the CloudFormation Endpoint. e.g. https://cloudformation.us-east-1.amazonaws.com | string | `"https://cloudformation.us-east-1.amazonaws.com"` | no |
| cloudwatch\_agent\_url | (Optional) S3 URL to CloudWatch Agent installer. Example: s3://amazoncloudwatch-agent/linux/amd64/latest/AmazonCloudWatchAgent.zip | string | `""` | no |
| desired\_capacity | (Optional) Desired number of instances in the Autoscaling Group | string | `"2"` | no |
| dynamodb\_table | Name of the Dynamodb to be used as storage backend for Vault | string | n/a | yes |
| ec2\_extra\_security\_group\_ids | List of additional security groups to add to EC2 instances | list | n/a | yes |
| ec2\_subnet\_ids | List of subnets where EC2 instances will be launched | list | n/a | yes |
| environment | Type of environment -- must be one of: dev, test, prod | string | n/a | yes |
| ingress\_cidr\_blocks | (Optional) List of CIDR block. | list | `<list>` | no |
| instance\_type | Amazon EC2 instance type | string | `"t2.medium"` | no |
| ip\_data\_url | URL to get ip address of the current user | string | `"http://ipv4.icanhazip.com"` | no |
| key\_pair\_name | Keypair to associate to launched instances | string | n/a | yes |
| kms\_key\_id | Id of an AWS KMS key use for auto unseal operation when vault is intialize | string | n/a | yes |
| lb\_certificate\_arn | Arn of a created certificate to be use for the load balancer | string | n/a | yes |
| lb\_internal | Boolean indicating whether the load balancer is internal or external | string | `"false"` | no |
| lb\_ssl\_policy | The name of the SSL Policy for the listener | string | `"ELBSecurityPolicy-FS-2018-06"` | no |
| lb\_subnet\_ids | List of subnets to associate to the Load Balancer | list | n/a | yes |
| max\_capacity | (Optional) Maximum number of instances in the Autoscaling Group | string | `"2"` | no |
| min\_capacity | (Optional) Minimum number of instances in the Autoscaling Group | string | `"1"` | no |
| name | Name of the vault stack, will be use to prefix resources | string | n/a | yes |
| pypi\_index\_url | (Optional) URL to the PyPi Index | string | `"https://pypi.org/simple"` | no |
| route53\_enabled | Creates Route53 DNS entries for Vault automatically | string | `"false"` | no |
| route53\_zone\_id | Zone ID for domain | string | n/a | yes |
| tags | (Optional) list of tags to include with resource | map | `<map>` | no |
| toggle\_update | (Optional) Toggle that triggers a stack update by modifying the launch config, resulting in new instances; must be one of: A or B | string | `"A"` | no |
| vault\_url | The DNS address that vault will be accessible at. Example: vault.domain.net | string | n/a | yes |
| vault\_version | Version of Vault to be installed on servers | string | n/a | yes |
| watchmaker\_admin\_groups | (Optional) Colon-separated list of domain groups that should have admin permissions on the EC2 instance | string | `""` | no |
| watchmaker\_admin\_users | (Optional) Colon-separated list of domain users that should have admin permissions on the EC2 instance | string | `""` | no |
| watchmaker\_config | (Optional) URL to a Watchmaker config file | string | `""` | no |
| watchmaker\_ou\_path | (Optional) DN of the OU to place the instance when joining a domain. If blank and WatchmakerEnvironment enforces a domain join, the instance will be placed in a default container. Leave blank if not joining a domain, or if WatchmakerEnvironment is false | string | `""` | no |

## Outputs

| Name | Description |
|------|-------------|
| vault\_url | URL to access Vault UI |

