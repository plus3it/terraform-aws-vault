## terraform-aws-vault

Terraform module that installs and configures Hashicorp Vault cluster with HA DyanamoDb storage backend.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|:----:|:-----:|:-----:|
| ami\_name\_filters | Will be use to filter out AMI | list(string) | `<list>` | no |
| ami\_name\_regex | Regex to help fine-grain filtering AMI | string | `"spel-minimal-centos-7-hvm-\\d{4}\\.\\d{2}\\.\\d{1}\\.x86_64-gp2"` | no |
| ami\_owners | Account id/alias of the AMI owners | list(string) | n/a | yes |
| api\_port | The port to use for Vault API calls | string | `"8200"` | no |
| certificate\_arn | The ARN of the default SSL server certificate to be use for HTTPS lb listener. | string | `"null"` | no |
| cfn\_bootstrap\_utils\_url | (Optional) URL to aws-cfn-bootstrap-latest.tar.gz | string | `"https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.tar.gz"` | no |
| cfn\_endpoint\_url | (Optional) URL to the CloudFormation Endpoint. e.g. https://cloudformation.us-east-1.amazonaws.com | string | `"https://cloudformation.us-east-1.amazonaws.com"` | no |
| cloudwatch\_agent\_url | (Optional) S3 URL to CloudWatch Agent installer. Example: s3://amazoncloudwatch-agent/linux/amd64/latest/AmazonCloudWatchAgent.zip | string | `""` | no |
| cluster\_port | The port to use for Vault server-to-server communication. | string | `"8201"` | no |
| desired\_capacity | (Optional) Desired number of instances in the Autoscaling Group | string | `"2"` | no |
| domain\_name | The domain name where vault url will be registered to. Example: domain.net | string | n/a | yes |
| dynamodb\_max\_read\_capacity | (Optional) The max capacity of the scalable target for DynamoDb table autoscaling. | number | `"100"` | no |
| dynamodb\_min\_read\_capacity | (Optional) The min capacity of the scalable target for DynamoDb table autoscaling. | number | `"5"` | no |
| dynamodb\_table | Name of the Dynamodb to be used as storage backend for Vault | string | `"null"` | no |
| dynamodb\_target\_value | (Optional) The target value for the metric of the scaling policy configuration. | number | `"70"` | no |
| ec2\_extra\_security\_group\_ids | List of additional security groups to add to EC2 instances | list(string) | `<list>` | no |
| ec2\_subnet\_ids | List of subnets where EC2 instances will be launched | list(string) | n/a | yes |
| enabled\_repos | (Optional) List of repos to be enabled with yum-config-manager. Epel repo will be enabled by default. | list(string) | `<list>` | no |
| environment | Type of environment -- must be one of: dev, test, prod | string | n/a | yes |
| inbound\_cidrs | (Optional) IP address or range of addresses to be allowed to Firewall Zone. | list(string) | `<list>` | no |
| ingress\_cidr\_blocks | (Optional) List of CIDR block. | list(string) | `<list>` | no |
| instance\_type | Amazon EC2 instance type | string | `"t2.medium"` | no |
| key\_pair\_name | Keypair to associate to launched instances | string | n/a | yes |
| kms\_key\_id | Id of an AWS KMS key use for auto unseal operation when vault is intialize | string | `"null"` | no |
| lb\_internal | Boolean indicating whether the load balancer is internal or external | bool | `"true"` | no |
| lb\_ssl\_policy | The name of the SSL Policy for the listener | string | `"ELBSecurityPolicy-FS-2018-06"` | no |
| lb\_subnet\_ids | List of subnets to associate to the Load Balancer | list(string) | n/a | yes |
| max\_capacity | (Optional) Maximum number of instances in the Autoscaling Group | string | `"2"` | no |
| min\_capacity | (Optional) Minimum number of instances in the Autoscaling Group | string | `"1"` | no |
| name | Name of the vault stack, will be use to prefix resources | string | n/a | yes |
| pypi\_index\_url | (Optional) URL to the PyPi Index | string | `"https://pypi.org/simple"` | no |
| route53\_zone\_id | Hosted zone ID Route 53 hosted zone | string | n/a | yes |
| tags | (Optional) list of tags to include with resource | map(string) | `<map>` | no |
| toggle\_update | (Optional) Toggle that triggers a stack update by modifying the launch config, resulting in new instances; must be one of: A or B | string | `"A"` | no |
| vault\_configs\_path | (Optional) Path to directory that contains configuration files for vault | string | `"null"` | no |
| vault\_url | The DNS address that vault will be accessible at. Stack name will be used as the url when value is set to empty. Example: vault.domain.net | string | `"null"` | no |
| vault\_version | Version of Vault to be installed on servers | string | n/a | yes |
| watchmaker\_admin\_groups | (Optional) Colon-separated list of domain groups that should have admin permissions on the EC2 instance | string | `""` | no |
| watchmaker\_admin\_users | (Optional) Colon-separated list of domain users that should have admin permissions on the EC2 instance | string | `""` | no |
| watchmaker\_config | (Optional) URL to a Watchmaker config file | string | `""` | no |
| watchmaker\_ou\_path | (Optional) DN of the OU to place the instance when joining a domain. If blank and WatchmakerEnvironment enforces a domain join, the instance will be placed in a default container. Leave blank if not joining a domain, or if WatchmakerEnvironment is false | string | `""` | no |

## Outputs

| Name | Description |
|------|-------------|
| vault\_url | URL to access Vault UI |

