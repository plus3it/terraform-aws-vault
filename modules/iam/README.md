<!-- BEGIN TFDOCS -->
## Requirements

No requirements.

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | n/a |
| <a name="provider_template"></a> [template](#provider\_template) | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.instance_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.instance_trust_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |
| [template_file.instance_policy](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/file) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_policy_vars"></a> [policy\_vars](#input\_policy\_vars) | Variables for interpolation within the template. Must include the following vars: bucket\_name, dynamodb\_table, kms\_key\_id, stack\_name, ssm\_path | `map(string)` | n/a | yes |
| <a name="input_role_name"></a> [role\_name](#input\_role\_name) | Name of the role to be create for vault | `string` | n/a | yes |
| <a name="input_override_json"></a> [override\_json](#input\_override\_json) | Override the current policy document. | `string` | `""` | no |
| <a name="input_url_suffix"></a> [url\_suffix](#input\_url\_suffix) | URL suffix associated with the current partition | `string` | `"amazonaws.com"` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_profile_name"></a> [profile\_name](#output\_profile\_name) | n/a |

<!-- END TFDOCS -->