
# Vault AWS Terraform Module 

## `terraform-aws-vault`


## Overview

This Terraform module installs and configures the Hashicorp Vault cluster with HA DyanamoDb storage backend. This module is built on top of the `terraform-aws-watchmaker` module. You can quickly deploy a single instance of Vault or an auto-scaled group of Vault instances.

This module uses AWS DynamoDB as the storage backend to persist Vault's data. AWS DynamoDB storage backend supports High Availablity (HA) and also Point-In-Time-Recovery ([PITR](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery_Howitworks.html)) capability.

This module, by default, deploys a Watchmaker Linux AutoScaling Group with a minimum group size of 2 instances running on `STIG-Partitioned Enterprise Linux (SPEL) Centos 7` Amazon Machine Image (AMI) distributed by [Plus3 IT Systems](https://github.com/plus3it). `spel` is a project that helps create and publish Enterprise Linux images that are partitioned according to the [DISA STIG](http://iase.disa.mil/stigs/os/unix-linux/Pages/red-hat.asp). To learn more about `spel` visit our project space [here](https://github.com/plus3it/spel).

* For more information on using `terraform-aws-watchmaker`, go to <https://registry.terraform.io/modules/plus3it/watchmaker>.
* For more information on installing and using `watchmaker`, go to <https://watchmaker.readthedocs.io>.

## How To Navigate This Module

This repo is structured as follows:

* [Root](https://github.com/plus3it/terraform-aws-vault/tree/master): This folder contains a standalone, reusable, production-grade module that you can use to deploy a single Vault instance or a cluster of Vault instances that are partitioned according to the [DISA STIG[(http://iase.disa.mil/stigs/os/unix-linux/Pages/red-hat.aspx) with the help of `[watchmaker](https://github.com/plus3it/watchmaker)`.
* [Modules](https://github.com/plus3it/terraform-aws-vault/tree/master/modules/): The folder contains an IAM module that manages the IAM Roles and permissions required for this module to work correctly.

* [Policies](https://github.com/plus3it/terraform-aws-vault/tree/master/policies): This folder contains policies that can be referred to by the resources.

* [Salt](https://github.com/plus3it/terraform-aws-vault/tree/master/salt): This folder contains the `saltstack` modules and states to apply the pre-defined configuration to Vault instances.

* [Scripts](https://github.com/plus3it/terraform-aws-vault/tree/master/scripts): This folder contains the scripts to help with bootstrapping the application by retrieving the salt modules and pillar information from S3 and then run `salt-call` on the local minion.

* [Tests](https://github.com/plus3it/terraform-aws-vault/tree/master/tests): This folder contains the test cases as well as examples of how to implement this module.

## Usage

1. Create a `main.auto.tfvars`  file. See [`variables.tf`](variables.tf) for the required and optional variables. This file is ignored intentionally by source control so it is not committed to the project.
2. Create `pillar` folder and files in the following structure.
```
├── pillar
│   ├── top.sls
│   └── vault
│       └── init.sls
``` 
> **NOTE**: See [`tests\vault-py2\pillar`](tests\vault-py2\pillar) for an example on how to structure the `pillar` folder.

3. Then run the following command to deploy the module:
* `terraform init` (first time only)
* `terraform plan`
* `terraform apply`

## Pillar
This module uses SaltStack to handle the configuration of the Vault instances. We are going to use [`salt pillar`](https://docs.saltstack.com/en/getstarted/config/pillar.html ) to hold all configurations that will persist to the Vault minion. With `salt pillar`, users can securely define data/settings that are assigned to the minions. Users can store configuration settings such as values ports, file paths, configuration parameters, passwords, and much more to `salt pillar`. 

All Vault's configuration settings, such as authentication methods, secrets engines, audit devices, and policies, will be stored in `pillar`. Once the bootstrap script finished installing and configuring on the elastic computing instance, several custom salt state modules will be called to persist all settings that were defined in the `pillar` to Vault's HA DynamoDB storage backend. 

Example:
```yaml
vault:
  lookup:
    # These pillar items are templated by the Terraform `template_dir` resource: [https://www.terraform.io/docs/providers/template/r/dir.html]
    # Input vars can be defined and provided to the module through the `terraform.auto.tfvar` file.
    # See `variables.var` file for more information on each variables.
    api_port:  ${api_port}
    cluster_port:  ${cluster_port}
    dynamodb_table:  ${dynamodb_table}
    inbound_cidrs:  ${inbound_cidrs}
    kms_key_id:  ${kms_key_id}
    logs_path:  ${logs_path}
    logs_dir:  ${logs_dir}
    region:  ${region}
    ssm_path:  ${ssm_path}
    version:  ${vault_version}

    secrets_engines:
      - type:  kv
        path:  services
        description:  Sevices specific folders
        config:
          default_lease_ttl:  1800
          max_lease_ttl:  1800
        secret_config: ${secrets_kv_config}
      # Additional secrets engines can be configure here


    auth_methods:
      - type:  token
        path:  token
        description:  token based credentials
        config:
          default_lease_ttl:  0
          max_lease_ttl:  0
        auth_config: ${auth_token_config}
      # Additional authentication methods can be configure here


    audit_devices:
      - type:  file
        path:  file_log
        description:  first audit device
        config:
        file_path:  /etc/vault/logs/audit.log
      # Additional audit devices can be configure here

    policies:
      # Following example of vault policy from https://learn.hashicorp.com/vault/identity-access-management/iam-policies
      admin:
        path:
          # Manage ad secret engines broadly across Vault
          'ad/*': {capabilities: [create, read, update, delete, list, sudo]}
          # Manage auth methods broadly across Vault
          'auth/*': {capabilities: [create, read, update, delete, list, sudo]}
```
> ***Note***: Additional configurations can be specified for authentication methods using the `auth_config` pillar item. This also applies for secrets engines. Specifying the configuration for a particular secrets engine under the `secret_config` pillar item of that secrets engine type.

In some use cases, passwords or sensitive information will need to be provided in order for Vault to communicate and function properly. For instance, when enabling the [Active Directory Secrets Engine](https://www.vaultproject.io/api/secret/ad/index.html), you need to specify the url of the LDAP server, a bind_dn and a bind_pass to perform user search. This information will need to be hidden from the public and only available to `salt` when it synchronizes the configs. One way to specify these config is via the input  `vault_pillar_extra_config` variable within the `terraform.auto.tfvar` file.

Example:
`terraform.auto.tfvar` file:
```terraform
template_vars = {
  auth_ldap_config = {
    user_dn =  "CN=Users,DC=ad,DC=example,DC=com"
    group_dn =  "CN=Users,DC=ad,DC=example,DC=com"
    url =  "ldaps://ad.example.com"
    insecure_tls =  true
    user_attr =  "cn"
    group_attr =  "memberOf"
    group_filter =  "{{ '(&(objectClass=person)(cn={{.Username}}))' | yaml }}"
  },
  auth_ldap_extra_config = {
    group_policy_map = {
      acb_admin = {
        name     = "administrator",
        policies = ["admin"]
      }
    }
  }
}
```
`init.sls` pillar file:
```yaml 
auth_methods:
  - type:  ldap
    path:  ldap
    description:  LDAP Auth
    config:
      default_lease_ttl:  1800
      max_lease_ttl:  1800
    secret_config:  ${auth_ldap_config}
    extra_config: ${auth_ldap_extra_config}
```

> ***Note***: You can use the `${type_name_config}` pattern to reference the config specified in the `template_vars` input var. 

## Vault Salt State Modules
This module contains several custom salt state modules to help with syncronizing Vault's configurations. Base on the values defined in the `pillar`, these custom state modules will enable, disable, or tune the configurations of Vault's auth methods, secrets engines, audit devices, and policies. The custom state modules interact with the Vault API endpoints via Python 2.7/3.x Hashicorp Vault API Client ([`hvac`](https://hvac.readthedocs.io/)). See details for each custom state module below:

#### `vault.secret_engines_synced` 
This state module responsible for syncronizing secrets engines configurations between the pillar and the remote Vault instances. The module will look for configuration within the key `secrets_engines` from the pillar. Specify configuration for the secrets engine within this key. 
Example:
```yaml
sync_secrets_engines:
  vault.secret_engines_synced:
    -  configs: {{ vault.secrets_engines | yaml }}
```
#### `vault.auth_methods_synced`
This state module responsible for syncronizing authentication methods configurations between the pillar and the remote Vault instances. The module will look for configuration within the key `auth_methods` from the pillar. Specify configuration for each auth method within this key. 
Example:
```yaml
sync_authentication_methods:
  vault.auth_methods_synced:
    -  configs: {{ vault.auth_methods | yaml }}
```
#### `vault.audit_devices_synced`
This state module responsible for syncronizing audit devices configurations between the pillar and the remote Vault instances. The module will look for configuration within the key `audit_devices` from the pillar. Specify configuration for each audit device within this key. 
Example:
```yaml
sync_audit_devices:
  vault.audit_devices_synced:
    - configs: {{ vault.audit_devices | yaml }}
```
#### `vault.policies_synced`
This state module responsible for synchronizing policies between the pillar and the remote Vault instances. The module will look for configuration within the key `policies` from the pillar. Specify configuration for each policy within this key. 
Example:
```yaml
sync_policies:
  vault.policies_synced:
    - policies: {{ vault.policies | yaml }}
```

<!-- BEGIN TFDOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 0.12 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_archive"></a> [archive](#provider\_archive) | n/a |
| <a name="provider_aws"></a> [aws](#provider\_aws) | n/a |
| <a name="provider_local"></a> [local](#provider\_local) | n/a |
| <a name="provider_random"></a> [random](#provider\_random) | n/a |
| <a name="provider_template"></a> [template](#provider\_template) | n/a |

## Resources

| Name | Type |
|------|------|
| [archive_file.pillar](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [archive_file.salt](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [aws_ami.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ami) | data source |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |
| [aws_route53_zone.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/route53_zone) | data source |
| [aws_subnet.lb](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/subnet) | data source |
| [template_file.appscript](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/file) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_ami_owners"></a> [ami\_owners](#input\_ami\_owners) | (Required) Account id/alias of the AMI owners | `list(string)` | n/a | yes |
| <a name="input_domain_name"></a> [domain\_name](#input\_domain\_name) | (Required) The domain name where vault url will be registered to. Example: domain.net | `string` | n/a | yes |
| <a name="input_ec2_subnet_ids"></a> [ec2\_subnet\_ids](#input\_ec2\_subnet\_ids) | (Required) List of subnets where EC2 instances will be launched | `list(string)` | n/a | yes |
| <a name="input_environment"></a> [environment](#input\_environment) | (Required) Type of environment -- must be one of: dev, test, prod | `string` | n/a | yes |
| <a name="input_key_pair_name"></a> [key\_pair\_name](#input\_key\_pair\_name) | (Required) Keypair to associate to launched instances | `string` | n/a | yes |
| <a name="input_lb_subnet_ids"></a> [lb\_subnet\_ids](#input\_lb\_subnet\_ids) | (Required) List of subnets to associate to the Load Balancer | `list(string)` | n/a | yes |
| <a name="input_name"></a> [name](#input\_name) | (Required) Name of the vault stack, will be use to prefix resources | `string` | n/a | yes |
| <a name="input_route53_zone_id"></a> [route53\_zone\_id](#input\_route53\_zone\_id) | (Required) Hosted zone ID Route 53 hosted zone | `string` | n/a | yes |
| <a name="input_vault_pillar_path"></a> [vault\_pillar\_path](#input\_vault\_pillar\_path) | (Required) Specify the path to vault pillar | `string` | n/a | yes |
| <a name="input_vault_version"></a> [vault\_version](#input\_vault\_version) | (Required) Version of Vault to be installed on servers | `string` | n/a | yes |
| <a name="input_ami_name_filters"></a> [ami\_name\_filters](#input\_ami\_name\_filters) | (Optional) Will be use to filter out AMI | `list(string)` | <pre>[<br>  "spel-minimal-centos-7-hvm-*.x86_64-gp2"<br>]</pre> | no |
| <a name="input_ami_name_regex"></a> [ami\_name\_regex](#input\_ami\_name\_regex) | (Optional) Regex to help fine-grain filtering AMI | `string` | `"spel-minimal-centos-7-hvm-\\d{4}\\.\\d{2}\\.\\d{1}\\.x86_64-gp2"` | no |
| <a name="input_api_port"></a> [api\_port](#input\_api\_port) | (Optional) The port to use for Vault API calls | `number` | `8200` | no |
| <a name="input_certificate_arn"></a> [certificate\_arn](#input\_certificate\_arn) | (Optional) The ARN of the default SSL server certificate to be use for HTTPS lb listener. | `string` | `null` | no |
| <a name="input_cfn_bootstrap_utils_url"></a> [cfn\_bootstrap\_utils\_url](#input\_cfn\_bootstrap\_utils\_url) | (Optional) URL to aws-cfn-bootstrap-latest.tar.gz | `string` | `"https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.tar.gz"` | no |
| <a name="input_cfn_endpoint_url"></a> [cfn\_endpoint\_url](#input\_cfn\_endpoint\_url) | (Optional) URL to the CloudFormation Endpoint. e.g. https://cloudformation.us-east-1.amazonaws.com | `string` | `"https://cloudformation.us-east-1.amazonaws.com"` | no |
| <a name="input_cloudwatch_agent_url"></a> [cloudwatch\_agent\_url](#input\_cloudwatch\_agent\_url) | (Optional) S3 URL to CloudWatch Agent installer. Example: s3://amazoncloudwatch-agent/linux/amd64/latest/AmazonCloudWatchAgent.zip | `string` | `""` | no |
| <a name="input_cluster_port"></a> [cluster\_port](#input\_cluster\_port) | (Optional) The port to use for Vault server-to-server communication. | `number` | `8201` | no |
| <a name="input_desired_capacity"></a> [desired\_capacity](#input\_desired\_capacity) | (Optional) Desired number of instances in the Autoscaling Group | `string` | `"2"` | no |
| <a name="input_dynamodb_max_read_capacity"></a> [dynamodb\_max\_read\_capacity](#input\_dynamodb\_max\_read\_capacity) | (Optional) The max capacity of the scalable target for DynamoDb table autoscaling. | `number` | `100` | no |
| <a name="input_dynamodb_min_read_capacity"></a> [dynamodb\_min\_read\_capacity](#input\_dynamodb\_min\_read\_capacity) | (Optional) The min capacity of the scalable target for DynamoDb table autoscaling. | `number` | `5` | no |
| <a name="input_dynamodb_table"></a> [dynamodb\_table](#input\_dynamodb\_table) | (Optional) Name of the Dynamodb to be used as storage backend for Vault | `string` | `null` | no |
| <a name="input_dynamodb_target_value"></a> [dynamodb\_target\_value](#input\_dynamodb\_target\_value) | (Optional) The target value for the metric of the scaling policy configuration. | `number` | `70` | no |
| <a name="input_ec2_extra_security_group_ids"></a> [ec2\_extra\_security\_group\_ids](#input\_ec2\_extra\_security\_group\_ids) | (Required) List of additional security groups to add to EC2 instances | `list(string)` | `[]` | no |
| <a name="input_enabled_repos"></a> [enabled\_repos](#input\_enabled\_repos) | (Optional) List of repos to be enabled with yum-config-manager. Epel repo will be enabled by default. | `list(string)` | `[]` | no |
| <a name="input_inbound_cidrs"></a> [inbound\_cidrs](#input\_inbound\_cidrs) | (Optional) IP address or range of addresses to be allowed to Firewall Zone. | `list(string)` | `[]` | no |
| <a name="input_ingress_cidr_blocks"></a> [ingress\_cidr\_blocks](#input\_ingress\_cidr\_blocks) | (Optional) List of CIDR block. | `list(string)` | <pre>[<br>  "0.0.0.0/0"<br>]</pre> | no |
| <a name="input_instance_type"></a> [instance\_type](#input\_instance\_type) | (Optional) Amazon EC2 instance type | `string` | `"t2.medium"` | no |
| <a name="input_kms_key_id"></a> [kms\_key\_id](#input\_kms\_key\_id) | (Optional) Id of an AWS KMS key use for auto unseal operation when vault is intialize | `string` | `null` | no |
| <a name="input_lb_internal"></a> [lb\_internal](#input\_lb\_internal) | (Optional) Boolean indicating whether the load balancer is internal or external | `bool` | `true` | no |
| <a name="input_lb_ssl_policy"></a> [lb\_ssl\_policy](#input\_lb\_ssl\_policy) | (Optional) The name of the SSL Policy for the listener | `string` | `"ELBSecurityPolicy-FS-2018-06"` | no |
| <a name="input_max_capacity"></a> [max\_capacity](#input\_max\_capacity) | (Optional) Maximum number of instances in the Autoscaling Group | `string` | `"2"` | no |
| <a name="input_min_capacity"></a> [min\_capacity](#input\_min\_capacity) | (Optional) Minimum number of instances in the Autoscaling Group | `string` | `"1"` | no |
| <a name="input_override_json"></a> [override\_json](#input\_override\_json) | (Optional) Override the current policy document | `string` | `""` | no |
| <a name="input_point_in_time_recovery"></a> [point\_in\_time\_recovery](#input\_point\_in\_time\_recovery) | (Optional) Enabling Amazon DynamoDB point-in-time recovery (PITR) provides automatic backups of your DynamoDB table data. | `bool` | `true` | no |
| <a name="input_pypi_index_url"></a> [pypi\_index\_url](#input\_pypi\_index\_url) | (Optional) URL to the PyPi Index | `string` | `"https://pypi.org/simple"` | no |
| <a name="input_scale_down_schedule"></a> [scale\_down\_schedule](#input\_scale\_down\_schedule) | (Optional) Scheduled Action in cron-format (UTC) to scale down to MinCapacity; ignored if empty or ScaleUpSchedule is unset (E.g. '0 0 * * *') | `string` | `null` | no |
| <a name="input_scale_up_schedule"></a> [scale\_up\_schedule](#input\_scale\_up\_schedule) | (Optional) Scheduled Action in cron-format (UTC) to scale up to MaxCapacity; ignored if empty or ScaleDownSchedule is unset (E.g. '0 10 * * Mon-Fri') | `string` | `null` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | (Optional) List of tags to include with resource | `map(string)` | `{}` | no |
| <a name="input_template_vars"></a> [template\_vars](#input\_template\_vars) | (Optional) List extra configurations to be referenced in the pillar | `map` | `{}` | no |
| <a name="input_toggle_update"></a> [toggle\_update](#input\_toggle\_update) | (Optional) Toggle that triggers a stack update by modifying the launch config, resulting in new instances; must be one of: A or B | `string` | `"A"` | no |
| <a name="input_vault_url"></a> [vault\_url](#input\_vault\_url) | (Optional) The DNS address that vault will be accessible at. Stack name will be used as the url when value is set to empty. Example: vault.domain.net | `string` | `null` | no |
| <a name="input_watchmaker_admin_groups"></a> [watchmaker\_admin\_groups](#input\_watchmaker\_admin\_groups) | (Optional) Colon-separated list of domain groups that should have admin permissions on the EC2 instance | `string` | `""` | no |
| <a name="input_watchmaker_admin_users"></a> [watchmaker\_admin\_users](#input\_watchmaker\_admin\_users) | (Optional) Colon-separated list of domain users that should have admin permissions on the EC2 instance | `string` | `""` | no |
| <a name="input_watchmaker_config"></a> [watchmaker\_config](#input\_watchmaker\_config) | (Optional) URL to a Watchmaker config file | `string` | `""` | no |
| <a name="input_watchmaker_ou_path"></a> [watchmaker\_ou\_path](#input\_watchmaker\_ou\_path) | (Optional) DN of the OU to place the instance when joining a domain. If blank and WatchmakerEnvironment enforces a domain join, the instance will be placed in a default container. Leave blank if not joining a domain, or if WatchmakerEnvironment is false | `string` | `""` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_vault_url"></a> [vault\_url](#output\_vault\_url) | URL to access Vault UI |

<!-- END TFDOCS -->
