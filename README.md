
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
      # More secrets engines can be configure here
    auth_methods:
      - type:  token
      path:  token
      description:  token based credentials
      config:
        default_lease_ttl:  0
        max_lease_ttl:  0
      auth_config: ${auth_token_config}
    # More authentication methods can be configure here
      audit_devices:
        - type:  file
          path:  file_log
          description:  first audit device
          config:
          file_path:  /etc/vault/logs/audit.log
    # More audit devices can be configure here
    policies:
      # Following example of vault policy from https://learn.hashicorp.com/vault/identity-access-management/iam-policies
        - name:  admin
          content:
            path:
              # Manage ad secret engines broadly across Vault
              'ad/*': {capabilities: [create, read, update, delete, list, sudo]}
              # List auth methods
              'sys/auth': {capabilities: [read]}
              # List existing secret engines.'
              sys/mounts': {capabilities: [read]}
              # Read health check
              'sys/health': {capabilities: [read, sudo]}
```
> ***Note***: Additional configurations can be specified for authentication methods using the `auth_config` pillar item. This also applies for secrets engines. Specifying the configuration for a particular secrets engine under the `secret_config` pillar item of that secrets engine type.

In some use cases, passwords or sensitive information will need to be provided in order for Vault to communicate and function properly. For instance, when enabling the [Active Directory Secrets Engine](https://www.vaultproject.io/api/secret/ad/index.html), you need to specify the url of the LDAP server, a bind_dn and a bind_pass to perform user search. This information will need to be hidden from the public and only available to `salt` when it synchronizes the configs. One way to specify these config is via the input  `vault_pillar_extra_config` variable within the `terraform.auto.tfvar` file.

Example:
`terraform.auto.tfvar` file:
```terraform
vault_pillar_extra_config = [
  {
    name =  "ldap"
    type =  "auth"
    config = {
      user_dn =  "CN=Users,DC=ad,DC=example,DC=com"
      group_dn =  "CN=Users,DC=ad,DC=example,DC=com"
      url =  "ldaps://ad.example.com"
      insecure_tls =  true
      user_attr =  "cn"
      group_attr =  "memberOf"
      group_filter =  "{{ '(&(objectClass=person)(cn={{.Username}}))' | yaml }}"
    }
  }
]
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
    auth_config:  ${auth_ldap_config}
```

> ***Note***: You can use the `${type_name_config}` pattern to reference the config specified in the `vault_pillar_extra_config` input var. 

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

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|:----:|:-----:|:-----:|
| ami\_name\_filters | Will be use to filter out AMI | list(string) | `<list>` | no |
| ami\_name\_regex | Regex to help fine-grain filtering AMI | string | `"spel-minimal-centos-7-hvm-\\d{4}\\.\\d{2}\\.\\d{1}\\.x86_64-gp2"` | no |
| ami\_owners | Account id/alias of the AMI owners | list(string) | n/a | yes |
| api\_port | The port to use for Vault API calls | string | `"8200"` | no |
| certificate\_arn | The ARN of the default SSL server certificate to be use for HTTPS lb listener. | string | `"null"` | no |
| cfn\_bootstrap\_utils\_url | \(Optional\) URL to aws-cfn-bootstrap-latest.tar.gz | string | `"https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.tar.gz"` | no |
| cfn\_endpoint\_url | \(Optional\) URL to the CloudFormation Endpoint. e.g. https://cloudformation.us-east-1.amazonaws.com | string | `"https://cloudformation.us-east-1.amazonaws.com"` | no |
| cloudwatch\_agent\_url | \(Optional\) S3 URL to CloudWatch Agent installer. Example: s3://amazoncloudwatch-agent/linux/amd64/latest/AmazonCloudWatchAgent.zip | string | `""` | no |
| cluster\_port | The port to use for Vault server-to-server communication. | string | `"8201"` | no |
| desired\_capacity | \(Optional\) Desired number of instances in the Autoscaling Group | string | `"2"` | no |
| domain\_name | The domain name where vault url will be registered to. Example: domain.net | string | n/a | yes |
| dynamodb\_max\_read\_capacity | \(Optional\) The max capacity of the scalable target for DynamoDb table autoscaling. | number | `"100"` | no |
| dynamodb\_min\_read\_capacity | \(Optional\) The min capacity of the scalable target for DynamoDb table autoscaling. | number | `"5"` | no |
| dynamodb\_table | Name of the Dynamodb to be used as storage backend for Vault | string | `"null"` | no |
| dynamodb\_target\_value | \(Optional\) The target value for the metric of the scaling policy configuration. | number | `"70"` | no |
| ec2\_extra\_security\_group\_ids | List of additional security groups to add to EC2 instances | list(string) | `<list>` | no |
| ec2\_subnet\_ids | List of subnets where EC2 instances will be launched | list(string) | n/a | yes |
| enabled\_repos | \(Optional\) List of repos to be enabled with yum-config-manager. Epel repo will be enabled by default. | list(string) | `<list>` | no |
| environment | Type of environment -- must be one of: dev, test, prod | string | n/a | yes |
| inbound\_cidrs | \(Optional\) IP address or range of addresses to be allowed to Firewall Zone. | list(string) | `<list>` | no |
| ingress\_cidr\_blocks | \(Optional\) List of CIDR block. | list(string) | `<list>` | no |
| instance\_type | Amazon EC2 instance type | string | `"t2.medium"` | no |
| key\_pair\_name | Keypair to associate to launched instances | string | n/a | yes |
| kms\_key\_id | Id of an AWS KMS key use for auto unseal operation when vault is intialize | string | `"null"` | no |
| lb\_internal | Boolean indicating whether the load balancer is internal or external | bool | `"true"` | no |
| lb\_ssl\_policy | The name of the SSL Policy for the listener | string | `"ELBSecurityPolicy-FS-2018-06"` | no |
| lb\_subnet\_ids | List of subnets to associate to the Load Balancer | list(string) | n/a | yes |
| max\_capacity | \(Optional\) Maximum number of instances in the Autoscaling Group | string | `"2"` | no |
| min\_capacity | \(Optional\) Minimum number of instances in the Autoscaling Group | string | `"1"` | no |
| name | Name of the vault stack, will be use to prefix resources | string | n/a | yes |
| override\_json | \(Optional\) Override the current policy document | string | `""` | no |
| point\_in\_time\_recovery | \(Optional\) Enabling Amazon DynamoDB point-in-time recovery \(PITR\) provides automatic backups of your DynamoDB table data. | bool | `"true"` | no |
| pypi\_index\_url | \(Optional\) URL to the PyPi Index | string | `"https://pypi.org/simple"` | no |
| route53\_zone\_id | Hosted zone ID Route 53 hosted zone | string | n/a | yes |
| scale\_down\_schedule | \(Optional\) Scheduled Action in cron-format \(UTC\) to scale down to MinCapacity; ignored if empty or ScaleUpSchedule is unset \(E.g. '0 0 \* \* \*'\) | string | `"null"` | no |
| scale\_up\_schedule | \(Optional\) Scheduled Action in cron-format \(UTC\) to scale up to MaxCapacity; ignored if empty or ScaleDownSchedule is unset \(E.g. '0 10 \* \* Mon-Fri'\) | string | `"null"` | no |
| tags | \(Optional\) List of tags to include with resource | map(string) | `<map>` | no |
| template\_vars | \(Optional\) List extra configurations to be referenced in the pillar | map | `<map>` | no |
| toggle\_update | \(Optional\) Toggle that triggers a stack update by modifying the launch config, resulting in new instances; must be one of: A or B | string | `"A"` | no |
| vault\_pillar\_path | Specify the path to vault pillar | string | n/a | yes |
| vault\_url | The DNS address that vault will be accessible at. Stack name will be used as the url when value is set to empty. Example: vault.domain.net | string | `"null"` | no |
| vault\_version | Version of Vault to be installed on servers | string | n/a | yes |
| watchmaker\_admin\_groups | \(Optional\) Colon-separated list of domain groups that should have admin permissions on the EC2 instance | string | `""` | no |
| watchmaker\_admin\_users | \(Optional\) Colon-separated list of domain users that should have admin permissions on the EC2 instance | string | `""` | no |
| watchmaker\_config | \(Optional\) URL to a Watchmaker config file | string | `""` | no |
| watchmaker\_ou\_path | \(Optional\) DN of the OU to place the instance when joining a domain. If blank and WatchmakerEnvironment enforces a domain join, the instance will be placed in a default container. Leave blank if not joining a domain, or if WatchmakerEnvironment is false | string | `""` | no |

## Outputs

| Name | Description |
|------|-------------|
| vault\_url | URL to access Vault UI |

