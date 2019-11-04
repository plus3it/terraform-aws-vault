
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
