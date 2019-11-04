## terraform-aws-vault Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/) and this project adheres to [Semantic Versioning](http://semver.org/).

### 0.0.4

**Commit Delta**: [Change from 0.0.3 release](https://github.com/plus3it/terraform-aws-vault/compare/0.0.3...0.0.4)

**Released**: 2019.11.04

**Summary**:

* Fixed unsupported argument error on Dynamnodb resource. `point-in-time-recovery` needs to be defined as a block type.
* Added more instructions to `README.md` on how to use the module and how to compose configs for the pillar.

### 0.0.3

**Commit Delta**: [Change from 0.0.2 release](https://github.com/plus3it/terraform-aws-vault/compare/0.0.2...0.0.3)

**Released**: 2019.11.01

**Summary**:

* Added `vault_pillar_extra_config` input var. Allowing users to add sensitive information to the pillar by `auto.tfvars`
* Added sample configs for `auth_ldap` and `secret_ad` to the test cases

### 0.0.2

**Commit Delta**: [Change from 0.0.1 release](https://github.com/plus3it/terraform-aws-vault/compare/0.0.1...0.0.2)

**Released**: 2019.10.31

**Summary**:

* Added `yaml` filter to vault.sync salt state
* Changed sample policies in the `pillar` for the test cases
* Added pillar to the local dev Vagrant setup
  
### 0.0.1

**Commit Delta**: [Change from 0.0.0 release](https://github.com/plus3it/terraform-aws-vault/compare/0.0.0...0.0.1)

**Released**: 2019.10.31

**Summary**:

*   Add `point-in-time-recovery` option to dynamodb resource

### 0.0.0

**Commit Delta**: N/A

**Released**: 2019.07.08

**Summary**:

*   Initial release!
