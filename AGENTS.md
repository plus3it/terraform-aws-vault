# Agent Instructions

Before starting any task in this repository:

1. Run `make agents/sync`. It writes the shared Plus3 IT instructions for this repository's tardigrade-ci version to `.agents/plus3it/AGENTS.md`.
2. Read `.agents/plus3it/AGENTS.md` and follow it together with this file. If the sync fails, tell the user, and don't guess the conventions.

These rules always apply, even without the shared instructions:

- Don't push, open pull requests, publish releases, or apply infrastructure changes unless the user asks. List those steps for a person in your final report.
- Don't edit files under `.agents/plus3it/`; they are generated and overwritten by the sync.

@.agents/plus3it/AGENTS.md

## Repository-specific

### Purpose

This Terraform module deploys a Vault server cluster on AWS. It creates an auto scaling group of instances (through the Plus3 IT `terraform-aws-watchmaker` module), an application load balancer with a Route 53 record and an ACM certificate, and an S3 bucket that holds the Salt files used to install and configure Vault. It also creates a DynamoDB table for Vault storage and a KMS key for auto unseal, unless you pass `dynamodb_table` or `kms_key_id`. The main inputs are `name`, `environment`, `vault_version`, `vault_pillar_path`, `domain_name`, `route53_zone_id`, and the subnet and AMI settings. The only output is `vault_url`.

### Module-specific files

- `modules/iam/` — Creates the instance IAM role, role policy, and instance profile; called by the root module, which passes the S3 bucket, DynamoDB table, KMS key, and SSM path into `iam_policy.json`; its only output is `profile_name`
- `policies/bucket_policy.json` — Template for the S3 bucket policy; rendered with `templatefile` in the root `main.tf`
- `scripts/appscript.sh` — Bootstrap script run on each instance; the root module renders it with the S3 locations of the Salt and pillar archives, and uploads it to the bucket; it downloads and unpacks those archives, then runs the `vault`, `vault.initialize`, and `vault.sync` Salt states
- `salt/` — Salt formula that the root module zips and uploads to the S3 bucket as `salt.zip`
  - `salt/vault/` — States that install, configure, run, initialize, and sync Vault, with Jinja templates in `files/` and OS maps in `maps/`
  - `salt/_modules/vault.py`, `salt/_states/vault.py`, `salt/_utils/vault.py` — Custom Salt extensions that use the `hvac` library to initialize Vault and to sync its secrets engines, auth methods, policies, and audit devices; `saltutil.sync_all` loads them on the instance
- `Vagrantfile` — Local development VM that mounts `salt/` as `/srv/salt` and syncs the Salt extensions
- `tests/vault-py2/` and `tests/vault-py3/` — Test scenarios that each call the root module, with a `prereq/` stack and a `pillar/` directory
