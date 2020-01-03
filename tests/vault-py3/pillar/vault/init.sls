vault:
  lookup:
    api_port: ${api_port}
    cluster_port: ${cluster_port}
    dynamodb_table: ${dynamodb_table}
    inbound_cidrs: ${inbound_cidrs}
    kms_key_id: ${kms_key_id}
    logs_path: ${logs_path}
    logs_dir: ${logs_dir}
    region: ${region}
    ssm_path: ${ssm_path}
    version: ${vault_version}

    secrets_engines:
      - type: kv
        path: services
        description: Sevices specific folders
        config:
          default_lease_ttl: 1800
          max_lease_ttl: 1800
      - type: ad
        path: ad
        description: Provides auto-rotate password for AD accounts
        config:
          default_lease_ttl: 1800
          max_lease_ttl: 1800
        secret_config: ${secrets_ad_config}
        extra_config: ${secrets_ad_extra_config}

    auth_methods:
      - type: aws
        path: aws #path will be auth/aws
        description: Authenticate AWS Instances
        config:
          default_lease_ttl: 1800
          max_lease_ttl: 1800
        extra_config: ${auth_aws_extra_config}
      - type: ldap
        path: ldap
        description: LDAP Auth
        config:
          default_lease_ttl: 1800
          max_lease_ttl: 1800
        auth_config: ${auth_ldap_config}
        extra_config: ${auth_ldap_extra_config}

    audit_devices:
      - type: file
        path: file_log
        description: first audit device
        config:
          file_path: /etc/vault/logs/audit.log

    policies:
      # Following example of vault policy from https://learn.hashicorp.com/vault/identity-access-management/iam-policies
      admin:
        path:
          # Manage ad secret engines broadly across Vault
          'ad/*': {capabilities: [create, read, update, delete, list, sudo]}
          # Manage auth methods broadly across Vault
          'auth/*': {capabilities: [create, read, update, delete, list, sudo]}
          # List, create, update, and delete key/value secrets
          'secret/*':  {capabilities: [create, read, update, delete, list, sudo]}
          # Manage secret engines
          'secret/mounts/*':  {capabilities: [create, read, update, delete, list, sudo]}
          # Create, update, and delete auth methods
          'sys/auth/*':  {capabilities: [create, update, delete, sudo]}
          # List auth methods
          'sys/auth':  {capabilities: [read]}
          # List existing policies
          'sys/policies/acl':  {capabilities: [list]}
          # Create and manage ACL policies
          'sys/policies/acl/*':  {capabilities: [create, read, update, delete, list, sudo]}
          # List existing secret engines.
          'sys/mounts':  {capabilities: [read]}
          # Read health check
          'sys/health':  {capabilities: [read, sudo]}
      watchmaker:
        path:
          # Manage ad secret engines broadly across Vault
          'ad/creds/join-domain-role': {capabilities: [create, read, update, delete, list, sudo]}
      ad_auto_rotate_pwd_read:
        path:
          # Manage ad secret engines broadly across Vault
          'ad/creds/svc_vault_test': {capabilities: [read]}
