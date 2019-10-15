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

    auth_methods:
      - type: token
        path: token
        description: token based credentials
        config:
          default_lease_ttl: 0
          max_lease_ttl: 0

    audit_devices:
      - type: file
        path: file_log
        description: first audit device
        config:
          file_path: /etc/vault/logs/audit.log

    policies:
      - name: xyz_admin
        content:
          path:
            '*': {capabilities: [read, create]}
            'stage/*': {capabilities: [read, create, update, delete, list]}

      - name: abc_admin
        content:
          path:
            '*': {capabilities: [read, create]}
            'stage/*': {capabilities: [read, create]}
