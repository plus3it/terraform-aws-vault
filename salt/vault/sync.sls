{% from "vault/map.jinja" import vault with context %}

vault_logs_dir:
  file.directory:
    - name: /etc/vault/logs
    - user: vault
    - group: vault
    - mode: '0755'

sync_secrets_engines:
  vault.secret_engines_synced:
    - configs:
      - type: kv
        path: services
        description: Sevices specific folders
        config:
          default_lease_ttl: 1800
          max_lease_ttl: 1800

sync_authentication_methods:
  vault.auth_methods_synced:
    - configs:
      - type: token
        path: token
        description: token based credentials
        config:
          default_lease_ttl: 0
          max_lease_ttl: 0

sync_audit_devices:
  vault.audit_devices_synced:
    - configs:
      - type: file
        path: file_log
        description: first audit device
        config:
          file_path: /etc/vault/logs/audit.log

sync_policies:
  vault.policies_synced:
    - policies:
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
