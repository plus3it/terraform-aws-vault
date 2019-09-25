{% from "vault/map.jinja" import vault with context %}

vault_logs_dir:
  file.directory:
    - name: /etc/vault/logs
    - user: vault
    - group: vault
    - mode: '0755'

sync_secrets_engines:
  vault.secret_engines_synced:
    - configs: {{ vault.secrets_engines }}

sync_authentication_methods:
  vault.auth_methods_synced:
    - configs: {{ vault.auth_methods }}

sync_audit_devices:
  vault.audit_devices_synced:
    - configs: {{ vault.audit_devices }}

sync_policies:
  vault.policies_synced:
    - policies: {{ vault.policies }}
