{% from "vault/map.jinja" import vault with context %}

Sync Vault Policies:
  module.run:
    - vault.policies_synced:
      - policies_dir_path: "{{ vault.config_dir_path }}/policies"

Sync Vault Authentication Methods:
  module.run:
    - vault.auth_methods_synced:
      - config_path: "{{ vault.config_dir_path }}/auth_config.yml"
    - required:
      - module.run: Sync Vault Policies

Sync Vault Secrets Engines:
  module.run:
    - vault.secrets_engines_synced:
      - config_path: "{{ vault.config_dir_path }}/secrets_config.yml"

Sync Vault Audit Devices:
  module.run:
    - vault.audit_devices_synced:
      - config_path: "{{ vault.config_dir_path }}/audit_config.yml"
