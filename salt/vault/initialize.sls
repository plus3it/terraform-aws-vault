{% from "vault/map.jinja" import vault with context %}

# Perform initialization and unseal process
vault_initialize_server:
  vault.initialized:
    - recovery_shares: {{ vault.recovery_shares }}
    - recovery_threshold: {{ vault.recovery_threshold }}
    - ssm_path: {{ vault.ssm_path }}

