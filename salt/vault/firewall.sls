
{% from "vault/map.jinja" import vault with context %}

{%- if not vault.dev_mode %}

firewalld_vault_service:
  firewalld.service:
    - name: vault
    - ports:
      - {{ vault.api_port }}/tcp
      - {{ vault.cluster_port }}/tcp

firewalld_vault_zone:
  firewalld.present:
    - name: vaultzone
    - services:
      - vault
    - sources: {{ vault.inbound_cidrs }}
    - require:
      - firewalld: firewalld_vault_service

{%- endif %}
