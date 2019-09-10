{% from "vault/map.jinja" import vault with context %}

manage_selinux_mode:
  selinux.mode:
    - name: permissive

vault_service_init_file_managed:
  file.managed:
    - name: {{ vault.service.path }}
    - source: {{ vault.service.source }}
    - template: jinja
    - defaults:
{%- if vault.dev_mode %}
        config: -dev -dev-root-token-id=root -config /srv/salt/vault/files/server.dev.hcl
{% else %}
        config: -config=/etc/vault/conf.d
{% endif -%}

vault_service_running:
  service.running:
    - name: vault
    - enable: True
    - reload: True
    - require:
      - selinux: manage_selinux_mode
