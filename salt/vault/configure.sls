
{% from "vault/map.jinja" import vault with context %}

{# only configure if vault is not in dev_mode #}
{%- if not vault.dev_mode %}

vault_configure_service_file:
  file.managed:
    - source: salt://vault/files/server.hcl.jinja
    - name: /etc/vault/conf.d/server.hcl
    - template: jinja
    - user: root
    - group: root
    - mode: '0755'
    - makedirs: True

{%- endif %}
