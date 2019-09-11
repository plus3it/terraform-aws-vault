
{% from "vault/map.jinja" import vault with context %}

vault_configure_service_file:
  file.managed:
{%- if vault.dev_mode %}
    - source: salt://vault/files/server.dev.hcl.jinja
{% else %}
    - source: salt://vault/files/server.hcl.jinja
{%- endif %}
    - name: /etc/vault/conf.d/server.hcl
    - template: jinja
    - defaults:
        ip_address: {{ grains.ip_interfaces.eth0.0 }}
        api_port: {{ vault.api_port }}
        cluster_port: {{ vault.cluster_port }}
        region: {{ vault.region }}
        dynamodb_table: {{ vault.dynamodb_table }}
        kms_key_id: {{ vault.kms_key_id }}
        listener_address: {{ vault.listener_address }}
        listener_tls_disable: {{ vault.listener_tls_disable }}
        default_lease_ttl: {{ vault.default_lease_ttl }}
        max_lease_ttl: {{ vault.max_lease_ttl }}
    - user: root
    - group: root
    - mode: '0755'
    - makedirs: True
