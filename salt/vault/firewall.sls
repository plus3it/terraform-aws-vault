
{% from "vault/map.jinja" import vault with context %}

firewalld_vault_service:
  firewalld.service:
    - name: vault
    - ports:
      - 8200/tcp
      - 8201/tcp

firewalld_vault_zone:
  firewalld.present:
    - name: vaultzone
    - services:
      - vault
    - sources:
{%- for mac, properties in salt.grains.get('meta-data:network:interfaces:macs', {}).items() %}
  {%- if properties['device-number'] == "0" %}
    {%- for cidr in properties['vpc-ipv4-cidr-blocks'].split('\n') %}
      - {{ cidr }}
    {%- endfor %}
  {%- endif %}
{%- endfor %}
    - require:
      - firewalld: firewalld_vault_service
