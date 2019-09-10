# -*- coding: utf-8 -*-

{% from "vault/map.jinja" import vault with context %}

vault_package_install_group_present:
  group.present:
    - name: vault
    - system: True

vault_package_install_user_present:
  user.present:
    - name: vault
    - system: True
    - gid_from_name: True
    - home: /var/lib/vault

vault_data_dir:
  file.directory:
    - name: /etc/vault
    - user: vault
    - group: vault
    - mode: '0755'

install_vault_binary:
  archive.extracted:
    - name: /usr/local/bin/
    - source: {{ vault.repo_base_url }}/{{ vault.version }}/vault_{{ vault.version }}_{{ vault.platform }}.zip
    - source_hash: {{ vault.repo_base_url }}/{{ vault.version }}/vault_{{ vault.version }}_SHA256SUMS
    - archive_format: zip
    - if_missing: /usr/local/bin/vault
    - source_hash_update: True
    - enforce_toplevel: False
  file.managed:
    - name: /usr/local/bin/vault
    - mode: '0755'
    - require:
      - archive: install_vault_binary

install_package_dependencies:
  pkg.installed:
    - pkgs: {{ vault.module_dependencies.pkgs | json }}
    - reload_modules: True

# Python2
{%- if salt.grains.get('pythonversion')[0] | int == 2 %}

install_pip_module:
  pkg.installed:
    - name: python2-pip

install_pip_upgrade:
  cmd.run:
    - name: python2 -m pip install --ignore-installed --upgrade 'pip==18.0.0'
    - unless: python2 -m pip -V | grep '18.0.0'
    - require:
      - pkg: install_pip_module
    - reload_modules: True

install_python_dependencies:
  pip.installed:
    - pkgs: {{ vault.module_dependencies.pip_deps | json }}
    - reload_modules: True
    - ignore_installed: True

{%- endif %}

# Python3
{%- if salt.grains.get('pythonversion')[0] | int == 3 %}
install_pip_module:
  pkg.installed:
    - name: python36-pip

install_python_dependencies:
  pip.installed:
    - pkgs: {{ vault.module_dependencies.pip_deps | json }}
    - target: /usr/lib/python3.6/site-packages
    - reload_modules: True
    - ignore_installed: True
{%- endif %}

