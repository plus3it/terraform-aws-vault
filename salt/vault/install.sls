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
    - mode: '0700'

vault_package_install_file_directory:
  file.directory:
    - name: /opt/vault/bin
    - makedirs: True

vault_package_install_file_managed:
  file.managed:
    - name: /opt/vault/{{ vault.version }}_SHA256SUMS
    - source: {{ vault.repo_base_url }}/{{ vault.version }}/vault_{{ vault.version }}_SHA256SUMS
    - skip_verify: True
    - makedirs: True

vault_package_install_archive_extracted:
  archive.extracted:
    - name: /opt/vault/bin
    - source: {{ vault.repo_base_url }}/{{ vault.version }}/vault_{{ vault.version }}_{{ vault.platform }}.zip
    - source_hash: {{ vault.repo_base_url }}/{{ vault.version }}/vault_{{ vault.version }}_SHA256SUMS
    - source_hash_name: vault_{{ vault.version }}_{{ vault.platform }}.zip
    - archive_format: zip
    - enforce_toplevel: False
    - overwrite: True
    - onchanges:
      - file: vault_package_install_file_managed

vault_package_install_service_dead:
  service.dead:
    - name: vault
    - onchanges:
      - file: vault_package_install_file_managed
    - onlyif: test -f /etc/systemd/system/vault.service

vault_package_install_file_symlink:
  file.symlink:
    - name: /usr/local/bin/vault
    - target: /opt/vault/bin/vault
    - force: true

vault_package_install_cmd_run:
  cmd.run:
    - name: setcap cap_ipc_lock=+ep /opt/vault/bin/vault
    - onchanges:
      - archive: vault_package_install_archive_extracted


install_package_dependencies:
  pkg.installed:
    - pkgs: {{ vault.module_dependencies.pkgs | json }}
    - reload_modules: True

install_pip_executable:
  cmd.run:
    - name: |
        curl -L "https://bootstrap.pypa.io/get-pip.py" > get_pip.py
        sudo python get_pip.py pip==18.0.0
        rm get_pip.py

    - reload_modules: True

install_python_dependencies:
  pip.installed:
    - pkgs: {{ vault.module_dependencies.pip_deps | json }}
    - reload_modules: True
    - ignore_installed: True
