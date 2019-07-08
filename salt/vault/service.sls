{% from "vault/map.jinja" import vault with context %}

manage_selinux_mode:
  selinux.mode:
    - name: permissive

vault_service_init_file_managed:
  file.managed:
    - name: {{ vault.service.path }}
    - source: {{ vault.service.source }}
    - template: jinja

vault_service_running:
  service.running:
    - name: vault
    - enable: True
    - reload: True
    - require:
      - selinux: manage_selinux_mode
    - watch:
      - archive: vault_package_install_archive_extracted
      - file: vault_configure_service_file


