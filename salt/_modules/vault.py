# -*- coding: utf-8 -*-
"""
This module provides methods for interacting with Hashicorp Vault via the HVAC
library.
"""
from __future__ import absolute_import
from builtins import super

import logging
import hashlib
import json
import os
import glob
from collections import OrderedDict

log = logging.getLogger(__name__)

DEPS_INSTALLED = False
try:
    import hvac
    DEPS_INSTALLED = True
except ImportError:
    pass


class InsufficientParameters(Exception):
    pass


def __virtual__():
    if DEPS_INSTALLED:
        return 'vault'
    else:
        return False, 'Missing required dependency, `hvac`'


def get_policies_manager():
    """Retrieve an object containing helper methods for the policy manager

    Returns:
        [VaultPolicyManager] -- Policy Manager
    """
    return VaultPolicyManager()


def get_secret_engines_manager():
    """Retrieve an object containing helper methods for the secrets engines manager

    Returns:
        [VaultSecretsManager] -- Secrets Engines Manager
    """
    return VaultSecretsManager()


def get_auth_methods_manager():
    """Retrieve an object containing helper methods for the auth methods manager

    Returns:
        [VaultAuthManager] -- Auth Methods Manager
    """
    return VaultAuthManager()


def get_audit_device_manager():
    """Retrieve an object containing helper methods for the audit device manager

    Returns:
        [VaultAuditManager] -- Audit Device Manager
    """
    return VaultAuditManager()


class VaultConfigBase(object):
    type = None
    path = None
    description = None
    config = None

    def __init__(self, type, path, description, config):
        """Initialize classs

        Arguments:
            type {string} -- The type of the config
            path {string} -- The path in which to enable the config
            description {[type]} -- A human-friendly description
        """

        config = config or {}

        self.type = type
        self.path = path.replace("/", "")
        self.description = (description if description else "")
        self.config = {k: v for k, v in config.items() if v != ''}

    def get_unique_id(self):
        """Return a unique hash of the config by only using the type and path

        Returns:
            string -- unique hash of the type and path
        """
        return self.hash_value(self.type + self.path)

    def get_tuning_hash(self):
        """Return a unique ID per tuning configuration

        Returns:
            string -- unique hash of the configuration
        """
        return self.hash_value(self.description + str(self.config))

    def hash_value(self, value):
        return hashlib.sha256(value.encode()).hexdigest()

    def __eq__(self, other):
        return self.get_unique_id() == other.get_unique_id()

    def __repr__(self):
        return ("Path: %s - Type: %s - Desc: %s - Config: %s - Hash : %s" %
                (self.path, self.type, self.description, str(self.config), self.get_unique_id()))


class VaultAuthMethod(VaultConfigBase):
    auth_config = None
    extra_config = None

    def __init__(self, type, path, description, config=None, auth_config=None, extra_config=None):
        super().__init__(type, path, description, config)

        self.auth_config = auth_config or {}
        self.extra_config = extra_config or {}


class VaultSecretEngine(VaultConfigBase):
    secret_config = None
    extra_config = None

    def __init__(self, type, path, description, config=None, secret_config=None, extra_config=None):
        super().__init__(type, path, description, config)

        self.secret_config = secret_config or {}
        self.extra_config = extra_config or {}


class VaultAuditDevice(VaultConfigBase):

    def __init__(self, type, path, description, config=None):
        super().__init__(type, path, description, config)


class VaultPolicyManager():
    """Module for handling Vault Policies
    """

    def __init__(self):
        """Initialize Vault Policies Manager
        """
        log.info("Initializing Vault Policies Manager...")

    def get_remote_policies(self, client, ret):
        """Retrieve policies from remote vault server

        Arguments:
            client {hvac} -- hvac client
            ret {dict} -- salt state result

        Returns:
            [list] -- policies
        """
        log.info('Retrieving policies from vault...')
        polices = []
        policies_resp = client.sys.list_policies()

        for policy in policies_resp['data']['policies']:
            if not (policy == 'root' or policy == 'default'):
                polices.append(policy)

        log.info('Finished retrieving policies from vault.')

        return polices

    def push_policies(self, client, remote_policies, local_policies, ret):
        """Push policies from local config to remote vault server

        Arguments:
            client {hvac} -- hvac client
            remote_policies {list} -- policies from the remote vault server
            local_policies {list} -- policies from local config
            ret {dict} -- salt state result
        """
        log.info('Pushing policies from local config folder to vault...')
        new_policies = []
        for policy in local_policies:
            client.sys.create_or_update_policy(
                name=policy['name'],
                policy=policy['content']
            )
            if policy['name'] in remote_policies:
                log.debug('Policy "%s" has been updated.', policy["name"])
            else:
                new_policies.append(policy["name"])
                log.debug('Policy "%s" has been created.', policy["name"])

        # Build return object
        ret['changes']['old'] = remote_policies
        ret['changes']['new'] = new_policies or "No changes"

        log.info('Finished pushing policies local config folder to vault.')

    def cleanup_policies(self, client, remote_policies, local_policies, ret):
        """Removes policies that are not present in the local config

        Arguments:
            client {hvac} -- hvac client
            remote_policies {list} -- policies current on the remote vault server
            local_policies {list} --policies from local config
            ret {dict} -- salt state result
        """
        log.info('Cleaning up vault policies...')
        has_change = False
        for policy in remote_policies:
            if policy not in [pol['name'] for pol in local_policies]:
                log.debug(
                    '"%s" is not found in configs folder. Removing it from vault...', policy)
                has_change = True
                client.sys.delete_policy(name=policy)
                log.debug('"%s" is removed.', policy)

        if has_change:
            ret['changes']['new'] = [ob['name'] for ob in local_policies]

        log.info('Finished cleaning up vault policies.')


class VaultAuthManager():
    """Module for managing Vault Authentication Methods
    """

    def __init__(self):
        """Initialize Authentication Manager
        """
        log.info("Initializing Vault Auth Manager...")

    def get_remote_auth_methods(self, client, ret):
        """Retrieve authentication methods from remote vault server

        Arguments:
            client {hvac} -- hvac client
            ret {dict} -- result from state

        Returns:
            list -- auth methods
        """
        log.info('Retrieving auth methods from Vault...')
        auth_resp = client.sys.list_auth_methods()

        auth_methods = []
        for auth_method in auth_resp['data']:
            auth_methods.append(
                VaultAuthMethod(
                    type=auth_resp[auth_method]['type'],
                    path=(auth_resp[auth_method]["path"]
                          if 'path' in auth_resp[auth_method] else auth_method),
                    description=auth_resp[auth_method]["description"],
                    config=OrderedDict(
                        sorted(auth_resp[auth_method]["config"].items()))
                )
            )

        log.info('Finished retrieving auth methods from vault.')

        return auth_methods

    def populate_local_auth_methods(self, configs, ret):
        """Get auth methods from local config

        Arguments:
            configs {list} -- auth methods information
            ret {dict} -- salt state result

        Returns:
            list -- auth methods
        """
        log.info('Populating local auth methods...')

        auth_methods = []
        for auth_method in configs:
            auth_config = None
            extra_config = None

            if "auth_config" in auth_method:
                auth_config = OrderedDict(
                    sorted(auth_method["auth_config"].items()))

            if "extra_config" in auth_method:
                extra_config = OrderedDict(
                    sorted(auth_method["extra_config"].items()))

            auth_methods.append(
                VaultAuthMethod(
                    type=auth_method["type"],
                    path=auth_method["path"],
                    description=auth_method["description"],
                    config=OrderedDict(
                        sorted(auth_method["config"].items())),
                    auth_config=auth_config,
                    extra_config=extra_config
                )
            )

        log.info('Finished populating local auth methods.')

        return auth_methods

    def configure_auth_methods(self, client, remote_methods, local_methods, ret):
        """Compare and configure local authentication methods with remote vault server

        Arguments:
            client {hvac} -- hvac client
            remote_methods {list} -- auth methods from remote vault server
            local_methods {list} -- auth methods from local config
            ret {dict} -- salt state result
        """
        log.info('Processing and configuring auth methods...')

        new_auth_methods = []
        ldap_groups = []

        for auth_method in local_methods:
            log.debug('Checking if auth method "%s" is enabled...',
                      auth_method.path)
            if auth_method in remote_methods:
                log.debug(
                    'Auth method "%s" is already enabled. Tuning...', auth_method.path)
                client.sys.tune_auth_method(
                    path=auth_method.path,
                    description=auth_method.description,
                    default_lease_ttl=auth_method.config["default_lease_ttl"],
                    max_lease_ttl=auth_method.config["max_lease_ttl"]
                )
                log.debug('Auth method "%s" is tuned.', auth_method.type)
            else:
                log.debug(
                    'Auth method "%s" is not enabled. Enabling now...', auth_method.path)
                client.sys.enable_auth_method(
                    method_type=auth_method.type,
                    path=auth_method.path,
                    description=auth_method.description,
                    config=auth_method.config
                )
                log.debug('Auth method "%s" is enabled.', auth_method.type)
                new_auth_methods.append(auth_method.type)

            # Provision config for specific auth method
            if auth_method.auth_config:
                if auth_method.type == "ldap":
                    ldap_configuration = client.auth.ldap.read_configuration()
                    log.debug('The LDAP auth method is configured with a LDAP server URL of: {url}'.format(
                        url=ldap_configuration['data']['url']))
                    log.debug('Provisioning configuration for LDAP...')
                    client.auth.ldap.configure(**auth_method.auth_config)
                    log.debug('Configuration for LDAP is provisioned.')
            else:
                log.debug(
                    'Auth method "%s" does not contain any specific configurations.', auth_method.type)

            if auth_method.extra_config:
                log.debug(
                    'Provisioning extra configurations for auth method "%s"', auth_method.type)

                # Get LDAP group mapping from vault
                try:
                    ldap_groups = client.auth.ldap.list_groups()
                    log.debug('The following groups are configured in the LDAP auth method: {groups}'.format(
                        groups=','.join(ldap_groups['data']['keys'])
                    ))
                except hvac.exceptions.InvalidPath:
                    pass

                # Update LDAP group mapping
                log.debug(
                    'Writing LDAP group -> Policy mappings for "%s"', str(auth_method.path))
                local_config_groups = auth_method.extra_config["group_policy_map"]
                for key in local_config_groups:
                    log.debug('LDAP Group ["%s"] -> Policies %s',
                              str(key), local_config_groups[key])

                    client.auth.ldap.create_or_update_group(
                        name=key,
                        policies=local_config_groups[key]
                    )

                # Clean up LDAP group mapping
                if ldap_groups:
                    for group in ldap_groups:
                        if group in {k.lower(): v for k, v in local_config_groups.items()}:
                            log.debug(
                                'LDAP group mapping ["%s"] exists in configuration, no cleanup necessary', group)
                        else:
                            log.debug(
                                'LDAP group mapping ["%s"] does not exist in configuration, deleting...', group)
                            client.auth.ldap.delete_group(name=group)
                            log.debug(
                                'LDAP group mapping ["%s"] deleted.', group)
            else:
                log.debug(
                    'Auth method "%s" does not contain any extra configurations.', auth_method.type
                )

        # Build return object
        ret['changes']['old'] = [ob.type for ob in remote_methods]
        ret['changes']['new'] = new_auth_methods or "No changes"

        log.info('Finished processing and configuring auth methods...')

    def cleanup_auth_methods(self, client, remote_methods, local_methods, ret):
        """Disabling any auth methods not present in the local config

        Arguments:
            client {hvac} -- hvac client
            remote_methods {list} -- auth methods from remote vault server
            local_methods {list} -- auth methods from local config
            ret {dict} -- salt state result
        """
        log.info('Cleaning up auth methods...')
        has_change = False
        for auth_method in remote_methods:
            if auth_method not in local_methods:
                has_change = True
                log.debug(
                    'Auth method "%s" does not exist in configuration. Disabling...', auth_method.type)
                client.sys.disable_auth_method(
                    path=auth_method.path
                )
                log.debug('Auth method "%s" is disabled.',
                          auth_method.type)

        if has_change:
            ret['changes']['new'] = [ob.type for ob in local_methods]

        log.info('Finished cleaning up auth methods.')


class VaultSecretsManager():
    """
    Module for handling Vault Secrets Engines
    """

    def __init__(self):
        """Initialize Vault Secrets Manager
        """
        log.info("Initializing Vault Secret Manager...")

    def get_remote_secrets_engines(self, client, ret):
        """Retrieve secrets engines from remote vault server

        Arguments:
            client {hvac} -- hvac client
            ret {dict} -- salt state result

        Returns:
            list -- secrets engines
        """
        log.info('Retrieving secrets engines from Vault')
        remote_secret_engines = []
        secrets_engines_resp = client.sys.list_mounted_secrets_engines()
        for engine in secrets_engines_resp['data']:
            remote_secret_engines.append(
                VaultSecretEngine(
                    type=secrets_engines_resp[engine]['type'],
                    path=(secrets_engines_resp[engine]["path"]
                          if 'path' in secrets_engines_resp[engine] else engine),
                    description=secrets_engines_resp[engine]["description"],
                    config=OrderedDict(
                        sorted(secrets_engines_resp[engine]["config"].items()))
                )
            )
        remote_secret_engines.sort(key=lambda x: x.type)

        log.info('Finished retrieving secrets engines from vault.')
        return remote_secret_engines

    def populate_local_secrets_engines(self, configs, ret):
        """Retrieve secrets engines from local config

        Arguments:
            configs {list} -- local secrets engines information
            ret {dict} -- salt state result

        Returns:
            list -- secrets engines
        """
        log.info('Populating local secret engines...')
        local_secret_engines = []
        for secret_engine in configs:
            config = None
            secret_config = None
            extra_config = None

            if 'config' in secret_engine:
                if secret_engine["config"]:
                    config = OrderedDict(
                        sorted(secret_engine["config"].items()))

            if 'secret_config' in secret_engine:
                if secret_engine["secret_config"]:
                    secret_config = OrderedDict(
                        sorted(secret_engine["secret_config"].items()))

            if 'extra_config' in secret_engine:
                if secret_engine["extra_config"]:
                    extra_config = OrderedDict(
                        sorted(secret_engine["extra_config"].items()))

            local_secret_engines.append(VaultSecretEngine(
                type=secret_engine["type"],
                path=secret_engine["path"],
                description=secret_engine["description"],
                config=config,
                secret_config=secret_config,
                extra_config=extra_config
            ))

        local_secret_engines.sort(key=lambda x: x.type)

        log.info('Finished populating local secret engines.')
        return local_secret_engines

    def configure_secrets_engines(self, client, remote_engines, local_engines, ret):
        """Compare and configure local vault secrets engines config with vault remote servers

        Arguments:
            client {hvac} -- hvac client
            remote_engines {list} -- secrets engines from remote vault server
            local_engines {list} -- secrets engines from local vault config
            ret {dict} -- salt state result
        """
        log.info('Processing and configuring secrets engines...')
        new_secrets_engines = []
        for secret_engine in local_engines:
            log.debug('Checking if secret engine "%s" at path "%s" is enabled...',
                      secret_engine.type,
                      secret_engine.path)
            if secret_engine in remote_engines:
                log.debug(
                    'Secret engine "%s" at path "%s" is already enabled. Tuning...',
                    secret_engine.type,
                    secret_engine.path)

                client.sys.tune_mount_configuration(
                    path=secret_engine.path,
                    description=secret_engine.description,
                    default_lease_ttl=secret_engine.config["default_lease_ttl"],
                    max_lease_ttl=secret_engine.config["max_lease_ttl"]
                )
                log.debug('Secret engine "%s" at path "%s" is tuned.',
                          secret_engine.type, secret_engine.path)
            else:
                log.debug(
                    'Secret engine "%s" at path "%s" is not enabled. Enabling now...',
                    secret_engine.type,
                    secret_engine.path)

                client.sys.enable_secrets_engine(
                    backend_type=secret_engine.type,
                    path=secret_engine.path,
                    description=secret_engine.description,
                    config=secret_engine.config
                )

                new_secrets_engines.append(
                    "type: {} - path: {}".format(secret_engine.type, secret_engine.path))

                log.debug('Secret engine "%s" at path "%s" is enabled.',
                          secret_engine.type, secret_engine.path)

            if secret_engine.secret_config:
                log.info(
                    'Provisioning specific configurations for "%s" secrets engine...', secret_engine.type)

                if secret_engine.type == 'ad':
                    client.secrets.activedirectory.configure(
                        **secret_engine.secret_config
                    )
                if secret_engine.type == 'database':
                    client.secrets.database.configure(
                        **secret_engine.secret_config
                    )

                log.info(
                    'Finished provisioning specific configurations for "%s" secrets engine...', secret_engine.type)

            if secret_engine.extra_config:
                log.info(
                    'Provisioning extra conifgurations for for "%s" secrets engine...', secret_engine.type)

                if secret_engine.type == 'ad':
                    # Get roles from vault
                    existing_roles = None
                    existing_roles = client.secrets.activedirectory.list_roles()
                    log.debug(existing_roles)

                    # Add new roles
                    local_roles = secret_engine.extra_config['roles']
                    for key in local_roles:
                        log.debug('AD Role ["%s"] -> Role %s',
                                  str(key), local_roles[key])

                        client.secrets.activedirectory.create_or_update_role(
                            name=key,
                            service_account_name=local_roles[key]['service_account_name'],
                            ttl=local_roles[key]['ttl']
                        )

                    # Remove missing roles
                    if existing_roles:
                        for role in existing_roles:
                            if role in {k.lower(): v for k, v in local_roles.items()}:
                                log.debug(
                                    'AD role ["%s"] exists in configuration, no cleanup necessary', role)
                            else:
                                log.debug(
                                    'Ad role ["%s"] does not exists in configuration, deleting...', role)
                                client.secrets.activedirectory.delete_role(
                                    name=role
                                )
                                log.debug(
                                    'AD role has been ["%s"] deleted.', role)
            else:
                log.debug(
                    'Secret engine "%s" does not contain any extra configurations.', secret_engine.type
                )
        # Build return object
        ret['changes']['old'] = [
            "type: {} - path: {}".format(ob.type, ob.path) for ob in remote_engines]
        ret['changes']['new'] = new_secrets_engines or "No changes"

        log.info('Finished proccessing and configuring secrets engines.')

    def cleanup_secrets_engines(self, client, remote_engines, local_engines, ret):
        """Disabling any secrets engines that are not present in the local config

        Arguments:
            client {hvac} -- hvac client
            remote_engines {list} -- secrets engines from remote vault server
            local_engines {list} -- secrets engines from local config
            ret {dict} -- salt state result
        """
        log.info('Cleaning up secrets engines...')
        has_changes = False
        for secret_engine in remote_engines:
            if not (secret_engine.type == "system" or
                    secret_engine.type == "cubbyhole" or
                    secret_engine.type == "identity" or
                    secret_engine.type == "generic"):
                if secret_engine in local_engines:
                    log.debug('Secrets engine "%s" at path "%s" exists in configuration, no cleanup necessary.',
                              secret_engine.type, secret_engine.path)
                else:
                    log.debug('Secrets engine "%s" at path "%s" does not exist in configuration. Disabling...',
                              secret_engine.type, secret_engine.path)
                    has_changes = True
                    client.sys.disable_secrets_engine(
                        path=secret_engine.path
                    )
                    log.debug('Secrets engine "%s" at path "%s" is disabled.',
                              secret_engine.type, secret_engine.type)

        if has_changes:
            ret['changes']['new'] = [
                "type: {} - path: {}".format(ob.type, ob.path) for ob in local_engines]

        log.info('Finished cleaning up secrets engines.')


class VaultAuditManager():
    """
    Module for handling Vault Audit Devices
    """

    def __init__(self):
        """Initialize Vault Audit Managers
        """
        log.info("Initializing Vault Audit Manager...")

    def get_remote_audit_devices(self, client, ret):
        """Get audit devices information from remote vault server

        Arguments:
            client {hvac} -- hvac client
            ret {dict} -- salt state result

        Returns:
            list -- audit devices
        """
        log.info("Retrieving audit devices from vault...")
        devices = []
        audit_devices_resp = client.sys.list_enabled_audit_devices()
        log.debug(audit_devices_resp)
        for device in audit_devices_resp['data']:
            audit_device = audit_devices_resp[device]
            devices.append(
                VaultAuditDevice(
                    type=audit_device['type'],
                    path=(audit_device["path"]
                          if 'path' in audit_device else device),
                    description=audit_device["description"],
                    config=OrderedDict(
                        sorted(audit_device["options"].items()))
                )
            )

        log.info('Finished retrieving audit devices from vault.')

        return devices

    def get_local_audit_devices(self, configs, ret):
        """Get audit device inforamtion from local config file

        Arguments:
            configs {list} -- audit devices
            ret {dict} -- salt state result

        Returns:
            list -- audit devices
        """
        log.info("Loading audit devices from local config...")
        devices = []
        if configs:
            for audit_device in configs:
                config = None
                if 'config' in audit_device:
                    if audit_device['config']:
                        config = OrderedDict(
                            sorted(audit_device["config"].items()))

                devices.append(
                    VaultAuditDevice(
                        type=audit_device["type"],
                        path=audit_device["path"],
                        description=audit_device["description"],
                        config=config
                    )
                )

        log.info('Finished loading audit devices from local config.')

        return devices

    def configure_audit_devices(self, client, remote_devices, local_devices, ret):
        """Compare and configure audit devices

        Arguments:
            client {hvac} -- hvac client
            remote_devices {list} -- audit devices from remote vault server
            local_devices {list} -- audit devices from local vault config file
            ret {dict} -- salt state result
        """
        log.info('Processing and configuring audit devices...')
        new_audit_devices = []
        for audit_device in local_devices:
            log.debug('Checking if audit device "%s" at path "%s" is enabled...',
                      audit_device.type, audit_device.path)

            if audit_device in remote_devices:
                log.debug('Audit device "%s" at path "%s" is already enabled.',
                          audit_device.type, audit_device.path)
            else:
                log.debug(
                    'Audit device "%s" at path "%s" is not enabled. Enabling now...',
                    audit_device.type,
                    audit_device.path
                )
                new_audit_devices.append(audit_device.type)
                client.sys.enable_audit_device(
                    device_type=audit_device.type,
                    path=audit_device.path,
                    description=audit_device.description,
                    options=audit_device.config
                )
                log.debug('Audit device "%s" at path "%s" is enabled.',
                          audit_device.type, audit_device.path)

        # Build return object
        ret['changes']['old'] = [ob.type for ob in remote_devices]
        ret['changes']['new'] = new_audit_devices or "No changes"

        log.info('Finished processing audit devices.')

    def cleanup_audit_devices(self, client, remote_devices, local_devices, ret):
        """Disabling any audit devices not present in the local config file

        Arguments:
            client {hvac} -- hvac client
            remote_devices {list} -- list of remote audit devices
            local_devices {list} -- list of local audit devices
            ret {dict} -- salt state result
        """
        log.info('Cleaning up audit devices...')
        has_changes = False
        for audit_device in remote_devices:
            if audit_device not in local_devices:
                log.info('Disabling audit device "%s" at path "%s"...',
                        audit_device.type, audit_device.path)
                has_changes = True
                client.sys.disable_audit_device(
                    path=audit_device.path
                )

        if has_changes:
            ret['changes']['new'] = [ob.type for ob in local_devices]

        log.info('Finished cleaning up audit devices.')
