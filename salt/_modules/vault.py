# -*- coding: utf-8 -*-
"""
This module provides methods for interacting with Hashicorp Vault via the HVAC
library.
"""
from __future__ import absolute_import

import logging
import hashlib
import json
import os
import glob
from collections import OrderedDict
from datetime import datetime, timedelta


import salt.config
import salt.syspaths
import salt.utils
import salt.exceptions


log = logging.getLogger(__name__)

try:
    import hvac
    DEPS_INSTALLED = True
except:
    log.debug('Unable to import the dependencies...')
    DEPS_INSTALLED = False

class InsufficientParameters(Exception):
    pass


def __virtual__():
    return DEPS_INSTALLED


class VaultAuthMethod:
    """
    Vault authentication method container
    """
    type = None
    path = None
    description = None
    config = None
    auth_config = None
    extra_config = None

    def __init__(self, type, path, description, config=None, auth_config=None, extra_config=None):
        """
        Instanciate class

        :param type: Authentication type
        :type type: str
        :param path: Authentication mount point
        :type path: str
        :param description: Authentication description
        :type description: str
        :param config: Authentication config
        :type config: dict
        :param auth_config: Authentification specific configuration
        :type auth_config: dict
        :param extra_config: Extra Authentification configurations
        :type extra_config: dict
        """
        self.type = type
        self.path = path.replace("/", "")
        self.description = (description if description else "")
        self.config = {}
        for elem in config:
            if config[elem] != "":
                self.config[elem] = config[elem]
        self.auth_config = auth_config
        self.extra_config = extra_config

    def get_unique_id(self):
        """
        Return a unique hash by auth method only using the type and path

        :return: str
        """
        unique_str = str(self.type + self.path)
        sha256_hash = hashlib.sha256(unique_str.encode()).hexdigest()
        return sha256_hash

    def get_tuning_hash(self):
        """
        Return a unique ID per tuning configuration

        :return: str
        """
        conf_str = self.description + str(self.config)
        sha256_hash = hashlib.sha256(conf_str.encode()).hexdigest()
        return sha256_hash

    def __eq__(self, other):
        return self.get_unique_id() == other.get_unique_id()

    def __repr__(self):
        return ("Path: %s - Type: %s - Desc: %s - Options: %s - Hash : %s" %
                (self.path, self.type, self.description, str(self.config),
                 self.get_unique_id()))


class VaultSecretEngine:
    """
    Vault secrete engine container
    """
    type = None
    path = None
    description = None
    config = None
    secret_config = None
    extra_config = None

    def __init__(self, type, path, description, config=None, secret_config=None, extra_config=None):
        """
        Instantiate Class

        :param type: Secret type
        :type type: str
        :param path: Secret mount point
        :type path: str
        :param description: Secret description
        :type description: str
        :param config: Secret basic config
        :type config: dict
        :param secret_config: Secret specific configuration
        :type secret_config: dict
        :param extra_config: Secret extra configuration
        :type extra_config: dict
        """
        self.type = type
        self.path = path.replace("/", "")
        self.description = (description if description else "")
        self.config = dict()
        self.config["force_no_cache"] = False
        for elem in config:
            if config[elem] != "":
                self.config[elem] = config[elem]
        self.secret_config = secret_config
        self.extra_config = extra_config

    def get_unique_id(self):
        """
        Return a unique hash by secret engine only using the type and path

        :return: str
        """
        unique_str = str(self.type + self.path)
        sha256_hash = hashlib.sha256(unique_str.encode()).hexdigest()
        return sha256_hash

    def __eq__(self, other):
        return self.get_unique_id() == other.get_unique_id()

    def __repr__(self):
        return ("Path: %s - Type: %s - Desc: %s - Options: %s - Hash : %s" %
                (self.path, self.type, self.description, str(self.config),
                 self.get_unique_id()))


class VaultAuditDevice:
    type = None
    path = None
    description = None
    options = None

    def __init__(self, type, path, description, options):
        self.type = type
        self.path = path.replace("/", "")
        self.description = (description if description else "")
        self.options = options

    def get_device_unique_id(self):
        unique_str = str(self.type + self.path +
                         self.description + str(self.options))
        sha256_hash = hashlib.sha256(unique_str.encode()).hexdigest()
        return sha256_hash

    def __eq__(self, other):
        return self.get_device_unique_id() == other.get_device_unique_id()

    def __repr__(self):
        return ("Path: %s - Type: %s - Desc: %s - Options: %s - Hash : %s" %
                (self.path, self.type, self.description, str(self.options),
                 self.get_device_unique_id()))


class VaultPolicyManager():
    """
    Module for managing policies within Vault
    """
    client = None
    local_policies = []
    remote_policies = []
    policies_folder = ''
    ret = {}

    def __init__(self, policies_dir_path):
        log.info("Initializing Vault Policy Manager...")
        self.policies_folder = policies_dir_path

    def get_remote_policies(self):
        """
        Reading policies from configs folder
        """
        log.info('Retrieving policies from vault...')
        try:
            policies_resp = self.client.sys.list_policies()

            for policy in policies_resp['data']['policies']:
                if not (policy == 'root' or policy == 'default'):
                    self.remote_policies.append(policy)

            log.debug('Current configured policies: %s' %
                      ', '.join(self.remote_policies))

        except Exception as e:
            log.exception(e)

        log.info('Finished retrieving policies from vault.')

    def get_local_policies(self):
        """
        Reading policies from configs folder
        """
        log.info('Loading policies from local config folder...')
        for policy_file in glob.iglob(os.path.join(self.policies_folder, "*.hcl")):
            name = os.path.splitext(os.path.basename(policy_file))[0]
            prefix = policy_file.split(os.sep)[-2]
            log.debug("Local policy %s - prefix: %s - name: %s found"
                      % (policy_file, prefix, name))

            with open(policy_file, 'r') as fd:
                self.local_policies.append({
                    "name": name,
                    "content": fd.read()
                })
        log.info('Finished loading policies local config folder.')

    def push_policies(self):
        """
        Sync policies from configs folder to vault
        """
        log.info('Pushing policies from local config folder to vault...')
        new_policies = []
        for policy in self.local_policies:
            self.client.sys.create_or_update_policy(
                name=policy['name'],
                policy=policy['content']
            )
            if policy['name'] in self.remote_policies:
                log.debug('Policy "%s" has been updated.', policy["name"])
            else:
                new_policies.append(policy["name"])
                log.debug('Policy "%s" has been created.', policy["name"])

        log.info('Finished pushing policies local config folder to vault.')

        # Build return object

        self.ret['old'] = self.remote_policies
        if len(new_policies) > 0:
            self.ret['new'] = json.loads(json.dumps(new_policies))
        else:
            self.ret['new'] = "No changes"

    def cleanup_policies(self):
        """
        Cleaning up policies
        """
        log.info('Cleaning up vault policies...')
        has_change = False
        for policy in self.remote_policies:
            if policy not in [pol['name'] for pol in self.local_policies]:
                log.debug(
                    '"%s" is not found in configs folder. Removing it from vault...', policy)
                has_change = True
                self.client.sys.delete_policy(name=policy)
                log.debug('"%s" is removed.', policy)

        if has_change:
            self.ret['new'] = json.loads(json.dumps(
                [ob['name'] for ob in self.local_policies]))

        log.info('Finished cleaning up vault policies.')

    def run(self):
        """
        Control the executions
        """
        log.info('-------------------------------------')
        self.client = __utils__['vault.build_client']()
        self.get_remote_policies()
        self.get_local_policies()
        self.push_policies()
        self.cleanup_policies()
        log.info('-------------------------------------')
        return self.ret


class VaultAuthManager():
    """
    Module for managing Vault Authentication Methods
    """
    auth_methods_remote = []
    auth_methods_local = []
    ldap_groups = []
    config_path = ''
    ret = {}
    client = None

    def __init__(self, config_path):
        log.info("Initializing Vault Auth Manager...")
        self.config_path = config_path

    def get_remote_auth_methods(self):
        """
        Retrieve auth methods from vault
        """
        log.info('Retrieving auth methods from Vault...')
        auth_resp = self.client.sys.list_auth_methods()
        log.debug('Current auth methods from Vault: %s',
                  ', '.join(auth_resp['data'].keys()))

        for auth_method in auth_resp['data']:
            self.auth_methods_remote.append(
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

    def get_local_auth_methods(self):
        log.info('Loading auth methods form local config file: %s',
                 self.config_path)
        config = __utils__['vault.load_config_file'](
            config_path=self.config_path)
        for auth_method in config["auth-methods"]:
            auth_config = None
            extra_config = None

            if "auth_config" in auth_method:
                auth_config = OrderedDict(
                    sorted(auth_method["auth_config"].items()))

            if "extra_config" in auth_method:
                extra_config = OrderedDict(
                    sorted(auth_method["extra_config"].items()))

            self.auth_methods_local.append(
                VaultAuthMethod(
                    type=auth_method["type"],
                    path=auth_method["path"],
                    description=auth_method["description"],
                    config=OrderedDict(sorted(auth_method["config"].items())),
                    auth_config=auth_config,
                    extra_config=extra_config
                )
            )
        log.info('Finished loading auth methods from local config file.')

    def configure_auth_methods(self):
        log.info('Processing and configuring auth methods...')
        new_auth_methods = []
        for auth_method in self.auth_methods_local:
            log.debug('Checking if auth method "%s" is enabled...',
                      auth_method.path)
            if auth_method in self.auth_methods_remote:
                log.debug(
                    'Auth method "%s" is already enabled. Tuning...', auth_method.path)
                self.client.sys.tune_auth_method(
                    path=auth_method.path,
                    description=auth_method.description,
                    default_lease_ttl=auth_method.config["default_lease_ttl"],
                    max_lease_ttl=auth_method.config["max_lease_ttl"]
                )
                log.debug('Auth method "%s" is tuned.', auth_method.type)
            else:
                log.debug(
                    'Auth method "%s" is not enabled. Enabling now...', auth_method.path)
                self.client.sys.enable_auth_method(
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
                    log.debug('Provisioning configuration for LDAP...')
                    self.client.auth.ldap.configure(**auth_method.auth_config)
                    log.debug('Configuration for LDAP is provisioned.')
            else:
                log.debug(
                    'Auth method "%s" does not contain any specific configurations.', auth_method.type)

            if auth_method.extra_config:
                log.debug(
                    'Provisioning extra configurations for auth method "%s"', auth_method.type)
                # Get LDAP group mapping from vault
                try:
                    ldap_list_group_response = self.client.auth.ldap.list_groups()
                    if ldap_list_group_response != None:
                        self.ldap_groups = ldap_list_group_response["data"]["keys"]

                except Exception as e:
                    log.exception(e)

                log.debug("LDAP groups from vault: %s", str(self.ldap_groups))

                # Update LDAP group mapping
                log.debug(
                    'Writing LDAP group -> Policy mappings for "%s"', str(auth_method.path))
                local_config_groups = auth_method.extra_config["group_policy_map"]
                for key in local_config_groups:
                    log.debug('LDAP Group ["%s"] -> Policies %s',
                              str(key), local_config_groups[key])
                    try:
                        self.client.auth.ldap.create_or_update_group(
                            name=key,
                            policies=local_config_groups[key]
                        )
                    except Exception as e:
                        log.exception(e)

                # Clean up LDAP group mapping
                if self.ldap_groups != None:
                    for group in self.ldap_groups:
                        if group in {k.lower(): v for k, v in local_config_groups.items()}:
                            log.debug(
                                'LDAP group mapping ["%s"] exists in configuration, no cleanup necessary', group)
                        else:
                            log.info(
                                'LDAP group mapping ["%s"] does not exists in configuration, deleting...', group)
                            self.client.auth.ldap.delete_group(
                                name=group
                            )
                            log.info(
                                'LDAP group mapping ["%s"] deleted.', group)
            else:
                log.debug(
                    'Auth method "%s" does not contain any extra configurations.', auth_method.type
                )
        log.info('Finished processing and configuring auth methods...')

        # Build return object
        self.ret['old'] = json.loads(json.dumps(
            [ob.type for ob in self.auth_methods_remote]))

        if len(new_auth_methods) > 0:
            self.ret['new'] = json.loads(json.dumps(new_auth_methods))
        else:
            self.ret['new'] = "No changes"

    def cleanup_auth_methods(self):
        log.info('Cleaning up auth methods...')
        has_change = False

        for auth_method in self.auth_methods_remote:
            if auth_method not in self.auth_methods_local:
                has_change = True
                log.info(
                    'Auth method "%s" does not exist in configuration. Disabling...', auth_method.type)
                self.client.sys.disable_auth_method(
                    path=auth_method.path
                )
                log.info('Auth method "%s" is disabled.', auth_method.type)
        log.info('Finished cleaning up auth methods.')

        if has_change:
            self.ret['new'] = json.loads(json.dumps(
                [ob.type for ob in self.auth_methods_local]))

    def run(self):
        """
        Control the executions
        """
        log.info('-------------------------------------')
        self.client = __utils__['vault.build_client']()
        self.get_remote_auth_methods()
        self.get_local_auth_methods()
        self.configure_auth_methods()
        self.cleanup_auth_methods()
        log.info('-------------------------------------')

        return self.ret


class VaultSecretsManager():
    """
    Module for handling Vault secret engines
    """
    client = None
    config_path = ''
    remote_secret_engines = []
    local_secret_engines = []
    ret = {}

    def __init__(self, config_path):
        log.info("Initializing Vault Secret Manager...")
        self.config_path = config_path

    def get_remote_secrets_engines(self):
        """
        Retrieve secret engines from vault server
        """
        log.info('Retrieving secrets engines from vault')
        try:
            secrets_engines_resp = self.client.sys.list_mounted_secrets_engines()
            for engine in secrets_engines_resp['data']:
                self.remote_secret_engines.append(
                    VaultSecretEngine(
                        type=secrets_engines_resp[engine]['type'],
                        path=(secrets_engines_resp[engine]["path"]
                              if 'path' in secrets_engines_resp[engine] else engine),
                        description=secrets_engines_resp[engine]["description"],
                        config=OrderedDict(
                            sorted(secrets_engines_resp[engine]["config"].items()))
                    )
                )
            self.remote_secret_engines.sort(key=lambda x: x.type)
        except Exception as e:
            log.exception(e)
        log.info('Finished retrieving secrets engines from vault.')

    def get_local_secrets_engines(self):
        """
        Retrieving secret engines from local config file
        """
        log.debug('Reding secret engines from config file...')
        try:
            config = __utils__['vault.load_config_file'](
                config_path=self.config_path)

            for secret_engine in config['secrets-engines']:
                secret_config = None
                extra_config = None
                if 'secret_config' in secret_engine:
                    secret_config = OrderedDict(
                        sorted(secret_engine["secret_config"].items()))

                if 'extra_config' in secret_engine:
                    extra_config = OrderedDict(
                        sorted(secret_engine["extra_config"].items()))

                self.local_secret_engines.append(
                    VaultSecretEngine(
                        type=secret_engine["type"],
                        path=secret_engine["path"],
                        description=secret_engine["description"],
                        config=OrderedDict(
                            sorted(secret_engine["config"].items())),
                        secret_config=secret_config,
                        extra_config=extra_config
                    )
                )
            self.local_secret_engines.sort(key=lambda x: x.type)
        except Exception as e:
            log.exception(e)
        log.debug('Finished reading secrets engines from config file.')

    def configure_secrets_engines(self):
        log.info('Processing and configuring secrets engines...')
        new_secrets_engines = []
        for secret_engine in self.local_secret_engines:
            log.debug('Checking if secret engine "%s" at path "%s" is enabled...',
                      secret_engine.type,
                      secret_engine.path)
            if secret_engine in self.remote_secret_engines:
                log.debug(
                    'Secret engine "%s" at path "%s" is already enabled. Tuning...',
                    secret_engine.type,
                    secret_engine.path)

                self.client.sys.tune_mount_configuration(
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
                new_secrets_engines.append(secret_engine.type)
                self.client.sys.enable_secrets_engine(
                    backend_type=secret_engine.type,
                    path=secret_engine.path,
                    description=secret_engine.description,
                    config=secret_engine.config
                )
                log.debug('Secret engine " % s" at path " % s" is enabled.',
                          secret_engine.type, secret_engine.path)

            if secret_engine.secret_config != None:
                log.info(
                    'Provisioning specific configurations for "%s" secrets engine...', secret_engine.type)

                if secret_engine.type == 'ad':
                    self.client.secrets.activedirectory.configure(
                        **secret_engine.secret_config
                    )
                if secret_engine.type == 'database':
                    self.client.secrets.database.configure(
                        **secret_engine.secret_config
                    )

                log.info(
                    'Finished provisioning specific configurations for "%s" secrets engine...', secret_engine.type)

            if secret_engine.extra_config != None:
                log.info(
                    'Provisioning extra conifgurations for for "%s" secrets engine...', secret_engine.type)

                if secret_engine.type == 'ad':
                    # Get roles from vault
                    existing_roles = None
                    try:
                        existing_roles = self.client.secrets.activedirectory.list_roles()
                        log.debug(existing_roles)
                    except Exception as e:
                        log.exception(e)

                    # Add new roles
                    local_roles = secret_engine.extra_config['roles']
                    for key in local_roles:
                        log.debug('AD Role ["%s"] -> Role %s',
                                  str(key), local_roles[key])
                        try:
                            self.client.secrets.activedirectory.create_or_update_role(
                                name=key,
                                service_account_name=local_roles[key]['service_account_name'],
                                ttl=local_roles[key]['ttl']
                            )
                        except Exception as e:
                            log.exception(e)
                            raise salt.exceptions.SaltInvocationError(e)

                    # Remove missing roles
                    if existing_roles != None:
                        for role in existing_roles:
                            if role in {k.lower(): v for k, v in local_roles.items()}:
                                log.debug(
                                    'AD role ["%s"] exists in configuration, no cleanup necessary', role)
                            else:
                                log.info(
                                    'Ad role ["%s"] does not exists in configuration, deleting...', role)
                                self.client.secrets.activedirectory.delete_role(
                                    name=role
                                )
                                log.info(
                                    'AD role has been ["%s"] deleted.', role)
            else:
                log.debug(
                    'Secret engine "%s" does not contain any extra configurations.', secret_engine.type
                )
        log.info('Finished proccessing and configuring secrets engines.')

        # Build return object
        self.ret['old'] = json.loads(json.dumps([
            "Type: {} - Path: {}".format(ob.type, ob.path) for ob in self.remote_secret_engines]))

        if len(new_secrets_engines) > 0:
            self.ret['new'] = json.loads(json.dumps(new_secrets_engines))
        else:
            self.ret['new'] = "No changes"

    def cleanup_secrets_engines(self):
        log.info('Cleaning up secrets engines...')
        has_changes = False
        for secret_engine in self.remote_secret_engines:
            if not (secret_engine.type == "system" or
                    secret_engine.type == "cubbyhole" or
                    secret_engine.type == "identity" or
                    secret_engine.type == "generic"):
                if secret_engine in self.local_secret_engines:
                    log.debug('Secrets engine "%s" at path "%s" exists in configuration, no cleanup necessary.',
                              secret_engine.type, secret_engine.path)
                else:
                    log.debug('Secrets engine "%s" at path "%s" does not exist in configuration. Disabling...',
                              secret_engine.type, secret_engine.path)
                    has_changes = True
                    self.client.sys.disable_secrets_engine(
                        path=secret_engine.path
                    )
                    log.info('Secrets engine "%s" at path "%s" is disabled.',
                             secret_engine.type, secret_engine.type)
        log.info('Finished cleaning up secrets engines.')

        if has_changes:
            self.ret['new'] = json.loads(json.dumps([
                "Type: {} - Path: {}".format(ob.type, ob.path) for ob in self.local_secret_engines]))

    def run(self):
        """
        Control the executions
        """
        log.info('-------------------------------------')
        self.client = __utils__['vault.build_client']()
        self.get_remote_secrets_engines()
        self.get_local_secrets_engines()
        self.configure_secrets_engines()
        self.cleanup_secrets_engines()
        log.info('-------------------------------------')

        return self.ret


class VaultAuditManager():
    """
    Module for handling Vault audit devices
    """
    client = None
    remote_audit_devices = []
    local_audit_devices = []
    config_path = ''
    ret = {}

    def __init__(self, config_path):
        log.info("Initializing Vault Audit Manager...")
        self.config_path = config_path

    def get_remote_audit_devices(self):
        log.info("Retrieving audit devices from vault...")
        try:
            audit_devices_resp = self.client.sys.list_enabled_audit_devices()
            for device in audit_devices_resp['data']:
                audit_device = audit_devices_resp[device]
                self.remote_audit_devices.append(
                    VaultAuditDevice(
                        type=audit_device['type'],
                        path=(audit_device["path"]
                              if 'path' in audit_device else device),
                        description=audit_device["description"],
                        options=json.dumps(audit_device["options"])
                    )
                )
        except Exception as e:
            log.exception(e)
        log.info('Finished retrieving audit devices from vault.')

    def get_local_audit_devices(self):
        log.info("Loading audit devices from local config...")
        config = __utils__['vault.load_config_file'](
            config_path=self.config_path)

        if config:
            for audit_device in config["audit-devices"]:
                if 'options' in audit_device:
                    options = json.dumps(audit_device["options"])
                    log.debug(options)

                self.local_audit_devices.append(
                    VaultAuditDevice(
                        type=audit_device["type"],
                        path=audit_device["path"],
                        description=audit_device["description"],
                        options=options
                    )
                )
        log.info('Finished loading audit devices from local config.')

    def configure_audit_devices(self):
        log.info('Processing and configuring audit devices...')
        new_audit_devices = []
        for audit_device in self.local_audit_devices:
            log.debug('Checking if audit device "%s" at path "%s" is enabled...',
                      audit_device.type, audit_device.path)

            if audit_device in self.remote_audit_devices:
                log.debug('Audit device "%s" at path "%s" is already enabled.',
                          audit_device.type, audit_device.path)
            else:
                log.debug(
                    'Audit device "%s" at path "%s" is not enabled. Enabling now...', audit_device.type, audit_device.path)
                new_audit_devices.append(audit_device.type)
                self.client.sys.enable_audit_device(
                    device_type=audit_device.type,
                    path=audit_device.path,
                    description=audit_device.description,
                    options=json.loads(audit_device.options)
                )
                log.debug('Audit device "%s" at path "%s" is enabled.',
                          audit_device.type, audit_device.path)

        log.info('Finished processing audit devices.')
        # Build return object
        self.ret['old'] = json.loads(json.dumps(
            [ob.type for ob in self.remote_audit_devices]))

        if len(new_audit_devices) > 0:
            self.ret['new'] = json.loads(json.dumps(new_audit_devices))
        else:
            self.ret['new'] = "No changes"

    def cleanup_audit_devices(self):
        log.info('Cleaning up audit devices...')
        has_changes = False
        for audit_device in self.remote_audit_devices:
            if audit_device not in self.local_audit_devices:
                log.info('Disabling audit device "%s" at path "%s"...',
                         audit_device.type, audit_device.path)
                has_changes = True
                self.client.sys.disable_audit_device(
                    path=audit_device.path
                )
        log.info('Finished cleaning up audit devices.')

        if has_changes:
            self.ret['new'] = json.loads(json.dumps(
                [ob.type for ob in self.local_audit_devices]))

    def run(self):
        log.info('-------------------------------------')
        self.client = __utils__['vault.build_client']()
        self.get_remote_audit_devices()
        self.get_local_audit_devices()
        self.configure_audit_devices()
        self.cleanup_audit_devices()
        log.info('-------------------------------------')
        return self.ret


def auth_methods_synced(config_path):
    """
    Ensure all auth method defined in the config file are synced with vault

    :param config_path: path to configuration file for auth methods
    :returns: Result of the execution
    :rtype: dict
    """
    return VaultAuthManager(config_path).run()


def policies_synced(policies_dir_path):
    """
    Ensure all policies defined are synced with vault

    :param policies_dir_path: path to directory contains all policies
    :returns: Result of the execution
    :rtype: dict
    """
    return VaultPolicyManager(policies_dir_path).run()


def secrets_engines_synced(config_path):
    """
    Ensure all secrets engines defined in the config file are synced with vault

    :param config_path: path to configuration file for secrets engines
    :returns: Result of the execution
    :rtype: dict
    """
    return VaultSecretsManager(config_path).run()


def audit_devices_synced(config_path):
    """
    Ensure all audit devices defined in the config file are synced with vault

    :param config_path: path to configuration file for audit devices
    :returns: Result of the execution
    :rtype: dict
    """
    return VaultAuditManager(config_path).run()
