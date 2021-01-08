# pylint: skip-file
from __future__ import absolute_import

import logging
import json
import salt.utils.dictdiffer

log = logging.getLogger(__name__)

DEPS_INSTALLED = False
IMPORT_ERROR = ""
try:
    import hvac
    import boto3

    DEPS_INSTALLED = True
except ImportError as e:
    IMPORT_ERROR = e
    pass

__all__ = ["initialize"]


def __virtual__():
    if DEPS_INSTALLED:
        return "vault"
    else:
        return False, "Missing required dependency. {}".format(IMPORT_ERROR)


def initialized(name, ssm_path, recovery_shares=5, recovery_threshold=3):
    """Ensure that the vault instance has been initialized and run the
    initialization if it has not. Storing the root token to SSM parameter store.

    Arguments:
        name {string} -- The id used for the state definition
        ssm_path {string} -- The path to SSM parameter that will store the root token

    Keyword Arguments:
        recovery_shares {int} -- Specifies the number of shares to split the recovery key into. (default: {5})
        recovery_threshold {int} -- Specifies the number of shares required to reconstruct the recovery key. This must be less than or equal to recovery_shares. (default: {3})

    Returns:
        ret {dict} --  Result of the execution
    """
    ret = {"name": name, "comment": "", "result": "", "changes": {}}

    client = __utils__["vault.build_client"]()

    is_initialized = client.sys.is_initialized()

    if is_initialized:
        ret["result"] = True
        ret["comment"] = "Vault is already initialized"
    else:
        result = client.sys.initialize(
            recovery_shares=recovery_shares, recovery_threshold=recovery_threshold
        )
        root_token = result["root_token"]
        recovery_keys = result["recovery_keys"]
        is_success = client.sys.is_initialized()

        ret["result"] = is_success
        ret["changes"] = {
            "root_credentials": {
                "new": {
                    "recover_keys": "/{}/{}".format(ssm_path, "recovery_keys"),
                    "root_token": "/{}/{}".format(ssm_path, "root_token"),
                },
                "old": {},
            }
        }

        # upload root token ssm parameter store
        if is_success:
            ssm_client = boto3.client("ssm")
            # saving root token
            ssm_client.put_parameter(
                Name="/{}/{}".format(ssm_path, "root_token"),
                Value=root_token,
                Type="SecureString",
                Overwrite=True,
            )

            # saving recovery keys
            ssm_client.put_parameter(
                Name="/{}/{}".format(ssm_path, "recovery_keys"),
                Value=json.dumps(recovery_keys),
                Type="SecureString",
                Overwrite=True,
            )

        ret["comment"] = "Vault has {}initialized".format(
            "" if is_success else "failed to be "
        )
    return ret


def secret_engines_synced(name, configs=[]):
    """Ensure secrets engines are synced with Vault

    Arguments:
        name {string} -- The id used for the state definition

    Keyword Arguments:
        configs {list} -- A list of configuration rules that defined the secrets engines (default: [])

    Returns:
        ret {dict} --  Result of the execution
    """

    client = __utils__["vault.build_client"]()
    remote_secret_engines = []
    local_secret_engines = []
    ret = {"name": name, "comment": "", "result": "", "changes": {}}

    secretsManager = __salt__["vault.get_secret_engines_manager"]()

    try:
        existing_secret_engines = client.sys.list_mounted_secrets_engines()["data"]

        remote_secret_engines = secretsManager.populate_remote_secrets_engines(
            existing_secret_engines
        )

        local_secret_engines = secretsManager.populate_local_secrets_engines(configs)

        secretsManager.configure_secrets_engines(
            client, remote_secret_engines, local_secret_engines
        )

        secretsManager.cleanup_secrets_engines(
            client, remote_secret_engines, local_secret_engines
        )
        ret["changes"] = salt.utils.dictdiffer.deep_diff(
            existing_secret_engines, client.sys.list_mounted_secrets_engines()["data"]
        )
        ret["result"] = True
    except Exception as e:
        ret["result"] = False
        log.exception(e)

    return ret


def auth_methods_synced(name, configs=[]):
    """
    Ensure authentication methods are synced with Vault

    Arguments:
        name {string} -- The id used for the state definition

    Keyword Arguments:
        configs {list} -- A list of configuration rules that defined the authentication methods (default: [])
    Returns:
        ret {dict} --  Result of the execution
    """

    client = __utils__["vault.build_client"]()
    remote_auth_methods = []
    local_auth_methods = []
    ret = {"name": name, "comment": "", "result": "", "changes": {}}

    authsManager = __salt__["vault.get_auth_methods_manager"]()

    try:
        existing_auth_methods = client.sys.list_auth_methods()["data"]
        remote_auth_methods = authsManager.populate_remote_auth_methods(
            existing_auth_methods
        )
        local_auth_methods = authsManager.populate_local_auth_methods(configs)

        authsManager.configure_auth_methods(
            client, remote_auth_methods, local_auth_methods
        )

        authsManager.cleanup_auth_methods(
            client, remote_auth_methods, local_auth_methods
        )

        ret["changes"] = salt.utils.dictdiffer.deep_diff(
            existing_auth_methods, client.sys.list_auth_methods()["data"]
        )
        ret["result"] = True
    except Exception as e:
        ret["result"] = False
        log.exception(e)

    return ret


def policies_synced(name, policies=[]):
    """Ensure policies are synced with Vault

    Arguments:
        name {string} -- The id used for the state definition

    Keyword Arguments:
        policies {list} -- A list of policies to by synced with Vault (default: [])
    Returns:
        ret {dict} --  Result of the execution
    """

    client = __utils__["vault.build_client"]()
    remote_policies = []
    ret = {"name": name, "comment": "", "result": "", "changes": {}}

    policiesManager = __salt__["vault.get_policies_manager"]()

    try:

        existing_policies = client.sys.list_policies()["data"]
        remote_policies = []

        for policy in existing_policies["policies"]:
            if not (policy == "root" or policy == "default"):
                remote_policies.append(policy)

        policiesManager.push_policies(client, remote_policies, policies)

        policiesManager.cleanup_policies(client, remote_policies, policies)

        ret["changes"] = salt.utils.dictdiffer.deep_diff(
            existing_policies, client.sys.list_policies()["data"]
        )
        ret["result"] = True
    except Exception as e:
        ret["result"] = False
        log.exception(e)
    return ret


def audit_devices_synced(name, configs=[]):
    """Ensure audit devices are synced with Vault

    Arguments:
        name {string} -- The id used for the state definition

    Keyword Arguments:
        configs {list} -- A list of configuration rules that defined the audit devices (default: [])
    Returns:
        ret {dict} --  Result of the execution
    """

    client = __utils__["vault.build_client"]()
    remote_audit_devices = []
    local_audit_devices = []
    ret = {"name": name, "comment": "", "result": "", "changes": {}}

    auditDevicesManager = __salt__["vault.get_audit_device_manager"]()
    try:
        existing_audit_devices = client.sys.list_enabled_audit_devices()["data"]

        remote_audit_devices = auditDevicesManager.populate_remote_audit_devices(
            existing_audit_devices
        )

        log.debug("remote audit devices, {}".format(remote_audit_devices))

        local_audit_devices = auditDevicesManager.get_local_audit_devices(configs)

        auditDevicesManager.configure_audit_devices(
            client, remote_audit_devices, local_audit_devices
        )

        auditDevicesManager.cleanup_audit_devices(
            client, remote_audit_devices, local_audit_devices
        )

        ret["changes"] = salt.utils.dictdiffer.deep_diff(
            existing_audit_devices, client.sys.list_enabled_audit_devices()["data"]
        )
        ret["result"] = True
    except Exception as e:
        ret["result"] = False
        log.exception(e)
    return ret
