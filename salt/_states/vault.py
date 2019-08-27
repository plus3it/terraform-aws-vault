# -*- coding: utf-8 -*-

from __future__ import absolute_import

import logging
import os
import json
import sys

import hvac
import boto3

log = logging.getLogger(__name__)

try:
    import hvac
    import boto3
    DEPS_INSTALLED = True
except ImportError:
    log.debug('Unable to import the libraries.')
    DEPS_INSTALLED = False

__all__ = ['initialize']


def __virtual__():
    return DEPS_INSTALLED


def initialized(name, ssm_path, recovery_shares=5, recovery_threshold=3):
    """
    Ensure that the vault instance has been initialized and run the
    initialization if it has not.

    :param name: The id used for the state definition
    :param recovery_shares: The number of recovery shares to use for the
    initialization key
    :param recovery_threshold: The number of recovery keys required to unseal the vault
    :param ssm_path: The path to store root token in SSM Parameter store

    :returns: Result of the execution
    :rtype: dict
    """
    ret = {'name': name,
          'comment': '',
          'result': '',
          'changes': {}}

    client = hvac.Client(url='http://localhost:8200')

    is_initialized = client.sys.is_initialized()

    if is_initialized:
        ret['result'] = True
        ret['comment'] = 'Vault is already initialized'
    else:
        result = client.sys.initialize(
            recovery_shares=recovery_shares,
            recovery_threshold=recovery_threshold
        )
        root_token = result['root_token']
        recovery_keys = result['recovery_keys']
        is_success = client.sys.is_initialized()

        ret['result'] = is_success
        ret['changes'] = {
            'root_credentials': {
                'new': {
                    'recover_keys': '/{}/{}'.format(ssm_path, 'recovery_keys'),
                    'root_token': '/{}/{}'.format(ssm_path, 'root_token')
                },
                'old': {}
            }
        }

        # upload root token ssm parameter store
        if is_success:
            ssm_client = boto3.client('ssm')
            # saving root token
            ssm_client.put_parameter(
                Name='/{}/{}'.format(ssm_path, 'root_token'),
                Value=root_token,
                Type="SecureString",
                Overwrite=True
            )

            # saving recovery keys
            ssm_client.put_parameter(
                Name='/{}/{}'.format(ssm_path, 'recovery_keys'),
                Value=json.dumps(recovery_keys),
                Type="SecureString",
                Overwrite=True
            )

        ret['comment'] = 'Vault has {}initialized'.format(
            '' if is_success else 'failed to be ')
    return ret
