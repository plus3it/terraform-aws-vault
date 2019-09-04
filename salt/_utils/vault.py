# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function, unicode_literals
import base64
import logging
import os
import requests
import json
import time
import yaml
import hvac
import hashlib
from collections import OrderedDict
from functools import wraps


log = logging.getLogger(__name__)
logging.getLogger("requests").setLevel(logging.WARNING)

def build_client(url=None,
                token=None,
                cert=None,
                verify=True,
                timeout=30,
                proxies=None,
                allow_redirects=True,
                session=None):
    """Instantiates and returns hvac Client class for HashiCorp’s Vault.

    Keyword Arguments:
        url {str} -- Base URL for the Vault instance being addressed. (default: {None})
        token {str} -- Authentication token to include in requests sent to Vault. (default: {None})
        cert {tuple} -- Certificates for use in requests sent to the Vault instance. This should be a tuple with the certificate and then key. (default: {None})
        verify {bool} -- Either a boolean to indicate whether TLS verification should be performed when sending requests to Vault, or a string pointing at the CA bundle to use for verification. (default: {True})
        timeout {int} -- The timeout value for requests sent to Vault. (default: {30})
        proxies {dict} -- Proxies to use when performing requests (default: {None})
        allow_redirects {bool} -- Whether to follow redirects when sending requests to Vault. (default: {True})
        session {request.Session} -- Optional session object to use when performing request. (default: {None})
    """
    vault_url = url if url != None else get_vault_url()
    client = hvac.Client(url=vault_url)

    client.token = os.environ.get('VAULT_TOKEN')

    return client

def get_vault_url():
    '''
    Returns a string consist of url and port number
    '''
    port = __grains__['vault']['api_port'] if __grains__['vault']['api_port'] != None else 8200
    url = "https://localhost"

    return "{}:{}".format(url, port)

def load_config_file(config_path):
    """Retrieve config file from provided path

    Arguments:
        config_path {str} -- path to config file

    Returns:
        [obj] -- parsed object of the config
    """
    config = None
    with open(os.path.join(config_path), 'r') as fd:
        try:
            config = yaml.load(fd)

        except yaml.YAMLError as e:
            log.critical("Unable to load conf file: " + str(e))
            return False
    return config


class VaultError(Exception):
    def __init__(self, message=None, errors=None):
        if errors:
            message = ', '.join(errors)

        self.errors = errors

        super(VaultError, self).__init__(message)


class InvalidRequest(VaultError):
    pass


class Unauthorized(VaultError):
    pass


class Forbidden(VaultError):
    pass


class InvalidPath(VaultError):
    pass


class RateLimitExceeded(VaultError):
    pass


class InternalServerError(VaultError):
    pass


class VaultNotInitialized(VaultError):
    pass


class VaultDown(VaultError):
    pass


class UnexpectedError(VaultError):
    pass


def vault_error():
    return VaultError
