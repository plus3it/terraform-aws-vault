
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


def build_client(url='http://localhost:8200',
                 token=None,
                 cert=None,
                 verify=True,
                 timeout=30,
                 proxies=None,
                 allow_redirects=True,
                 session=None):

    client = hvac.Client(url=url)

    client.token = os.environ.get('VAULT_TOKEN')

    return client


def load_config_file(config_path):
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
