
from __future__ import absolute_import, print_function, unicode_literals
import logging
import os
import requests
import json
import yaml
import hvac
from collections import OrderedDict
from functools import wraps


log = logging.getLogger(__name__)
logging.getLogger("requests").setLevel(logging.WARNING)


def build_client(url=None, token=None):

    vault_url = url if url != None else get_vault_url()
    client = hvac.Client(
        url=vault_url,
        token=token
    )

    if token == None:
        client.token = os.environ.get('VAULT_TOKEN')

    return client


def get_vault_url():
    '''
    Returns a string consist of url and port number
    '''
    port = __grains__['vault']['api_port'] if __grains__[
        'vault']['api_port'] != None else 8200
    url = "http://localhost"

    return "{}:{}".format(url, port)


def load_config_file(config_path):
    configs = None
    with open(os.path.join(config_path), 'r') as fd:
        try:
            configs = yaml.load(fd)
        except yaml.YAMLError as e:
            log.critical("Unable to load conf file: " + str(e))
            return False
    return configs
