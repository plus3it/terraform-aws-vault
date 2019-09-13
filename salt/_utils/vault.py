
from __future__ import absolute_import
import logging
import os
import hvac

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
