from __future__ import absolute_import
import logging
import os
import hvac

log = logging.getLogger(__name__)
logging.getLogger("requests").setLevel(logging.WARNING)


def build_client(url=None, token=None):
    vault_url = url if url != None else get_vault_url()
    client = hvac.Client(url=vault_url, token=token)

    if token == None:
        client.token = os.environ.get("VAULT_TOKEN")

    return client


def get_vault_url():
    """Construct Vault server's URL

    Returns:
        string -- URL of the the vault server
    """

    # default port for vault server is 8200
    port = 8200

    try:
        port = __pillar__["vault"]["lookup"]["api_port"]
    except Exception:
        pass

    return "http://localhost:{}".format(port)
