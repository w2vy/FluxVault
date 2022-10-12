#!/usr/bin/python3
'''This module is a single file that supports the loading of secrets into a Flux Node'''
import json
import sys
import os
import requests
from fluxvault import FluxAgent

VAULT_NAME = os.getenv('VAULT_NAME')      # EDIT ME
VAULT_OPORT = os.getenv('VAULT_PORT')      # EDIT ME
APP_NAME = os.getenv('VAULT_APP')         # EDIT ME
FILE_DIR = os.getenv('VAULT_FILE_DIR')    # EDIT ME

VERBOSE = True

if VAULT_NAME is None:
    VAULT_NAME = 'localhost'
if VAULT_OPORT is None:
    VAULT_OPORT = 39898
else:
    VAULT_OPORT = int(VAULT_OPORT)
if APP_NAME is None:
    APP_NAME = 'VaultDemo'
if FILE_DIR is None:
    FILE_DIR = './files/'

class MyFluxAgent(FluxAgent):
    '''User class to allow easy configuration, see EDIT ME above'''
    def __init__(self) -> None:
        super().__init__()
        self.vault_name = VAULT_NAME
        self.file_dir = FILE_DIR
        self.vault_port = VAULT_OPORT
        self.verbose = VERBOSE

def node_vault():
    '''Vault runs this to poll every Flux node running their app'''
    url = "https://api.runonflux.io/apps/location/" + APP_NAME
    req = requests.get(url, timeout=30)
    # Get the list of nodes where our app is deplolyed
    if req.status_code == 200:
        values = json.loads(req.text)
        if values["status"] == "success":
            # json looks good and status correct, iterate through node list
            nodes = values["data"]

            for this_node in nodes:
                agent = MyFluxAgent() # Each connection to a node get a fresh agent
                ipadr = this_node['ip'].split(':')[0]
                if VERBOSE:
                    print(this_node['name'], ipadr)
                agent.node_vault_ip(ipadr)
        else:
            print("Error", req.text)
    else:
        print("Error", url, "Status", req.status_code)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        node_vault()
        sys.exit(0)
    if sys.argv[1].lower() == "--ip":
        if len(sys.argv) > 2:
            IPADR = sys.argv[2]
            one_node = MyFluxAgent()
            one_node.node_vault_ip(IPADR)
            print(IPADR, one_node.result)
            sys.exit(0)
        else:
            print("Missing Node IP Address: --ip ipaddress")
    print("Incorrect arguments:")
    print("With no arguments all nodes running ", APP_NAME, " will be polled")
    print("If you specify '--ip ipaddress' then that ipaddress will be polled")
    sys.exit(1)
