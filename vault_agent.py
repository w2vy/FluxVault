#!/usr/bin/python3
'''This module is a single file that supports the loading of secrets into a Flux Node'''
import json
import sys
import requests
import vault

VAULT_NAME = "localhost"                    # EDIT ME
FILE_DIR = "./files/"                       # EDIT ME
VAULT_PORT = 39898                          # EDIT ME
APP_NAME = "demo"                           # EDIT ME

class MyFluxAgent(vault.FluxAgent):
    '''User class to allow easy configuration, see EDIT ME above'''
    def __init__(self) -> None:
        super().__init__()
        self.vault_name = VAULT_NAME
        self.file_dir = FILE_DIR
        self.vault_port = VAULT_PORT

def node_vault():
    '''Vault runs this to poll every Flux node running their app'''
    url = "https://api.runonflux.io/apps/location/" + APP_NAME
    req = requests.get(url)
    # Get the list of nodes where our app is deplolyed
    if req.status_code == 200:
        values = json.loads(req.text)
        if values["status"] == "success":
            # json looks good and status correct, iterate through node list
            nodes = values["data"]
            for node in nodes:
                agent = MyFluxAgent() # Each connection to a node get a fresh agent
                ipadr = node['ip'].split(':')[0]
                print(node['name'], ipadr)
                agent.node_vault_ip(ipadr)
        else:
            print("Error", req.text)
    else:
        print("Error", url, "Status", req.status_code)

if __name__ == "__main__":
    if sys.argv[1].lower() == "--ip":
        if len(sys.argv[2]) > 0:
            ipaddr = sys.argv[2]
            one_node = MyFluxAgent()
            one_node.node_vault_ip(ipaddr)
            sys.exit(0)
        else:
            print("Missing Node IP Address: --ip ipaddress")
    if len(sys.argv[1]) == 0:
        node_vault()
        sys.exit(0)
    else:
        print("Incorrect arguments:")
        print("With no arguments all nodes running ", APP_NAME, " will be polled")
        print("If you specify '--ip ipaddress' then that ipaddress will be polled")
        sys.exit(1)
