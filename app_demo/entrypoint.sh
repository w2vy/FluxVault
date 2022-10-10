#!/bin/sh

echo Version 0.1 8/21/2022 p1test Vault $VAULT_DNS Port $FLUX_PORT

git clone https://github.com/RunOnFlux/FluxVault.git
cd FluxVault
git checkout python_class
cd ..
pip3 install ./FluxVault

rm -f /tmp/node/quotes.txt /tmp/node/readme.txt

python3 app_node.py
