#!/bin/sh

echo Version 0.5 10/12/2022 p1test Vault $VAULT_NAME Port $VAULT_PORT

nginx

git clone https://github.com/RunOnFlux/FluxVault.git
cd FluxVault
git checkout python_class
cd ..
pip3 install ./FluxVault

rm -f /tmp/node/quotes.txt /tmp/node/readme.txt

python3 vault_node.py
