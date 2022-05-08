# FluxVault
Flux Vault - load private data into running docker

The goal of this is to provide a way to securely load passwords on a running FLux Docker

There are two modes for the script NODE and VAULT

The NODE run on the Flux Node and the VAULT runs on a single secure system, typically behind a firewall.

In my case the Vault is in my Home LAN and the Nodes are running on FLux

The Node will only accept connections from a predefined host name, which could be controlled by dyn-dns

The Vault will query FluxOS to determine what IP addresses are running the application the Vault supports.
The Vault will connect to the nodes periodically to see if they need any files sent securely.

This is not designed to send large files, just simple configuration withs and passwords