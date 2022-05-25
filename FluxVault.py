#!/usr/bin/python

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import binascii
import json
import sys
import os
import time
import requests

MaxMessage = 8192

VaultName = ""
RequestFiles = []

def encrypt_data(keypem, data):
    key = RSA.import_key(keypem)
    session_key = get_random_bytes(16)
    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    
    msg = {
        "enc_session_key":enc_session_key.hex(),
        "nonce": cipher_aes.nonce.hex(),
        "tag": tag.hex(),
        "cipher": ciphertext.hex()
    }
    return msg

def decrypt_data(keypem, cipher):
    private_key = RSA.import_key(keypem)
    enc_session_key = bytes.fromhex(cipher["enc_session_key"])
    nonce = bytes.fromhex(cipher["nonce"])
    tag = bytes.fromhex(cipher["tag"])
    ciphertext = bytes.fromhex(cipher["cipher"])

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return data

def send_AESkey(keypem, aeskey):
    message = encrypt_data(keypem, aeskey)
    return message

def receive_AESkey(keypem, message):
    cipher = json.loads(message)
    data = decrypt_data(keypem, cipher)
    data = data.decode("utf-8")
    return data

def decrypt_aes_data(key, data):
    jdata = json.loads(data)
    nonce = bytes.fromhex(jdata["nonce"])
    tag = bytes.fromhex(jdata["tag"])
    ciphertext = bytes.fromhex(jdata["ciphertext"])

    # let's assume that the key is somehow available again
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    msg = cipher.decrypt_and_verify(ciphertext, tag)
    return json.loads(msg)

def encrypt_aes_data(key, message):
    msg = json.dumps(message)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode("utf-8"))
    jdata = {
        "nonce": cipher.nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex()
    }
    data = json.dumps(jdata)
    return data

def send_receive(sock, request):
    request += "\n"

    try:
        sock.sendall(request.encode("utf-8"))
    except socket.error:
        print('Send failed')
        sys.exit()

    # Receive data
    reply = sock.recv(MaxMessage)
    reply = reply.decode("utf-8")
    return reply

def receive_only(sock):
    # Receive data
    reply = sock.recv(MaxMessage)
    reply = reply.decode("utf-8")
    return reply

CONNECTED = "CONNECTED"
KEYSENT = "KEYSENT"
STARTAES = "STARTAES"
READY = "READY"
REQUEST = "REQUEST"
DONE = "DONE"
AESKEY = "AESKEY"

 # A server program which accepts requests from clients to capitalize strings. When
 # clients connect, a new thread is started to handle a client. The receiving of the
 # client data, the capitalizing, and the sending back of the data is handled on the
 # worker thread, allowing much greater throughput because more clients can be handled
 # concurrently.

import socketserver
import threading
import socket

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

class NodeKeyClient(socketserver.StreamRequestHandler):
    def handle(self):
        client = f'{self.client_address} on {threading.currentThread().getName()}'
        print(f'Connected: {client}')
        peer_ip = self.connection.getpeername()
        result = socket.gethostbyname(VaultName)
        if (peer_ip[0] != result):
          print("Reject Connection, wrong IP:", peer_ip[0], result)
          time.sleep(15)
          return
        nkData = { "State": CONNECTED }
        # Copy file list into local variable
        BootFiles = BOOTFILES.copy()
          
        while True:
          try:
              reply = ""
              if (nkData["State"] == CONNECTED):
                # New incoming connection from Vault, maybe validate source IP here or in server listen
                # Create a new RSA key and send the Public Key the Vault
                # We appear to ignore any initial data
                nkData["RSAkey"] = RSA.generate(2048)
                nkData["Private"] = nkData["RSAkey"].export_key()
                nkData["Public"] = nkData["RSAkey"].publickey().export_key()
                nkData["State"] = KEYSENT
                jdata = { "State": KEYSENT, "PublicKey": nkData["Public"].decode("utf-8")}
                reply = json.dumps(jdata)
              else:
                data = self.rfile.readline()
                if not data:
                  break
                if (nkData["State"] == KEYSENT):
                  jdata = json.loads(data)
                  if (jdata["State"] != AESKEY):
                    break # Tollerate no errors
                  nkData["AESKEY"] = decrypt_data(nkData["Private"], jdata)
                  nkData["State"] = STARTAES
                  random = get_random_bytes(16).hex()
                  jdata = { "State": STARTAES, "Text": "Test", "fill": random}
                  reply = encrypt_aes_data(nkData["AESKEY"], jdata)
                else:
                  if (nkData["State"] == STARTAES):
                    jdata = decrypt_aes_data(nkData["AESKEY"], data)
                    if (jdata["State"] == STARTAES and jdata["Text"] == "Passed"):
                      nkData["State"] = READY # We are good to go!
                      data = ""
                    else:
                      break # Failed
              if (nkData["State"] == READY):
                if (len(data) == 0):
                  jdata = {"State": READY}
                else:
                  jdata = decrypt_aes_data(nkData["AESKEY"], data)
                if (jdata["State"] == "DATA"):
                  if (jdata["Status"] == "Success"):
                    open(file_dir+BootFiles[0], "w").write(jdata["Body"])
                  BootFiles.pop(0)
                # Send request for first (or next file)
                # If no more we are Done (close connection?)
                random = get_random_bytes(16).hex()
                if (len(BootFiles) == 0):
                  jdata = { "State": DONE, "fill": random }
                else:
                  try:
                    content = open(file_dir+BootFiles[0]).read()
                    crc = binascii.crc32(content.encode("utf-8"))
                    # File exists
                  except FileNotFoundError:
                    crc = 0
                  jdata = { "State": REQUEST, "FILE": BootFiles[0], "crc32": crc, "fill": random }
                reply = encrypt_aes_data(nkData["AESKEY"], jdata)
              if (len(reply) > 0):
                reply += "\n"
                self.wfile.write(reply.encode("utf-8"))
          except ValueError:
            print("try failed")
            break
        print(f'Closed: {client}')

def NodeServer(port, vaultname, bootfiles, base):
    global VaultName
    VaultName = vaultname
    global BOOTFILES
    BOOTFILES = bootfiles
    global file_dir
    file_dir = base
    if (len(BOOTFILES) > 0):
        with ThreadedTCPServer(('', port), NodeKeyClient) as server:
            print(f'The NodeKeyClient server is running on port ' + str(port))
            server.serve_forever()
    else:
        print("BOOTFILES missing from comamnd line, see usage")

def NodeVaultIP(port, AppIP, file_dir):
    # We have a node try sending it config data
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error:
        print('Failed to create socket')
        return

    try:
        remote_ip = socket.gethostbyname( AppIP )
    except socket.gaierror:
        print('Hostname could not be resolved')
        return

    # Set short timeout
    sock.settimeout(5)

    # Connect to remote serverAESData
    try:
        print('# Connecting to server, ' + AppIP + ' (' + remote_ip + ')')
        sock.connect((remote_ip , port))
    except socket.timeout:
        print("Connect timed out")
        sock.close
        return

    sock.settimeout(None)

    reply = receive_only(sock)

    try:
        jdata = json.loads(reply)
        PublicKey = jdata["PublicKey"].encode("utf-8")
    except ValueError:
        print("No Public Key received:", reply)
        return
    # Generate and send AES Key encrypted with PublicKey
    AESKey = get_random_bytes(16).hex().encode("utf-8")
    jdata = send_AESkey(PublicKey, AESKey)
    jdata["State"] = AESKEY
    data = json.dumps(jdata)
    reply = send_receive(sock, data)
    # AES Encryption should be started now
    jdata = decrypt_aes_data(AESKey, reply)
    if (jdata["State"] != STARTAES):
        print("StartAES not found")
        return
    if (jdata["Text"] != "Test"):
        print("StartAES Failed")
        return
    jdata["Text"] = "Passed"
    while (True):
        data = encrypt_aes_data(AESKey, jdata)
        reply = send_receive(sock, data)
        jdata = decrypt_aes_data(AESKey, reply)
        reply = ""
        if (jdata["State"] == DONE):
            break
        if (jdata["State"] == REQUEST):
            fname = jdata["FILE"]
            crc = int(jdata["crc32"])
            jdata["State"] = "DATA"
            try:
                secret = open(file_dir+fname).read()
                mycrc = binascii.crc32(secret.encode("utf-8"))
                if (crc == mycrc):
                    print("File ", fname, " Match!")
                    jdata["Status"] = "Match"
                    jdata["Body"] = ""
                else:
                    print("File ", fname, " sent!")
                    jdata["Body"] = secret
                    jdata["Status"] = "Success"
            except FileNotFoundError:
                print("File Not Found: " + file_dir+fname)
                jdata["Body"] = ""
                jdata["Status"] = "FileNotFound"
        else:
            jdata["Body"] = ""
            jdata["Status"] = "Unknown Command"
    sock.close()

def NodeVault(port, AppName, file_dir):
    url = "https://api.runonflux.io/apps/location/" + AppName
    req = requests.get(url)
    if (req.status_code == 200):
        values = json.loads(req.text)
        if (values["status"] == "success"):
            nodes = values["data"]
            for node in nodes:
                ipadr = node['ip'].split(':')[0]
                print(node['name'], ipadr)
                NodeVaultIP(port, ipadr, file_dir)
        else:
            print("Error", req.text)
    else:
        print("Error", url, "Status", req.status_code)
    return

def usage(argv):
    if (usage):
        print("Usage:")
        print(argv[0] + " Node --port port --vault VaultDomain [--dir dirname] file1 [file2 file3 ...]")
        print("")
        print("Run on node with the port and Domain/IP of the Vault and the list of files")
        print("")
        print(argv[0] + " Vault --port port --app AppName --dir dirname")
        print("")
        print("Run on Vault the AppName will be used to get the list of nodes where the App is running")
        print("The vault will connect to each node : Port and provide the files requested")
        print("")
        print(argv[0] + " VaultIP --port port --ip IPadr [--dir dirname]")
        print("")
        print("The Vault will connect to a single ip : Port to provide files")
        print("")

# NodeServer port VaultDomain
# NodeVault port NodeIP

node_opts = ["--port", "--vault", "--dir"]
vault_opts = ["--port", "--app", "--ip", "--dir"]

files = []
port = -1
vault = ""
base_dir = ""
ipadr = ""
appName = ""
error = False

if (sys.argv[1].upper() == "NODE"):
    args = sys.argv[2:]
    while (len(args) > 0):
      if (args[0] in node_opts):
          if (args[0].lower() == "--port"):
              try:
                  port = int(args[1])
                  args.pop(0)
                  args.pop(0)
              except ValueError:
                  print(args[1] + " invalid port number")
                  sys.exit()
          if (args[0].lower() == "--vault"):
              vault = args[1]
              args.pop(0)
              args.pop(0)
          if (args[0].lower() == "--dir"):
              base_dir = args[1]
              if (base_dir.endswith("/") == False):
                  base_dir = base_dir + "/"
              args.pop(0)
              args.pop(0)
              if (os.path.isdir(base_dir) == False):
                  print(base_dir + " is not a directory or does not exist")
      else:
          files = args
          break
    if (port == -1):
        print("Port number must be specified like --port 31234")
        error = True
    if (len(vault) == 0):
        print("Vault Domain or IP must be set like: --vault 1.2.3.4 or --vault my.vault.host.io")
        error = True
    if (len(files) == 0):
        print("Secret files must be listed after all other arguments")
        error = True
    if (error == True):
        usage(sys.argv)
    else:
        NodeServer(port, vault, files, base_dir)
    sys.exit()

if (sys.argv[1].upper() == "VAULT"):
    args = sys.argv[2:]
    while (len(args) > 0):
        if (args[0] in node_opts):
            if (args[0].lower() == "--port"):
                try:
                    port = int(args[1])
                    args.pop(0)
                    args.pop(0)
                except ValueError:
                    print(args[1] + " invalid port number")
                    sys.exit()
            if (args[0].lower() == "--app"):
                appName = args[1]
                args.pop(0)
                args.pop(0)
            if (args[0].lower() == "--ip"):
                ipadr = args[1]
                args.pop(0)
                args.pop(0)
            if (args[0].lower() == "--dir"):
                base_dir = args[1]
                if (base_dir.endswith("/") == False):
                    base_dir = base_dir + "/"
                args.pop(0)
                args.pop(0)
                if (os.path.isdir(base_dir) == False):
                    print(base_dir + " is not a directory or does not exist")
        else:
          print("Unknown option: ", args[0])
          args.pop(0)
    if (port == -1):
        print("Port number must be specified like --port 31234")
        error = True
    if (len(appName) == 0 and len(ipadr) == 0):
        print("Application Name OR IP must be set but not Both! like: --appname myapp or --ip 2.3.45.6")
        error = True
    if (len(appName) > 0 and len(ipadr) > 0):
        print("Application Name OR IP must be set but not Both! like: --appname myapp or --ip 2.3.45.6")
        error = True
    if (error == True):
        usage(sys.argv)
    else:
        if (len(appName) > 0):
            NodeVault(port, appName, base_dir)
        else:
            NodeVaultIP(port, ipadr, base_dir)
    sys.exit()
