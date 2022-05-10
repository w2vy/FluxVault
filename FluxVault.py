#!/usr/bin/python

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import json
import binascii
import sys
import time

VaultName = ""

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
  #print("encoded ", aeskey)
  message = encrypt_data(keypem, aeskey)
  return message

def receive_AESkey(keypem, message):
  cipher = json.loads(message)
  data = decrypt_data(keypem, cipher)
  data = data.decode("utf-8")
  #print("Received ", data)
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
    # Send data to remote server
  #print('# Sending data to server')
  request += "\n"

  try:
      sock.sendall(request.encode("utf-8"))
  except socket.error:
      print('Send failed')
      sys.exit()

  # Receive data
  #print('# Receive data from server')
  reply = sock.recv(8192)
  reply = reply.decode("utf-8")
  #print(reply)
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
        #print("PeerIP ", peer_ip[1])
        result = socket.gethostbyname(VaultName)
        #print("Vault Host", VaultName, result)
        if (peer_ip[0] != result):
          print("Reject Connection, wrong IP:", peer_ip[0], result)
          time.sleep(15)
          return
        nkData = { "State": CONNECTED }
        file_recd = False
        while True:
          try:
              data = self.rfile.readline()
              reply = ""
              if not data:
                print("No Data!")
                break
              if (nkData["State"] == CONNECTED):
                # New incoming connection from Vault, maybe validate source IP here or in server listen
                # Create a new RSA key and send the Public Key the Vault
                # We appear to ignore any initial data
                print("Connected: ", data)
                nkData["RSAkey"] = RSA.generate(2048)
                nkData["Private"] = nkData["RSAkey"].export_key()
                nkData["Public"] = nkData["RSAkey"].publickey().export_key()
                nkData["State"] = KEYSENT
                #print("Public: ", type(nkData["Public"]), nkData["Public"])
                jdata = { "State": KEYSENT, "PublicKey": nkData["Public"].decode("utf-8")}
                reply = json.dumps(jdata)
              else:
                if (nkData["State"] == KEYSENT):
                  jdata = json.loads(data)
                  if (jdata["State"] != AESKEY):
                    break # Tollerate no errors
                  nkData["AESKEY"] = decrypt_data(nkData["Private"], jdata)
                  #print("AESKey RX ", type(nkData["AESKEY"]), nkData["AESKEY"])
                  nkData["State"] = STARTAES
                  random = get_random_bytes(16).hex()
                  jdata = { "State": STARTAES, "Text": "Test", "fill": random}
                  reply = encrypt_aes_data(nkData["AESKEY"], jdata)
                else:
                  if (nkData["State"] == STARTAES):
                    #print("Pass?", data)
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
                  print(jdata["Body"])
                  open(BOOTFILE, "w").write(jdata["Body"])
                  file_recd = True
                # Send request for first (or next file)
                # If no more we are Done (close connection?)
                random = get_random_bytes(16).hex()
                if (file_recd):
                  jdata = { "State": DONE, "fill": random }
                else:
                  jdata = { "State": REQUEST, "FILE": BOOTFILE, "fill": random }
                reply = encrypt_aes_data(nkData["AESKEY"], jdata)
              #print("Reply: ", len(reply), " ", reply)
              if (len(reply) > 0):
                reply += "\n"
                self.wfile.write(reply.encode("utf-8"))
          except ValueError:
            print("try failed")
            break
        print(f'Closed: {client}')

def NodeServer(port, vaultname, bootfile):
  global VaultName
  VaultName = vaultname
  global BOOTFILE
  BOOTFILE = bootfile
  if (len(BOOTFILE) > 0):
    with ThreadedTCPServer(('', port), NodeKeyClient) as server:
        print(f'The NodeKeyClient server is running on port 59898')
        server.serve_forever()
  else:
    print("BOOTFILE missing from comamnd line, see usage")

def NodeVault(port, AppIP):
  #print('# Creating socket')
  try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  except socket.error:
    print('Failed to create socket')
    sys.exit()

  #print('# Getting remote IP address') 
  try:
      remote_ip = socket.gethostbyname( AppIP )
  except socket.gaierror:
      print('Hostname could not be resolved. Exiting')
      sys.exit()

  # Connect to remote serverAESData
  print('# Connecting to server, ' + AppIP + ' (' + remote_ip + ')')
  sock.connect((remote_ip , port))

  reply = send_receive(sock, "Hello")

  try:
    jdata = json.loads(reply)
    PublicKey = jdata["PublicKey"].encode("utf-8")
  except ValueError:
    print("No Public Key received:", reply)
    sys.exit()
  #print(PublicKey)
  # Generate and send AES Key encrypted with PublicKey
  AESKey = get_random_bytes(16).hex().encode("utf-8")
  #print("AESKey TX ", type(AESKey), AESKey)
  jdata = send_AESkey(PublicKey, AESKey)
  jdata["State"] = AESKEY
  data = json.dumps(jdata)
  reply = send_receive(sock, data)
  # AES Encryption should be started now
  jdata = decrypt_aes_data(AESKey, reply)
  #print("AESData ", jdata)
  if (jdata["State"] != STARTAES):
    print("StartAES not found")
    sys.exit()
  if (jdata["Text"] != "Test"):
    print("StartAES Failed")
    sys.exit()
  jdata["Text"] = "Passed"
  while (True):
    data = encrypt_aes_data(AESKey, jdata)
    reply = send_receive(sock, data)
    jdata = decrypt_aes_data(AESKey, reply)
    #print("Ready ", jdata)
    reply = ""
    if (jdata["State"] == DONE):
      break
    if (jdata["State"] == REQUEST):
      fname = jdata["FILE"]
      jdata["State"] = "DATA"
      try:
        secret = open(fname).read()
        print(secret)
        jdata["Body"] = secret
        jdata["Status"] = "Success"
      except FileNotFoundError:
        jdata["Body"] = ""
        jdata["Status"] = "FileNotFound"
    else:
      jdata["Body"] = ""
      jdata["Status"] = "Unknown Command"
    #print(jdata)
  sock.close()
  return

# NodeServer port VaultDomain
# NodeVault port NodeIP
usage = False

if (len(sys.argv) > 3):
  try:
    port = int(sys.argv[2])
  except ValueError:
    print(sys.argv[2] + " invalid port number")
    usage = True

if (usage):
  print("Usage:")
  print(sys.argv[0] + " NodeServer port VaultDomain")
  print(sys.argv[0] + " NodeVault port AppNodeIP")
  sys.exit()

print(sys.argv[1].upper(), sys.argv[1])

if (sys.argv[1].upper() == "NODE"):
  NodeServer(port, sys.argv[3], sys.argv[4])
else:
  NodeVault(port, sys.argv[3])

