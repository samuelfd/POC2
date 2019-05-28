import socket
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from base64 import b64decode,b64encode
import scapy.all






HOST = '127.0.0.1'     # Endereco IP do Servidor
PORT = 5000          # Porta que o Servidor esta
cifras = 'TLS_AES_256_GCM_SHA384'
bytes_random_client = os.urandom(32)
master_secret = os.urandom(48)
version_tls = "1.2"
certificado = ""
tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
dest = (HOST, PORT)
tcp.connect(dest)
tcp.send (cifras +","+ bytes_random_client + "," + version_tls)
msg = tcp.recv(4096)
bytes_random_server = msg.split(",")
public_key = msg.split("Public Key\n")
str1 = str(public_key[1])
key = RSA.importKey(str1)
master_secret_encrypt = key.encrypt(master_secret, 32)
master_secret_encrypt_str =  ''.join(master_secret_encrypt) 
print master_secret
print "\n\n" 
print bytes_random_server[0]
print "\n\n"  
print bytes_random_client

tcp.sendall(master_secret_encrypt_str) 

prf_instance = scapy.layers.tls.crypto.prf.PRF()
key_session =  prf_instance.compute_master_secret(master_secret,bytes_random_client,bytes_random_server[0])
print type(key_session)
print "bla\n",key_session,"bla"

tcp.close()
