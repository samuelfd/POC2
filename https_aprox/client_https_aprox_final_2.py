

import socket
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from base64 import b64decode,b64encode
import scapy.all
import hashlib






HOST = '127.0.0.1'     # Endereco IP do Servidor
PORT = 5001          # Porta que o Servidor esta
cifras = 'TLS_AES_256_GCM_SHA384'
bytes_random_client = os.urandom(32)
pre_master_secret = os.urandom(48)
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
master_secret_encrypt = key.encrypt(pre_master_secret, 32)
master_secret_encrypt_str =  ''.join(master_secret_encrypt) 
""" print pre_master_secret
print "\n\n" 
print bytes_random_server[0]
print "\n\n"  
print bytes_random_client """

tcp.sendall(master_secret_encrypt_str) 

prf_instance = scapy.layers.tls.crypto.prf.PRF()
master_secret =  prf_instance.compute_master_secret(pre_master_secret,bytes_random_client,bytes_random_server[0])
key_session = prf_instance.derive_key_block(master_secret,bytes_random_server[0],bytes_random_client,128)
print "\n" + key_session
iv_block = prf_instance.prf("",b"IV block",bytes_random_client + bytes_random_server[0], 16)
print "IVBLOCK  " + iv_block
client_write_key = key_session[0:32]
print "client_write_key  " + client_write_key +"\n"
MAC_write_key_client = key_session [32:64]
print "MAC_write_key_client  " + MAC_write_key_client +"\n"
server_write_key = key_session[64:96]
print "server_write_key  " + server_write_key +"\n"
MAC_write_key_server = key_session[96:128]
print "MAC_write_key_server  " + MAC_write_key_server +"\n"
obj = AES.new(client_write_key, AES.MODE_CBC, iv_block)
message = "finished"
length = 16 - (len(message) % 16)
message += bytes([length])*length
print "MESSAGE" + message
ciphertext = obj.encrypt(message)
print "ciphertext " + ciphertext
pre_MAC = ciphertext + MAC_write_key_client
pre_MAC = hashlib.sha256(pre_MAC) 
MAC = pre_MAC.hexdigest()
print "\nMAC " + MAC + "\n"
mensagem_MAC_cipher = MAC + ciphertext
print "\n mensagem_MAC_cipher  " + mensagem_MAC_cipher + "\n"
tcp.send("final" +","+ mensagem_MAC_cipher)
msg = tcp.recv(4096)
text_cipher = msg[len(msg)-32:len(msg)]
print "text_cipher  " + text_cipher 
MAC_server = msg[0:64]
print "MAC_server  " + MAC_server
pre_MAC = ciphertext + MAC_write_key_server
pre_MAC = hashlib.sha256(pre_MAC) 
MAC = pre_MAC.hexdigest()
if MAC == MAC_server : 
    obj2 = AES.new(server_write_key, AES.MODE_CBC, iv_block)      
    plain_text = obj2.decrypt(text_cipher)
    print plain_text
    plain_text = plain_text[:8]
    print plain_text
    if plain_text == message :
        tcp.close()
