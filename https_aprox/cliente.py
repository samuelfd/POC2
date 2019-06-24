import socket
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from base64 import b64decode,b64encode
import scapy.all
import hashlib
import cPickle as pickle

def encrypta_rsa(public_key,pre_master_secret):    

    key = RSA.importKey(public_key_rsa_string)    
    master_secret_encrypt = key.encrypt(pre_master_secret,32)
    master_secret_encrypt_str  = pickle.dumps(master_secret_encrypt)

    return master_secret_encrypt_str 

def gera_chaves(pre_master_secret, bytes_random_client, bytes_random_server) :
    prf_instance = scapy.layers.tls.crypto.prf.PRF()
    master_secret =  prf_instance.compute_master_secret(pre_master_secret, bytes_random_client, bytes_random_server)
    key_session = prf_instance.derive_key_block(master_secret,bytes_random_server,bytes_random_client,128)
    print ("\n key_session   " + key_session)
    iv_block = prf_instance.prf("",b"IV block",bytes_random_client + bytes_random_server, 16)
    print ("\nIVBLOCK  " + iv_block)
    client_write_key = key_session[0:32]
    print ("\nclient_write_key  " + client_write_key +"\n")
    MAC_write_key_client = key_session [32:64]
    print ("\nMAC_write_key_client  " + MAC_write_key_client +"\n")
    server_write_key = key_session[64:96]
    print ("\nserver_write_key  " + server_write_key +"\n")
    MAC_write_key_server = key_session[96:128]

    return iv_block, client_write_key,  MAC_write_key_client, server_write_key , MAC_write_key_server

def gera_MAC (ciphertext, MAC_write_key_client) :    
    print ("\nciphertext " + ciphertext)
    pre_MAC = ciphertext + MAC_write_key_client
    pre_MAC = hashlib.sha256(pre_MAC) 
    MAC = pre_MAC.hexdigest()

    return MAC

def encrypt_AES (client_write_key,iv_block,message):
    obj = AES.new(client_write_key, AES.MODE_CBC, iv_block)
    print ("\nMESSAGE" + message)
    ciphertext = obj.encrypt(message)

    return ciphertext

def verifica_MAC (msg, server_write_key, iv_block, MAC_write_key_server) :
    text_cipher = msg[len(msg)-32:len(msg)]
    print ("\ntext_cipher  " + text_cipher )
    MAC_server = msg[0:64]
    print ("\nMAC_server_client  " + MAC_server)
    pre_MAC = text_cipher + MAC_write_key_server
    pre_MAC = hashlib.sha256(pre_MAC) 
    MAC = pre_MAC.hexdigest()
    print ("\nMAC_server  " + MAC)
    if MAC == MAC_server : 
        obj2 = AES.new(server_write_key, AES.MODE_CBC, iv_block)
        plain_text = obj2.decrypt(text_cipher)
        plain_text = plain_text[:8]
        print ("\nPLAIN TEXT" + plain_text)
        if plain_text == message :
            print ("###########################FINALLY######################################")
            print ("\n\n\n")
            tcp.close()



if __name__ == "__main__":
    while i < 15
    HOST = '127.0.0.1'     # Endereco IP do Servidor
    PORT = 5026       # Porta que o Servidor esta
    cifras = 'TLS_AES_256_CBC_SHA256'
    bytes_random_client = os.urandom(32)
    pre_master_secret = os.urandom(48)
    version_tls = "1.2"
    certificado = ""
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dest = (HOST, PORT)
    tcp.connect(dest)
    tcp.send (cifras +","+ bytes_random_client + "," + version_tls)
    msg = tcp.recv(4096)
    aux = msg.split(",")
    bytes_random_server = aux[0]    
    public_key = msg.split("Public Key\n")
    public_key_rsa_string = str(public_key[1])
    master_secret_encrypt_str = encrypta_rsa(public_key_rsa_string,pre_master_secret)#
    tcp.send(master_secret_encrypt_str)
    iv_block, client_write_key,  MAC_write_key_client, server_write_key , MAC_write_key_server = gera_chaves(pre_master_secret, bytes_random_client, bytes_random_server)
    message = "finished"
    length = 16 - (len(message) % 16)
    message += bytes([length])*length
    ciphertext = encrypt_AES(client_write_key, iv_block, message)#
    MAC = gera_MAC(ciphertext, MAC_write_key_client)#
    mensagem_MAC_cipher = MAC + ciphertext
    tcp.send("final" +","+ mensagem_MAC_cipher)
    msg = tcp.recv(4096)
    verifica_MAC(msg, server_write_key, iv_block, MAC_write_key_server)#