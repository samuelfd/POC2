import socket
import scapy.all
import os
from Crypto.PublicKey import RSA 
from Crypto.Cipher import AES
import shutil
import sys
import hashlib
import cPickle as pickle

def generate_RSA(bits=4096):   
    
    new_key = RSA.generate(bits, e=65537) 
    public_key = new_key.publickey().exportKey("PEM") 
    private_key = new_key.exportKey("PEM") 

    return private_key, public_key 

def certificado(aux):
    bytes_random_client = aux[1]
    shutil.copyfile('certificado2.txt','certificado3.txt')
    arq = open('certificado3.txt', 'ab')
    private_key, public_key = generate_RSA()            
    arq.write(public_key)            
    arq.close()          
    arq = open('certificado3.txt', 'rb')
    certificado = arq.read()                 
    con.sendall(bytes_random_server + "," + cifras +","+ certificado)              
    flag = False

    return flag, bytes_random_client, private_key

def decrypt_master_secret (msg,key):
    master_secret_bytes = pickle.loads(msg)
    master_secret_decrypt = key.decrypt(master_secret_bytes)

    return master_secret_decrypt
     
def gera_chaves (master_secret_decrypt, bytes_random_server, bytes_random_client):
    prf_instance = scapy.layers.tls.crypto.prf.PRF()
    master_secret =  prf_instance.compute_master_secret(master_secret_decrypt, bytes_random_client, bytes_random_server)
    key_session = prf_instance.derive_key_block(master_secret, bytes_random_server, bytes_random_client,128)
    print "\nkey_session  " + key_session 
    iv_block = prf_instance.prf("",b"IV block",bytes_random_client + bytes_random_server, 16)
    print "\nIVBLOCK  " + iv_block
    client_write_key = key_session[0:32]
    print "\nclient_write_key  " + client_write_key +"\n"
    MAC_write_key_client = key_session [32:64]
    print "\nMAC_write_key_client  " + MAC_write_key_client +"\n"
    server_write_key = key_session[64:96]
    print "\nserver_write_key  " + server_write_key +"\n"
    MAC_write_key_server = key_session[96:128]
    print "\nMAC_write_key_server  " + MAC_write_key_server +"\n"

    return iv_block,client_write_key, MAC_write_key_client, server_write_key,  MAC_write_key_server
             
def calcula_MAC (text_cipher, MAC_write_key):
    pre_MAC = text_cipher + MAC_write_key
    pre_MAC = hashlib.sha256(pre_MAC)
    MAC = pre_MAC.hexdigest()

    return MAC

def decrypt_text_cliente (client_write_key, iv_block, text_cipher):
    obj = AES.new(client_write_key, AES.MODE_CBC, iv_block)
    pre_plain_text = obj.decrypt(text_cipher)
    plain_text = pre_plain_text[:8]
    return plain_text


def encrypt_text_server (server_write_key, iv_block):
    message = "finished"
    length = 16 - (len(message) % 16)
    message += bytes([length])*length
    obj = AES.new(server_write_key, AES.MODE_CBC, iv_block)
    text_cipher_server = obj.encrypt(message)
    return text_cipher_server



if __name__ == "__main__":
    HOST = ''              # Endereco IP do Servidor
    PORT = 5028          # Porta que o Servidor esta
    cifras = 'TLS_AES_256_CBC_SHA256'
    bytes_random_server = os.urandom(32)
    print "bytes_random_server  " + bytes_random_server
    version_tls = "1.2"
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    orig = (HOST, PORT)
    tcp.bind(orig)
    tcp.listen(5)

    while True:
        con, cliente = tcp.accept()
        print 'Concetado por', cliente
        flag = True
        while True :
            msg = con.recv(4096)
            if not msg: break
            print "-------------RONALDO--------------------------------"         
            aux = msg.split(',')
            if flag :
                flag, bytes_random_client, private_key = certificado(aux)
            elif aux[0] == "final" :
                mensagem_MAC_cipher = aux[1]
                text_cipher = mensagem_MAC_cipher[len(mensagem_MAC_cipher)-32:len(mensagem_MAC_cipher)]
                MAC_client = mensagem_MAC_cipher[0:64]
                MAC = calcula_MAC (text_cipher, MAC_write_key_client)
                if MAC == MAC_client :
                    plain_text  = decrypt_text_cliente(client_write_key, iv_block, text_cipher)
                    if plain_text == "finished" :
                        text_cipher_server = encrypt_text_server(server_write_key, iv_block)
                        MAC_server = calcula_MAC(text_cipher_server,MAC_write_key_server)
                        mensagem_MAC_cipher_server = MAC_server + text_cipher_server
                        con.send(mensagem_MAC_cipher_server)
                
            else :
                key = RSA.importKey(private_key)
                master_secret_decrypt = decrypt_master_secret (msg,key)
                iv_block,client_write_key, MAC_write_key_client, server_write_key,  MAC_write_key_server = gera_chaves (master_secret_decrypt,bytes_random_server, bytes_random_client)

        print 'Finalizando conexao do cliente', cliente
    con.close()            
        
