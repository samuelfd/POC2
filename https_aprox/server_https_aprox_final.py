# coding: latin-1

import socket
#from scapy.all import *
import scapy.all
import os
from Crypto.PublicKey import RSA 
from Crypto.Cipher import AES
import shutil
import sys
import hashlib

def generate_RSA(bits=4096):   
    
    new_key = RSA.generate(bits, e=65537) 
    public_key = new_key.publickey().exportKey("PEM") 
    private_key = new_key.exportKey("PEM") 
    return private_key, public_key 


HOST = ''              # Endereco IP do Servidor
PORT = 5000            # Porta que o Servidor esta
cifras = 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA'
bytes_random_server = os.urandom(32)
version_tls = "1.2"
tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
orig = (HOST, PORT)
tcp.bind(orig)
tcp.listen(1)

while True:
    con, cliente = tcp.accept()
    print 'Concetado por', cliente
    flag = True
    while True:
        msg = con.recv(4096)
        print "-------------RONALDO--------------------------------"
        #print msg 
        aux = msg.split(',')
        if(len(aux)>1 and flag == True):
            bytes_random_client = aux[1]
            
        if not msg: break        
        if flag :
            shutil.copyfile('certificado2.txt','certificado3.txt')
            arq = open('certificado3.txt', 'ab')
            private_key, public_key = generate_RSA()            
            arq.write(public_key)            
            arq.close()          
            arq = open('certificado3.txt', 'rb')
            certificado = arq.read()                 
            con.sendall(bytes_random_server + "," + cifras +","+ certificado)              
            flag = False     
        else :
            key = RSA.importKey(private_key)
            master_secret_bytes = (msg,)
            master_secret_decrypt = key.decrypt(master_secret_bytes)            
            print "\n\n" + master_secret_decrypt
            print "\n\n" + bytes_random_server
            print "\n\n" + bytes_random_client

            prf_instance = scapy.layers.tls.crypto.prf.PRF()
            master_secret =  prf_instance.compute_master_secret(master_secret_decrypt,bytes_random_client,bytes_random_server)
            key_session = prf_instance.derive_key_block(master_secret,bytes_random_server,bytes_random_client,64)  
            server_write_key = key_session[0:32]
            MAC_write_key = key_session [32:64]   
            iv_block = prf_instance.prf("",b"IV block",bytes_random_client + bytes_random_server, 16)
            print "IVBLOCK  " + iv_block
            obj = AES.new(server_write_key, AES.MODE_CBC, iv_block)
            message = "The answer is no"
            ciphertext = obj.encrypt(message)
            print "ciphertext " + ciphertext
            obj2 = AES.new(server_write_key, AES.MODE_CBC, iv_block)
            print obj2.decrypt(ciphertext)
        if aux[0] == "final" :
            mensagem_MAC_cipher = aux[1]            
            text_cipher = mensagem_MAC_cipher[len(mensagem_MAC_cipher)-32:len(mensagem_MAC_cipher)]
            pre_MAC = text_cipher + MAC_write_key            
            pre_MAC = hashlib.sha256(pre_MAC)
            MAC = pre_MAC.hexdigest()
            if MAC == MAC_client :
                obj2 = AES.new(server_write_key, AES.MODE_CBC, iv_block)
                plain_text = obj2.decrypt(ciphertext)
                plain_text = plain_text[:-plain_text[-1]]
                if plain_text == "finished" :
                    con.send()



            
            

             
            
            
        


         
    print 'Finalizando conexao do cliente', cliente
con.close()