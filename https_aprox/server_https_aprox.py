# coding: latin-1

import socket
#from scapy.all import *
import scapy.all
import os
from Crypto.PublicKey import RSA 
import shutil
import sys



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
            #print master_secret_bytes
            print "\n\n" + master_secret_decrypt
            print "\n\n" + bytes_random_server
            print "\n\n" + bytes_random_client

            prf_instance = scapy.layers.tls.crypto.prf.PRF()
            master_secret =  prf_instance.compute_master_secret(master_secret_decrypt,bytes_random_client,bytes_random_server)
            key_session = prf_instance.derive_key_block(master_secret,bytes_random_server,bytes_random_client,64)
            decoded_str = key_session.decode("windows-1252")
            encoded_str = decoded_str.encode("utf8")             
            #key_write_server = encoded_str [0:31]            
            #print "bla\n",encoded_str,"bla"
            #print sys.getsizeof(key_write_server)            
            #key_write_server = []
            count = 0
            i = 0
            while count < 32 :
                count += sys.getsizeof(encoded_str[i])
                print count
                i = i + 1
            palavra = key_session[0:i]                    

            print "bla\n",palavra,"\nbla"
            print sys.getsizeof(palavra) 

        


         
    print 'Finalizando conexao do cliente', cliente
con.close()