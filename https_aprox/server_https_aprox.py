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
            key_session =  prf_instance.compute_master_secret(master_secret_decrypt,bytes_random_client,bytes_random_server)
            print "bla\n",key_session,"bla"
            print sys.getsizeof(key_session)

        


         
    print 'Finalizando conexao do cliente', cliente
con.close()