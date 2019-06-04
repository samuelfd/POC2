

import socket
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
PORT = 5001            # Porta que o Servidor esta
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
    i = 0
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
        elif aux[0] == "final" :
            mensagem_MAC_cipher = aux[1]
            print "\n mensagem_MAC_cipher  " + mensagem_MAC_cipher + "\n"           
            text_cipher = mensagem_MAC_cipher[len(mensagem_MAC_cipher)-32:len(mensagem_MAC_cipher)]
            print "text_cipher  " + text_cipher 
            MAC_client = mensagem_MAC_cipher[0:64]
            print "MAC_client  " + MAC_client
            pre_MAC = text_cipher + MAC_write_key
            pre_MAC = hashlib.sha256(pre_MAC)
            MAC = pre_MAC.hexdigest()
            if MAC == MAC_client :
                message = "finished"
                obj2 = AES.new(server_write_key, AES.MODE_CBC, iv_block)
                plain_text = obj2.decrypt(text_cipher)
                print plain_text
                print type(plain_text)
                plain_text = plain_text[:8]
                print plain_text
                if plain_text == message :
                    print "MAC  " + MAC
                    length = 16 - (len(message) % 16)
                    message += bytes([length])*length
                    print "message  " + message
                    ciphertext = obj2.encrypt(message)                    
                    print "ciphertext  "  + ciphertext                
                    mensagem_MAC_cipher = MAC + ciphertext
                    con.send(mensagem_MAC_cipher)     
        else :
            key = RSA.importKey(private_key)
            master_secret_bytes = (msg,)
            master_secret_decrypt = key.decrypt(master_secret_bytes)
            prf_instance = scapy.layers.tls.crypto.prf.PRF()
            master_secret =  prf_instance.compute_master_secret(master_secret_decrypt,bytes_random_client,bytes_random_server)
            key_session = prf_instance.derive_key_block(master_secret,bytes_random_server,bytes_random_client,64)
            print "\n" + key_session 
            iv_block = prf_instance.prf("",b"IV block",bytes_random_client + bytes_random_server, 16)
            print "IVBLOCK  " + iv_block
            server_write_key = key_session[0:32]
            print "server_write_key  " + server_write_key +"\n"
            MAC_write_key = key_session [32:64] 
            print "MAC_write_key  " + MAC_write_key +"\n"
            obj = AES.new(server_write_key, AES.MODE_CBC, iv_block)
            message = "finished"
            length = 16 - (len(message) % 16)
            message += bytes([length])*length
            print "MESSAGE" + message
            ciphertext = obj.encrypt(message)
            print "ciphertext " + ciphertext            
        i = i + 1
        print i 



            
            

             
            
            
        


         
    print 'Finalizando conexao do cliente', cliente
con.close()