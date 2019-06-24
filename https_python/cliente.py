import socket, ssl, pprint

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

ssl_sock = ssl.wrap_socket(s,ca_certs="server.crt",cert_reqs=ssl.CERT_REQUIRED)
ssl_sock.connect(('127.0.0.1', 5050))

ssl_sock.write("Samuel")
    
ssl_sock.close()