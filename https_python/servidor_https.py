#from http.server import HTTPServer, SimpleHTTPRequestHandler
#import ssl

#httpd = HTTPServer(('localhost', 4443), SimpleHTTPRequestHandler)
#httpd.socket = ssl.wrap_socket(httpd.socket, certfile="server.includesprivatekey.pem", server_side=False)
#httpd.serve_forever()

import BaseHTTPServer, SimpleHTTPServer
import ssl

httpd = BaseHTTPServer.HTTPServer(('localhost', 4443), SimpleHTTPServer.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, certfile="server.pem", server_side=True)
httpd.serve_forever()
