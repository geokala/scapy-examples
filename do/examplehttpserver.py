#! /usr/bin/env python
# Taken from docs.python.org example of SimpleHTTPServer
# Don't use this in production.
import SimpleHTTPServer
import SocketServer

PORT = 8000

Handler = SimpleHTTPServer.SimpleHTTPRequestHandler

httpd = SocketServer.TCPServer(("", PORT), Handler)

print("Serving at port: %s" % PORT)
httpd.serve_forever()
