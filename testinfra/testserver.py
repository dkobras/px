#!/usr/bin/python

import BaseHTTPServer

class TestHTTPHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(self):
        msg = [ 'OK', 'ECHO HEADERS' ]
        msg += ['{}: {}'.format(*x) for x in self.headers.items()]
        msg += ['']
        msg = '\r\n'.join(msg)
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', len(msg))
        self.end_headers()
        self.wfile.write(msg)

def run(server_class=BaseHTTPServer.HTTPServer,
        handler_class=BaseHTTPServer.BaseHTTPRequestHandler):
    server_address = ('', 80)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()

if __name__ == '__main__':
    run(handler_class=TestHTTPHandler)
