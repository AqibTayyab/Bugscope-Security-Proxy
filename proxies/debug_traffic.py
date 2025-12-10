# debug_proxy.py
import socketserver
import http.server
from urllib.parse import urlparse
import select
import socket
import sys

class DebugHandler(http.server.BaseHTTPRequestHandler):
    def do_CONNECT(self):
        print(f"[DEBUG] CONNECT {self.path}")
        try:
            host, port = self.path.split(":")
            port = int(port)
        except Exception as e:
            self.send_error(400, "Bad CONNECT")
            return
        try:
            remote = socket.create_connection((host, port))
        except Exception as e:
            print("[DEBUG] CONNECT remote error:", e)
            self.send_error(502, f"Cannot connect: {e}")
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        self.connection.setblocking(False)
        remote.setblocking(False)
        sockets = [self.connection, remote]
        try:
            while True:
                r, _, _ = select.select(sockets, [], sockets, 1)
                for s in r:
                    other = remote if s is self.connection else self.connection
                    data = s.recv(8192)
                    if not data:
                        return
                    other.sendall(data)
        except Exception as e:
            print("[DEBUG] CONNECT tunnel ended:", e)
            return

    def do_GET(self):
        self.log_and_forward()

    def do_POST(self):
        self.log_and_forward()

    def log_and_forward(self):
        print("----- NEW REQUEST -----")
        print("Client:", self.client_address)
        print("Request line:", self.requestline)
        print("Command:", self.command)
        print("Path:", self.path)
        print("Headers:")
        for k,v in self.headers.items():
            print(f"  {k}: {v}")
        print("-----------------------")
        # Reply with simple 200 so browser sees something (we don't forward in debug)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"DEBUG PROXY RECEIVED REQUEST\n")

    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    PORT = 8080
    print(f"[DEBUG] Starting debug proxy on 127.0.0.1:{PORT}")
    server = socketserver.ThreadingTCPServer(('', PORT), DebugHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[DEBUG] stopping")
        server.server_close()
        sys.exit(0)
