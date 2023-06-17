import atexit
import threading
import logging
from socketserver import ThreadingTCPServer, StreamRequestHandler
from typing import Optional

logging.basicConfig(level=logging.DEBUG, format='[%(name)s]: %(message)s')
log = logging.getLogger('server')

class Data:
    def __init__(self):
        self.data = {}
        self.passwd = {}

    def __repr__(self):
        return f"Data({repr(self.data)})"

class ServerProtocol:

    def __init__(self, rfile, wfile):
        self.rfile = rfile
        self.wfile = wfile
        self.encoding = "ascii"
    
    def readline(self) -> Optional[str]:
        line = self.rfile.readline()
        if not line:
            return None
        return line.decode(self.encoding).rstrip()
    
    def type(self) -> Optional[str]:
        line = self.readline()
        if line is None:
            return None
        kv_pair = line.split(":")
        key, value = map(str.strip, kv_pair)

        assert key == "message-type", "invalid message type"
        return value
    
    def pair(self) -> Optional[str]:
        line = self.readline()
        if line is None:
            return None
        kv_pair = line.split(":")
        key, value = map(str.strip, kv_pair)
        return key, value
    
    def key(self, key: str) -> Optional[str]:
        pair = self.pair()
        if pair is None:
            return None
        k, v = pair
        assert k == key, f"invalid key: {k}, expected: {key}"
        return v
    
    def writeline(self, line: str):
        self.wfile.write(bytes(line+"\n", self.encoding))

class RequestHandler(StreamRequestHandler):

    def handle(self):
        log.info(f"connected to {self.client_address}")
        protocol = ServerProtocol(self.rfile, self.wfile)
        while True:
            ty = protocol.type()
            if ty == "register":
                username = protocol.key("username")
            if ty is None or ty == "Close":
                break
            data = ty
            print(f"Got: data={data}")
            print(f"Sending data back: {repr(data)}")
            protocol.writeline(data)


@atexit.register
def cleanup():
    log.critical("shutting server down")

    # Prevents zombie threads running in the background
    # as daemons
    server.shutdown()

if __name__ == '__main__':
    HOST, PORT = "127.0.0.1", 6969

    server = ThreadingTCPServer((HOST, PORT), RequestHandler)
    with server:
        ip, port = server.server_address

        # Start a thread with the server -- that thread will then start one
        # more thread for each request
        server_thread = threading.Thread(target=server.serve_forever)
        # Exit the server thread when the main thread terminates
        server_thread.daemon = True
        server_thread.start()
        log.info(f"server loop running in thread: {server_thread}")
        while True:
            pass