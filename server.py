import atexit
import hmac
import json
import base64
import logging
import threading
from socketserver import StreamRequestHandler, ThreadingTCPServer
from typing import Optional

logging.basicConfig(level=logging.INFO, format='[%(name)s]: %(message)s')
log = logging.getLogger('server')



class DataStore:
    def __init__(self):
        self.files = {}
        self.passwd = {}
    
    def user_exists(self, username: str) -> bool:
        return username in self.passwd
    
    def store_file(self, name: str, content: bytes):
        self.files[name] = content

DATA = DataStore()

class ServerProtocol:

    def __init__(self, rfile, wfile):
        self.rfile = rfile
        self.wfile = wfile
        self.encoding = "ascii"

    def read_bytes(self, nbytes: int) -> bytes:
        return self.rfile.read(nbytes)
    
    def write_bytes(self, content: bytes):
        self.wfile.write(content)

    def readline(self) -> Optional[str]:
        line = self.rfile.readline()
        if not line:
            return None
        ret = line.decode(self.encoding).rstrip()
        log.debug(ret)
        return ret
    
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
    
    def send_pair(self, key: str, value: str):
        self.writeline(f"{key}: {value}")
    
    def key(self, key: str) -> Optional[str]:
        pair = self.pair()
        if pair is None:
            return None
        k, v = pair
        assert k == key, f"invalid key: {k}, expected: {key}"
        return v
    

    def writeline(self, line: str):
        self.wfile.write(bytes(line+"\n", self.encoding))
    
    def register(self):
        username = self.key("username")
        password = self.key("password")
        if not DATA.user_exists(username):
            DATA.passwd[username] = password
            self.send_pair("result", "success")
        else:
            self.send_pair("result", "exists")
    
    def upload(self):
        name = self.key("name")
        nbytes = int(self.key("bytes"))
        content = self.read_bytes(nbytes)
        DATA.store_file(name, content)
        self.send_pair("result", "success")
    
    def download(self):
        """
        From client:
        message-type: download
        name: <name>

        Server:
        bytes: <bytes>
        <content>
        """        
        name = self.key("name")
        content = DATA.files[name]
        self.send_pair("bytes", len(content))
        self.write_bytes(content)

class RequestHandler(StreamRequestHandler):
    timeout = 5

    def handle(self):
        log.info(f"connected to {self.client_address}")
        protocol = ServerProtocol(self.rfile, self.wfile)
        while True:
            ty = protocol.type()
            if ty == "register":
                protocol.register()
            elif ty == "upload":
                protocol.upload()
            elif ty == "download":
                protocol.download()
            if ty is None or ty == "close":
                break

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
        #server_thread.daemon = True
        server_thread.start()
        log.info(f"main: {server_thread}")
        while True:
            pass