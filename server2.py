import atexit
import hmac
import json
import base64
import logging
import threading
from socketserver import StreamRequestHandler, ThreadingTCPServer
from typing import Optional, Dict

logging.basicConfig(level=logging.DEBUG, format='[%(name)s]: %(message)s')
log = logging.getLogger('server')

ENCODING = 'utf-8'

class DataAccessLayer:

    def __init__(self):
        self.files = {}
        self.users = {}

    def store_file(self, name: str, content: bytes):
        self.files[name] = content
    
    def check_user_exists(self, username: str) -> bool:
        return username in self.users

DATA = DataAccessLayer()

class ServerProtocol:

    def handle(self, data: Dict):
        handlers = {
            "register": self.handle_register,
            "upload": self.handle_upload,
            "download": self.handle_download
        }

        ty = data["type"]

        handler = handlers.get(ty, lambda _: {
            "result": "error",
            "message": f"unknown message type: {ty}"
        })

        return handler(data)
    
    def handle_register(self, data: Dict):
        assert data["type"] == "register"
        username = data["username"]
        password = data["password"]

        if DATA.check_user_exists(username):
            return {
                "result": "error",
                "message": f"user already exists: {username}"
            }
        
        DATA.users[username] = password

        return {
            "result": "success"
        }
    
    def handle_upload(self, data: Dict):
        assert data["type"] == "upload"
        name = data["name"]
        content = data["content"]
        decoded = base64.b64decode(content)
        DATA.store_file(name, decoded)

        return {
            "result": "success"
        }
    
    def handle_download(self, data: Dict):
        assert data["type"] == "download"
        name = data["name"]
        content = DATA.files[name]
        encoded = base64.b64encode(content).decode(ENCODING)
        return {
            "result": "success",
            "content": encoded
        }
    
    def handle_login(self, data: Dict):
        pass


class RequestHandler(StreamRequestHandler):
    timeout = 5

    def handle(self):
        log.info(f"connected to {self.client_address}")
        protocol = ServerProtocol()
        while True:
            line = self.rfile.readline().rstrip()
            if not line:
                break

            try:
                data = json.loads(line)
                log.debug(f"got: {data}")
            except json.JSONDecodeError:
                log.error(f"received invalid json: {line}")
                break

            response = protocol.handle(data)
            self.wfile.write(
                bytes(
                    json.dumps(response)+"\n", 
                    ENCODING
                )
            )

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