import atexit
import base64
import hmac
import json
import logging
import threading
from socketserver import StreamRequestHandler, ThreadingTCPServer
from typing import Dict, Optional

logging.basicConfig(level=logging.DEBUG, format='[%(name)s]: %(message)s')
log = logging.getLogger('server')

ENCODING = 'utf-8'
# im hardcoding it cuz im lazy
# but ill load from an environment variable
# for "production" lmao
SECRET_KEY = b"LOAD_FROM_ENVVAR_THIS_IS_UNSAFE_LMAOOO_IDGAF"

class DataAccessLayer:

    def __init__(self):
        self.files = {}
        self.users = {}
        self.owners = {}

    def store_file(self, username: str, name: str, content: bytes):
        if username not in self.owners:
            self.owners[username] = []
        self.owners[username].append(name)
        self.files[name] = content
    
    def check_user_exists(self, username: str) -> bool:
        return username in self.users
    
    def authenticate(self, username: str, password: str):
        return self.users.get(username) == password

DATA = DataAccessLayer()

class ServerProtocol:

    def handle(self, data: Dict):
        handlers = {
            "register": self.handle_register,
            "upload": self.handle_upload,
            "download": self.handle_download,
            "login": self.handle_login
        }

        ty = data["type"]

        handler = handlers.get(ty, lambda _: {
            "result": "error",
            "message": f"unknown message type: {ty}"
        })

        return handler(data)
    
    def authorize(self, token: Dict) -> Optional[Dict]:
        username = token["username"]
        signature = token["sign"]
        computed = self.compute_signature(username)
        return computed == signature

    
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
        token = data["token"]

        if "token" not in data or not self.authorize(token):
            return {
                "result": "error",
                "message": "invalid token"
            }
        
        name = data["name"]
        username = token["username"]
        content = data["content"]
        decoded = base64.b64decode(content)
        DATA.store_file(username, name, decoded)

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
        username = data["username"]
        password = data["password"]

        if not DATA.check_user_exists(username):
            return {
                "result": "error",
                "message": f"no such user: {username}. please register first"
            }
        
        if not DATA.authenticate(username, password):
            return {
                "result": "error",
                "message": f"invalid credentials for user: {username}"
            }
        
        # We generate a token for the user
        # and send it back to the client
        return {
            "result": "success",
            "username": username,
            "sign": self.compute_signature(username)
        }
    
    @staticmethod
    def compute_signature(string: str):
        signature = hmac.new(SECRET_KEY, string.encode(ENCODING), "sha256").digest()
        signature = base64.b64encode(signature).decode(ENCODING)
        return signature


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