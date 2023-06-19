import atexit
import base64
import hmac
import json
import logging
import threading
import pathlib
import sqlite3
import uuid
from functools import wraps
from socketserver import StreamRequestHandler, ThreadingTCPServer
from typing import Dict, Optional

logging.basicConfig(level=logging.DEBUG, format='[%(name)s]: %(message)s')
log = logging.getLogger('server')

ENCODING = 'utf-8'
# im hardcoding it cuz im lazy
# but ill load from an environment variable
# for "production" lmao
SECRET_KEY = b"LOAD_FROM_ENVVAR_THIS_IS_UNSAFE_LMAOOO_IDGAF"
DB_PATH = "db.sqlite3"
FILE_DIR =  "filestorage"

class DataAccessLayer:

    def __init__(self):
        self.files = {}
        self.users = {}
        self.owners = {}
        self.lock = threading.RLock()

        self.file_dir = pathlib.Path(FILE_DIR)
        # Create the directory if it doesn't exist
        self.file_dir.mkdir(exist_ok=True)
        log.info(f"using FILE_DIR = {str(self.file_dir.absolute())}")

        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.cursor = self.conn.cursor()

        with open("schema.sql") as f:
            self.cursor.executescript(f.read())
        
        self.conn.commit()
        atexit.register(self.conn.close)

        log.info(f"initialized database at {str(pathlib.Path(DB_PATH).absolute())}")

    def store_file(self, username: str, name: str, content: bytes):
        if username not in self.owners:
            self.owners[username] = []
        self.owners[username].append(name)
        self.files[(username, name)] = content
    
    def _store_file(self, username: str, name: str, content: bytes):
        file_id = uuid.uuid4().hex
        exists, user_id = self._check_user_exists(username)
        assert exists, f"user {username} does not exist"

        file_path = self.file_dir / file_id
        with open(file_path, "wb") as f:
            f.write(content)

        with self.lock:
            self.cursor.execute(
                "INSERT INTO files (file_id, file_name, owner_id) VALUES (?, ?, ?)",
                (file_id, name, user_id)
            )
            self.conn.commit()
        

    
    def load_file(self, username: str, name: str) -> Optional[bytes]:
        return self.files.get((username, name))
    
    def _load_file(self, username: str, name: str) -> Optional[bytes]:
        exists, user_id = self._check_user_exists(username)
        assert exists, f"user {username} does not exist"
        with self.lock:
            self.cursor.execute(
                "SELECT file_id FROM files WHERE file_name = ? AND owner_id = ?",
                (name, user_id)
            )
            res = self.cursor.fetchone()
            if res is None:
                return None
            else:
                file_id = res[0]
                file_path = self.file_dir / file_id
                with open(file_path, "rb") as f:
                    return f.read()
    
    def check_file_exists(self, username: str, name: str) -> bool:
        return (username, name) in self.files
    
    def _check_file_exists(self, username: str, name: str) -> bool:
        exists, user_id = self._check_user_exists(username)
        assert exists, f"user {username} does not exist"
        with self.lock:
            self.cursor.execute(
                "SELECT id FROM files WHERE file_name = ? AND owner_id = ?",
                (name, user_id)
            )
            res = self.cursor.fetchone()
            return res is not None
    
    def new_user(self, username: str, password: str):
        self.users[username] = password
    
    def _new_user(self, username: str, password: str):
        with self.lock:
            self.cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            self.conn.commit()

    def check_user_exists(self, username: str) -> bool:
        return username in self.users
    
    
    def _check_user_exists(self, username: str) -> bool:
        with self.lock:
            self.cursor.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            )
            res = self.cursor.fetchone()
            if res is not None:
                return (True, res[0])
            else:
                return (False, None)
    
    def authenticate(self, username: str, password: str):
        return self.users.get(username) == password
    
    def _authenticate(self, username: str, password: str):
        with self.lock:
            self.cursor.execute(
                "SELECT password FROM users WHERE username = ?", (username,)
            )
            res = self.cursor.fetchone()
            if res is not None:
                return res[0] == password
            else:
                return False

DATA = DataAccessLayer()

class ServerProtocol:

    def handle(self, data: Dict):
        handlers = {
            "register": self.handle_register,
            "upload": self.authorized_only(self.handle_upload),
            "download": self.authorized_only(self.handle_download),
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

        if DATA._check_user_exists(username)[0]:
            return {
                "result": "error",
                "message": f"user already exists: {username}"
            }
        
        DATA.new_user(username, password)
        # CHANGELATER
        DATA._new_user(username, password)

        return {
            "result": "success"
        }
    
    def handle_upload(self, data: Dict):
        assert data["type"] == "upload"
        token = data["token"]
        name = data["name"]
        username = token["username"]
        content = data["content"]
        decoded = base64.b64decode(content)

        if DATA._check_file_exists(username, name):
            return {
                "result": "error",
                "message": f"file already exists: {name}"
            }

        DATA.store_file(username, name, decoded)
        DATA._store_file(username, name, decoded)

        log.debug(f"files: {DATA.files}")
        return {
            "result": "success"
        }
    
    def handle_download(self, data: Dict):
        assert data["type"] == "download"
        name = data["name"]
        username = data["token"]["username"]

        if not DATA._check_file_exists(username, name):
            return {
                "result": "error",
                "message": f"no such file: {name}"
            }
        
        content = DATA._load_file(username, name)
        encoded = base64.b64encode(content).decode(ENCODING)
        return {
            "result": "success",
            "content": encoded
        }
    
    def handle_login(self, data: Dict):
        username = data["username"]
        password = data["password"]

        if not DATA._check_user_exists(username):
            return {
                "result": "error",
                "message": f"no such user: {username}. please register first"
            }
        
        if not DATA._authenticate(username, password):
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
    
    def authorized_only(self, func):

        @wraps(func)
        def _authorized_handler(data: Dict):
            if "token" not in data:
                return {
                    "result": "error",
                    "message": "missing token (invalid json protocol)"
                }
            
            token = data["token"]
            if not self.authorize(token):
                return {
                    "result": "error",
                    "message": "invalid token"
                }
            
            return func(data)
    
        return _authorized_handler


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