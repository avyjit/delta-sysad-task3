#!/usr/bin/env python3

import os
import socket
import sys
import zlib
import json
import base64
from typing import Optional, Dict

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 6969  # The port used by the server


class ClientProtocol:

    def __init__(self, socket):
        self.socket = socket
        self.encoding = "utf-8"
    
    def readline(self) -> Optional[str]:
        line = ""
        while True:
            char = self.socket.recv(1)
            if not char:
                return None
            char = char.decode(self.encoding)
            if char == "\n":
                break
            line += char
        return line
    
    def read_bytes(self, nbytes: int) -> Optional[bytes]:
        data = b""
        while nbytes > 0:
            chunk = self.socket.recv(nbytes)
            if not chunk:
                return None
            data += chunk
            nbytes -= len(chunk)
        return data
    
    def writeline(self, line: str):
        self.socket.sendall(bytes(line+"\n", self.encoding))
    
    def send(self, data: Dict):
        self.writeline(json.dumps(data))
    
    def response(self) -> Optional[Dict]:
        line = self.readline()
        if not line:
            return None
        return json.loads(line)
    
    def register(self, username: str, password: str) -> str:
        self.send({
            "type": "register",
            "username": username,
            "password": password
        })

        return self.response()
    
    def upload(self, path: str):
        with open(path, "rb") as f:
            content = f.read()
        
        content = zlib.compress(content, level=9)
        b64 = base64.b64encode(content).decode(self.encoding)

        self.send({
            "type": "upload",
            "name": os.path.basename(path),
            "content": b64
        })

        return self.response()
    
    def download(self, name: str):
        self.send({
            "type": "download",
            "name": name
        })

        response = self.response()
        assert response["result"] == "success"
        print(response)
        content = base64.b64decode(response["content"])
        content = zlib.decompress(content)

        print(content)
    
    

    def upload__(self, path: str):
        self.message_type("upload")
        self.pair("name", os.path.basename(path))
        with open(path, "rb") as f:
            data = f.read()
        
        # compress at maximum level
        # trades cpu time for smaller size
        data = zlib.compress(data, level=9)

        self.pair("bytes", len(data))
        # Send the raw file over the socket
        self.socket.sendall(data)
        data = self.read_pair()
        assert data[0] == "result"
        return data[1]
    
    def download__(self, name: str):
        self.message_type("download")
        self.pair("name", name)
        nbytes = self.read_key("bytes")
        content = self.read_bytes(int(nbytes))
        content = zlib.decompress(content)
        with open(name, "wb") as f:
            f.write(content)

    def close(self):
        self.message_type("close")
        self.socket.close()




socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((HOST, PORT))
p = ClientProtocol(socket)
print(p.register("alloo", "paratha"))
print(p.upload("file.log"))
p.download("file.log")