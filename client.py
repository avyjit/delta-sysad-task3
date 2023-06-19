#!/usr/bin/env python3

import os
import socket
import sys
import zlib
from typing import Optional

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 6969  # The port used by the server


class ClientProtocol:

    def __init__(self, socket):
        self.socket = socket
        self.encoding = "ascii"
    
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
    
    def message_type(self, type: str):
        self.writeline(f"message-type: {type}")
    
    def pair(self, key: str, value: str):
        self.writeline(f"{key}: {value}")
    
    def read_pair(self) -> Optional[str]:
        line = self.readline()
        if line is None:
            return None
        kv_pair = line.split(":")
        key, value = map(str.strip, kv_pair)
        return key, value
    
    def read_key(self, key: str) -> Optional[str]:
        pair = self.read_pair()
        if pair is None:
            return None
        k, v = pair
        assert k == key, f"invalid key: {k}, expected: {key}"
        return v
    
    
    def register(self, username: str, password: str) -> str:
        self.message_type("register")
        self.pair("username", username)
        self.pair("password", password)
        data = self.read_pair()
        assert data[0] == "result"
        return data[1]
    
    def upload(self, path: str):
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
    
    def download(self, name: str):
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


if len(sys.argv) < 2:
    print("Usage: client.py <command> [args...]")
    sys.exit(0)



socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((HOST, PORT))
p = ClientProtocol(socket)

cmd = sys.argv[1]
if cmd == "register":
    username = sys.argv[2]
    password = sys.argv[3]
    result = p.register(username, password)
    print(result)
elif cmd == "upload":
    path = sys.argv[2]
    result = p.upload(path)
    print(result)
elif cmd == "download":
    name = sys.argv[2]
    p.download(name)


p.message_type("close")
