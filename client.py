import socket
from typing import Optional
import sys

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
    
    def register(self, username: str, password: str) -> str:
        self.message_type("register")
        self.pair("username", username)
        self.pair("password", password)
        data = self.read_pair()
        assert data[0] == "result"
        return data[1]
    
    def upload(self, path: str):
        self.message_type("upload")
        with open(path, "rb") as f:
            data = f.read()
        self.pair("bytes", len(data))
        # Send the raw file over the socket
        self.socket.sendall(data)
        data = self.read_pair()
        assert data[0] == "result"
        return data[1]

    def close(self):
        self.message_type("close")
        self.socket.close()

class Client:

    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((HOST, PORT))

    
    def close(self):
        self.socket.close()
    
    def send(self, data):
        self.socket.sendall(data)
    
    def recv(self, size):
        return self.socket.recv(size)


socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((HOST, PORT))
p = ClientProtocol(socket)
res = p.upload("file.log")
p.message_type("close")
#data = client.recv(1024) 
print('Received', res)

