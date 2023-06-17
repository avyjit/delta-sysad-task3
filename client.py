import socket
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


client = Client()
p = ClientProtocol(client.socket)
p.message_type("register")
p.pair("username", "test")
p.pair("password", "1234")
data = p.read_pair()
#data = client.recv(1024) 
print('Received', data)

