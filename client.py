#!/usr/bin/env python3

import os
import socket
import sys
import zlib
import json
import base64
import argparse
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
        token = self.token()

        if token is None:
            return
        with open(path, "rb") as f:
            content = f.read()
        
        content = zlib.compress(content, level=9)
        b64 = base64.b64encode(content).decode(self.encoding)

        self.send({
            "type": "upload",
            "name": os.path.basename(path),
            "content": b64,
            "token": token
        })

        return self.response()
    
    def download(self, name: str, output: Optional[str] = None):
        token = self.token()

        if token is None:
            return
        
        self.send({
            "type": "download",
            "name": name,
            "token": token
        })

        response = self.response()
        if response["result"] != "success":
            print(f"Download failed: {response['message']}")
            return
        content = base64.b64decode(response["content"])
        content = zlib.decompress(content)

        if output is None:
            output = name
        
    
        with open(output, "wb") as f:
            f.write(content)
    
    def login(self, username: str, password: str):
        if os.path.exists("token.json"):
            print("Already logged in.")
            return
        
        self.send({
            "type": "login",
            "username": username,
            "password": password
        })

        token = self.response()
        if token["result"] != "success":
            print(f"Login failed: {token['message']}")
        else:
            print(f"Login successful.")
            with open("token.json", "w") as f:
                json.dump(token, f)
    
    def token(self) -> Optional[Dict]:
        if not os.path.exists("token.json"):
            print("You have not logged in yet.")
            return None
        
        with open("token.json", "r") as f:
            return json.load(f)

    def close(self):
        self.message_type("close")
        self.socket.close()



def main():
    parser = argparse.ArgumentParser(description='Delta Fileserver Client')

    subparsers = parser.add_subparsers(title='subcommands', dest='subcommand')

    # Register subcommand
    register_parser = subparsers.add_parser('register', help='register a user')
    register_parser.add_argument('username', type=str, help='Username')
    register_parser.add_argument('password', type=str, help='Password')


    # Upload subcommand
    upload_parser = subparsers.add_parser('upload', help='upload a file')
    upload_parser.add_argument('path', type=str, help='path to file to be uploaded')


    # Download subcommand
    download_parser = subparsers.add_parser('download', help='download a file')
    download_parser.add_argument('name', type=str, help='file name to download')
    # Add an optional output file
    download_parser.add_argument('-o', '--output', type=str, required=False, help='output file to given path')

    login_parser = subparsers.add_parser('login', help='login using credentials')
    login_parser.add_argument('username', type=str, help='username')
    login_parser.add_argument('password', type=str, help='password')


    args = parser.parse_args()
    if args.subcommand is None:
        parser.print_help()
        sys.exit(1)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    p = ClientProtocol(sock)

    if args.subcommand == "register":
        print(p.register(args.username, args.password))
    elif args.subcommand == "upload":
        print(p.upload(args.path))
    elif args.subcommand == "download":
        p.download(args.name, args.output)
    elif args.subcommand == "login":
        p.login(args.username, args.password)

if __name__ == '__main__':
    main()