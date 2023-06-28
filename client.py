#!/usr/bin/env python3

import argparse
import base64
import hashlib
import json
import os
import socket
import sys
import zlib
from typing import Dict, Optional

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
        self.socket.sendall(bytes(line + "\n", self.encoding))

    def send(self, data: Dict):
        self.writeline(json.dumps(data))

    def response(self) -> Optional[Dict]:
        line = self.readline()
        if not line:
            return None
        return json.loads(line)

    def register(self, username: str, password: str) -> str:
        # Hash the password before sending it to the server
        password = hashlib.sha256(password.encode(self.encoding)).hexdigest()

        self.send({"type": "register", "username": username, "password": password})

        return self.response()

    def upload(self, path: str):
        token = self.token()

        if token is None:
            return {"result": "error", "message": "not logged in."}

        with open(path, "rb") as f:
            content = f.read()

        content = zlib.compress(content, level=9)
        b64 = base64.b64encode(content).decode(self.encoding)

        self.send(
            {
                "type": "upload",
                "name": os.path.basename(path),
                "content": b64,
                "token": token,
            }
        )

        return self.response()

    def download(self, name: str, output: Optional[str] = None):
        token = self.token()

        if token is None:
            return {"result": "error", "message": "not logged in."}

        self.send({"type": "download", "name": name, "token": token})

        response = self.response()
        if response["result"] != "success":
            return response
        content = base64.b64decode(response["content"])
        content = zlib.decompress(content)

        if output is None:
            output = name

        with open(output, "wb") as f:
            f.write(content)

        return {
            "result": "success",
        }

    def list_files(self):
        token = self.token()

        if token is None:
            return {"result": "error", "message": "not logged in."}

        self.send({"type": "list", "token": token})

        return self.response()

    def login(self, username: str, password: str):
        if os.path.exists("token.json"):
            return {"result": "info", "message": "already logged in."}

        # Since the password was hashed while registering, we need to
        # to hash it before sending it also
        password = hashlib.sha256(password.encode(self.encoding)).hexdigest()
        self.send({"type": "login", "username": username, "password": password})

        token = self.response()
        if token["result"] != "success":
            return token
        else:
            with open("token.json", "w") as f:
                json.dump(token, f)

        return {
            "result": "success",
        }

    def token(self) -> Optional[Dict]:
        if not os.path.exists("token.json"):
            return None

        with open("token.json", "r") as f:
            return json.load(f)

    def logout(self):
        if not os.path.exists("token.json"):
            return {"result": "error", "message": "not logged in."}

        os.remove("token.json")
        return {"result": "success"}


def main():
    parser = argparse.ArgumentParser(description="Delta Fileserver Client")

    parser.add_argument("--host", type=str, default=HOST, help="server hostname")
    parser.add_argument("-p", "--port", type=int, default=PORT, help="server port")

    subparsers = parser.add_subparsers(title="subcommands", dest="subcommand")

    # Register subcommand
    register_parser = subparsers.add_parser("register", help="register a user")
    register_parser.add_argument("username", type=str, help="Username")
    register_parser.add_argument("password", type=str, help="Password")

    # Upload subcommand
    upload_parser = subparsers.add_parser("upload", help="upload a file")
    upload_parser.add_argument("path", type=str, help="path to file to be uploaded")

    # Download subcommand
    download_parser = subparsers.add_parser("download", help="download a file")
    download_parser.add_argument("name", type=str, help="file name to download")
    # Add an optional output file
    download_parser.add_argument(
        "-o", "--output", type=str, required=False, help="output file to given path"
    )

    login_parser = subparsers.add_parser("login", help="login using credentials")
    login_parser.add_argument("username", type=str, help="username")
    login_parser.add_argument("password", type=str, help="password")

    logout_parser = subparsers.add_parser("logout", help="logout")
    list_parser = subparsers.add_parser("list", help="list files")

    args = parser.parse_args()
    if args.subcommand is None:
        parser.print_help()
        sys.exit(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((args.host, args.port))
    p = ClientProtocol(sock)
    ret = None
    if args.subcommand == "register":
        ret = p.register(args.username, args.password)
    elif args.subcommand == "upload":
        ret = p.upload(args.path)
    elif args.subcommand == "download":
        ret = p.download(args.name, args.output)
    elif args.subcommand == "login":
        ret = p.login(args.username, args.password)
    elif args.subcommand == "logout":
        ret = p.logout()
    elif args.subcommand == "list":
        ret = p.list_files()
        for file in ret["files"]:
            print(file)

    if ret is not None and ret["result"] != "success":
        print(f"{ret['result']}: {ret['message']}")
        sys.exit(1)


if __name__ == "__main__":
    main()
