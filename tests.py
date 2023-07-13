#!/usr/bin/env python3
import unittest
import socket
import os
import shutil
from client import ClientProtocol

HOST = "0.0.0.0"
PORT = 6969

class TestClient(unittest.TestCase):

    def setUp(self) -> None:
        super().setUp()

        # Remove token.json if it exists
        if os.path.exists("token.json"):
            os.remove("token.json")

        # Remove existing DB & files
        # if os.path.exists("db.sqlite3"):
        #     os.remove("db.sqlite3")
        # if os.path.exists("filestorage"):
        #     shutil.rmtree("filestorage")

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((HOST, PORT))
        except ConnectionRefusedError:
            msg = "Unable to connect. Is the server running?"
            print("=" * len(msg))
            print(msg)
            print("=" * len(msg))
            raise
        self.p = ClientProtocol(self.sock)
    
    def test_register(self):
        ret = self.p.register("testuser010", "testpass")
        self.assertEqual(ret["result"], "success", msg=ret)

        ret = self.p.register("testuser010", "testpass")
        self.assertEqual(ret["result"], "error")
    
    def test_login(self):
        ret = self.p.register("username", "testpass")
        self.assertEqual(ret["result"], "success")

        ret = self.p.login("username", "wrongpass")
        self.assertNotEqual(ret["result"], "success")

        ret = self.p.login("username", "testpass")
        self.assertEqual(ret["result"], "success")
        self.assertTrue(os.path.exists("token.json"))
    
    def test_logout(self):
        ret = self.p.logout()
        self.assertFalse(os.path.exists("token.json"))
        ret = self.p.login("username", "testpass")
        self.assertEqual(ret["result"], "success")
        self.assertTrue(os.path.exists("token.json"))
        self.p.logout()
        self.assertFalse(os.path.exists("token.json"))
    
    def test_upload(self):
        ret = self.p.login("username", "testpass")
        self.assertEqual(ret["result"], "success", msg=ret)

        ret = self.p.upload("tests.py")
        self.assertEqual(ret["result"], "success")

        ret = self.p.download("tests.py", "out.log")
        self.assertEqual(ret["result"], "success")
        self.assertTrue(os.path.exists("out.log"))
        with open("tests.py", "r") as f:
            with open("out.log", "r") as f2:
                c1 = f.read()
                c2 = f2.read()
                self.assertEqual(c1, c2)
        
        os.remove("out.log")
    
    def test_list(self):
        ret = self.p.register("testuser", "testpass")
        ret = self.p.login("testuser", "testpass")
        self.assertEqual(ret["result"], "success", msg=ret)

        ret = self.p.upload("server.py")
        ret = self.p.upload("client.py")

        self.assertEqual(ret["result"], "success", msg=ret)

        ret = self.p.list_files()
        self.assertEqual(ret["result"], "success", msg=ret)

        files = ["server.py", "client.py"]
        self.assertEqual(sorted(ret["files"]), sorted(files))
    
    def test_delete(self):
        ret = self.p.register("deluser", "testpass")
        ret = self.p.login("deluser", "testpass")
        self.assertEqual(ret["result"], "success", msg=ret)

        ret = self.p.upload("server.py")
        ret = self.p.upload("client.py")

        self.assertEqual(ret["result"], "success", msg=ret)

        ret = self.p.list_files()
        self.assertEqual(ret["result"], "success", msg=ret)

        files = ["server.py", "client.py"]
        self.assertEqual(sorted(ret["files"]), sorted(files))

        ret = self.p.delete("server.py")
        self.assertEqual(ret["result"], "success", msg=ret)

        ret = self.p.list_files()
        self.assertEqual(ret["result"], "success", msg=ret)

        files = ["client.py"]
        self.assertEqual(sorted(ret["files"]), sorted(files))

    def tearDown(self) -> None:
        super().tearDown()
        self.p.logout()
        self.sock.close()

if __name__ == "__main__":
    unittest.main()