#!/usr/bin/env bash

# remove existing files & db
rm -rf db.sqlite3
rm -rf filestorage
rm token.json
python3 server.py &

server_pid=$!

# give some time for server initialization
sleep 1

# run the tests
python3 tests.py

# stop the server
kill $server_pid

# cleanup
rm -rf db.sqlite3
rm -rf filestorage
rm token.json
