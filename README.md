# File Archival server

## Running the server
First, grap a copy of the code:
```bash
git clone https://github.com/avyjit/delta-sysad-task3.git
cd delta-sysad-task3
```

Make sure you have docker installed. If not, install it from [here](https://docs.docker.com/engine/installation/).

To ensure the server runs properly, the code comes with a test script. To run the test script,
```bash
chmod +x runtests.sh
./runtests.sh
```

If everything goes well, you should see output similar to:
```
Ran 6 tests in 0.036s

OK
```

To run the server, run the following command:
```bash
docker compose up
# (or)
docker-compose up
```
The server should now be listening on port `6969`.

## Using the client
Make sure to make the client executable:
```bash
chmod +x client.py
```

To view all the options available to the client, run:
```
$ ./client.py --help
usage: client.py [-h] [--host HOST] [-p PORT]
                 {register,upload,download,login,logout,list,delete} ...

Delta Fileserver Client

options:
  -h, --help            show this help message and exit
  --host HOST           server hostname
  -p PORT, --port PORT  server port

subcommands:
  {register,upload,download,login,logout,list,delete}
    register            register a user
    upload              upload a file
    download            download a file
    login               login using credentials
    logout              logout
    list                list files
    delete              delete a file
```