# File Archival server

## Running the server
First, grap a copy of the code:
```bash
git clone https://github.com/avyjit/delta-sysad-task3.git
cd delta-sysad-task3
```

Make sure you have docker installed. If not, install it from [here](https://docs.docker.com/engine/installation/).

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
```bash
./client.py --help
```