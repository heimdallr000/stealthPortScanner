# stealthPortScanner
A Linux stealth port scanner to bypass the port scan detection

## Overview
![overview](https://github.com/heimdallr000/stealthPortScanner/assets/67891766/67a3311d-7045-435b-80f9-20e70c583a72)

## Build
Before you build the source codes, you need to fill up masked target ports in `scan.cpp`, server port in `server.c`, server IP and server port in `client.c` with your values.
```
$ g++ -o scan scan.cpp
$ gcc -o server server.c
$ gcc -o client client.c
```

## Usage
Befor you run the programs, you need to create `ipList.txt` and `sourceIPs.txt` on Scanning Server.

**Step 1. Scanning Server**
```
$ sudo ./server
```

**Step 2. Scanning Client**
```
$ sudo ./client
```

**Step 3. Scanning Server**
```
$ sudo ./scan
```

