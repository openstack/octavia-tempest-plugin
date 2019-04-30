====================
Amphorae test server
====================

test_server is a static application that simulates an HTTP and a UDP server.


Building
--------

To build a statically linked binary for test_server (can run anywhere):

Install dependencies for Ubuntu/Debian:

    sudo apt-get install -y golang

Install dependencies for Centos (use golang 1.10 from go-toolset-7) and launch
a shell into the new environment:

    sudo yum install -y centos-release-scl
    sudo yum install -y go-toolset-7-golang-bin glibc-static openssl-static zlib-static
    scl enable go-toolset-7 bash

Build the binary:

    CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-s -w -extldflags -static' -o test_server.bin test_server.go
