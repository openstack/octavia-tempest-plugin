====================
Amphorae test server
====================

test_server.bin is a static application that simulates HTTP, HTTPS, and UDP
servers. This server can properly handle concurrent requests.

Building
--------

To build a statically linked binary for test_server (can run anywhere):

Install dependencies for Ubuntu/Debian:

::

    sudo apt-get install -y golang

Install dependencies for Centos:

::

    sudo dnf install -y golang

Build the binary:

::

    CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-s -w -extldflags -static' -o test_server.bin test_server.go


Usage
-----

The usage string can be output from the command by running:

::

    ./test_server.bin --help

Example output:

::

  Usage of ./test_server.bin:
    -cert string
          Server side PEM format certificate file path.
    -client_ca string
          Client auth PEM format CA certificate file path.
    -https_port int
          HTTPS port to listen on, -1 is disabled. (default -1)
    -https_client_auth_port int
          HTTPS with client authentication port to listen on, -1 is disabled.
          (default -1)
    -id string
          Server ID (default "1")
    -key string
          Server side PEM format key file path.
    -port int
          Port to listen on (default 8080)

If -https_port is not specified, the server will not accept HTTPS requests.
When --https_port is specified, -cert and -key are required parameters.

If -https_client_auth_port is specified, the -client_ca parameter is required.
When -client_ca is specified, it will configure the HTTPS client auth port to
require a valid client certificate to connect.
