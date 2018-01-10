To build a statically linked binary for httpd on Ubuntu (can run anywhere):

```sh
sudo apt-get install -y golang
go build -ldflags "-s -w -linkmode external -extldflags -static" -o httpd.bin httpd.go
```
