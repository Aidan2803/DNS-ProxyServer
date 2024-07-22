# DNS-Proxy-Server
Simple DNS Proxy server

### Introduction
This is a simple DNS Proxy server that accepts DNS requests and sends response to the client. DNS Proxy server has a config file that contains adress of a DNS server and a black list of site domain names. If client tries to access site from the black list, DNS Proxy server will send a response with an error, if site`s domain is not in the blacklist then DNS Proxy server will send a query to the DNS Server and will send DNS response back to client

### Build
For building gcc is used:
```
gcc main_server.c -o <binary_desired_name>
```
### Usage
1) Start server
2) Send a DNS query to the server, for example via dig comand:
   ```
   dig example.com @127.0.0.1 -p 18000
   ```
   By default DNS Proxy server uses 18000 port, this can be changed in the code via changing RESOLVER_PORT variable
4) Look for response from the dig, look for loged answer from the DNS Proxy server
