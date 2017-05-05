Go (MP)TCP Gate
================

Command line arguments
----------------------

  - s - whether run in server (`true`) or client (`false`) mode.
  - lsnaddr - listening address (both modes, `localhost:10011` is default).
  - proxyaddr - address to proxy connection to (client mode only, `localhost:10012` is default).
  - f - configuration file name (server mode only, `config.json` is default).
  - userid - user id (client mode only).
  - pass - passphrase (client mode only).
  - logfile - log file name (stdout if not set, default is stdout).

build and run 
---------
go build proxy.go config.go header.go  log.go  mptcp.go  network.go  packethelper.go   tcp.go  utils.go ; sudo ./proxy -lsnaddr 10.10.1.1:10011 -loglevel=debug

How to run
----------

proxy -s --lsnaddr="localhost:10012"

redirect http:

iptables -A OUTPUT -t nat -p tcp --dport 80 -j REDIRECT --to-port 10011
iptables -A PREROUTING -t nat -p tcp -s 192.168.77.1 --dport 22 -j REDIRECT --to-port 10011

test it:
on server run (ip address 10.10.0.2):
simpleClientServer/server

on client:
iptables -A OUTPUT -t nat -p tcp -d 10.10.0.2 --dport 10012 -j REDIRECT --to-port 10011
simpleClientServer/client
