Go (MP)TCP Proxy
================

Features
--------

  - Read command line arguments.
  - Use logging facilities.

Command line arguments
----------------------

  - s - whether run in server (`true`) or client (`false`) mode.

TODO
----

  - Can't find why logging does not work with formats with `Fatal` loglevel.

How to run
----------

export GOPATH=/home/ilya/works/go
go run proxy.go -s --lsnaddr="localhost:10012"
