package main

import (
	"crypto/md5"
	"flag"
	log "github.com/Sirupsen/logrus"
	"net"
)

var config Configuration

var Md5Sum [16]byte

var isServer = flag.Bool("s", false, "Server mode.")
var listenAddr = flag.String("lsnaddr", "localhost:10011", "Proxy listening address in both modes.")
var proxyAddr = flag.String("proxyaddr", "localhost:10012", "Address to proxy connection to (client mode only).")
var cfgName = flag.String("f", "config.json", "Configuration file name (server mode only).")
var userId = flag.Int("userid", 0, "User id. (client mode only).")
var passPhrase = flag.String("pass", "", "Passphrase. (client mode only).")
var daemonize = flag.Bool("d", false, "Daemonize.")

func main() {
	// Parse command line arguments.
	flag.Parse()

	if *daemonize {
		daemon(1, 1)
	}

	if *isServer {
		readConfig(*cfgName)
		log.Info("Starting in server mode.")
		log.Infof("Listen on: %s", *listenAddr)
	} else {
		Md5Sum = md5.Sum([]byte(*passPhrase))
		log.Info("Starting in client mode.")
		log.Infof("Listen on: %s", *listenAddr)
		log.Infof("Proxy connecions to: %s", *proxyAddr)
	}

	laddr, err := net.ResolveTCPAddr("tcp", *listenAddr)
	if err != nil {
		log.Fatal("Failed to resolve: ", err)
	}

	listener, err := net.ListenTCP("tcp", laddr)
	if listener == nil {
		log.Fatal("Failed listen on address: ", err)
	}
	defer listener.Close()

	for {
		conn, err := listener.AcceptTCP()
		if conn == nil {
			log.Infof("Failed to accept connection: %v", err)
			continue
		} else {
			log.Infof("Received connection from %s.", conn.RemoteAddr())
		}

		if *isServer {
			go handleServer(conn)
		} else {
			go handleClient(conn)
		}
	}
}
