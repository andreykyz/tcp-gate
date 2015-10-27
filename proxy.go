package main

import (
	"crypto/md5"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
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

var (
	Trace   *log.Logger
	Info    *log.Logger
	Warning *log.Logger
	Error   *log.Logger
)

func Init(
	traceHandle io.Writer,
	infoHandle io.Writer,
	warningHandle io.Writer,
	errorHandle io.Writer) {

	Trace = log.New(traceHandle,
		"TRACE: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Info = log.New(infoHandle,
		"INFO: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Warning = log.New(warningHandle,
		"WARNING: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Error = log.New(errorHandle,
		"ERROR: ",
		log.Ldate|log.Ltime|log.Lshortfile)
}

func main() {
	Init(ioutil.Discard, os.Stdout, os.Stdout, os.Stderr)

	// Parse command line arguments.
	flag.Parse()

	if *daemonize {
		daemon(1, 1)
	}

	if *isServer {
		readConfig(*cfgName)
		Info.Printf("Starting in server mode.")
		Info.Printf("Listen on: %s", *listenAddr)
	} else {
		Md5Sum = md5.Sum([]byte(*passPhrase))
		Info.Printf("Starting in client mode.")
		Info.Printf("Listen on: %s", *listenAddr)
		Info.Printf("Proxy connecions to: %s", *proxyAddr)
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
			Error.Printf("Failed to accept connection: %v", err)
			continue
		} else {
			Info.Printf("Received connection from %s.", conn.RemoteAddr())
		}

		if *isServer {
			go handleServer(conn)
		} else {
			go handleClient(conn)
		}
	}
}
