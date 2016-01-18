package main

import (
	"crypto/md5"
	"flag"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
	"net"
	"os"
)

var config Configuration

var Md5Sum [16]byte

var isServer = flag.Bool("s", false, "Server mode.")
var listenAddr = flag.String("lsnaddr", "localhost:10011", "Proxy listening address in both modes.")
var proxyAddr = flag.String("proxyaddr", "localhost:10012", "Address to proxy connection to (client mode only).")
var cfgName = flag.String("f", "example.conf", "Configuration file name (server mode only).")
var userId = flag.Int("userid", 0, "User id. (client mode only).")
var passPhrase = flag.String("pass", "", "Passphrase. (client mode only).")
var logLevel = flag.String("loglevel", "info", "Possible values: debug, info, warning, error")
var logFile = flag.String("logfile", "", "Log file name.")
var showVersion = flag.Bool("v", false, "Display version and exit.")
var disableResp = flag.Bool("r", false, "Disable check response")

func main() {
	// Parse command line arguments.
	flag.Parse()
	log.SetOutput(os.Stderr)
	if *logLevel == "debug" {
		log.SetLevel(log.DebugLevel)
	}
	if *logLevel == "info" {
		log.SetLevel(log.InfoLevel)
	}
	if *logLevel == "warning" {
		log.SetLevel(log.WarnLevel)
	}
	if *logLevel == "error" {
		log.SetLevel(log.ErrorLevel)
	}

	if *showVersion {
		fmt.Println("Version 1.1.")
		return
	}

	if *logFile != "" {
		log.SetFormatter(&log.TextFormatter{DisableColors: true})
		// Standard logger interface set output has no return value.
		// So, we have no change to know if there was errors.
		log.SetOutput(&lumberjack.Logger{
			Filename:   *logFile,
			MaxSize:    50, // megabytes
			MaxBackups: 3,
			MaxAge:     28, //days
		})
	}

	if *isServer {
		config.readConfig(*cfgName)
		log.Info("Starting in server mode.")
		log.Infof("Listen on: %s", *listenAddr)
	} else {
		Md5Sum = md5.Sum([]byte(*passPhrase))
		log.Info("Starting in client mode.")
		log.Infof("Listen on: %s", *listenAddr)
		log.Infof("Proxy connecions to: %s", *proxyAddr)
	}

	laddr, err := net.ResolveTCPAddr("tcp4", *listenAddr)
	if err != nil {
		log.Fatal("Failed to resolve: ", err)
	}

	listener, err := net.ListenTCP("tcp4", laddr)
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
			log.Debugf("Received connection from %s.", conn.RemoteAddr())
		}

		if *isServer {
			go handleServer(conn)
		} else {
			go handleClient(conn)
		}
	}
}
