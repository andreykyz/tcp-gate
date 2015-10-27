package main 
import ( 
    "os"
    "flag"
	"log"
	"net"
	"io"
	"syscall"
	"fmt"
	"errors"
	"encoding/binary"
	"crypto/md5"
	"io/ioutil"
	"encoding/json"
)

type UserInfo struct {
	Id uint32
	Name string
	Passwd string
}

type Configuration struct {
	Users []UserInfo
}

// TODO: Get from headers.
const SO_ORIGINAL_DST = 80

var config Configuration

var Md5Sum [16]byte

type ConnectionHeader struct {
	MAGIC [4]byte
	UserId uint32
	Md5Sum [16]byte
	Len uint16
	Addr4 [4]byte
	Port uint16
}
const HDR_LEN = 6

var isServer = flag.Bool("s", false, "Server mode.")
var listenAddr = flag.String("lsnaddr", "localhost:10011", "Proxy listening address in both modes.")
var proxyAddr = flag.String("proxyaddr", "localhost:10012", "Address to proxy connection to (client mode only).")
var userId = flag.Int("userid", 0, "User id. (client mode only)")
var passPhrase = flag.String("pass", "", "Passphrase. (client mode only)")

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
	
	if *isServer {
		readConfig("config.json")
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
		
		if (*isServer) {
			go handleServer(conn)
		} else {
			go handleClient(conn)
		}
    }
}

func readConfig(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		Error.Printf("Failed to open config file %s", filename)
	}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
  		Error.Println("error:", err)
	}
	Info.Println(config.Users) 
}
	
func readHeader(conn *net.TCPConn) (hdr ConnectionHeader, err error) {
	err = binary.Read(conn, binary.BigEndian, &hdr)
	return
}

func sendHeader(conn *net.TCPConn, hdr ConnectionHeader) (err error) {
    err = binary.Write(conn, binary.BigEndian, hdr)
	return
}

func handleServer(conn *net.TCPConn) {
	defer conn.Close()

	hdr, _ := readHeader(conn)
	//Info.Printf("Original destination is %v:%d", hdr.Addr4, hdr.Port)

	// Find user
	// TODO: Precompute all Md5Sums.
	userChecked := false
	for i := 0; i < len(config.Users); i++ {
		if config.Users[i].Id == hdr.UserId && md5.Sum([]byte(config.Users[i].Passwd)) == hdr.Md5Sum {
			userChecked = true		
			break
		}
	}
	if userChecked == false {
		Error.Printf("Wrong user credentials.")
		return
	}

	raddr := &net.TCPAddr{IP: net.IPv4(hdr.Addr4[0], hdr.Addr4[1], hdr.Addr4[2], hdr.Addr4[3]), Port: int(hdr.Port) + 1}

	// Try to connect to remote server.
	remote, err := net.DialTCP("tcp", nil, raddr)
	if err != nil {
    	// Exit out when an error occurs
    	Error.Printf("Failed to connect to server: %v", err)
    	return
	}
	defer remote.Close()

	copyData(conn, remote)
}

func handleClient(conn *net.TCPConn) {
	// BUG?: We create new connection in getOriginalDst.
	defer func() {
		conn.Close()
//		Info.Printf("Client connection closed.")
	}()

	ipv4, port, conn, err := getOriginalDst(conn)
    if err != nil {
        Error.Printf("handleConnection(): can not handle this connection, error occurred in getting original destination ip address/port: %v", err)
        return
    } else {
    	Info.Printf("Original destination is %v:%d", ipv4, port)
    }

    raddr, err := net.ResolveTCPAddr("tcp", *proxyAddr)
	if err != nil {
		log.Fatal("Failed to resolve: ", err)
	}

   	// Try to connect to remote server.
	remote, err := net.DialTCP("tcp", nil, raddr)
	if err != nil {
    	// Exit out when an error occurs
    	Error.Printf("Failed to connect to server: %v", err)
    	return
	}
	defer func() {
		remote.Close()
//		Info.Printf("Remote connection closed.")
	}()

	hdr := ConnectionHeader{MAGIC: [4]byte{73, 77, 67, 65}, UserId: uint32(*userId), Md5Sum: Md5Sum, Len: HDR_LEN, Addr4: ipv4, Port: port}
	sendHeader(remote, hdr)

	copyData(conn, remote)

}

func getOriginalDst(clientConn *net.TCPConn) (ipv4 [4]byte, port uint16, newTCPConn *net.TCPConn, err error) {
    if clientConn == nil {
        err = errors.New("ERR: clientConn is nil")
        return
    }

    // test if the underlying fd is nil
    remoteAddr := clientConn.RemoteAddr()
    if remoteAddr == nil {
        err = errors.New("ERR: clientConn.fd is nil")
        return
    }

    srcipport := fmt.Sprintf("%v", clientConn.RemoteAddr())

    newTCPConn = nil
    // net.TCPConn.File() will cause the receiver's (clientConn) socket to be placed in blocking mode.
    // The workaround is to take the File returned by .File(), do getsockopt() to get the original 
    // destination, then create a new *net.TCPConn by calling net.Conn.FileConn().  The new TCPConn
    // will be in non-blocking mode.  What a pain.
    clientConnFile, err := clientConn.File()
    if err != nil {
        Info.Printf("GETORIGINALDST|%v->?->FAILEDTOBEDETERMINED|ERR: could not get a copy of the client connection's file object", srcipport)
        return
    } else {
        clientConn.Close()
    }

    // Get original destination
    // this is the only syscall in the Golang libs that I can find that returns 16 bytes
    // Example result: &{Multiaddr:[2 0 31 144 206 190 36 45 0 0 0 0 0 0 0 0] Interface:0}
    // port starts at the 3rd byte and is 2 bytes long (31 144 = port 8080)
    // IPv4 address starts at the 5th byte, 4 bytes long (206 190 36 45)
    addr, err :=  syscall.GetsockoptIPv6Mreq(int(clientConnFile.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
    if err != nil {
        Info.Printf("GETORIGINALDST|%v->?->FAILEDTOBEDETERMINED|ERR: getsocketopt(SO_ORIGINAL_DST) failed: %v", srcipport, err)
        return
    }
    newConn, err := net.FileConn(clientConnFile)
    if err != nil {
        Info.Printf("GETORIGINALDST|%v->?->%v|ERR: could not create a FileConn fron clientConnFile=%+v: %v", srcipport, addr, clientConnFile, err)
        return
    }
    if _, ok := newConn.(*net.TCPConn); ok {
        newTCPConn = newConn.(*net.TCPConn)
        clientConnFile.Close()
    } else {
        errmsg := fmt.Sprintf("ERR: newConn is not a *net.TCPConn, instead it is: %T (%v)", newConn, newConn)
        Info.Printf("GETORIGINALDST|%v->?->%v|%s", srcipport, addr, errmsg)
        err = errors.New(errmsg)
        return
    }

    ipv4  = [...]byte{ byte(addr.Multiaddr[4]),
    				   byte(addr.Multiaddr[5]),
    				   byte(addr.Multiaddr[6]),
    				   byte(addr.Multiaddr[7]) }
    port = uint16(addr.Multiaddr[2]) << 8 + uint16(addr.Multiaddr[3])

    return
}

func copyData(conn1 *net.TCPConn, conn2 *net.TCPConn) {
	// I'm waiting on finished to be able to close
	// connection correctly.
	finished := make(chan bool, 2)

	go func() {
		io.Copy(conn1, conn2)
		finished <- true
	}()

	go func() {
		io.Copy(conn2, conn1)
		finished <- true
	}()

	<- finished
}