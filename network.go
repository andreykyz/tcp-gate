package main

import (
	"crypto/md5"
	"encoding/binary"
	"log"
	"net"
)

type ConnectionHeader struct {
	MAGIC  [4]byte
	UserId uint32
	Md5Sum [16]byte
	Len    uint16
	Addr4  [4]byte
	Port   uint16
}

const HDR_LEN = 6

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
		//	Info.Printf("Client connection closed.")
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
		//	Info.Printf("Remote connection closed.")
	}()

	hdr := ConnectionHeader{MAGIC: [4]byte{73, 77, 67, 65}, UserId: uint32(*userId), Md5Sum: Md5Sum, Len: HDR_LEN, Addr4: ipv4, Port: port}
	sendHeader(remote, hdr)

	copyData(conn, remote)
}
