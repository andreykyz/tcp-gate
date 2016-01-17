package main

import (
	"encoding/binary"
	"errors"
	log "github.com/Sirupsen/logrus"
	"net"
)

type ConnectionHeader struct {
	MAGIC  [4]byte  // 4
	UserId uint32   // 8
	Md5Sum [16]byte // 24
	OptLen uint16   // 26
	Addr4  [4]byte  // 30
	Port   uint16   // 32
}

type Response struct {
	MAGIC [4]byte
}

func readHeader(conn *net.TCPConn) (hdr ConnectionHeader, err error) {
	err = binary.Read(conn, binary.BigEndian, &hdr)
	return
}

func sendHeader(conn *net.TCPConn, hdr ConnectionHeader) (err error) {
	err = binary.Write(conn, binary.BigEndian, hdr)
	return
}

func checkResponse(conn *net.TCPConn) (err error) {
	var resp Response
	err = binary.Read(conn, binary.BigEndian, &resp)
	if err == nil {
		if resp.MAGIC != [4]byte{73, 77, 67, 65} {
			err = errors.New("Error response from server")
		}
	}
	return err
}

func sendResponse(conn *net.TCPConn) (err error) {
	resp := Response{MAGIC: [4]byte{73, 77, 67, 65}}
	err = binary.Write(conn, binary.BigEndian, resp)
	return
}

func handleServer(conn *net.TCPConn) {
	defer conn.Close()

	hdr, _ := readHeader(conn)

	// Check user id and hash
	if hdr.UserId > uint32(len(config.User)) {
		log.Errorf("User with id %d so big", hdr.UserId)
		return
	}
	if !config.User[hdr.UserId].enabled {
		log.Errorf("id %d not found", hdr.UserId)
		return
	}

	log.Debugf("User with id %d hash %x connecting", hdr.UserId, hdr.Md5Sum)

	if config.User[hdr.UserId].hash == hdr.Md5Sum {
		log.Debugf("User %s with id %d hash %x accepted", config.User[hdr.UserId].Name, hdr.UserId, hdr.Md5Sum)
	} else {
		log.Errorf("id %d wrong hash %x", hdr.UserId, hdr.Md5Sum)
		return
	}

	sendResponse(conn)

	raddr := &net.TCPAddr{IP: net.IPv4(hdr.Addr4[0], hdr.Addr4[1], hdr.Addr4[2], hdr.Addr4[3]), Port: int(hdr.Port)}

	// Try to connect to remote server.
	remote, err := net.DialTCP("tcp4", nil, raddr)
	if err != nil {
		// Exit out when an error occurs
		log.Errorf("Failed to connect to server: %v", err)
		return
	}
	defer remote.Close()

	copyData(conn, remote)
}

func handleClient(conn *net.TCPConn) {
	ipv4, port, conn, err := getOriginalDst(conn)
	if err != nil {
		log.Errorf("handleConnection(): can not handle this connection, error occurred in getting original destination ip address/port: %v", err)
		return
	}
	// defer here because of getOriginalDst. It creates new connection
	// and closes old one (if everything is ok).
	defer conn.Close()
	log.Infof("Original destination is %v:%d", ipv4, port)

	raddr, err := net.ResolveTCPAddr("tcp4", *proxyAddr)
	if err != nil {
		log.Fatal("Failed to resolve: ", err)
	}

	// Try to connect to remote server.
	remote, err := net.DialTCP("tcp4", nil, raddr)
	if err != nil {
		// Exit out when an error occurs
		log.Errorf("Failed to connect to server: %v", err)
		return
	}
	defer remote.Close()

	hdr := ConnectionHeader{MAGIC: [4]byte{73, 77, 67, 65}, UserId: uint32(*userId), Md5Sum: Md5Sum, OptLen: 0, Addr4: ipv4, Port: port}
	sendHeader(remote, hdr)

	err1 := checkResponse(remote)
	if err1 != nil {
		log.Error("Bad server response.")
	}

	copyData(conn, remote)
}
