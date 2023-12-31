package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	log "github.com/Sirupsen/logrus"
)

type ConnectionHeader struct {
	MAGIC      [4]byte  // 4
	UserID     uint32   // 8
	Md5Sum     [16]byte // 24
	OptLen     uint16   // 26
	Addr4      [4]byte  // 30
	Port       uint16   // 32
	SrcAddr4   [4]byte  // 36
	SrcPort    uint16   // 38
	SrcMac     [6]byte  // 44
	LocalAddr4 [4]byte  // 48
	LocalPort  uint16   // 50
}

type Response struct {
	MAGIC [4]byte
}

func readHeader(conn *net.TCPConn) (hdr ConnectionHeader, err error) {
	err = binary.Read(conn, binary.BigEndian, &hdr)
	if err != nil {
		log.Error("Read header error", err)
		return
	}
	return
}

func sendHeader(conn io.Writer, hdr ConnectionHeader) (err error) {
	err = binary.Write(conn, binary.BigEndian, hdr)
	return
}

func checkResponse(conn io.Reader) (err error) {
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
	var hdr ConnectionHeader
	hdr, _ = readHeader(conn)

	log.Infof("%s src %s:%d; dst %s:%d; proxy addr: %s:%d proxy src: %s proxy dst %s",
		time.Now().Local().String(),                                                                    //date
		net.IPv4(hdr.SrcAddr4[0], hdr.SrcAddr4[1], hdr.SrcAddr4[2], hdr.SrcAddr4[3]), int(hdr.SrcPort), //src ip1:port
		net.IPv4(hdr.Addr4[0], hdr.Addr4[1], hdr.Addr4[2], hdr.Addr4[3]), int(hdr.Port), //dst ip5:port
		net.IPv4(hdr.LocalAddr4[0], hdr.LocalAddr4[1], hdr.LocalAddr4[2], hdr.LocalAddr4[3]), int(hdr.LocalPort), //proxy addr: IP2:port
		conn.RemoteAddr().String(), //proxy src: ip3:port
		conn.LocalAddr().String(),  //proxy src: ip4:port
	)
	// Check user id and hash
	if hdr.UserID > uint32(len(config.User)) {
		log.Errorf("User with id %d so big", hdr.UserID)
		return
	}
	if !config.User[hdr.UserID].enabled {
		log.Errorf("id %d not found", hdr.UserID)
		return
	}

	log.Debugf("User with id %d hash %x connecting", hdr.UserID, hdr.Md5Sum)

	if config.User[hdr.UserID].hash == hdr.Md5Sum {
		log.Debugf("User %s with id %d hash %x accepted", config.User[hdr.UserID].Name, hdr.UserID, hdr.Md5Sum)
	} else {
		log.Errorf("id %d wrong hash %x", hdr.UserID, hdr.Md5Sum)
		return
	}
	if config.User[hdr.UserID].Skipack {
		log.Debugf("Ignore ack sending for user id %d name %s ", hdr.UserID, config.User[hdr.UserID].Name)
	} else {
		log.Debugf("Send ack for user id %d name %s ", hdr.UserID, config.User[hdr.UserID].Name)
		sendResponse(conn)
	}

	raddr := &net.TCPAddr{IP: net.IPv4(hdr.Addr4[0], hdr.Addr4[1], hdr.Addr4[2], hdr.Addr4[3]), Port: int(hdr.Port)}

	// Try to connect to remote server.
	remote, err := net.DialTCP("tcp4", nil, raddr)
	if err != nil {
		// Exit out when an error occurs
		log.Errorf("Failed to connect to server: %v", err)
		return
	}
	defer remote.Close()

	copyData(conn, remote, &config.User[hdr.UserID])
}

func handleClient(conn *net.TCPConn, pool *TCPConnPool) {
	//	srcPort := uint16(conn.RemoteAddr().(*net.TCPAddr).Port)
	//	srcAddr4 := conn.RemoteAddr().(*net.TCPAddr).IP
	//	srcAddr := [4]byte{srcAddr4[0], srcAddr4[1], srcAddr4[2], srcAddr4[3]}
	//	localPort := uint16(conn.LocalAddr().(*net.TCPAddr).Port)
	//	localAddr4 := conn.RemoteAddr().(*net.TCPAddr).IP
	//	localAddr := [4]byte{localAddr4[0], localAddr4[1], localAddr4[2], localAddr4[3]}
	ipv4, port, conn, err := getOriginalDst(conn)
	if err != nil {
		log.Errorf("handleConnection(): can not handle this connection, error occurred in getting original destination ip address/port: %v", err)
		return
	}
	// defer here because of getOriginalDst. It creates new connection
	// and closes old one (if everything is ok).
	defer conn.Close()
	log.Infof("Original destination is %v:%d", ipv4, port)

	//	raddr, err := net.ResolveTCPAddr("tcp4", *proxyAddr)
	//	if err != nil {
	//		log.Fatal("Failed to resolve: ", err)
	//	}
	raddr := &net.TCPAddr{IP: net.IPv4(ipv4[0], ipv4[1], ipv4[2], ipv4[3]), Port: int(port)}
	//	remoteU := pool.DialUserSpaceTCP(raddr)
	remoteU := pool.DialUserSpaceTCP(raddr)
	/*	hdr := ConnectionHeader{
			MAGIC: [4]byte{73, 77, 67, 65}, UserID: uint32(*userID), Md5Sum: Md5Sum, OptLen: 0,
			Addr4: ipv4, Port: port,
			SrcAddr4: srcAddr, SrcPort: srcPort,
			SrcMac:     [6]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			LocalAddr4: localAddr, LocalPort: localPort,
		}
			sendHeader(remoteU, hdr)
		if !*disableResp {
			log.Debug("Check response")
			err1 := checkResponse(remoteU)
			if err1 != nil {
				log.Error("Bad server response.")
			}
		}
	*/
	copyData(conn, remoteU, nil)
}
