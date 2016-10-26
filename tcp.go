/*
Copyright 2013-2014 Graham King

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

For full license details see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"syscall"
	"unsafe"

	log "github.com/Sirupsen/logrus"

	tuntap "github.com/songgao/water"
)

const (
	FIN = 1  // 00 0001
	SYN = 2  // 00 0010
	RST = 4  // 00 0100
	PSH = 8  // 00 1000
	ACK = 16 // 01 0000
	URG = 32 // 10 0000
)

/*
 *    TCP option from include/net/tcp.h of linux kernel
 *    http://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
 */
const (
	TCPOptNOP       = 1   // Padding */
	TCPOptEOL       = 0   // End of options */
	TCPOptMSS       = 2   // Segment size negotiating */
	TCPOptWindow    = 3   // Window scaling */
	TCPOptSACKPerm  = 4   // SACK Permitted */
	TCPOptSACK      = 5   // SACK Block */
	TCPOptTimeStamp = 8   // Better RTT estimations/PAWS */
	TCPOptMD5Sig    = 19  // MD5 Signature (RFC2385) */
	TCPOptMPTCP     = 30  //
	TCPOptFastOpen  = 34  // Fast open (RFC7413) */
	TCPOptExp       = 254 // Experimental */
)

/* Magic number to be after the option value for sharing TCP
 * experimental options. See draft-ietf-tcpm-experimental-options-00.txt
 */
const (
	TCPOptFastOpenMagic = 0xF989
)

const (
	NetPortAmount = 65536
)

type TcpState int

const (
	TCPStateConnect     TcpState = 0
	TCPStateSYNSent     TcpState = 1
	TCPStateACKWait     TcpState = 2
	TCPStateEstablished TcpState = 3
)

type iflags struct {
	name  [syscall.IFNAMSIZ]byte //interface name
	flags uint16                 //interface flags
}

type ifnet struct {
	name   [syscall.IFNAMSIZ]byte //interface name
	family int16                  //struct sockaddr
	port   uint16                 //struct sockaddr
	ip     [4]byte                //struct sockaddr
	zero   [8]byte                //struct sockaddr
}

type TCPConnHash struct {
	hash [12]byte
}

type TCPConnPool struct {
	iface       *tuntap.Interface
	ifaceIP     net.IP
	portUsing   []bool
	connHashMap map[TCPConnHash]*TCPConnUserSpace
}

type TCPConnUserSpace struct {
	iface     *tuntap.Interface
	srcAddr   *net.TCPAddr
	dstAddr   *net.TCPAddr
	readChan  chan []byte
	writeChan chan []byte
	connHash  [12]byte
	done      bool
	tcpState  TcpState
}

// Parse packet into TCPHeader structure
func NewTCPHeader(data []byte) *TCPHeader {
	var tcp TCPHeader
	r := bytes.NewReader(data)
	binary.Read(r, binary.BigEndian, &tcp.Source)
	binary.Read(r, binary.BigEndian, &tcp.Destination)
	binary.Read(r, binary.BigEndian, &tcp.SeqNum)
	binary.Read(r, binary.BigEndian, &tcp.AckNum)

	var mix uint16
	binary.Read(r, binary.BigEndian, &mix)
	tcp.DataOffset = byte(mix >> 12)  // top 4 bits
	tcp.Reserved = byte(mix >> 9 & 7) // 3 bits
	tcp.ECN = byte(mix >> 6 & 7)      // 3 bits
	tcp.Ctrl = byte(mix & 0x3f)       // bottom 6 bits

	binary.Read(r, binary.BigEndian, &tcp.Window)
	binary.Read(r, binary.BigEndian, &tcp.Checksum)
	binary.Read(r, binary.BigEndian, &tcp.Urgent)

	return &tcp
}

func getTCPSyn(srcAddr, dstAddr *net.TCPAddr) []byte {

	tcpHeader := TCPHeader{
		Source:      uint16(srcAddr.Port), // Random ephemeral port
		Destination: uint16(dstAddr.Port),
		SeqNum:      rand.Uint32(), // initial seg num
		AckNum:      0,
		DataOffset:  5,      // 4 bits
		Reserved:    0,      // 3 bits
		ECN:         0,      // 3 bits
		Ctrl:        2,      // 6 bits (000010, SYN bit set)
		Window:      0xaaaa, // The amount of data that it is able to accept in bytes
		Checksum:    0,      // Kernel will set this if it's 0
		Urgent:      0,
		Options:     []TCPOption{},
	}
	data := tcpHeader.Marshal()
	tcpHeader.Checksum = Csum(data, srcAddr.IP, dstAddr.IP)

	ipHeader := &Header{
		Version:  Version,
		Len:      HeaderLen,
		TOS:      0,
		TotalLen: HeaderLen,    //must be calc later
		ID:       0x0000,       //must be increment by 1 (uniq per packet)
		Flags:    DontFragment, //syn packet must be DONT FRAGMENT
		FragOff:  0x0000,       //this field use for ip packet fragmentation
		TTL:      64,
		Protocol: 6, // 6 means tcp
		Checksum: 0, //calc later
		Src:      srcAddr.IP,
		Dst:      dstAddr.IP,
	}

	data, _ = ipHeader.Marshal()
	var checkSum uint32
	checkSum = 0
	for i := 0; i+1 < ipHeader.Len; i += 2 {
		checkSum += uint32(uint16(data[i])<<8 | uint16(data[i+1]))
	}
	if checkSum > 0xffff {
		checkSum = (checkSum >> 16) + (checkSum & 0xffff)
		if checkSum > 0xffff {
			checkSum = (checkSum >> 16) + (checkSum & 0xffff)
		}
	}
	ipHeader.Checksum = ^uint16(checkSum)
	data, _ = ipHeader.Marshal()
	data = append(data, tcpHeader.Marshal()...)
	return data
}
func getTCPPool() *TCPConnPool {
	pool := &TCPConnPool{connHashMap: make(map[TCPConnHash]*TCPConnUserSpace)}
	var err error
	pool.iface, err = tuntap.NewTUN("")
	if err != nil {
		log.Fatal("Failed to open tun device ", err)
		return nil
	}
	//	defer pool.iface.Close()

	pool.ifaceIP = net.ParseIP(*tunIP)
	fd, error := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if error == nil {
		defer syscall.Close(fd)
	}
	log.Debug("socket open fd ", fd, " err ", error, " ")
	var ifn ifnet
	copy(ifn.name[:], pool.iface.Name())
	ifn.port = 0
	ifn.family = syscall.AF_INET
	copy(ifn.ip[0:4], pool.ifaceIP.To4()[0:4])

	log.Info("tun name is ", pool.iface.Name(), " addr is ", pool.ifaceIP)

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCSIFADDR, uintptr(unsafe.Pointer(&ifn)))

	log.Debug(" SIOCSIFADDR called ")

	log.Debug(errno.Error())

	var ifl iflags
	copy(ifl.name[:], ifn.name[:])

	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifl)))
	log.Debugf(" SIOCGIFFLAGS called ")

	ifl.flags |= syscall.IFF_UP | syscall.IFF_RUNNING //| syscall.IFF_NOARP | syscall.IFF_TUN

	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifl)))

	log.Debugf(" SIOCSIFFLAGS called ")

	log.Debugf(errno.Error())

	return pool
}

/**
get uniq pair srcAddr/dstAddr
*/
func (pool *TCPConnPool) getSrcAddr(dstAddr *net.TCPAddr) *net.TCPAddr {
	rndPort := rand.Int() % NetPortAmount
	var srcAddr *net.TCPAddr
	for i := 0; i < NetPortAmount; i++ { //look for free port for uniq srcAddr/dstAddr
		rndPort++
		if rndPort >= NetPortAmount {
			rndPort = 0
		}
		srcAddr = &net.TCPAddr{IP: pool.ifaceIP, Port: rndPort}
		if _, ok := pool.connHashMap[GetTCPConnHash(srcAddr, dstAddr)]; !ok {
			break
		}
	}
	return srcAddr
}

func (pool *TCPConnPool) DialUserSpaceTCP(dstAddr *net.TCPAddr) *TCPConnUserSpace {
	srcAddr := pool.getSrcAddr(dstAddr)
	conn := &TCPConnUserSpace{srcAddr: srcAddr, dstAddr: dstAddr, done: false, tcpState: TCPStateConnect, iface: pool.iface}
	//	conn.iface.Write(sendTcpSyn(srcAddr, dstAddr))

	return conn

}

func (conn *TCPConnUserSpace) readLoop() {
	buf := make([]byte, 32*1024)
	conn.iface.Read(buf)
	h, _ := ParseHeader(buf)
	log.Debug(h)
	switch conn.tcpState {
	case TCPStateConnect:
	case TCPStateSYNSent:
	}
}

func (conn *TCPConnUserSpace) writeLoop() {

	switch conn.tcpState {
	case TCPStateConnect:
		conn.iface.Write(getTCPSyn(conn.srcAddr, conn.dstAddr))
	case TCPStateSYNSent:

	}

}

/**
Get hash from srcAddr/dstAddr as [12]byte
*/
func GetTCPConnHash(addr1, addr2 *net.TCPAddr) TCPConnHash {
	return TCPConnHash{hash: [12]byte{addr1.IP[0], addr1.IP[1], addr1.IP[2], addr1.IP[3],
		byte(uint16(addr1.Port) >> 8), byte(uint16(addr1.Port) & 0xff),
		addr2.IP[0], addr2.IP[1], addr2.IP[2], addr2.IP[3],
		byte(uint16(addr2.Port) >> 8), byte(uint16(addr2.Port) & 0xff)}}

}

func (conn *TCPConnUserSpace) Read(p []byte) (n int, err error) {
	if conn.done {
		return 0, io.EOF
	}
	p = <-conn.readChan //32*1024 max
	n = len(p)
	return n, err
}

func (conn *TCPConnUserSpace) Write(p []byte) (n int, err error) {
	if conn.done {
		return 0, io.EOF
	}
	if len(p) > 32*1024 {
		n = 32 * 1024
		conn.writeChan <- p[:n]
	} else {
		conn.writeChan <- p //32*1024 max
		n = len(p)
	}
	return n, err
}

func (conn *TCPConnUserSpace) Close() (err error) {
	return io.EOF
}
