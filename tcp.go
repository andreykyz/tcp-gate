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
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
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
	TCPInitCwnd         = 29200
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

type TCPConnHash [12]byte

type TCPConnPool struct {
	iface        *tuntap.Interface
	ifaceIP      net.IP
	portUsing    []bool
	connHashMap  map[TCPConnHash]*TCPConnUserSpace
	packetHelper PacketHelper
}

type TCPConnUserSpace struct {
	iface   *tuntap.Interface
	srcAddr *net.TCPAddr
	dstAddr *net.TCPAddr
	shared  struct {
		sync.RWMutex
		SeqNum         uint32
		SentAckNum     uint32
		RecvSeqNum     uint32
		RecvNextSeqNum uint32
		ID             uint16
		Window         uint16
		WindowShift    int
		byteOnFly      int
	}
	readChan        chan []byte
	readPacketChan  chan []byte
	writePacketChan chan []byte
	writeDataChan   chan []byte
	connHash        [12]byte
	done            bool
	stopChans       []chan struct{} // we need to use this slice for stop all goroutines
	minMSS          int
	tcpState        TcpState
}

// Parse packet into TCPHeader structure
func ParseTCPHeader(data []byte) *TCPHeader {
	var tcp TCPHeader
	r := bytes.NewReader(data)
	binary.Read(r, binary.BigEndian, &tcp.SrcPort)
	binary.Read(r, binary.BigEndian, &tcp.DstPort)
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

func (h *TCPHeader) String() string {
	if h == nil {
		return "<nil>"
	}
	Ctrtl := ""
	if (h.Ctrl & FIN) == FIN {
		Ctrtl += "FIN"
	}
	if (h.Ctrl & SYN) == SYN {
		Ctrtl += " SYN"
	}
	if (h.Ctrl & RST) == RST {
		Ctrtl += " RST"
	}
	if (h.Ctrl & PSH) == PSH {
		Ctrtl += " PSH"
	}
	if (h.Ctrl & ACK) == ACK {
		Ctrtl += " ACK"
	}
	if (h.Ctrl & URG) == URG {
		Ctrtl += " URG"
	}
	return fmt.Sprintf("SrcPort=%d DstPort=%d SeqNum=%d AckNum=%d DataOffset=%d Ctrl=%s Window=%d Checksum=%#x", h.SrcPort, h.DstPort, h.SeqNum, h.AckNum, h.DataOffset, Ctrtl, h.Window, h.Checksum)
}

func (conn *TCPConnUserSpace) getTCPSyn() []byte {

	tcpHeader := TCPHeader{
		SrcPort:    uint16(conn.srcAddr.Port),
		DstPort:    uint16(conn.dstAddr.Port),
		SeqNum:     conn.shared.SeqNum, // initial seg num
		AckNum:     conn.shared.SentAckNum,
		DataOffset: 5,                  // 4 bits
		Reserved:   0,                  // 3 bits
		ECN:        0,                  // 3 bits
		Ctrl:       2,                  // 6 bits (000010, SYN bit set)
		Window:     conn.shared.Window, // The amount of data that it is able to accept in bytes
		Checksum:   0,                  // Kernel will set this if it's 0
		Urgent:     0,
		Options:    []TCPOption{},
	}
	TCPData := tcpHeader.Marshal()
	tcpCheckSum := Csum(TCPData, conn.srcAddr.IP, conn.dstAddr.IP)
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
		Src:      conn.srcAddr.IP,
		Dst:      conn.dstAddr.IP,
	}

	data, _ := ipHeader.Marshal()
	TCPData[16] = byte(tcpCheckSum >> 8)
	TCPData[17] = byte(tcpCheckSum & 0xff)

	data = append(data, TCPData...)
	//full len calc
	data[2] = byte(len(data) >> 8)
	data[3] = byte(len(data) & 0xff)

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
	// calculate header Checksum at the end
	data[10] = byte(^uint16(checkSum) >> 8)
	data[11] = byte(^uint16(checkSum) & 0xff)
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
	ifn.ip[3]++
	if ifn.ip[3] == 255 {
		ifn.ip[3]++
	}
	if ifn.ip[3] == 0 {
		ifn.ip[3]++
	}
	log.Info("tun name is ", pool.iface.Name(), " addr is ", pool.ifaceIP)

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCSIFADDR, uintptr(unsafe.Pointer(&ifn)))

	copy(ifn.ip[0:4], pool.ifaceIP.To4()[0:4])

	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCSIFDSTADDR, uintptr(unsafe.Pointer(&ifn)))

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

	pool.packetHelper = PacketHelper{iface: pool.iface}

	pool.packetHelper.StartHelper()

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
	conn := &TCPConnUserSpace{srcAddr: srcAddr, dstAddr: dstAddr, tcpState: TCPStateConnect, done: false, iface: pool.iface, minMSS: 1460, connHash: GetTCPConnHash(srcAddr, dstAddr)}
	conn.shared.Window = TCPInitCwnd
	conn.shared.SeqNum = rand.Uint32() // init seqnum
	//chR := make(chan []byte)
	//	chW := make(chan []byte)
	//	pool.packetHelper.readChan.Lock()
	//	pool.packetHelper.readChan.m[GetTCPConnHash(srcAddr, dstAddr)] = &chR
	//	pool.packetHelper.readChan.Unlock()
	log.Debug("DialUserSpaceTCP srcAddr ", srcAddr, " dstAddr ", dstAddr)

	log.Debug("DialUserSpaceTCP new conn hash is : ", conn.connHash)
	conn.writePacketChan = make(chan []byte, 1)
	conn.writeDataChan = make(chan []byte, 1)
	conn.readChan = make(chan []byte, 1)
	conn.readPacketChan = make(chan []byte, 1)

	pool.packetHelper.AddReadChan(conn.readPacketChan, conn.connHash)

	log.Debug("writePacketChan is writing")
	conn.writePacketChan <- conn.getTCPSyn()
	log.Debug("writePacketChan is written")

	conn.tcpState = TCPStateSYNSent

	readLoopStopChan := make(chan struct{})
	conn.stopChans = append(conn.stopChans, readLoopStopChan)
	go conn.readLoop(readLoopStopChan)

	writePacketLoopStopChan := make(chan struct{})
	conn.stopChans = append(conn.stopChans, writePacketLoopStopChan)
	go conn.writePacketLoop(writePacketLoopStopChan)

	return conn

}

func (conn *TCPConnUserSpace) readLoop(stopChan chan struct{}) { //need to implement stopChan
	for {
		log.Debug("readLoop reading from readPacketChan...")
		buf := <-conn.readPacketChan
		//		conn.iface.Read(buf)
		h, _ := ParseHeader(buf)
		log.Debug("readLoop Recv ip header: ", h)
		hTCP := ParseTCPHeader(buf[h.Len:])
		log.Debug("readLoop Recv tcp header: ", hTCP)
		switch conn.tcpState {
		case TCPStateEstablished:
			offset := h.Len + int(hTCP.DataOffset<<2)
			log.Debug("readLoop data len: ", h.TotalLen-offset)
			if (hTCP.Ctrl & ACK) == ACK {
				conn.shared.Lock()
				conn.shared.RecvNextSeqNum += uint32(h.TotalLen - offset) // need to sync
				conn.shared.Unlock()
			}
			if (h.TotalLen - offset) > 0 {
				log.Debug("readLoop write readChan")
				conn.readChan <- buf[offset:h.TotalLen]
				log.Debug("readLoop written readChan")
			}
			var null []byte
			log.Debug("readLoop writeDataChan notify 1")
			conn.writeDataChan <- null
			log.Debug("readLoop writeDataChan notify 2")
		case TCPStateSYNSent:
			if ((hTCP.Ctrl & ACK) == ACK) && ((hTCP.Ctrl & SYN) == SYN) {
				conn.shared.Lock()
				//conn.shared.AckNum = conn.RecvAckNum
				conn.shared.SentAckNum = hTCP.SeqNum + 1
				conn.shared.RecvNextSeqNum = conn.shared.SentAckNum
				conn.shared.SeqNum++
				conn.shared.Unlock()
				log.Debug("SYN ACK recv ")
				h := &Header{}
				opt := []TCPOption{{Kind: TCPOptMSS, Length: 4}}
				opt[0].Data = make([]byte, 2)
				binary.BigEndian.PutUint16(opt[0].Data, uint16(1500))
				hTCP := &TCPHeader{
					Ctrl:    ACK,
					Options: opt,
				}
				p := conn.GetPacket(h, hTCP, nil)
				log.Debug("writePacketChan writing ")
				conn.writePacketChan <- p
				log.Debug("writePacketChan written ")
				conn.tcpState = TCPStateEstablished
				writeDataLoopStopChan := make(chan struct{})
				conn.stopChans = append(conn.stopChans, writeDataLoopStopChan)
				go conn.writeDataLoop(writeDataLoopStopChan)
			}
		}
	}
}

func (conn *TCPConnUserSpace) writePacketLoop(stopChan chan struct{}) {
	for {
		log.Debug("writePacketChan is reading")
		select {
		case <-stopChan:
			return
		case buf := <-conn.writePacketChan:
			log.Debug("writePacketChan is read len ", len(buf))
			//Send ip headertime.Sleep(1 * time.Second)
			if buf == nil {
				continue
			}
			if len(buf) == 0 {
				continue
			}
			h, _ := ParseHeader(buf)
			log.Debug("writePacketLoop Send ip header: ", h)
			hTCP := ParseTCPHeader(buf[h.Len:])
			log.Debug("writePacketLoop tcp header: ", hTCP)
			conn.iface.Write(buf)
		}
	}
}
func (conn *TCPConnUserSpace) writeDataLoop(stopChan chan struct{}) {
	for {
		log.Debug("writeChan is reading")
		select {
		case <-stopChan:
			return
		case buf := <-conn.writeDataChan:
			log.Debug("writeDataLoop get buf ", len(buf), " bytes")
			for {
				log.Debug("Cycle")
				//time.Sleep(1 * time.Second)
				select {
				case <-stopChan:
					return
				default:
				}
				h := &Header{}
				hTCP := &TCPHeader{
					Ctrl: 0,
				}
				conn.shared.Lock()
				if conn.shared.SentAckNum != conn.shared.RecvNextSeqNum { //need to sync
					conn.shared.SentAckNum = conn.shared.RecvNextSeqNum
					hTCP.Ctrl |= ACK
				}
				conn.shared.Unlock()
				p := conn.GetPacket(h, hTCP, buf)
				h, _ = ParseHeader(p)
				log.Debug("writeDataLoop pack packet len ", len(p), " mss ", conn.minMSS)
				log.Debug("writeDataLoop check ip header: ", h)
				hTCP = ParseTCPHeader(p[h.Len:])
				log.Debug("writeDataLoop check tcp header: ", hTCP)

				//conn.writePacketChan
				if len(p) > conn.minMSS {
					buf = p[conn.minMSS:]
					conn.writePacketChan <- p[:conn.minMSS]
					continue
				} else {
					conn.writePacketChan <- p
					break
				}
			}
		}
	}
}

/**
Get hash from srcAddr/dstAddr as [12]byte for outgoing packet
*/
func GetTCPConnHash(addr2, addr1 *net.TCPAddr) TCPConnHash {
	hash := TCPConnHash{8: byte(uint16(addr1.Port) >> 8), 9: byte(uint16(addr1.Port) & 0xff),
		10: byte(uint16(addr2.Port) >> 8), 11: byte(uint16(addr2.Port) & 0xff)}
	copy(hash[0:4], addr1.IP.To4()[0:4])
	copy(hash[4:8], addr2.IP.To4()[0:4])
	return hash

}

func (conn *TCPConnUserSpace) Read(p []byte) (n int, err error) {
	if conn.done {
		return 0, io.EOF
	}
	log.Debug("read")
	buf := <-conn.readChan //32*1024 max
	n = len(buf)
	copy(p, buf[0:n])
	log.Debug("read len ", n)
	return n, err
}

func (conn *TCPConnUserSpace) Write(p []byte) (n int, err error) {
	if conn.done {
		return 0, io.EOF
	}
	//	if len(p) == 0 {
	//		return 0, err
	//	}
	if len(p) > 32*1024 {
		n = 32 * 1024
		conn.writeDataChan <- p[:n]
	} else {
		conn.writeDataChan <- p //32*1024 max
		n = len(p)
	}
	return n, err
}

func (conn *TCPConnUserSpace) Close() (err error) {
	return io.EOF
}

// GetPacket need to sync by shared.Lock
func (conn *TCPConnUserSpace) GetPacket(h *Header, hTCP *TCPHeader, d []byte) (b []byte) {
	conn.shared.Lock()
	conn.shared.ID++

	// IP Header
	h.Version = Version
	h.Len = HeaderLen
	h.TOS = 0
	h.ID = conn.shared.ID
	h.TTL = 64
	h.Protocol = 6 // 6 means tcp
	h.Src = conn.srcAddr.IP
	h.Dst = conn.dstAddr.IP

	// TCP Header

	hTCP.SrcPort = uint16(conn.srcAddr.Port)
	hTCP.DstPort = uint16(conn.dstAddr.Port)
	hTCP.SeqNum = conn.shared.SeqNum
	if (hTCP.Ctrl & ACK) == ACK {
		hTCP.AckNum = conn.shared.SentAckNum
	} else {
		hTCP.AckNum = 0
	}
	//	hTCP.DataOffset = 5
	hTCP.Reserved = 0
	hTCP.ECN = 0
	hTCP.Window = conn.shared.Window
	hTCP.Urgent = 0

	TCPData := hTCP.Marshal()

	//full len calc
	if d != nil {
		h.TotalLen = h.Len + len(TCPData) + len(d)
		if h.TotalLen > conn.minMSS {
			h.TotalLen = conn.minMSS
		}
		conn.shared.SeqNum += uint32(h.TotalLen - (20 + len(TCPData)))
		//		binary.BigEndian.PutUint32(TCPData[4:8], conn.SeqNum)
		TCPData = append(TCPData, d...)
	} else {
		h.TotalLen = h.Len + len(TCPData)
	}
	conn.shared.Unlock()
	tcpCheckSum := Csum(TCPData, conn.srcAddr.IP, conn.dstAddr.IP)
	TCPData[16] = byte(tcpCheckSum >> 8)
	TCPData[17] = byte(tcpCheckSum & 0xff)

	b, _ = h.Marshal()
	b = append(b, TCPData...)
	//	b = append(b, d...)

	//full len calc
	//	b[2] = byte(len(b) >> 8)
	//	b[3] = byte(len(b) & 0xff)

	//Header checksum calc
	checkSum := uint32(0)
	for i := 0; i+1 < h.Len; i += 2 {
		checkSum += uint32(uint16(b[i])<<8 | uint16(b[i+1]))
	}
	if checkSum > 0xffff {
		checkSum = (checkSum >> 16) + (checkSum & 0xffff)
		if checkSum > 0xffff {
			checkSum = (checkSum >> 16) + (checkSum & 0xffff)
		}
	}
	// calculate header Checksum at the end
	b[10] = byte(^uint16(checkSum) >> 8)
	b[11] = byte(^uint16(checkSum) & 0xff)

	return b
}
