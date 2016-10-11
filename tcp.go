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
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
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
	TCPOPT_NOP       = 1   // Padding */
	TCPOPT_EOL       = 0   // End of options */
	TCPOPT_MSS       = 2   // Segment size negotiating */
	TCPOPT_WINDOW    = 3   // Window scaling */
	TCPOPT_SACK_PERM = 4   // SACK Permitted */
	TCPOPT_SACK      = 5   // SACK Block */
	TCPOPT_TIMESTAMP = 8   // Better RTT estimations/PAWS */
	TCPOPT_MD5SIG    = 19  // MD5 Signature (RFC2385) */
	TCPOPT_MPTCP     = 30  //
	TCPOPT_FASTOPEN  = 34  // Fast open (RFC7413) */
	TCPOPT_EXP       = 254 // Experimental */
)

/* Magic number to be after the option value for sharing TCP
 * experimental options. See draft-ietf-tcpm-experimental-options-00.txt
 */
const (
	TCPOPT_FASTOPEN_MAGIC = 0xF989
)

type TCPHeader struct {
	Source      uint16
	Destination uint16
	SeqNum      uint32
	AckNum      uint32
	DataOffset  uint8 // 4 bits
	Reserved    uint8 // 3 bits
	ECN         uint8 // 3 bits
	Ctrl        uint8 // 6 bits
	Window      uint16
	Checksum    uint16 // Kernel will set this if it's 0
	Urgent      uint16
	Options     []TCPOption
}

type TCPOption struct {
	Kind   uint8
	Length uint8
	Data   []byte
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

func (tcp *TCPHeader) HasFlag(flagBit byte) bool {
	return tcp.Ctrl&flagBit != 0
}

func (tcp *TCPHeader) Marshal() []byte {

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, tcp.Source)
	binary.Write(buf, binary.BigEndian, tcp.Destination)
	binary.Write(buf, binary.BigEndian, tcp.SeqNum)
	binary.Write(buf, binary.BigEndian, tcp.AckNum)

	var mix uint16
	mix = uint16(tcp.DataOffset)<<12 | // top 4 bits
		uint16(tcp.Reserved)<<9 | // 3 bits
		uint16(tcp.ECN)<<6 | // 3 bits
		uint16(tcp.Ctrl) // bottom 6 bits
	binary.Write(buf, binary.BigEndian, mix)

	binary.Write(buf, binary.BigEndian, tcp.Window)
	binary.Write(buf, binary.BigEndian, tcp.Checksum)
	binary.Write(buf, binary.BigEndian, tcp.Urgent)

	for _, option := range tcp.Options {
		binary.Write(buf, binary.BigEndian, option.Kind)
		if option.Length > 1 {
			binary.Write(buf, binary.BigEndian, option.Length)
			binary.Write(buf, binary.BigEndian, option.Data)
		}
	}

	out := buf.Bytes()

	// Pad to min tcp header size, which is 20 bytes (5 32-bit words)
	pad := 20 - len(out)
	for i := 0; i < pad; i++ {
		out = append(out, 0)
	}

	return out
}

// TCP Checksum
func Csum(data []byte, srcip, dstip net.IP) uint16 {

	pseudoHeader := []byte{
		srcip[0], srcip[1], srcip[2], srcip[3],
		dstip[0], dstip[1], dstip[2], dstip[3],
		0,                  // zero
		6,                  // protocol number (6 == TCP)
		0, byte(len(data)), // TCP length (16 bits), not inc pseudo header
	}

	sumThis := make([]byte, 0, len(pseudoHeader)+len(data))
	sumThis = append(sumThis, pseudoHeader...)
	sumThis = append(sumThis, data...)
	//fmt.Printf("% x\n", sumThis)

	lenSumThis := len(sumThis)
	var nextWord uint16
	var sum uint32
	for i := 0; i+1 < lenSumThis; i += 2 {
		nextWord = uint16(sumThis[i])<<8 | uint16(sumThis[i+1])
		sum += uint32(nextWord)
	}
	if lenSumThis%2 != 0 {
		//fmt.Println("Odd byte")
		sum += uint32(sumThis[len(sumThis)-1])
	}

	// Add back any carry, and any carry from adding the carry
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)

	// Bitwise complement
	return uint16(^sum)
}

func to4byte(addr string) [4]byte {
	parts := strings.Split(addr, ".")
	b0, err := strconv.Atoi(parts[0])
	if err != nil {
		log.Fatalf("to4byte: %s (latency works with IPv4 addresses only, but not IPv6!)\n", err)
	}
	b1, _ := strconv.Atoi(parts[1])
	b2, _ := strconv.Atoi(parts[2])
	b3, _ := strconv.Atoi(parts[3])
	return [4]byte{byte(b0), byte(b1), byte(b2), byte(b3)}
}

func sendTcpSyn(src net.IP, dst net.IP, port uint16) []byte {

	tcpHeader := TCPHeader{
		Source:      1001, // Random ephemeral port
		Destination: port,
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
	tcpHeader.Checksum = Csum(data, src, dst)
	data = tcpHeader.Marshal()

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
		Src:      src,
		Dst:      dst,
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
	return data
}
