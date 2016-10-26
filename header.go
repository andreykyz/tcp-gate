// Copyright 2012 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"syscall"
)

// IP header const
const (
	Version      = 4  // Version of protocol
	HeaderLen    = 20 // header length without extension headers
	maxHeaderLen = 60 // sensible default, revisit if later RFCs define new usage of version and header length fields
)

var (
	errMissingAddress           = errors.New("missing address")
	errMissingHeader            = errors.New("missing header")
	errHeaderTooShort           = errors.New("header too short")
	errBufferTooShort           = errors.New("buffer too short")
	errInvalidConnType          = errors.New("invalid conn type")
	errOpNoSupport              = errors.New("operation not supported")
	errNoSuchInterface          = errors.New("no such interface")
	errNoSuchMulticastInterface = errors.New("no such multicast interface")

	// See http://www.freebsd.org/doc/en/books/porters-handbook/freebsd-versions.html.
	freebsdVersion uint32

	nativeEndian binary.ByteOrder
)

// HeaderFlags is const for header flag field see below
type HeaderFlags int

// const of HeaderFlags
const (
	MoreFragments HeaderFlags = 1 << iota // more fragments flag
	DontFragment                          // don't fragment flag
)

// A Header represents an IPv4 header.
type Header struct {
	Version  int         // protocol version
	Len      int         // header length
	TOS      int         // type-of-service
	TotalLen int         // packet total length
	ID       int         // identification
	Flags    HeaderFlags // flags
	FragOff  int         // fragment offset
	TTL      int         // time-to-live
	Protocol int         // next protocol
	Checksum uint16      // checksum
	Src      net.IP      // source address
	Dst      net.IP      // destination address
	Options  []byte      // options, extension headers
}

// TCPHeader is struct for Marshal or UnMarshal header
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
	Checksum    uint16 // Kernel will set this if it's 0 but not in our situation
	Urgent      uint16
	Options     []TCPOption
}

// TCPOption is sequence which is end of TCPHeader
type TCPOption struct {
	Kind   uint8
	Length uint8
	Data   []byte
}

func (h *Header) String() string {
	if h == nil {
		return "<nil>"
	}
	return fmt.Sprintf("ver=%d hdrlen=%d tos=%#x totallen=%d id=%#x flags=%#x fragoff=%#x ttl=%d proto=%d cksum=%#x src=%v dst=%v", h.Version, h.Len, h.TOS, h.TotalLen, h.ID, h.Flags, h.FragOff, h.TTL, h.Protocol, h.Checksum, h.Src, h.Dst)
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

// Csum is calculate TCP Checksum
func Csum(data []byte, srcip, dstip net.IP) uint16 {

	pseudoHeader := []byte{
		srcip.To4()[0], srcip.To4()[1], srcip.To4()[2], srcip.To4()[3],
		dstip.To4()[0], dstip.To4()[1], dstip.To4()[2], dstip.To4()[3],
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

// Marshal returns the binary encoding of the IPv4 header h.
func (h *Header) Marshal() ([]byte, error) {
	if h == nil {
		return nil, syscall.EINVAL
	}
	if h.Len < HeaderLen {
		return nil, errHeaderTooShort
	}
	hdrlen := HeaderLen + len(h.Options)
	b := make([]byte, hdrlen)
	b[0] = byte(Version<<4 | (hdrlen >> 2 & 0x0f))
	b[1] = byte(h.TOS)
	flagsAndFragOff := (h.FragOff & 0x1fff) | int(h.Flags<<13)

	binary.BigEndian.PutUint16(b[2:4], uint16(h.TotalLen))
	binary.BigEndian.PutUint16(b[6:8], uint16(flagsAndFragOff))

	binary.BigEndian.PutUint16(b[4:6], uint16(h.ID))
	b[8] = byte(h.TTL)
	b[9] = byte(h.Protocol)
	binary.BigEndian.PutUint16(b[10:12], h.Checksum)
	if ip := h.Src.To4(); ip != nil {
		copy(b[12:16], ip[:net.IPv4len])
	}
	if ip := h.Dst.To4(); ip != nil {
		copy(b[16:20], ip[:net.IPv4len])
	} else {
		return nil, errMissingAddress
	}
	if len(h.Options) > 0 {
		copy(b[HeaderLen:], h.Options)
	}
	return b, nil
}

// ParseHeader parses b as an IPv4 header.
func ParseHeader(b []byte) (*Header, error) {
	if len(b) < HeaderLen {
		return nil, errHeaderTooShort
	}
	hdrlen := int(b[0]&0x0f) << 2
	if hdrlen > len(b) {
		return nil, errBufferTooShort
	}
	h := &Header{
		Version:  int(b[0] >> 4),
		Len:      hdrlen,
		TOS:      int(b[1]),
		ID:       int(binary.BigEndian.Uint16(b[4:6])),
		TTL:      int(b[8]),
		Protocol: int(b[9]),
		Checksum: uint16(binary.BigEndian.Uint16(b[10:12])),
		Src:      net.IPv4(b[12], b[13], b[14], b[15]),
		Dst:      net.IPv4(b[16], b[17], b[18], b[19]),
	}

	h.TotalLen = int(binary.BigEndian.Uint16(b[2:4]))
	h.FragOff = int(binary.BigEndian.Uint16(b[6:8]))

	h.Flags = HeaderFlags(h.FragOff&0xe000) >> 13
	h.FragOff = h.FragOff & 0x1fff
	if hdrlen-HeaderLen > 0 {
		h.Options = make([]byte, hdrlen-HeaderLen)
		copy(h.Options, b[HeaderLen:])
	}
	return h, nil
}
