package main

import (
	//	"encoding/binary"
	"errors"
	//	log "github.com/Sirupsen/logrus"
	"net"
	"time"
)

//RFC 6824
const (
	MPCapable   = 0x0 // Multipath Capable
	MPJoin      = 0x1 // Join Connection
	DSS         = 0x2 // Data Sequence Signal like tcp ACK (Data ACK and data sequence mapping)
	AddAddr     = 0x3 // Add Address
	RemoveAddr  = 0x4 // Remove Address
	MPPrio      = 0x5 // Change Subflow Priority
	MPFail      = 0x6 // Fallback
	MPFastclose = 0x7 // Fast Close
)

func DialTCP(network string, laddr, raddr *net.TCPAddr) (*net.TCPConn, error) {
	switch network {
	case "tcp", "tcp4":
	case "tcp6":
		return nil, errors.New("tcp6 not supported yet")
	default:
		return nil, errors.New("Unknown Network, allow only tcp, tcp4")
	}
	if raddr == nil {
		return nil, errors.New("Missing address")
	}

	return dialTCP(network, laddr, raddr, time.Time{})

}

func dialTCP(network string, laddr, raddr *net.TCPAddr, deadline time.Time) (*net.TCPConn, error) {
	return nil, nil
}
