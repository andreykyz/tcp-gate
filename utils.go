package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	log "github.com/Sirupsen/logrus"
)

type Supervisor struct {
	sync.Mutex
	datath   int
	dataStop int
	timeout  int
}

//
//	Following code was copied from go-any-proxy.
//
func getOriginalDst(clientConn *net.TCPConn) (ipv4 [4]byte, port uint16, newTCPConn *net.TCPConn, err error) {
	const SOOriginalDst = 80

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
		log.Errorf("GETORIGINALDST|%v->?->FAILEDTOBEDETERMINED|ERR: could not get a copy of the client connection's file object", srcipport)
		return
	} else {
		clientConn.Close()
	}

	// Get original destination
	// this is the only syscall in the Golang libs that I can find that returns 16 bytes
	// Example result: &{Multiaddr:[2 0 31 144 206 190 36 45 0 0 0 0 0 0 0 0] Interface:0}
	// port starts at the 3rd byte and is 2 bytes long (31 144 = port 8080)
	// IPv4 address starts at the 5th byte, 4 bytes long (206 190 36 45)
	addr, err := syscall.GetsockoptIPv6Mreq(int(clientConnFile.Fd()), syscall.IPPROTO_IP, SOOriginalDst)
	if err != nil {
		log.Errorf("GETORIGINALDST|%v->?->FAILEDTOBEDETERMINED|ERR: getsocketopt(SO_ORIGINAL_DST) failed: %v", srcipport, err)
		return
	}
	newConn, err := net.FileConn(clientConnFile)
	if err != nil {
		log.Errorf("GETORIGINALDST|%v->?->%v|ERR: could not create a FileConn fron clientConnFile=%+v: %v", srcipport, addr, clientConnFile, err)
		return
	}
	if _, ok := newConn.(*net.TCPConn); ok {
		newTCPConn = newConn.(*net.TCPConn)
		clientConnFile.Close()
	} else {
		errmsg := fmt.Sprintf("ERR: newConn is not a *net.TCPConn, instead it is: %T (%v)", newConn, newConn)
		log.Errorf("GETORIGINALDST|%v->?->%v|%s", srcipport, addr, errmsg)
		err = errors.New(errmsg)
		return
	}

	ipv4 = [...]byte{byte(addr.Multiaddr[4]),
		byte(addr.Multiaddr[5]),
		byte(addr.Multiaddr[6]),
		byte(addr.Multiaddr[7])}
	port = uint16(addr.Multiaddr[2])<<8 + uint16(addr.Multiaddr[3])

	return
}

func Copy(dst io.Writer, src io.Reader, supervisor *Supervisor) (written int64, err error) {

	buf := make([]byte, 32*1024)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			supervisor.Lock()
			if supervisor.datath < supervisor.dataStop {
				supervisor.datath += nw
			}
			supervisor.Unlock()
			//log.Debug("data ", nw, " ", nr, " ", supervisor.datath, "data stop ", supervisor.dataStop)

			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er == io.EOF {
			break
		}
		if er != nil {
			err = er
			break
		}
	}
	return written, err
}

func copyData(conn1 io.ReadWriter, conn2 io.ReadWriter, userInfo *UserInfo) {
	// I'm waiting on finished to be able to close
	// connection correctly.
	finished := make(chan bool, 2)
	var supervisor *Supervisor
	if userInfo != nil {
		supervisor = &Supervisor{datath: 0, timeout: 0, dataStop: userInfo.Datath}
	}
	go func() {
		//	if userInfo == nil {
		io.Copy(conn1, conn2)
		//	} else {
		//		Copy(conn1, conn2, supervisor)
		//	}
		finished <- true
	}()

	go func() {
		//	if userInfo == nil {
		io.Copy(conn2, conn1)
		//	} else {
		//		Copy(conn2, conn1, supervisor)
		//	}
		finished <- true
	}()
	<-finished
	return
	if userInfo != nil {
		if userInfo.Timeout > 0 && userInfo.Datath > 0 {
			for {
				//log.Debug("time ", supervisor.timeout, " time limit ", userInfo.Timeout, " data ", supervisor.datath, " data min ", userInfo.Datath)
				supervisor.Lock()
				if supervisor.timeout > userInfo.Timeout {
					if supervisor.datath < userInfo.Datath {
						return
					} else {
						supervisor.datath = 0
						supervisor.timeout = 0
					}
				}
				supervisor.Unlock()
				select {
				case <-finished:
					return
				default:
					time.Sleep(1 * time.Second)
					supervisor.timeout++
					continue
				}
			}
		}
	}
	<-finished
}
