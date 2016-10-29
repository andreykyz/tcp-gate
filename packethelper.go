package main

/* try to without PacketHelper*/
import (
	"bytes"
	"errors"
	"sync"

	tuntap "github.com/songgao/water"
)

type PacketHelper struct {
	iface     *tuntap.Interface
	writeChan map[[12]byte]*chan []byte
	readChan  struct {
		sync.RWMutex
		m map[[12]byte]*chan []byte
	}
	stopHelper chan bool
}

func (helper *PacketHelper) WriteHelper() {
	for _, packetChan := range helper.writeChan {
		select {
		case <-helper.stopHelper:
			return
		default:
			select {
			case packet := <-(*packetChan):
				helper.iface.Write(packet)
			default:
				//nothink
			}
		}
	}
}

func (helper *PacketHelper) ReadHelper() {
	for {
		select {
		case <-helper.stopHelper:
			return
		default:
			// Do other stuff
		}

		buf := new(bytes.Buffer)
		buf.ReadFrom(helper.iface)
		hash, dropLen, err := getPacketHash(buf.Bytes())
		if err != nil {
			continue
		}
		helper.readChan.RLock()
		ch, ok := helper.readChan.m[hash]
		if !ok {
			helper.readChan.Unlock()
			continue
		}
		*ch <- buf.Bytes()[dropLen:]
		helper.readChan.Unlock()

	}
}

func (helper *PacketHelper) StartHelper() {
	go helper.ReadHelper()
	go helper.WriteHelper()
}

func (helper *PacketHelper) StopHelper() {
	helper.stopHelper <- true
}

func getPacketHash(buf []byte) (hash [12]byte, dropLen int, err error) {
	if (buf[0] >> 4) != 4 {
		return hash, dropLen, errors.New("Packet is not IPv4")
	}
	if buf[9] != 6 { // 6 means tcp
		return hash, dropLen, errors.New("Protocol is not TCP")
	}

	IPHeaderLen := int(buf[0] & 0x0f)
	if IPHeaderLen == 5 {
		copy(hash[0:12], buf[12:24])
		return hash, 24, nil
	}

	IPHeaderLen = IPHeaderLen << 2
	copy(hash[0:8], buf[12:20])
	copy(hash[8:12], buf[IPHeaderLen:IPHeaderLen+4])

	return hash, IPHeaderLen + 4, nil
}
