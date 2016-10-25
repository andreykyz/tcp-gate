package main

/* try to without PacketHelper*/
import (
	"bytes"

	tuntap "github.com/songgao/water"
)

type PacketHelper struct {
	iface      *tuntap.Interface
	writeChan  []*chan []byte
	readChan   []*chan []byte
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

		buf := new(bytes.Buffer)
		buf.ReadFrom(helper.iface)

		select {
		case <-helper.stopHelper:
			return
		default:
			// Do other stuff
		}
	}
}

func (helper *PacketHelper) StartHelper() {
	go helper.ReadHelper()
	go helper.WriteHelper()
}

func (helper *PacketHelper) StopHelper() {
	helper.stopHelper <- true
}
