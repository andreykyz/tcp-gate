package main

/* try to without PacketHelper*/
import (
	"errors"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"

	tuntap "github.com/songgao/water"
)

type PacketHelper struct {
	iface     *tuntap.Interface
	writeChan map[[12]byte]chan []byte
	readChan  struct {
		sync.RWMutex
		m map[[12]byte]chan []byte
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
			case packet := <-packetChan:
				helper.iface.Write(packet)
			default:
				//nothink
			}
		}
	}
}
func (helper *PacketHelper) AddReadChan(c chan []byte, hash [12]byte) {
	helper.readChan.Lock()
	helper.readChan.m[hash] = c
	helper.readChan.Unlock()
}
func (helper *PacketHelper) ReadHelper() {
	for {
		select {
		case <-helper.stopHelper:
			return
		default:
			// Do other stuff
		}
		buf := make([]byte, 32*1024)

		//buf := new(bytes.Buffer)
		//		log.Debug("Interface ", helper.iface.Name(), " reading...")
		helper.iface.Read(buf)
		time.Sleep(1 * time.Second)
		//		log.Debug("Interface ", helper.iface.Name(), " just read")
		hash, _, err := getPacketHash(buf)
		if err != nil { // if packet is bad, continue
			log.Debug("Interface ", helper.iface, " read error ", err)
			continue
		}
		/*		h, _ := ParseHeader(buf)
				log.Debug("Read from ", helper.iface.Name())
				log.Debug("ReadHelper ", h)
				hTCP := ParseTCPHeader(buf[h.Len:])
				log.Debug("ReadHelper ", hTCP)
		*/
		helper.readChan.RLock()
		ch, ok := helper.readChan.m[hash]
		if !ok {
			//			log.Debug("Hash ", hash, " error ", err)
			helper.readChan.RUnlock() // if conn not found, continue
			continue
		}
		ch <- buf //[dropLen:] todo we need to once header parce
		helper.readChan.RUnlock()
		log.Debug("Read from ", helper.iface.Name(), " packet hash ", hash)

	}
}

func (helper *PacketHelper) StartHelper() {
	helper.readChan.m = make(map[[12]byte]chan []byte)
	go helper.ReadHelper()
	//	go helper.WriteHelper()
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
