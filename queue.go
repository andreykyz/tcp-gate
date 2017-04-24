package main

type ParcedPacket struct {
	ipHeader  Header
	tcpHeader TCPHeader
	data      []byte
}

/*
PacketQ is a packet queue fo sequentially data flushing
nextPacketKey = seqNum + len
*/
type PacketQ struct {
	in            chan *ParcedPacket
	out           chan []byte
	done          chan bool
	queue         map[uint32]*ParcedPacket // map key is packet seqNum
	minNextSeqNum uint32                   //is a minimal next seq num seqNum + len. SeqNum wait for
}

func newPacketQ() (packetQ *PacketQ) {

	packetQ = &PacketQ{}
	packetQ.in = make(chan *ParcedPacket, 100)
	packetQ.out = make(chan []byte, 100)
	go packetQ.QueueListener()
	return packetQ
}

func (packetQ *PacketQ) QueueListener() {
	for {
		exit := false
		select {
		case <-packetQ.done:
			exit = true
			break
		case packet := <-packetQ.in:
			if packet.tcpHeader.SeqNum == packetQ.minNextSeqNum {
				if len(packet.data) > 0 {
					packetQ.out <- packet.data
				}
				packetQ.minNextSeqNum = packet.tcpHeader.SeqNum + uint32(len(packet.data))
			} else {
				packetQ.queue[packet.tcpHeader.SeqNum] = packet
			}

			for {
				ok := true
				if packet, ok = packetQ.queue[packetQ.minNextSeqNum]; !ok {
					break
				}
				if len(packet.data) > 0 {
					packetQ.out <- packet.data
				}
				packetQ.minNextSeqNum = packet.tcpHeader.SeqNum + uint32(len(packet.data))
				delete(packetQ.queue, packetQ.minNextSeqNum)
			}
		}
		if exit {
			break
		}
	}
}

func (packetQ *PacketQ) addPacket(packet *ParcedPacket) {
	packetQ.in <- packet
}
