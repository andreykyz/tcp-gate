package main

type ParcedPacket struct {
	ipHeader  Header
	tcpHeader TCPHeader
	data      []byte
}

type PacketQ struct {
	in    chan ParcedPacket
	out   chan []byte
	queue map[int32]*ParcedPacket
}

func newPacketQ() (packetQ *PacketQ) {

	packetQ = &PacketQ{}
	packetQ.in = make(chan ParcedPacket, 100)
	packetQ.out = make(chan []byte, 100)

	return packetQ
}

func (packetQ *PacketQ) Listener {

}