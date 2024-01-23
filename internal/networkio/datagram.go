package networkio

import (
	"fmt"
	"math"
	"net"

	"golang.org/x/net/ipv4"
)

// datagramConn wraps a datagram socket and implements OpenVPN framing.
type datagramConn struct {
	net.Conn
	pc *ipv4.PacketConn
}

var _ FramingConn = &datagramConn{}

// ReadRawPacket implements FramingConn
func (c *datagramConn) ReadRawPacket() ([]byte, error) {
	buffer := make([]byte, math.MaxUint16) // maximum UDP datagram size
	count, err := c.Read(buffer)
	if err != nil {
		return nil, err
	}
	pkt := buffer[:count]
	return pkt, nil
}

func (c *datagramConn) ReadRawPackets() ([][]byte, error) {
	size := 10
	msgs := make([]ipv4.Message, size)
	for i := 0; i < size; i++ {
		msgs[i] = ipv4.Message{
			Buffers: [][]byte{make([]byte, 4096)},
		}
	}

	cnt, err := c.pc.ReadBatch(msgs, 0)
	if err != nil {
		return nil, err
	}

	pkts := make([][]byte, cnt)
	for i := 0; i < cnt; i++ {
		msg := msgs[i]
		if msg.N == 0 || msg.Buffers[0] == nil {
			continue
		}
		pkts = append(pkts, msg.Buffers[0][:msg.N])
	}
	return pkts, nil
}

// WriteRawPacket implements FramingConn
func (c *datagramConn) WriteRawPacket(pkt []byte) error {
	if len(pkt) > math.MaxUint16 {
		return ErrPacketTooLarge
	}
	_, err := c.Conn.Write(pkt)
	return err
}

func (c *datagramConn) WriteRawPackets(pkts [][]byte) error {
	msgs := make([]ipv4.Message, len(pkts))

	for _, m := range pkts {
		msg := ipv4.Message{
			Buffers: [][]byte{m},
			Addr:    c.RemoteAddr(),
		}
		msgs = append(msgs, msg)
	}

	_, err := c.pc.WriteBatch(msgs, 0)
	if err != nil {
		fmt.Println(err.Error())
	}
	return err
}
