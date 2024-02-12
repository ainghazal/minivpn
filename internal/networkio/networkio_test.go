package networkio

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/vpntest"
)

type mockedConn struct {
	conn    *vpntest.Conn
	dataIn  [][]byte
	dataOut [][]byte
}

func (mc *mockedConn) DataIn() [][]byte {
	return mc.dataIn
}

func newDialer(underlying *mockedConn) *vpntest.Dialer {
	dialer := &vpntest.Dialer{
		MockDialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return underlying.conn, nil
		},
	}
	return dialer
}

func newMockedConn(network string, dataIn, dataOut [][]byte) *mockedConn {
	conn := &mockedConn{
		dataIn:  dataIn,
		dataOut: dataOut,
	}
	conn.conn = &vpntest.Conn{
		MockLocalAddr: func() net.Addr {
			addr := &vpntest.Addr{
				MockString:  func() string { return "1.2.3.4" },
				MockNetwork: func() string { return network },
			}
			return addr
		},
		MockRead: func(b []byte) (int, error) {
			if len(conn.dataOut) > 0 {
				copy(b[:], conn.dataOut[0])
				ln := len(conn.dataOut[0])
				conn.dataOut = conn.dataOut[1:]
				return ln, nil
			}
			return 0, errors.New("EOF")
		},
		MockWrite: func(b []byte) (int, error) {
			conn.dataIn = append(conn.dataIn, b)
			return len(b), nil
		},
	}
	return conn
}

func Test_TCPLikeConn(t *testing.T) {
	t.Run("A tcp-like conn implements the openvpn framing", func(t *testing.T) {
		dataIn := make([][]byte, 0)
		dataOut := make([][]byte, 0)
		// write size
		dataOut = append(dataOut, []byte{0, 8})
		// write payload
		want := []byte("deadbeef")
		dataOut = append(dataOut, want)

		underlying := newMockedConn("tcp", dataIn, dataOut)
		testDialer := newDialer(underlying)
		dialer := NewDialer(log.Log, testDialer)
		framingConn, err := dialer.DialContext(context.Background(), "tcp", "1.1.1.1")

		if err != nil {
			t.Errorf("should not error getting a framingConn")
		}
		got, err := framingConn.ReadRawPacket()
		if err != nil {
			t.Errorf("should not error: err = %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("got = %v, want = %v", got, want)
		}

		written := []byte("ingirumimusnocteetconsumimurigni")
		framingConn.WriteRawPacket(written)
		gotWritten := underlying.DataIn()
		if !bytes.Equal(gotWritten[0], append([]byte{0, byte(len(written))}, written...)) {
			t.Errorf("got = %v, want = %v", gotWritten, written)
		}
	})
}

func Test_UDPLikeConn(t *testing.T) {
	t.Run("A udp-like conn returns the packets directly", func(t *testing.T) {
		dataIn := make([][]byte, 0)
		dataOut := make([][]byte, 0)
		// write payload
		want := []byte("deadbeef")
		dataOut = append(dataOut, want)

		underlying := newMockedConn("udp", dataIn, dataOut)
		testDialer := newDialer(underlying)
		dialer := NewDialer(log.Log, testDialer)
		framingConn, err := dialer.DialContext(context.Background(), "tcp", "1.1.1.1")
		if err != nil {
			t.Errorf("should not error getting a framingConn")
		}
		got, err := framingConn.ReadRawPacket()
		if err != nil {
			t.Errorf("should not error: err = %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("got = %v, want = %v", got, want)
		}
		written := []byte("ingirumimusnocteetconsumimurigni")
		framingConn.WriteRawPacket(written)
		gotWritten := underlying.DataIn()
		if !bytes.Equal(gotWritten[0], written) {
			t.Errorf("got = %v, want = %v", gotWritten, written)
		}
	})
}
