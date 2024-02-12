package networkio

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/vpntest"
)

type testTCPConn struct {
	conn    *vpntest.Conn
	dataIn  [][]byte
	dataOut [][]byte
}

func newTestTCPDialer(underlying *testTCPConn) *vpntest.Dialer {
	dialer := &vpntest.Dialer{
		MockDialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return underlying.conn, nil
		},
	}
	return dialer
}

func Test_TCPLikeConn(t *testing.T) {
	t.Run("A tcp-like conn implements the openvpn framing", func(t *testing.T) {
		dataIn := make([][]byte, 0)
		dataOut := make([][]byte, 0)

		underlying := &testTCPConn{
			conn: &vpntest.Conn{
				MockLocalAddr: func() net.Addr {
					addr := &vpntest.Addr{
						MockString:  func() string { return "1.2.3.4" },
						MockNetwork: func() string { return "tcp" },
					}
					return addr
				},
				MockRead: func(b []byte) (int, error) {
					if len(dataOut) > 0 {
						data := dataOut[0]
						copy(b[:len(data)], data)
						return len(data), nil
					}
					return 0, errors.New("EOF")
				},
				MockWrite: func(b []byte) (int, error) {
					dataIn = append(dataIn, b)
					return len(b), nil
				},
			},
			dataIn:  dataIn,
			dataOut: dataOut,
		}
		want := []byte("deadbeef")
		dataOut = append(dataOut, want)

		testDialer := newTestTCPDialer(underlying)
		dialer := NewDialer(log.Log, testDialer)
		framingConn, err := dialer.DialContext(context.Background(), "udp", "1.1.1.1")
		if err != nil {
			t.Errorf("should not error")
		}
		if err := framingConn.WriteRawPacket([]byte{0, 0, 0, 0}); err != nil {
			t.Errorf("should not error: err = %v", err)
		}
		got, err := framingConn.ReadRawPacket()
		if err != nil {
			t.Errorf("should not error: err = %v", err)
		}
		fmt.Println("got", got)
		/*
			if !bytes.Equal(got, want) {
				t.Errorf("got = %v, want = %v", got, want)
			}
		*/

	})
}
