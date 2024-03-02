package networkio

import (
	"bytes"
	"context"
	"testing"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/runtimex"
	"github.com/ooni/minivpn/internal/workers"
	"github.com/ooni/minivpn/pkg/config"
)

// test that we can initialize, start and stop the networkio workers.
func TestService_StartStopWorkers(t *testing.T) {
	if testing.Verbose() {
		log.SetLevel(log.DebugLevel)
	}
	workersManager := workers.NewManager(log.Log)

	wantToRead := []byte("deadbeef")

	dataIn := make([][]byte, 0)

	// out is out of the network (i.e., incoming data, reads)
	dataOut := make([][]byte, 0)
	dataOut = append(dataOut, wantToRead)

	underlying := newMockedConn("udp", dataIn, dataOut)
	testDialer := newDialer(underlying)
	dialer := NewDialer(log.Log, testDialer)

	framingConn, err := dialer.DialContext(context.Background(), "udp", "1.1.1.1")
	runtimex.PanicOnError(err, "should not error on getting new context")

	muxerToNetwork := make(chan []byte, 1024)
	networkToMuxer := make(chan []byte, 1024)
	muxerToNetwork <- []byte("AABBCCDD")

	s := Service{
		MuxerToNetwork: muxerToNetwork,
		NetworkToMuxer: &networkToMuxer,
	}

	cfg, _ := config.NewConfig(config.WithLogger(log.Log))
	s.StartWorkers(cfg, workersManager, framingConn)
	got := <-networkToMuxer

	workersManager.StartShutdown()
	workersManager.WaitWorkersShutdown()

	if !bytes.Equal(got, wantToRead) {
		t.Errorf("expected word %s in networkToMuxer, got %s", wantToRead, got)
	}

	networkWrites := underlying.NetworkWrites()
	if len(networkWrites) == 0 {
		t.Errorf("expected network writes")
		return
	}
	if !bytes.Equal(networkWrites[0], []byte("AABBCCDD")) {
		t.Errorf("network writes do not match")
	}
}
