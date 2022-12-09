// obfs4 connection wrappers

//
// SPDX-License-Identifier: MIT
// (c) 2015-2022 rhui zheng
// (c) 2015-2022 ginuerzh and gost contributors
// (c) 2022 Ain Ghazal

// Code in this package is derived from:
// https://github.com/ginuerzh/gost
//
// These convenience functions might be removed in the future in favor of reusing
// OONI's probe_cli/internal/ptx/obfs4.go dialers. For the time being I'm exploring
// the utility of providing adaptors for other gost transports.

package obfs4

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"

	pt "git.torproject.org/pluggable-transports/goptlib.git"

	"gitlab.com/yawning/obfs4.git/transports/base"
	"gitlab.com/yawning/obfs4.git/transports/obfs4"
	"golang.org/x/net/proxy"
)

var (
	// this error can be caused for the backward-compat upgrade >= 0.0.14, if the endpoints were not updated
	InvalidAuthError = errors.New("handshake: ntor auth mismatch")
)

type DialFunc func(string, string) (net.Conn, error)

type ObfuscationDialer struct {
	node ProxyNode
	// If UnderlyingDialer is set, it will be passed to the pluggable transport.
	UnderlyingDialer DialFunc
}

func NewDialer(node ProxyNode) *ObfuscationDialer {
	return &ObfuscationDialer{node, nil}
}

func (d *ObfuscationDialer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	cd, err := d.newCancellableDialer()
	if err != nil {
		return nil, err
	}
	return cd.dial(ctx, network, address)
}

func (d *ObfuscationDialer) newCancellableDialer() (*obfs4CancellableDialer, error) {
	return &obfs4CancellableDialer{
		done:             make(chan interface{}),
		node:             d.node,
		underlyingDialer: d.UnderlyingDialer,
	}, nil
}

type obfs4CancellableDialer struct {
	done             chan interface{}
	node             ProxyNode
	underlyingDialer DialFunc
}

// taken from ooni/probe_cli/internal/ptx/obfs4.go
func (ocd *obfs4CancellableDialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	connch, errch := make(chan net.Conn), make(chan error, 1)

	go func() {
		defer close(ocd.done) // signal we're joining
		dialFn := obfs4Dialer(ocd.node.Addr, ocd.underlyingDialer)
		conn, err := dialFn(network, address)
		var ntorErr *obfs4.InvalidAuthError
		if errors.As(err, &ntorErr) {
			log.Println("error (minivpn-obfs4):", err)
			errch <- InvalidAuthError
			return
		}
		if err != nil {
			errch <- err // buffered channel
			return
		}
		select {
		case connch <- conn:
		default:
			conn.Close() // context won the race
		}
	}()

	select {
	case err := <-errch:
		return nil, err
	case conn := <-connch:
		return conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// The server certificate given to the client is in the following format:
// obfs4://server_ip:443?cert=4UbQjIfjJEQHPOs8vs5sagrSXx1gfrDCGdVh2hpIPSKH0nklv1e4f29r7jb91VIrq4q5Jw&iat-mode=0'
// be sure to urlencode the certificate you obtain from obfs4proxy or other software.

type obfs4Context struct {
	cf    base.ClientFactory
	cargs interface{} // type obfs4ClientArgs
}

var obfs4Map = make(map[string]obfs4Context)

// Init initializes the obfs4 client
func Init(node ProxyNode) error {
	if _, ok := obfs4Map[node.Addr]; ok {
		return fmt.Errorf("obfs4 context already initialized")
	}

	t := new(obfs4.Transport)

	stateDir := node.Values.Get("state-dir")
	if stateDir == "" {
		stateDir = "."
	}

	ptArgs := pt.Args(node.Values)

	// we're only dealing with the client side here, we assume
	// server side is running obfs4proxy or the likes. in the future it would perhaps be
	// nice to support other obfs4-based transporters as gost is doing.
	cf, err := t.ClientFactory(stateDir)
	if err != nil {
		log.Println("obfs4: error on clientFactory")
		return err
	}

	cargs, err := cf.ParseArgs(&ptArgs)
	if err != nil {
		log.Println("error on parseArgs:", err.Error())
		return err
	}

	obfs4Map[node.Addr] = obfs4Context{cf: cf, cargs: cargs}
	return nil
}

// obfsDialer returns a DialFunc for a given nodeAddr
func obfs4Dialer(nodeAddr string, dial DialFunc) DialFunc {
	oc := obfs4Map[nodeAddr]
	// From the documentation of the ClientFactory interface:
	// https://github.com/Yawning/obfs4/blob/master/transports/base/base.go#L42
	// Dial creates an outbound net.Conn, and does whatever is required
	// (eg: handshaking) to get the connection to the point where it is
	// ready to relay data.
	// Dial(network, address string, dialFn DialFunc, args interface{}) (net.Conn, error)
	if dial == nil {
		dial = proxy.Direct.Dial
	}
	return func(network, address string) (net.Conn, error) {
		return oc.cf.Dial(network, nodeAddr, base.DialFunc(dial), oc.cargs)
	}
}
