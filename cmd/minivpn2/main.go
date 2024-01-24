package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"

	"github.com/Doridian/water"
	"github.com/apex/log"
	"github.com/jackpal/gateway"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/networkio"
	"github.com/ooni/minivpn/internal/tun"
)

func runCmd(binaryPath string, args ...string) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	err := cmd.Run()
	if nil != err {
		log.WithError(err).Warn("error running /sbin/ip")
	}
}

func runIP(args ...string) {
	runCmd("/sbin/ip", args...)
}

func runRoute(args ...string) {
	runCmd("/sbin/route", args...)
}

/*
func logWithElapsedTime(logger log.Interface, message string, start time.Time) {
	elapsedTime := time.Since(startTime).Round(time.Millisecond)
	logger.WithField("elapsed_time", elapsedTime).Info(message)
}
*/

func main() {
	log.SetLevel(log.DebugLevel)

	// parse the configuration file
	options, err := model.ReadConfigFile(os.Args[1])
	if err != nil {
		log.WithError(err).Fatal("NewOptionsFromFilePath")
	}
	log.Infof("parsed options: %s", options.ServerOptionsString())

	// TODO(ainghazal): move the initialization step to an early phase and keep a ref in the muxer
	if !options.HasAuthInfo() {
		log.Fatal("options are missing auth info")
	}

	log.SetHandler(NewHandler(os.Stderr))
	log.SetLevel(log.DebugLevel)

	// connect to the server
	dialer := networkio.NewDialer(log.Log, &net.Dialer{})
	ctx := context.Background()

	endpoint := net.JoinHostPort(options.Remote, options.Port)

	conn, err := dialer.DialContext(ctx, options.Proto.String(), endpoint)
	if err != nil {
		log.WithError(err).Fatal("dialer.DialContext")
	}

	// The TLS will expire in 60 seconds by default, but we can pass
	// a shorter timeout.
	//ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	//defer cancel()

	// create a vpn tun Device
	tunnel, err := tun.StartTUN(ctx, conn, options, log.Log)
	if err != nil {
		log.WithError(err).Fatal("init error")
		return
	}
	fmt.Printf("Local IP: %s\n", tunnel.LocalAddr())
	fmt.Printf("Gateway:  %s\n", tunnel.RemoteAddr())

	// create a tun interface on the OS
	iface, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		log.WithError(err).Fatal("Unable to allocate TUN interface:")
	}

	// TODO: investigate what's the maximum working MTU, additionally get it from flag.
	MTU := 1420
	iface.SetMTU(MTU)

	localAddr := tunnel.LocalAddr().String()
	remoteAddr := tunnel.RemoteAddr().String()
	netMask := tunnel.NetMask()

	// discover local gateway IP, we need it to add a route to our remote via our network gw
	defaultGatewayIP, err := gateway.DiscoverGateway()
	if err != nil {
		log.Warn("could not discover default gateway IP, routes might be broken")
	}
	defaultInterfaceIP, err := gateway.DiscoverInterface()
	if err != nil {
		log.Warn("could not discover default route interface IP, routes might be broken")
	}
	defaultInterface, err := getInterfaceByIP(defaultInterfaceIP.String())
	if err != nil {
		log.Warn("could not get default route interface, routes might be broken")
	}

	if defaultGatewayIP != nil && defaultInterface != nil {
		log.Infof("route add %s gw %v dev %s", options.Remote, defaultGatewayIP, defaultInterface.Name)
		runRoute("add", options.Remote, "gw", defaultGatewayIP.String(), defaultInterface.Name)
	}

	// we want the network CIDR for setting up the routes
	network := &net.IPNet{
		IP:   net.ParseIP(localAddr).Mask(netMask),
		Mask: netMask,
	}

	// configure the interface and bring it up
	runIP("addr", "add", localAddr, "dev", iface.Name())
	runIP("link", "set", "dev", iface.Name(), "up")
	runRoute("add", remoteAddr, "gw", localAddr)
	runRoute("add", "-net", network.String(), "dev", iface.Name())
	runIP("route", "add", "default", "via", remoteAddr, "dev", iface.Name())

	go func() {
		for {
			packet := make([]byte, 2000)
			n, err := iface.Read(packet)
			if err != nil {
				log.WithError(err).Fatal("error reading from tun")
			}
			tunnel.Write(packet[:n])
		}
	}()
	go func() {
		for {
			packet := make([]byte, 2000)
			n, err := tunnel.Read(packet)
			if err != nil {
				log.WithError(err).Fatal("error reading from tun")
			}
			iface.Write(packet[:n])
		}
	}()
	select {}
}
