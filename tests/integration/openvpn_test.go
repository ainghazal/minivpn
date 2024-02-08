// build: +integration
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/apex/log"
	"github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"

	"github.com/ooni/minivpn/extras/ping"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/networkio"
	"github.com/ooni/minivpn/internal/tun"
)

const (
	dockerImage = "ainghazal/openvpn"
	dockerTag   = "latest"
)

var (
	target = "172.17.0.1"
	count  = 3
)

func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	dstFile := filepath.Join(dst, src)
	err = os.WriteFile(dstFile, input, 0744)
	if err != nil {
		fmt.Println("Error creating", dstFile)
		return err
	}
	return nil
}

func launchDocker(cipher, auth string) ([]byte, *dockertest.Pool, *dockertest.Resource, error) {
	pool, err := dockertest.NewPool("")
	if err != nil {
		log.Fatalf("Could not connect to docker: %s", err)
	}

	options := &dockertest.RunOptions{
		Repository: dockerImage,
		Tag:        dockerTag,
		PortBindings: map[dc.Port][]dc.PortBinding{
			"1194/udp": {{HostPort: "1194"}},
			"8080/tcp": {{HostPort: "8080"}},
		},
		Env:    []string{"OPENVPN_CIPHER=" + cipher, "OPENVPN_AUTH=" + auth},
		CapAdd: []string{"NET_ADMIN"},
	}
	resource, err := pool.RunWithOptions(options)
	if err != nil {
		log.Fatalf("Could not start resource: %s", err)
	}
	// exponential backoff-retry, because the application in the container might not be ready to accept connections yet
	// the minio client does not do service discovery for you (i.e. it does not check if connection can be established), so we have to use the health check
	var config []byte
	if err := pool.Retry(func() error {
		url := "http://localhost:8080/"
		resp, err := http.Get(url)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status code not OK")
		}
		config, err = io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
		fmt.Println("Got OpenVPN client config")
		return nil
	}); err != nil {
		log.Fatalf("Could not connect to docker: %s", err)
	}
	return config, pool, resource, nil
}

func stopContainer(p *dockertest.Pool, res *dockertest.Resource) {
	fmt.Println("[!] Stopping container")
	if err := p.Purge(res); err != nil {
		log.Warnf("Could not purge resource: %s\n", err)
	}
}

func TestClientAES256GCM(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	tmp := t.TempDir()

	fmt.Println("launching docker")
	config, pool, resource, err := launchDocker("AES-256-GCM", "SHA256")
	if err != nil {
		t.Errorf("cannot start docker: %v", err)
	}
	// when all test done, time to kill and remove the container
	defer stopContainer(pool, resource)

	cfgFile, err := os.CreateTemp(tmp, "minivpn-e2e-")
	if err != nil {
		t.Errorf("Cannot create temporary file: %v", err)
	}
	defer cfgFile.Close()
	fmt.Println("Config written to: " + cfgFile.Name())

	if _, err = cfgFile.Write(config); err != nil {
		t.Errorf("Failed to write config to temporary file: %v", err)
	}

	// actual test begins
	vpnConfig := model.NewConfig(model.WithConfigFile(cfgFile.Name()))

	dialer := networkio.NewDialer(log.Log, &net.Dialer{})
	conn, err := dialer.DialContext(context.TODO(), vpnConfig.Remote().Protocol, vpnConfig.Remote().AddrPort)
	if err != nil {
		t.Errorf("dial error: %v", err)
	}

	tunnel, err := tun.StartTUN(context.TODO(), conn, vpnConfig)
	if err != nil {
		t.Errorf("cannot start tunnel: %v", err)
	}

	pinger := ping.New(target, tunnel)
	pinger.Count = count
	err = pinger.Run(context.Background())
	defer pinger.Stop()
	if err != nil {
		log.Fatalf("VPN Error: %s", err)
	}
	if pinger.PacketLoss() != 0 {
		log.Fatalf("packet loss is not zero")
	}
	// let's assert something wise about the pings
	// can we parse the logs? get initialization etc
}

func readLines(f string) ([]string, error) {
	var ll []string
	rf, err := os.Open(f)
	if err != nil {
		return ll, err
	}
	defer rf.Close()
	fs := bufio.NewScanner(rf)
	fs.Split(bufio.ScanLines)
	for fs.Scan() {
		ll = append(ll, fs.Text())
	}
	return ll, nil
}
