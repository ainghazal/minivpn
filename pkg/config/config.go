package config

import (
	"fmt"
	"net"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/model"
)

// Config contains options to initialize the OpenVPN tunnel.
type Config struct {
	// openVPNOptions contains options related to openvpn.
	openvpnOptions *OpenVPNOptions

	// logger will be used to log events.
	logger model.Logger

	// if a tracer is provided, it will be used to trace the openvpn handshake.
	tracer model.HandshakeTracer
}

// NewConfig returns a Config ready to intialize a vpn tunnel. In case any error is raised during the
// initialization, it will be returned too.
func NewConfig(options ...Option) (*Config, error) {
	cfg := &Config{
		openvpnOptions: &OpenVPNOptions{},
		logger:         log.Log,
		tracer:         &model.DummyTracer{},
	}
	for _, opt := range options {
		opt(cfg)
	}
	return cfg, nil
}

// Option is an option you can pass to initialize minivpn. It will return any error
// that should be propagated by the constructor.
type Option func(config *Config) error

// WithLogger configures the passed [Logger].
func WithLogger(logger model.Logger) Option {
	return func(config *Config) error {
		config.logger = logger
		return nil
	}
}

// Logger returns the configured logger.
func (c *Config) Logger() model.Logger {
	return c.logger
}

// WithHandshakeTracer configures the passed [HandshakeTracer].
func WithHandshakeTracer(tracer model.HandshakeTracer) Option {
	return func(config *Config) error {
		config.tracer = tracer
		return nil
	}
}

// Tracer returns the handshake tracer.
func (c *Config) Tracer() model.HandshakeTracer {
	return c.tracer
}

// WithConfigFile configures OpenVPNOptions parsed from the given file.
func WithConfigFile(configPath string) Option {
	return func(config *Config) error {
		openvpnOpts, err := ReadConfigFile(configPath)
		if err != nil {
			return err
		}
		if !openvpnOpts.HasAuthInfo() {
			return fmt.Errorf("%w: %s", ErrBadConfig, "missing auth info")
		}
		config.openvpnOptions = openvpnOpts
		return nil
	}
}

// WithOpenVPNOptions configures the passed OpenVPN options.
func WithOpenVPNOptions(openvpnOptions *OpenVPNOptions) Option {
	return func(config *Config) error {
		config.openvpnOptions = openvpnOptions
		return nil
	}
}

// OpenVPNOptions returns the configured openvpn options.
func (c *Config) OpenVPNOptions() *OpenVPNOptions {
	return c.openvpnOptions
}

// Remote has info about the OpenVPN remote, useful to pass to the external dialer.
type Remote struct {
	// IPAddr is the IP Address for the remote.
	IPAddr string

	// Endpoint is in the form ip:port.
	Endpoint string

	// Protocol is either "tcp" or "udp"
	Protocol string
}

// Remote returns the OpenVPN remote.
func (c *Config) Remote() *Remote {
	return &Remote{
		IPAddr:   c.openvpnOptions.Remote,
		Endpoint: net.JoinHostPort(c.openvpnOptions.Remote, c.openvpnOptions.Port),
		Protocol: c.openvpnOptions.Proto.String(),
	}
}
