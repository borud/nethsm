package nethsm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/borud/tunnel"
	"golang.org/x/crypto/ssh"
)

// Config for NetHSM session.
type Config struct {
	// Username we are logging into the NetHSM as.
	Username string
	// Password for the user we are logging in as
	Password string
	// APIURL of the NetHSM endpoint
	APIURL string
	// Server certificate of the NetHSM
	ServerCertificate []byte
	// TLSMode sets how we verify the server certificate
	TLSMode TLSMode

	DisableKeepAlives     bool
	MaxIdleConns          int
	MaxIdleConnsPerHost   int
	IdleConnTimeout       time.Duration
	TLSHandshakeTimeout   time.Duration
	ExpectContinueTimeout time.Duration
	ResponseHeaderTimeout time.Duration

	// SSHTunnelHops is a list of hostnames we will tunnel through. Entries can
	// be host names or can optionally specify username and port using some
	// subset of user@host:port
	SSHTunnelHops []string

	// SSHEnableAgent enables SSH agent support
	SSHEnableAgent bool

	// SSHKeyFilename path to SSH secret key file
	SSHKeyFilename string

	// SSHKeyFilePassword optional password for ssh private key file
	SSHKeyFilePassword string

	// SSHKnownHostsFilename if specified we will use the known hosts to verify
	// the server keys along the tunnel hop chain.
	SSHKnownHostsFilename string
}

// TLSMode specifies what TLS checking we are going to do.
type TLSMode uint8

type contextDialerFunc func(ctx context.Context, network, addr string) (net.Conn, error)

const (
	// TLSModeDefault uses the secure system defaults for TLS verification.
	TLSModeDefault TLSMode = iota
	// TLSModeSkipVerify skips verification of server certificate completely.
	TLSModeSkipVerify
	// TLSModeWithoutSANCheck ensures the server certificate provided in
	// ServerCertificate checks out, but makes no further verifications. This
	// is used to get around missing SAN fields.
	TLSModeWithoutSANCheck
)

const (
	defaultMaxIdleConns          = 10
	defaultMaxIdleConnsPerHost   = 5
	defaultIdleConnTimeout       = 30 * time.Second
	defaultTLSHandshakeTimeout   = 30 * time.Second
	defaultExpectContinueTimeout = 120 * time.Second // some calls can take a long time
	defaultResponseHeaderTimeout = 120 * time.Second // some calls can take a long time
)

// newDialContextFunc returns a newDialContextFunc if we have defined an SSH tunnel and nil otherwise.
func (c *Config) newDialContextFunc() (contextDialerFunc, error) {
	if len(c.SSHTunnelHops) == 0 {
		return nil, nil
	}

	slog.Debug("using SSH tunnel", "tunnel", c.SSHTunnelHops)

	//tun, err := tunnel.Create(tunnel.Config{Hops: c.SSHTunnel})
	hops, err := tunnel.ParseHops(c.SSHTunnelHops)
	if err != nil {
		return nil, err
	}

	options := []tunnel.Option{
		tunnel.WithConnTracking(true),
		tunnel.WithHops(hops...),
	}

	// use SSH key from file if specified
	if c.SSHKeyFilename != "" {
		if c.SSHKeyFilePassword != "" {
			options = append(options, tunnel.WithKeyFile(c.SSHKeyFilename, []byte(c.SSHKeyFilePassword)))
		} else {
			options = append(options, tunnel.WithKeyFile(c.SSHKeyFilename, nil))
		}
	}

	// If we specify a known hosts file we will verify host keys for the
	// tunnel chain.  If not we skip this.
	if c.SSHKnownHostsFilename != "" {
		options = append(options, tunnel.WithKnownHosts(c.SSHKnownHostsFilename))
	} else {
		options = append(options, tunnel.WithHostKeyCallback(ssh.InsecureIgnoreHostKey()))
	}

	// if c.SSHEnableAgent is set we will use the SSH agent
	if c.SSHEnableAgent {
		options = append(options, tunnel.WithAgent())
	}

	tun, err := tunnel.Create(options...)
	if err != nil {
		return nil, err
	}

	return func(_ context.Context, network, addr string) (net.Conn, error) {
		slog.Debug("dial using tunnel", "tunnel", c.SSHTunnelHops, "network", network, "addr", addr)
		conn, err := tun.Dial(network, addr)
		if err != nil {
			slog.Debug("dial failed", "tunnel", c.SSHTunnelHops, "network", network, "addr", addr)
			return nil, err
		}
		slog.Debug("dial success", "tunnel", c.SSHTunnelHops, "network", network, "addr", addr)
		return conn, nil
	}, nil
}

// tlsConfig constructs a TLS config based on the TLSMode and ServerCertificate fields.
func (c *Config) tlsConfig() *tls.Config {
	switch c.TLSMode {
	case TLSModeSkipVerify:
		return &tls.Config{
			InsecureSkipVerify: true,
		}

	case TLSModeWithoutSANCheck:
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(c.ServerCertificate) {
			// fall back to safe default if this fails.
			return nil
		}

		return &tls.Config{
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(certificates [][]byte, _ [][]*x509.Certificate) error {
				cert, err := x509.ParseCertificate(certificates[0])
				if err != nil {
					return err
				}

				// Verify using the provided certificate only. If this fails it
				// means that we got the wrong certificate.
				_, err = cert.Verify(x509.VerifyOptions{Roots: caCertPool})
				if err != nil {
					return errors.Join(ErrTLSCertificateMismatch, err)
				}
				return nil
			},
		}

	case TLSModeDefault:
		// included for documentation purposes
		fallthrough

	default:
		return nil
	}
}
