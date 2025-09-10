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
	// SSHTunnel is a list of hops on the form <username>@<host>:<sshport> to allow
	// for tunneling through intermediate hosts
	SSHTunnel []string

	DisableKeepAlives     bool
	MaxIdleConns          int
	MaxIdleConnsPerHost   int
	IdleConnTimeout       time.Duration
	TLSHandshakeTimeout   time.Duration
	ExpectContinueTimeout time.Duration
	ResponseHeaderTimeout time.Duration
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
	if len(c.SSHTunnel) == 0 {
		return nil, nil
	}

	slog.Debug("using SSH tunnel", "tunnel", c.SSHTunnel)

	tunnel, err := tunnel.Create(tunnel.Config{Hops: c.SSHTunnel})
	if err != nil {
		return nil, err
	}

	return func(_ context.Context, network, addr string) (net.Conn, error) {
		slog.Debug("dial using tunnel", "tunnel", c.SSHTunnel, "network", network, "addr", addr)
		conn, err := tunnel.Dial(network, addr)
		if err != nil {
			slog.Debug("dial failed", "tunnel", c.SSHTunnel, "network", network, "addr", addr)
			return nil, err
		}
		slog.Debug("dial success", "tunnel", c.SSHTunnel, "network", network, "addr", addr)
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
