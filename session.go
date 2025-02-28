package nethsm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"

	"github.com/borud/tunnel"

	api "github.com/borud/nethsm/api"
)

// Session is a NetHSM session.
type Session struct {
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
}

type contextDialerFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// TLSMode specifies what TLS checking we are going to do.
type TLSMode uint8

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

// newClientAndContext is a convenience function that is used to get a usable REST client and a context object.
func (s *Session) newClientAndContext() (*api.DefaultAPIService, context.Context, error) {
	dialer, err := s.newDialContextFunc()
	if err != nil {
		return nil, nil, err
	}

	// Create the HTTP client depending on parameters
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: s.tlsConfig(),
			DialContext:     dialer,
		},
	}

	// Set the API endpoint URL and the http client
	config := api.NewConfiguration()
	config.Servers = api.ServerConfigurations{{URL: s.APIURL}}
	config.HTTPClient = httpClient

	return api.NewAPIClient(config).DefaultAPI,
		context.WithValue(context.Background(), api.ContextBasicAuth, api.BasicAuth{
			UserName: s.Username,
			Password: s.Password,
		}), nil
}

// newDialContextFunc returns a newDialContextFunc if we have defined an SSH tunnel and nil otherwise.
func (s *Session) newDialContextFunc() (contextDialerFunc, error) {
	if len(s.SSHTunnel) == 0 {
		return nil, nil
	}

	slog.Debug("using SSH tunnel", "tunnel", s.SSHTunnel)

	tunnel, err := tunnel.Create(tunnel.Config{Hops: s.SSHTunnel})
	if err != nil {
		return nil, err
	}

	return func(_ context.Context, network, addr string) (net.Conn, error) {
		conn, err := tunnel.Dial(network, addr)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}, nil
}

// tlsConfig constructs a TLS config based on the TLSMode and ServerCertificate fields.
func (s *Session) tlsConfig() *tls.Config {
	switch s.TLSMode {
	case TLSModeSkipVerify:
		return &tls.Config{
			InsecureSkipVerify: true,
		}

	case TLSModeWithoutSANCheck:
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(s.ServerCertificate) {
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
