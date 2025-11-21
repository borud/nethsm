package nethsm

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"

	"github.com/borud/nethsm/api"
)

// GetTLSCertificate retrieves the TLS Certificate for the NetHSM.
func (s *Session) GetTLSCertificate() (string, error) {
	tlsCert, resp, err := s.client.ConfigTlsCertPemGet(s.authCtx).Execute()
	defer closeBody(resp)
	if err != nil {
		return "", errors.Join(err, asError(resp))
	}

	return tlsCert, nil
}

// GetTLSCertificateFromConnection returns the server TLS certificate.  We
// added this because the API mysteriously requires you to connect as an Admin
// user to fetch the server TLS certificate.
func (s *Session) GetTLSCertificateFromConnection() (string, error) {
	dialContext, err := s.config.newDialContextFunc()
	if err != nil {
		return "", err
	}
	if dialContext == nil {
		dialContext = (&net.Dialer{}).DialContext
	}

	apiURL, err := url.Parse(s.config.APIURL)
	if err != nil {
		return "", fmt.Errorf("error parsing APIURL [%s]: %w", s.config.APIURL, err)
	}

	// cheekily re-use ResponseHeaderTimeout rather than invent a new timeout.
	ctx, cancel := context.WithTimeout(context.Background(), s.config.ResponseHeaderTimeout)
	defer cancel()

	conn, err := dialContext(ctx, "tcp", apiURL.Host)
	if err != nil {
		return "", err
	}

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	err = tlsConn.Handshake()
	if err != nil {
		log.Fatal(err)
	}

	state := tlsConn.ConnectionState()

	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("[%s] did not present a certificate", apiURL.Host)
	}

	cert := state.PeerCertificates[0]
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	pemData := pem.EncodeToMemory(block)
	return string(pemData), nil
}

// GenerateTLSKey generates a TLS key for the NetHSM.
func (s *Session) GenerateTLSKey(keyType api.TlsKeyType, length int32) error {
	resp, err := s.client.ConfigTlsGeneratePost(s.authCtx).TlsKeyGenerateRequestData(api.TlsKeyGenerateRequestData{
		Type:   keyType,
		Length: &length,
	}).Execute()
	defer closeBody(resp)
	if err != nil {
		return errors.Join(err, asError(resp))
	}

	return nil
}

// GenerateTLSCSR generates a certificate signing request for the TLS key.
func (s *Session) GenerateTLSCSR(dn api.DistinguishedName) (string, error) {
	csrPEM, resp, err := s.client.ConfigTlsCsrPemPost(s.authCtx).DistinguishedName(dn).Execute()
	defer closeBody(resp)
	if err != nil {
		return "", errors.Join(err, asError(resp))
	}

	return csrPEM, nil
}

// SetTLSCertificate sets the TLS certificate for the NetHSM.
func (s *Session) SetTLSCertificate(pem string) error {
	resp, err := s.client.ConfigTlsCertPemPut(s.authCtx).Body(pem).Execute()
	defer closeBody(resp)
	if err != nil {
		return errors.Join(err, asError(resp))
	}

	return nil
}

// GetUnattendedBoot returns *api.Switch type.  If an error occurs it returns nil and an error.
func (s *Session) GetUnattendedBoot() (*api.Switch, error) {
	conf, resp, err := s.client.ConfigUnattendedBootGet(s.authCtx).Execute()
	defer closeBody(resp)
	if err != nil {
		return nil, errors.Join(err, asError(resp))
	}

	return conf.GetStatus().Ptr(), nil
}

// SetUnattendedBoot sets unattended boot.  If on parameter is true we turn
// unattended boot on.  If it is false we turn it off.
func (s Session) SetUnattendedBoot(unattended api.Switch) error {
	res, err := s.client.
		ConfigUnattendedBootPut(s.authCtx).
		UnattendedBootConfig(api.UnattendedBootConfig{Status: unattended}).
		Execute()
	defer closeBody(res)
	if err != nil {
		return errors.Join(err, asError(res))
	}
	return nil
}

// GetNetworkConfig fetches the network config.
func (s *Session) GetNetworkConfig() (*api.NetworkConfig, error) {
	conf, resp, err := s.client.ConfigNetworkGet(s.authCtx).Execute()
	defer closeBody(resp)
	if err != nil {
		return nil, errors.Join(err, asError(resp))
	}

	return conf, nil
}

// SetNetworkConfig set the network config.
func (s *Session) SetNetworkConfig(conf api.NetworkConfig) error {
	resp, err := s.client.ConfigNetworkPut(s.authCtx).NetworkConfig(conf).Execute()
	defer closeBody(resp)
	if err != nil {
		return errors.Join(err, asError(resp))
	}
	return nil
}

// GetLoggingConfig returns the logging config.
func (s *Session) GetLoggingConfig() (*api.LoggingConfig, error) {
	conf, resp, err := s.client.ConfigLoggingGet(s.authCtx).Execute()
	defer closeBody(resp)
	if err != nil {
		return nil, errors.Join(err, asError(resp))
	}

	return conf, nil
}

// SetLoggingConfig set the logging config
func (s *Session) SetLoggingConfig(conf api.LoggingConfig) error {
	resp, err := s.client.ConfigLoggingPut(s.authCtx).LoggingConfig(conf).Execute()
	defer closeBody(resp)
	if err != nil {
		return errors.Join(err, asError(resp))
	}
	return nil
}

// GetTime returns the current system time.
func (s *Session) GetTime() (*api.TimeConfig, error) {
	timeConfig, resp, err := s.client.ConfigTimeGet(s.authCtx).Execute()
	defer closeBody(resp)
	if err != nil {
		return nil, errors.Join(err, asError(resp))
	}
	return timeConfig, nil
}

// SetTime set the system time.
func (s *Session) SetTime(conf api.TimeConfig) error {
	// the REST API requires the time to be in UTC, so ensure the timezone is UTC.
	conf.Time = conf.GetTime().UTC()

	resp, err := s.client.ConfigTimePut(s.authCtx).TimeConfig(conf).Execute()
	defer closeBody(resp)
	if err != nil {
		return errors.Join(err, asError(resp))
	}
	return nil
}
