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
