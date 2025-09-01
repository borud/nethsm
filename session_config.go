package nethsm

import (
	"errors"

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
