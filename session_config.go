package nethsm

import (
	"errors"

	"github.com/borud/nethsm/api"
)

// GetTLSCertificate retrieves the TLS Certificate for the NetHSM.
func (s *Session) GetTLSCertificate() (string, error) {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return "", err
	}

	tlsCert, resp, err := client.ConfigTlsCertPemGet(ctx).Execute()
	if err != nil {
		return "", errors.Join(err, asError(resp))
	}

	return tlsCert, nil
}

// GenerateTLSKey generates a TLS key for the NetHSM.
func (s *Session) GenerateTLSKey(keyType api.TlsKeyType, length int32) error {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return err
	}

	resp, err := client.ConfigTlsGeneratePost(ctx).TlsKeyGenerateRequestData(api.TlsKeyGenerateRequestData{
		Type:   keyType,
		Length: &length,
	}).Execute()
	if err != nil {
		return errors.Join(err, asError(resp))
	}

	return nil
}

// GenerateTLSCSR generates a certificate signing request for the TLS key.
func (s *Session) GenerateTLSCSR(dn api.DistinguishedName) (string, error) {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return "", err
	}

	csrPEM, resp, err := client.ConfigTlsCsrPemPost(ctx).DistinguishedName(dn).Execute()
	if err != nil {
		return "", errors.Join(err, asError(resp))
	}

	return csrPEM, nil
}

// SetTLSCertificate sets the TLS certificate for the NetHSM.
func (s *Session) SetTLSCertificate(pem string) error {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return err
	}

	resp, err := client.ConfigTlsCertPemPut(ctx).Body(pem).Execute()
	if err != nil {
		return errors.Join(err, asError(resp))
	}

	return nil
}
