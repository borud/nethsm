package nethsm

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func decodeCertificatePEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	return x509.ParseCertificate(block.Bytes)
}

func decodeCSRPEM(pemBytes []byte) (*x509.CertificateRequest, error) {
	csrPEMBlock, _ := pem.Decode(pemBytes)
	if csrPEMBlock == nil {
		return nil, errors.Join(ErrParsingPEM, fmt.Errorf("PEM block was nil"))
	}

	csr, err := x509.ParseCertificateRequest(csrPEMBlock.Bytes)
	if err != nil {
		return nil, errors.Join(ErrParsingPEM, err)
	}

	// Validate the CSR signature
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.Join(ErrParsingCSR, err)
	}

	return csr, nil
}
