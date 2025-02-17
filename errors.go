package nethsm

import (
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Errors for nethsm package.
var (
	ErrParsingPEM              = errors.New("error parsing PEM block")
	ErrPEMBlockNotCSR          = errors.New("PEM block was not a Certificate Signing Request")
	ErrParsingCSR              = errors.New("error parsing Certificate Signing Request")
	ErrInvalidCSRSignature     = errors.New("invalid Certificate Signing Request signature")
	ErrInvalidSigningAlgorithm = errors.New("invalid signature algorithm")
	ErrFailedToCreatePipe      = errors.New("failed to create pipe")
	ErrReadingCertificate      = errors.New("error reading certificate")
	ErrKeyIDTooShort           = errors.New("keyID is too short")
	ErrKeyIDTooLong            = errors.New("keyID is too long")
	ErrInvalidKeyID            = errors.New("invalid keyID, must match regexp " + keyIDRegexpString)
	ErrUnknownPublicKeyType    = errors.New("unknown public key type")
	ErrDecodingRSAPublicKey    = errors.New("error decoding RSA key public key")
	ErrDecodingECPublicKey     = errors.New("error decoding EC key public key")
	ErrDecodingEDPublicKey     = errors.New("error decoding ED key public key")
	ErrNotSupported            = errors.New("operation not supported for key")
	ErrNotECDSAPublicKey       = errors.New("not an ECDSA public key")
	ErrNotED25519PublicKey     = errors.New("not an ED25519 public key")
	ErrGeneratingSerialNumber  = errors.New("error generating serial number")
	ErrSerialTooShort          = errors.New("serial must be at least 64 bits")
	ErrSerialTooLong           = errors.New("serial must be 160 bits or less")
	ErrBase64Decode            = errors.New("error decoding base64")
	ErrInitialVectorMismatch   = errors.New("initial vector mismatch")
	ErrUnsupportedAlgorithm    = errors.New("unsupported algorithm")
	ErrAddingTLSCertificate    = errors.New("error adding TLS certificate")
	ErrTLSCertificateMismatch  = errors.New("NetHSM server TLS certificate mismatch")
)

// asError takes a pointer to an http.Response and returns an error type.
func asError(resp *http.Response) error {
	if resp == nil {
		return fmt.Errorf("http.Response was nil")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	return fmt.Errorf("HTTP %d: [%s]", resp.StatusCode, string(body))
}
