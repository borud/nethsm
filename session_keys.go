package nethsm

// This file contains the key operations supported by the NetHSM.  For now it
// does not include decrypting data encrypted with asymmetric keys since we
// have no use case to test against.

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/borud/nethsm/api"
	"github.com/zenazn/pkcs7pad"
)

// CSRSigningParameters are the signing parameters for signing a CSR.
type CSRSigningParameters struct {
	SelfSign           bool
	SignatureAlgorithm x509.SignatureAlgorithm
	SigningKeyID       string
	CSRPEM             string
	KeyUsage           x509.KeyUsage
	ExtKeyUsage        []x509.ExtKeyUsage
	NotBefore          time.Time
	NotAfter           time.Time
	IsCA               bool
	MaxPathLen         int
	MaxPathLenZero     bool
}

// GenerateKey generates a key.
func (s *Session) GenerateKey(keyID string, keyType api.KeyType, keyMechanisms []api.KeyMechanism, length int32) error {
	// Validate the KeyID
	err := ValidateKeyID(keyID)
	if err != nil {
		return err
	}

	// Create the request data
	requestData := api.NewKeyGenerateRequestData(keyMechanisms, keyType)
	requestData.SetId(keyID)
	requestData.SetLength(length)
	// TODO(borud): we should probably expose this
	// requestData.SetRestrictions()

	// Create the key
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return err
	}

	_, resp, err := client.KeysGeneratePost(ctx).KeyGenerateRequestData(*requestData).Execute()
	if err != nil {
		return errors.Join(err, asError(resp))
	}
	return nil
}

// GetPublicKey fetches the public key for keyID from NetHSM.
func (s *Session) GetPublicKey(keyID string) (crypto.PublicKey, error) {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return nil, err
	}

	pub, resp, err := client.KeysKeyIDGet(ctx, keyID).Execute()
	if err != nil {
		return nil, errors.Join(err, asError(resp))
	}

	return decodePublicKey(pub)
}

// GetKey fetches the (public) key for keyID and returns the api.PublicKey type.
func (s *Session) GetKey(keyID string) (*api.PublicKey, error) {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return nil, err
	}

	pub, resp, err := client.KeysKeyIDGet(ctx, keyID).Execute()
	if err != nil {
		return nil, errors.Join(err, asError(resp))
	}

	return pub, nil
}

// ListKeys returns an array of key names.
func (s *Session) ListKeys() ([]string, error) {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return []string{}, err
	}

	keyItems, resp, err := client.KeysGet(ctx).Execute()
	if err != nil {
		return []string{}, errors.Join(err, asError(resp))
	}

	keyIDs := make([]string, len(keyItems))
	for i, keyItem := range keyItems {
		keyIDs[i] = keyItem.Id
	}

	return keyIDs, nil
}

// GenerateCSR for key identified by keyID with subject and email. We return
// the CSR as a string in PEM format since that is usually the most practical
// format users of this library will be interested in.
func (s *Session) GenerateCSR(keyID string, subject pkix.Name, email string) (string, error) {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return "", err
	}

	dn := pkixNameToDistinguishedName(subject)
	dn.EmailAddress = &email

	res, resp, err := client.KeysKeyIDCsrPemPost(ctx, keyID).DistinguishedName(dn).Execute()
	if err != nil {
		return "", errors.Join(err, asError(resp))
	}
	return res, nil
}

// GenerateCSRUsingGoStdlib for key identified by keyID with subject and email. We return
// the CSR as a string in PEM format since that is usually the most practical
// format users of this library will be interested in.
//
// This variant uses the Go standard library to create the certificate request
// rather than the CSR generation endpoint of the NetHSM.  This is due to certain
// differences in
func (s *Session) GenerateCSRUsingGoStdlib(keyID string, subject pkix.Name, email string, alg x509.SignatureAlgorithm) (string, error) {
	hsmSigner := &Signer{
		KeyID:              keyID,
		SignatureAlgorithm: alg,
		Session:            s,
	}

	csrTemplate := &x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: alg,
		EmailAddresses:     []string{email},
	}

	csrDER, err := x509.CreateCertificateRequest(nil, csrTemplate, hsmSigner)
	if err != nil {
		return "", fmt.Errorf("create certificate request error: %w", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})), nil
}

// Sign the digest using the key with id keyID using signing mode given by signMode.
//
// Valid values for signatureAlgorithm are:
//   - x509.ECDSAWithSHA1
//   - x509.ECDSAWithSHA256
//   - x509.ECDSAWithSHA384
//   - x509.ECDSAWithSHA512
//   - x509.PureEd25519
//   - x509.SHA256WithRSAPSS
//   - x509.SHA384WithRSAPSS
//   - x509.SHA512WithRSAPSS
func (s *Session) Sign(keyID string, signatureAlgorithm x509.SignatureAlgorithm, digest []byte) (string, error) {
	signMode, err := apiSigningModeFromSignatureAlgorithm(signatureAlgorithm)
	if err != nil {
		return "", err
	}

	if !signMode.IsValid() {
		return "", ErrInvalidSigningAlgorithm
	}

	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return "", err
	}

	res, resp, err := client.KeysKeyIDSignPost(ctx, keyID).
		SignRequestData(api.SignRequestData{
			Mode:    signMode,
			Message: base64.StdEncoding.EncodeToString(digest),
		}).
		Execute()
	if err != nil {
		return "", errors.Join(err, asError(resp))
	}

	return res.Signature, nil
}

// CreateCertificate is used to create a certificate given
// CertificateParameters.  Note that you have to be careful about correctly
// populating the parameters.  If you make a root CA you should not include ExtKeyUsage.
func (s *Session) CreateCertificate(param CSRSigningParameters) (string, error) {
	csr, err := decodeCSRPEM([]byte(param.CSRPEM))
	if err != nil {
		return "", err
	}

	serial, err := GenerateSerialNumber()
	if err != nil {
		return "", err
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             param.NotBefore,
		NotAfter:              param.NotAfter,
		KeyUsage:              param.KeyUsage,
		ExtKeyUsage:           param.ExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  param.IsCA,
		MaxPathLen:            param.MaxPathLen,
		MaxPathLenZero:        param.MaxPathLenZero,
		SignatureAlgorithm:    param.SignatureAlgorithm,
	}

	hsmSigner := &Signer{
		KeyID:              param.SigningKeyID,
		SignatureAlgorithm: param.SignatureAlgorithm,
		Session:            s,
	}

	parent := &template
	// if we are not self-signing the parent value set above is overridden.
	if !param.SelfSign {
		pemBytes, err := s.GetCertificate(param.SigningKeyID)
		if err != nil {
			return "", fmt.Errorf("error fetching signing certificate for keyID [%s]: %w", param.SigningKeyID, err)
		}

		parent, err = decodeCertificatePEM([]byte(pemBytes))
		if err != nil {
			return "", err
		}
	}

	certDERBytes, err := x509.CreateCertificate(nil, &template, parent, csr.PublicKey, hsmSigner)
	if err != nil {
		return "", fmt.Errorf("error creating certificate: %w", err)
	}

	certificate := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDERBytes,
	})

	return string(certificate), nil
}

// SetCertificate uploads a certificate for a given keyID.
func (s *Session) SetCertificate(keyID string, certPEM []byte) error {
	// The openapi-generator expects an os.File as input. This is a design
	// blunder and not something we can do a lot about here. Other than cope
	// with it.
	r, w, err := os.Pipe()
	if err != nil {
		return errors.Join(ErrFailedToCreatePipe, err)
	}
	defer r.Close()

	go func() {
		defer w.Close()
		_, err := w.Write(certPEM)
		if err != nil {
			slog.Error("error writing certificate to NetHSM", "keyID", keyID, "err", err)
		}
	}()

	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return err
	}
	resp, err := client.KeysKeyIDCertPut(ctx, keyID).Body(r).Execute()
	if err != nil {
		return errors.Join(err, asError(resp))
	}

	return err
}

// GetCertificate returns the certificate for a given keyID
func (s *Session) GetCertificate(keyID string) (string, error) {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return "", err
	}

	file, resp, err := client.KeysKeyIDCertGet(ctx, keyID).Execute()
	if err != nil {
		return "", errors.Join(err, asError(resp))
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return "", errors.Join(ErrReadingCertificate, err)
	}

	return string(data), nil
}

// DeleteKey deletes a key from the NetHSM
func (s *Session) DeleteKey(keyID string) error {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return err
	}

	resp, err := client.KeysKeyIDDelete(ctx, keyID).Execute()
	if err != nil {
		return errors.Join(err, asError(resp))
	}
	return nil
}

// DeleteCertificate deletes a certificate from the NetHSM
func (s *Session) DeleteCertificate(keyID string) error {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return err
	}

	resp, err := client.KeysKeyIDCertDelete(ctx, keyID).Execute()
	if err != nil {
		return errors.Join(err, asError(resp))
	}
	return nil
}

// EncryptSymmetric is used to encrypt data using a symmetric (AES) key identified by keyID.  The only
// mode available is CBC.  This function takes care of padding the data using blocksize of 16.
func (s *Session) EncryptSymmetric(keyID string, message []byte, initialVector []byte) ([]byte, error) {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return nil, err
	}

	// AES block size
	blockSize := 16

	iv := base64.StdEncoding.EncodeToString(initialVector)
	paddedMessage := base64.StdEncoding.EncodeToString(pkcs7pad.Pad(message, blockSize))

	data, resp, err := client.KeysKeyIDEncryptPost(ctx, keyID).EncryptRequestData(api.EncryptRequestData{
		Mode:    api.ENCRYPTMODE_AES_CBC,
		Message: paddedMessage,
		Iv:      &iv,
	}).Execute()
	if err != nil {
		return nil, errors.Join(err, asError(resp))
	}

	encryptedData, err := base64.StdEncoding.DecodeString(data.Encrypted)
	if err != nil {
		return nil, errors.Join(ErrBase64Decode, err)
	}

	returnedIV, err := base64.StdEncoding.DecodeString(data.Iv)
	if !bytes.Equal(initialVector, returnedIV) {
		return nil, ErrInitialVectorMismatch
	}

	return encryptedData, nil
}

// DecryptSymmetric decrypts enciphered message usig the key identified by keyID. This function takes
// care of unpadding the data before returning it.
func (s *Session) DecryptSymmetric(keyID string, encipheredMessage []byte, initialVector []byte) ([]byte, error) {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return nil, err
	}

	iv := base64.StdEncoding.EncodeToString(initialVector)

	data, resp, err := client.KeysKeyIDDecryptPost(ctx, keyID).DecryptRequestData(api.DecryptRequestData{
		Mode:      api.DECRYPTMODE_AES_CBC,
		Encrypted: base64.StdEncoding.EncodeToString(encipheredMessage),
		Iv:        &iv,
	}).Execute()
	if err != nil {
		return nil, errors.Join(err, asError(resp))
	}

	decrypted, err := base64.StdEncoding.DecodeString(data.Decrypted)
	if err != nil {
		return nil, errors.Join(ErrBase64Decode, err)
	}

	unpadded, err := pkcs7pad.Unpad(decrypted)
	if err != nil {
		return nil, err
	}

	return unpadded, nil
}
