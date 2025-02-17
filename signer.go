package nethsm

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"io"
	"log/slog"
)

// signer provides a crypto.Signer interface.
type signer struct {
	keyID              string
	signatureAlgorithm x509.SignatureAlgorithm
	session            *Session
}

// Public returns the public key.
func (h *signer) Public() crypto.PublicKey {
	pub, err := h.session.GetPublicKey(h.keyID)
	if err != nil {
		slog.Error("signer is unable to get public key", "keyID", h.keyID, "err", err)
		return nil
	}

	return pub
}

// Sign signs the digest.
func (h *signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// not sure if we need to deal with the opts so log it for now
	slog.Debug("Signing operation",
		"keyID", h.keyID,
		"expectedHashFunc", h.signatureAlgorithm, // Log expected hash mode
		"receivedHashFunc", opts.HashFunc().String(), // Log received hash mode
		"digestSize", len(digest),
	)

	ret, err := h.session.Sign(h.keyID, h.signatureAlgorithm, digest)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(ret)
}
