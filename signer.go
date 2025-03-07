package nethsm

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"io"
	"log/slog"
)

// Signer provides a crypto.Signer interface.
type Signer struct {
	KeyID              string
	SignatureAlgorithm x509.SignatureAlgorithm
	Session            *Session
}

// Public returns the public key.
func (h *Signer) Public() crypto.PublicKey {
	pub, err := h.Session.GetPublicKey(h.KeyID)
	if err != nil {
		slog.Error("signer is unable to get public key", "keyID", h.KeyID, "err", err)
		return nil
	}

	return pub
}

// Sign signs the digest.
func (h *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// not sure if we need to deal with the opts so log it for now
	slog.Debug("Signing operation",
		"keyID", h.KeyID,
		"expectedHashFunc", h.SignatureAlgorithm, // Log expected hash mode
		"receivedHashFunc", opts.HashFunc().String(), // Log received hash mode
		"digestSize", len(digest),
	)

	ret, err := h.Session.Sign(h.KeyID, h.SignatureAlgorithm, digest)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(ret)
}
