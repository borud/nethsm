package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/borud/nethsm"
	"github.com/borud/nethsm/api"
)

// Demo is just a struct to manage the sessions and the temporary key name.
type demo struct {
	adminSession    *nethsm.Session
	operatorSession *nethsm.Session
	keyName         string
}

// NewDemo creates a new demo instance
func NewDemo(adminSession, operatorSession *nethsm.Session) *demo {
	return &demo{
		adminSession:    adminSession,
		operatorSession: operatorSession,
		keyName:         fmt.Sprintf("rsaDemoKey%d", time.Now().UnixMilli()),
	}
}

// getKeyName returns the key name
func (d *demo) getKeyName() string {
	return d.keyName
}

// createKey creates the key we use for encryption and decryption.
func (d *demo) createKey() error {
	err := d.adminSession.GenerateKey(
		d.keyName,
		api.KEYTYPE_RSA,
		[]api.KeyMechanism{
			api.KEYMECHANISM_RSA_DECRYPTION_RAW,
			api.KEYMECHANISM_RSA_DECRYPTION_PKCS1,
			api.KEYMECHANISM_RSA_DECRYPTION_OAEP_SHA256,
		},
		2048)
	if err != nil {
		return fmt.Errorf("error creating key: %w", err)
	}
	return nil
}

// getPublicKey fetches the public key and ensures it is an RSA key.
func (d *demo) getPublicKey() (*rsa.PublicKey, error) {
	pub, err := d.operatorSession.GetPublicKey(d.keyName)
	if err != nil {
		return nil, err
	}

	pk, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA key")
	}

	return pk, nil
}

// cleanup removes the key we use for testing
func (d *demo) cleanup() error {
	err := d.adminSession.DeleteKey(d.keyName)
	if err != nil {
		return fmt.Errorf("error removing key %s: %w", d.keyName, err)
	}
	return nil
}

// messageRaw demonstrates usage of the api.DECRYPTMODE_RAW mode
func (d *demo) messageRaw() error {
	pub, err := d.getPublicKey()
	if err != nil {
		return err
	}

	plaintext := []byte("raw test")

	m := new(big.Int).SetBytes(plaintext)
	n := pub.N
	if m.Cmp(n) >= 0 {
		return fmt.Errorf("message too large for modulus")
	}

	e := big.NewInt(int64(pub.E))
	c := new(big.Int).Exp(m, e, n)

	k := (n.BitLen() + 7) / 8
	ciphertext := leftPad(c.Bytes(), k)

	clearText, err := d.operatorSession.Decrypt(d.keyName, api.DECRYPTMODE_RAW, ciphertext)
	if err != nil {
		return fmt.Errorf("decrypt RAW: %w", err)
	}

	// RAW decrypt returns the full k-byte integer; trim leading zeros before compare.
	clearText = bytes.TrimLeft(clearText, "\x00")
	if !bytes.Equal(clearText, plaintext) {
		return fmt.Errorf("RAW round-trip mismatch: got %q want %q", string(clearText), string(plaintext))
	}
	slog.Info("  RAW: round-trip OK")
	return nil
}

// messagePKCS1 demonstrates usage of the api.DECRYPTMODE_PKCS1 mode
func (d *demo) messagePKCS1() error {
	pub, err := d.getPublicKey()
	if err != nil {
		return err
	}

	plaintext := []byte("hello from PKCS#1 v1.5")
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, plaintext)
	if err != nil {
		return fmt.Errorf("EncryptPKCS1v15: %w", err)
	}

	clearText, err := d.operatorSession.Decrypt(d.getKeyName(), api.DECRYPTMODE_PKCS1, ciphertext)
	if err != nil {
		return fmt.Errorf("decrypt PKCS1: %w", err)
	}
	if !bytes.Equal(clearText, plaintext) {
		return fmt.Errorf("PKCS1 round-trip mismatch: got %q want %q", string(clearText), string(plaintext))
	}
	slog.Info("  PKCS1: round-trip OK")
	return nil
}

// messageOAEP demonstrates usage of the api.DECRYPTMODE_OAEP_SHA256
func (d *demo) messageOAEP() error {
	pub, err := d.getPublicKey()
	if err != nil {
		return err
	}

	plaintext := []byte("hello from RSA-OAEP-SHA256")
	hash := sha256.New()
	// Label is nil for this demo; if you use a label, you must pass the same on decrypt (HSM handles it)
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, plaintext, nil)
	if err != nil {
		return fmt.Errorf("EncryptOAEP(SHA-256): %w", err)
	}

	clearText, err := d.operatorSession.Decrypt(d.getKeyName(), api.DECRYPTMODE_OAEP_SHA256, ciphertext)
	if err != nil {
		return fmt.Errorf("decrypt OAEP-SHA256: %w", err)
	}
	if !bytes.Equal(clearText, plaintext) {
		return fmt.Errorf("OAEP-SHA256 round-trip mismatch: got %q want %q", string(clearText), string(plaintext))
	}
	slog.Info("  OAEP-SHA256: round-trip OK")
	return nil
}

// leftPad pads b with leading zeros to size n bytes.
func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}
