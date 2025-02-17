package nethsm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/borud/nethsm/api"
)

func decodePublicKey(pub *api.PublicKey) (crypto.PublicKey, error) {
	switch pub.Type {
	case api.KEYTYPE_CURVE25519:
		return decodeEDPublicKey(pub)

	case api.KEYTYPE_EC_P224:
		return decodeECPublicKey(pub)

	case api.KEYTYPE_EC_P256:
		return decodeECPublicKey(pub)

	case api.KEYTYPE_EC_P384:
		return decodeECPublicKey(pub)

	case api.KEYTYPE_EC_P521:
		return decodeECPublicKey(pub)

	case api.KEYTYPE_RSA:
		return decodeRSAPublicKey(pub)

	case api.KEYTYPE_GENERIC:
		return nil, ErrNotSupported

	default:
		return nil, errors.Join(ErrUnknownPublicKeyType, fmt.Errorf("%s", pub.Type))
	}
}

func decodeRSAPublicKey(pub *api.PublicKey) (*rsa.PublicKey, error) {
	modulusBytes, err := base64.StdEncoding.DecodeString(*pub.Public.Modulus)
	if err != nil {
		return nil, errors.Join(ErrDecodingRSAPublicKey, err)
	}
	modulus := new(big.Int).SetBytes(modulusBytes)

	exponentBytes, err := base64.StdEncoding.DecodeString(*pub.Public.PublicExponent)
	if err != nil {
		return nil, fmt.Errorf("error decoding public exponent: %w", err)
	}
	publicExponent := new(big.Int).SetBytes(exponentBytes).Int64()

	return &rsa.PublicKey{
		N: modulus,
		E: int(publicExponent),
	}, nil
}

func decodeEDPublicKey(pub *api.PublicKey) (ed25519.PublicKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(*pub.Public.Data)
	if err != nil {
		return nil, errors.Join(ErrDecodingEDPublicKey, err)
	}

	// Determine if the key is raw key bytes
	if len(keyBytes) == ed25519.PublicKeySize {
		pub := ed25519.PublicKey(keyBytes)
		return pub, nil
	}

	// Otherwise assume it is PKIX-encoded
	pubKey, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return nil, errors.Join(ErrDecodingEDPublicKey, err)
	}

	if edPub, ok := pubKey.(*ed25519.PublicKey); ok {
		return *edPub, nil
	}

	return nil, errors.Join(ErrDecodingEDPublicKey, ErrNotED25519PublicKey)
}

// decodeECPublicKey decodes a ECDSA public key.
//
// Note that ECDSA is deprecated in Go, so you might get some deprecation warnings.
func decodeECPublicKey(pub *api.PublicKey) (*ecdsa.PublicKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(*pub.Public.Data)
	if err != nil {
		return nil, errors.Join(ErrDecodingECPublicKey, err)
	}

	// Attempt to parse as PKIX (ASN.1 DER-encoded) ECDSA public key
	pubKey, err := x509.ParsePKIXPublicKey(keyBytes)
	if err == nil {
		// Ensure it's actually an ECDSA key
		if ecPub, ok := pubKey.(*ecdsa.PublicKey); ok {
			return ecPub, nil
		}
		return nil, errors.Join(ErrDecodingECPublicKey, ErrNotECDSAPublicKey)
	}

	// if we are here it means the PKIX parsing failed and we are dealing
	// with a raw, uncompressed, EC key

	if len(keyBytes) < 65 || keyBytes[0] != 0x04 {
		return nil, errors.Join(ErrDecodingECPublicKey, fmt.Errorf("invalid raw EC public key format"))
	}

	var curve elliptic.Curve
	switch pub.Type {
	case api.KEYTYPE_EC_P224:
		curve = elliptic.P224()
	case api.KEYTYPE_EC_P256:
		curve = elliptic.P256()
	case api.KEYTYPE_EC_P384:
		curve = elliptic.P384()
	case api.KEYTYPE_EC_P521:
		curve = elliptic.P521()
	default:
		return nil, errors.Join(ErrDecodingECPublicKey, fmt.Errorf("unsupported curve %s", pub.Type))
	}

	fieldSize := (curve.Params().BitSize + 7) / 8 // 32 bytes for P-256, etc.

	if len(keyBytes) != 1+2*fieldSize { // 1 byte (prefix) + X + Y
		return nil, errors.Join(ErrDecodingECPublicKey, errors.New("invalid key length for chosen curve"))
	}

	// Extract X and Y coordinates
	x := new(big.Int).SetBytes(keyBytes[1 : 1+fieldSize])
	y := new(big.Int).SetBytes(keyBytes[1+fieldSize:])

	// Verify that the public key is valid
	if !curve.IsOnCurve(x, y) {
		return nil, errors.Join(ErrDecodingECPublicKey, errors.New("invalid EC public key: point not on curve"))
	}

	// Return ECDSA public key
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}
