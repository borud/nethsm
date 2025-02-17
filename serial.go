package nethsm

import (
	"crypto/rand"
	"math/big"
)

const (
	// The default number of bits for the serial number.
	defaultSerialNumBits = uint(128)
)

// GenerateSerialNumber to be used in certificates.  Produces a random *big.Int
// serial number.  Optionally you can specify the number of bits to be used in
// the serial. The default length is defined by defaultSerialNumBits (128).
//
// Collision probability for random values from crypto/rand follows the Birthday Problem:
// - 64-bit: A collision is likely after ~5 billion values.
// - 128-bit: A collision is likely after ~22 quintillion values.
// - 160-bit: Likely collision after ~1.5 x 10^24 values.
//
// In practice 128 bit serial numbers should be safe to use for serial numbers.
func GenerateSerialNumber(nbits ...uint) (*big.Int, error) {
	numBits := defaultSerialNumBits

	// nbits represents an optional length parameter.  If present the first value is the length.
	if len(nbits) > 0 {
		numBits = nbits[0]

		if numBits > 160 {
			return nil, ErrSerialTooLong
		}

		if numBits < 64 {
			return nil, ErrSerialTooShort
		}
	}

	// Generate a 128-bit (16-byte) serial number, which is common in X.509 certificates
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), numBits))
	if err != nil {
		return nil, err
	}

	return serialNumber, nil
}
