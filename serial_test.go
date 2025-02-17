package nethsm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateSerial(t *testing.T) {
	serial, err := GenerateSerialNumber()
	require.NoError(t, err)
	require.NotNil(t, serial)

	// test with too short
	serial, err = GenerateSerialNumber(63)
	require.ErrorIs(t, ErrSerialTooShort, err)
	require.Nil(t, serial)

	// test with too long
	serial, err = GenerateSerialNumber(161)
	require.ErrorIs(t, ErrSerialTooLong, err)
	require.Nil(t, serial)
}
