package nethsm

import (
	"encoding/json"
	"log/slog"
	"reflect"
	"testing"

	"github.com/borud/nethsm/api"
	"github.com/stretchr/testify/require"
)

// publicKeysForTesting was extracted from a NetHSM and the map below maps from
// a name to the JSON representation of the api.PublicKey type that was
// generated. We then use this to test parsing the public keys.
var publicKeysForTesting = map[string]string{
	"rsa": `
		{
		  "mechanisms": [
		    "RSA_Signature_PSS_SHA512"
		  ],
		  "operations": 0,
		  "public": {
		    "modulus": "uTmxhn0OcYQw68oNgz+hsZpaK+0Mbp5XDrX9xOocMSh2KtqNn5CZ5IA0yAOwvmgXAXN8s7AUEthI4Z0L2RZW9ZAyaEaPwTYOGDL/jaG+tea1x2BtAD9W3hOKNPYjfe3icw3PKVcL60RQINoDnLdl2hdqRqc7u54SkRtme9g9aPB1YumaDx7RuXd43B2fJcuc6eaMrwoAHcUJUx+ZTNWrKj0L6rmxM6NCVt2YGtdP8m3ipUYiWljBjvHIlkqD2Bj+NE8okQ8ut5iUwCHdVBQRC1Q8wieMRKUeK4E/HDMaGoWVte7o3vWlA4mtXxEInGTsuaKasqhjqu0PpPyYncou8Q==",
		    "publicExponent": "AQAB"
		  },
		  "restrictions": {},
		  "type": "RSA"
		}
	`,
	"curve25519": `
		{
		  "mechanisms": [
		    "EdDSA_Signature"
		  ],
		  "operations": 0,
		  "public": {
		    "data": "21ccjXD3+/jbzkZ21Q31xNJYbTf4QnltHm1WAAV0YN8="
		  },
		  "restrictions": {},
		  "type": "Curve25519"
		}
	`,
	"ecp384": `
		{
		  "mechanisms": [
		    "ECDSA_Signature"
		  ],
		  "operations": 0,
		  "public": {
		    "data": "BO116IfqTsN6ZgkC0RPnsvSPq+jkA2tQz4VwSgcvtXkKaIbz6ON546o99OWS8c0VRSWNY3wxVBipQMJ5hdXvpuIpFyyoHjsksO6toYh9Kr7wckKIfVD15yQewr/HOJIj/Q=="
		  },
		  "restrictions": {},
		  "type": "EC_P384"
		}
	`,
	"ecp521": `
		{
		  "mechanisms": [
		    "ECDSA_Signature"
		  ],
		  "operations": 0,
		  "public": {
		    "data": "BAGlgu08X/MkEZwVMV4knXi6rF+xzQIDk2qLFJ/ai8AcrTqNXDb/Uflhqgc8asdEVYU2Sam8aLqyIXiyIHajivwHagDeCMrXaDCNlEaa+XV4B/48jR6oUW7ErcYv6w8DctD4yc1KUHO2FZxPGmTeJuQKF391/reetm6xdAWRT4Kslm2JYw=="
		  },
		  "restrictions": {},
		  "type": "EC_P521"
		}
	`,
}

func TestDecodePublicKey(t *testing.T) {
	for name, val := range publicKeysForTesting {
		slog.Info("decoding", "name", name)
		var pub api.PublicKey
		err := json.Unmarshal([]byte(val), &pub)
		require.NoError(t, err)

		key, err := decodePublicKey(&pub)
		require.NoError(t, err)

		slog.Info("decoded key", "type", reflect.TypeOf(key))
	}
}
