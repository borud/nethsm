package nethsm

import (
	"crypto/x509"
	"fmt"

	"github.com/borud/nethsm/api"
)

// apiSigningModeFromSignatureAlgorithm maps from the x509.SignatureAlgorithm to the api.SignMode type.
// Anything not in this mapping we do not support.
func apiSigningModeFromSignatureAlgorithm(algo x509.SignatureAlgorithm) (api.SignMode, error) {
	switch algo {
	case x509.ECDSAWithSHA1:
		return api.SIGNMODE_ECDSA, nil

	case x509.ECDSAWithSHA256:
		return api.SIGNMODE_ECDSA, nil

	case x509.ECDSAWithSHA384:
		return api.SIGNMODE_ECDSA, nil

	case x509.ECDSAWithSHA512:
		return api.SIGNMODE_ECDSA, nil

	case x509.PureEd25519:
		return api.SIGNMODE_ED_DSA, nil

	case x509.SHA256WithRSAPSS:
		return api.SIGNMODE_PSS_SHA256, nil

	case x509.SHA384WithRSAPSS:
		return api.SIGNMODE_PSS_SHA384, nil

	case x509.SHA512WithRSAPSS:
		return api.SIGNMODE_PSS_SHA512, nil

	default:
		panic(fmt.Sprintf("Unsupported signature algorithm %d", algo))
		// return "", errors.Join(ErrUnsupportedAlgorithm, fmt.Errorf("%#v", algo))
	}
}
