package nethsm

import (
	"regexp"
)

const (
	keyIDMinLength    = 1
	keyIDMaxLength    = 128
	keyIDRegexpString = "^[a-zA-Z0-9]+$"
)

var (
	keyIDRegexp = regexp.MustCompile(keyIDRegexpString)
)

// ValidateKeyID to make sure the key conforms to the NetHSM requirements
// referred here:
//
//	<https://nethsmdemo.nitrokey.com/api_docs/index.html#/default/post_keys_generate>
func ValidateKeyID(id string) error {
	if len(id) < keyIDMinLength {
		return ErrKeyIDTooShort
	}

	if len(id) > keyIDMaxLength {
		return ErrKeyIDTooLong
	}

	if !keyIDRegexp.MatchString(string(id)) {
		return ErrInvalidKeyID
	}

	return nil
}
