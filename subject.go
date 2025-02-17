package nethsm

import (
	"crypto/x509/pkix"
	"strings"

	"github.com/borud/nethsm/api"
)

const dnSeparatorChar = ","

// pkixNameToDistinguishedName is used to map from the type used for the
// subject in the Go standard library to the type used by the api types. How
// multiple values of OU, for instance, are handled has not been documented for
// NetHSM, so we are making some assumptions.
//
// The assumption we are making is that multiple values are joined together by
// some separator character defined by dnSeparatorChar.
func pkixNameToDistinguishedName(name pkix.Name) api.DistinguishedName {
	return api.DistinguishedName{
		CountryName:            joinSubjectFields(name.Country),
		StateOrProvinceName:    joinSubjectFields(name.Province),
		LocalityName:           joinSubjectFields(name.Locality),
		OrganizationName:       joinSubjectFields(name.Organization),
		OrganizationalUnitName: joinSubjectFields(name.OrganizationalUnit),
		CommonName:             name.CommonName,
	}
}

// joinSubjectFields takes an array of fields, combines them into a string and
// then returns a pointer to that string.
func joinSubjectFields(fields []string) *string {
	s := strings.Join(fields, dnSeparatorChar)
	return &s
}
