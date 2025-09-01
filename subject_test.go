package nethsm

import (
	"crypto/x509/pkix"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPKIXToDistinguishedName is slightly pointless
func TestPKIXToDistinguishedName(t *testing.T) {
	name := pkix.Name{
		Country:            []string{"NO"},
		Organization:       []string{"Company"},
		OrganizationalUnit: []string{"FOO", "BAR", "BAZ"},
		Locality:           []string{"Trondheim"},
		Province:           []string{"Trondelag"},
		CommonName:         "common name",
	}

	dn := pkixNameToDistinguishedName(name)
	require.Equal(t, "NO", *dn.CountryName)
	require.Equal(t, "Company", *dn.OrganizationName)
	require.Equal(t, strings.Join([]string{"FOO", "BAR", "BAZ"}, dnSeparatorChar), *dn.OrganizationalUnitName)
	require.Equal(t, "Trondheim", *dn.LocalityName)
	require.Equal(t, "Trondelag", *dn.StateOrProvinceName)
	require.Equal(t, "common name", dn.CommonName)
	fmt.Printf("%+v\n", dn)
}
