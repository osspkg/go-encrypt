package pki_test

import (
	"testing"

	"go.osspkg.com/encrypt/pki"
)

func TestConfigSubjectIncludesConfiguredFields(t *testing.T) {
	got := (pki.Config{Country: "US", Organization: "Example Org", OrganizationalUnit: "Security", Locality: "Boston", Province: "MA", StreetAddress: "1 Main St", PostalCode: "02110", CommonName: "root.example"}).Subject()
	if got.Country[0] != "US" || got.Organization[0] != "Example Org" || got.OrganizationalUnit[0] != "Security" || got.Locality[0] != "Boston" || got.Province[0] != "MA" || got.StreetAddress[0] != "1 Main St" || got.PostalCode[0] != "02110" || got.CommonName != "root.example" {
		t.Fatalf("unexpected subject: %#v", got)
	}
}
