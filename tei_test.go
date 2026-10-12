package teainsights

import "testing"

func TestParseTEIBothForms(t *testing.T) {
	id := "0f9c6b0e-6a0f-5e0e-9e5e-0123456789ab"
	purl := "pkg:github/acme/widget@1.2.3"

	cases := []struct {
		name, in string
		want     TEI
		ok       bool
	}{
		{"urn uuid", UUIDTEI(id), TEI{Type: "uuid", Domain: Domain, ID: id}, true},
		{"uri uuid", UUIDTEIURI(id), TEI{Type: "uuid", Domain: Domain, ID: id}, true},
		{"urn purl", PURLTEI(purl), TEI{Type: "purl", Domain: Domain, ID: purl}, true},
		{"uri purl", PURLTEIURI(purl), TEI{Type: "purl", Domain: Domain, ID: purl}, true},
		{"uri purl padded", PURLTEIURI(purl) + "==", TEI{Type: "purl", Domain: Domain, ID: purl}, true},
		{"uri upper scheme and domain", "TEI://Vulnetix.COM/uuid/" + id, TEI{Type: "uuid", Domain: Domain, ID: id}, true},
		{"uri missing id", "tei://vulnetix.com/uuid/", TEI{}, false},
		{"uri extra segment", "tei://vulnetix.com/uuid/a/b", TEI{}, false},
		{"uri encoded slash", "tei://vulnetix.com/uuid/a%2Fb", TEI{Type: "uuid", Domain: Domain, ID: "a/b"}, true},
		{"uri bad base64", "tei://vulnetix.com/purl/!!!", TEI{}, false},
		{"garbage", "nope", TEI{}, false},
	}
	for _, c := range cases {
		got, ok := ParseTEI(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: ParseTEI(%q) = %+v, %v; want %+v, %v", c.name, c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestTEIFormConversionRoundTrips(t *testing.T) {
	id := "0f9c6b0e-6a0f-5e0e-9e5e-0123456789ab"
	purl := "pkg:github/acme/widget@1.2.3"

	for _, urn := range []string{UUIDTEI(id), PURLTEI(purl)} {
		uri := ToURIForm(urn)
		if uri == urn {
			t.Fatalf("ToURIForm(%q) did not change the form", urn)
		}
		if back := ToURNForm(uri); back != urn {
			t.Errorf("round trip %q -> %q -> %q", urn, uri, back)
		}
		if ToURIForm(uri) != uri || ToURNForm(urn) != urn {
			t.Errorf("converting an identifier already in the target form changed it")
		}
	}
	if got := ToURIForm("not a tei"); got != "not a tei" {
		t.Errorf("unparseable input changed: %q", got)
	}
}
