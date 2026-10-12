package teainsights

import (
	"strings"
	"testing"
)

func TestParseTEI(t *testing.T) {
	cases := []struct {
		raw             string
		ok              bool
		typ, domain, id string
	}{
		{"urn:tei:uuid:vulnetix.com:54e8820d-0803-5a4f-858d-88a279486564", true, "uuid", "vulnetix.com", "54e8820d-0803-5a4f-858d-88a279486564"},
		{"URN:TEI:UUID:Vulnetix.com:ABC", true, "uuid", "vulnetix.com", "ABC"},
		{"  urn:tei:purl:vulnetix.com:pkg:github/acme/store@abc123  ", true, "purl", "vulnetix.com", "pkg:github/acme/store@abc123"},
		{"urn%3Atei%3Apurl%3Avulnetix.com%3Apkg%3Anpm%2Flodash%404.17.20", true, "purl", "vulnetix.com", "pkg:npm/lodash@4.17.20"},
		{"urn:tei:swid:example.com:acme-widget-1.0", true, "swid", "example.com", "acme-widget-1.0"},
		{"urn:tei:hash:example.com:sha256:abcd", true, "hash", "example.com", "sha256:abcd"},
		{"urn:tei:uuid:vulnetix.com:", false, "", "", ""},
		{"urn:tei:uuid", false, "", "", ""},
		{"urn:isbn:uuid:vulnetix.com:x", false, "", "", ""},
		{"", false, "", "", ""},
	}
	for _, c := range cases {
		got, ok := ParseTEI(c.raw)
		if ok != c.ok {
			t.Errorf("ParseTEI(%q) ok = %v, want %v", c.raw, ok, c.ok)
			continue
		}
		if ok && (got.Type != c.typ || got.Domain != c.domain || got.ID != c.id) {
			t.Errorf("ParseTEI(%q) = %+v, want %s %s %s", c.raw, got, c.typ, c.domain, c.id)
		}
	}
}

func TestIsLocalDomain(t *testing.T) {
	for _, d := range []string{"vulnetix.com", "www.vulnetix.com", "api.vulnetix.com", "tea.vulnetix.com"} {
		if !IsLocalDomain(d) {
			t.Errorf("%s should be local", d)
		}
	}
	for _, d := range []string{"example.com", "evilvulnetix.com", "vulnetix.com.evil.io", ""} {
		if IsLocalDomain(d) {
			t.Errorf("%s should not be local", d)
		}
	}
}

func TestResolveUUIDFindsEveryObjectKind(t *testing.T) {
	const org = "org-1"
	keys := []ReleaseKey{{Repo: "acme/store", Commit: "c1"}, {Repo: "acme/store", Commit: "c2"}, {Repo: "acme/api", Commit: "c9"}}
	cases := []struct {
		id   string
		want Subject
	}{
		{ProductUUID(org, "acme/store"), Subject{Kind: SubjectProduct, Repo: "acme/store"}},
		{ComponentUUID(org, "acme/api"), Subject{Kind: SubjectComponent, Repo: "acme/api"}},
		{ProductReleaseUUID(org, "acme/store", "c2"), Subject{Kind: SubjectProductRelease, Repo: "acme/store", Commit: "c2"}},
		{strings.ToUpper(ComponentReleaseUUID(org, "acme/api", "c9")), Subject{Kind: SubjectComponentRelease, Repo: "acme/api", Commit: "c9"}},
	}
	for _, c := range cases {
		got, ok := ResolveUUID(org, c.id, keys)
		if !ok || got != c.want {
			t.Errorf("ResolveUUID(%s) = %+v %v, want %+v", c.id, got, ok, c.want)
		}
	}
	if _, ok := ResolveUUID("other-org", ProductUUID(org, "acme/store"), keys); ok {
		t.Error("a UUID minted for one tenant must not resolve for another")
	}
	if _, ok := ResolveUUID(org, "00000000-0000-0000-0000-000000000000", keys); ok {
		t.Error("an unknown UUID must not resolve")
	}
}

func TestSeedsForMatchesTheIndexProducts(t *testing.T) {
	s := SeedsFor("org-1", []ReleaseKey{{Repo: "acme/store", Commit: "a"}, {Repo: "acme/store", Commit: "b"}, {Repo: "acme/api", Commit: "c"}})
	if len(s.Products) != 2 {
		t.Fatalf("one product per repository, got %d", len(s.Products))
	}
	if s.Products[0].ID != ProductUUID("org-1", "acme/store") || s.Products[0].PURL != "pkg:github/acme/store" {
		t.Errorf("seed = %+v", s.Products[0])
	}
}
