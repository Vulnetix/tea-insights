// Package teainsights is the data layer of the Vulnetix Transparency Exchange
// API, shared by vdb-site (which serves TEA and Insights) and vdb-api (which
// accepts a TEI or an Insights CEL expression as an input to its other
// endpoints). It owns identifier derivation and TEI parsing, the tenant's
// Insights inventory, the CEL engine, and the release keys a TEI uuid resolves
// against. Rendering TEA objects stays with vdb-site.
package teainsights

// Identifier derivation for the Transparency Exchange API.
//
// TEA requires every object UUID to be stable "for the lifetime of the
// resource" (doc/tea-uuid-scope.md) and unique within (authoritative domain,
// object type). Vulnetix has no TEA tables to allocate from — the objects are
// projections over scan data — so the UUIDs are *derived* rather than stored:
// a UUIDv5 over a namespace-per-object-type and a natural key.
//
// That buys three things at once:
//   - Stability across restore/re-host, for free. Nothing to migrate, nothing
//     to reassign, because nothing is stored.
//   - No write path. Every TEA endpoint is a pure read, which is what lets the
//     whole surface stay on read replicas.
//   - Tenant isolation baked into the identifier. The tenant's Org UUID is part
//     of every key, so two tenants scanning the same repository name get
//     different TEA UUIDs and neither can guess the other's.
//
// The natural keys are:
//
//	product           <orgId>|<repoFullName>
//	component         <orgId>|<repoFullName>
//	productRelease    <orgId>|<repoFullName>@<gitCommit>
//	componentRelease  <orgId>|<repoFullName>@<gitCommit>
//
// TEA Artifact UUIDs are not derived: the Artifact table's primary key is
// already a UUID, and reusing it turns artifact lookup into a primary-key hit.

import (
	"encoding/base64"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Domain is the authoritative domain for every TEI this server mints, and
// the DNS name a consumer resolves to find /.well-known/tea.
const Domain = "vulnetix.com"

// Per-object-type namespaces. Each is a UUIDv5 of a type-scoped URL under the
// URL namespace, which is what keeps a product UUID and a component UUID
// distinct even though they share a natural key.
var (
	teaNSProduct          = Namespace("product")
	teaNSComponent        = Namespace("component")
	teaNSProductRelease   = Namespace("productRelease")
	teaNSComponentRelease = Namespace("componentRelease")

	// Insights answers are not TEA objects, but their CycloneDX serial numbers
	// are derived the same way so an identical query yields an identical
	// document.
	NSInsights = Namespace("insights")

	// Distributions are TEA objects with their own UUID scope.
	NSDistribution = Namespace("distribution")
)

// DistributionUUID identifies one delivered file of one release.
func DistributionUUID(repo, version, assetName string) string {
	return uuid.NewSHA1(NSDistribution, []byte(repo+"@"+version+"#"+assetName)).String()
}

func Namespace(objectType string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("https://"+Domain+"/tea/v1#"+objectType))
}

func ProductUUID(orgID, repo string) string {
	return uuid.NewSHA1(teaNSProduct, []byte(orgID+"|"+repo)).String()
}

func ComponentUUID(orgID, repo string) string {
	return uuid.NewSHA1(teaNSComponent, []byte(orgID+"|"+repo)).String()
}

func ProductReleaseUUID(orgID, repo, commit string) string {
	return uuid.NewSHA1(teaNSProductRelease, []byte(orgID+"|"+repo+"@"+commit)).String()
}

func ComponentReleaseUUID(orgID, repo, commit string) string {
	return uuid.NewSHA1(teaNSComponentRelease, []byte(orgID+"|"+repo+"@"+commit)).String()
}

// RepoPURL renders a repository as a Package URL. Every product here is a
// git repository, and pkg:github is the canonical purl type for one, so this is
// derivable rather than stored. Non-GitHub hosts fall back to pkg:generic so
// the identifier list is never empty (the schema requires the key, and an empty
// list would make the object unusable for correlation).
func RepoPURL(repo, version string) string {
	suffix := ""
	if version != "" {
		suffix = "@" + version
	}
	owner, name, ok := strings.Cut(repo, "/")
	if !ok || owner == "" || name == "" {
		return "pkg:generic/" + url.PathEscape(repo) + suffix
	}
	return "pkg:github/" + url.PathEscape(owner) + "/" + url.PathEscape(name) + suffix
}

// UUIDTEI renders the `urn:tei:uuid:` form for a product release. This is
// the TEI a consumer feeds back into /discovery.
func UUIDTEI(id string) string {
	return "urn:tei:uuid:" + Domain + ":" + id
}

// PURLTEI renders the `urn:tei:purl:` form for a product release.
func PURLTEI(purl string) string {
	return "urn:tei:purl:" + Domain + ":" + purl
}

// UUIDTEIURI renders the TEA 1.0.0 `tei://<domain>/uuid/<id>` form.
func UUIDTEIURI(id string) string {
	return "tei://" + Domain + "/uuid/" + id
}

// PURLTEIURI renders the TEA 1.0.0 `tei://<domain>/purl/<id>` form, where the
// id is the Package URL base64url encoded without padding.
func PURLTEIURI(purl string) string {
	return "tei://" + Domain + "/purl/" + base64.RawURLEncoding.EncodeToString([]byte(purl))
}

// ToURIForm converts a `urn:tei:` identifier to the 1.0.0 `tei://` form. An
// input already in URI form is returned unchanged, and so is one that does not
// parse.
func ToURIForm(raw string) string {
	t, ok := ParseTEI(raw)
	if !ok {
		return raw
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(raw)), "tei://") {
		return strings.TrimSpace(raw)
	}
	id := t.ID
	if t.Type == "purl" {
		id = base64.RawURLEncoding.EncodeToString([]byte(id))
	} else {
		id = url.PathEscape(id)
	}
	return "tei://" + t.Domain + "/" + t.Type + "/" + id
}

// ToURNForm converts a `tei://` identifier to the 0.x `urn:tei:` form, the form
// the index stores. A `urn:tei:` input is returned unchanged.
func ToURNForm(raw string) string {
	t, ok := ParseTEI(raw)
	if !ok {
		return raw
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(raw)), "urn") {
		return strings.TrimSpace(raw)
	}
	return "urn:tei:" + t.Type + ":" + t.Domain + ":" + t.ID
}

// TEI is a decomposed Transparency Exchange Identifier.
type TEI struct {
	Type   string // uuid | purl | hash | swid | …
	Domain string
	ID     string
}

// ParseTEI decomposes `urn:tei:<type>:<domain>:<unique-identifier>` (TEA 0.x)
// and `tei://<domain>/<type>/<unique-identifier>` (TEA 1.0.0). For the URI form
// the identifier is percent-decoded, and a purl identifier is base64url decoded
// (padding tolerated), so TEI.ID always carries the Package URL itself.
//
// The unique-identifier may itself contain colons — a PURL always does — so the
// split is bounded to four parts and the remainder is taken verbatim. Callers
// receive the value percent-decoded already: RFC 3986 encoding is mandated on
// the wire for the /discovery query parameter, and Go's query parser has
// decoded it once by the time we see it, but clients that double-encode a PURL
// are common enough to be worth tolerating.
func ParseTEI(raw string) (TEI, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return TEI{}, false
	}
	// Tolerate a still-encoded URN from a client that encoded twice.
	if strings.HasPrefix(strings.ToLower(s), "urn%3a") {
		if dec, err := url.QueryUnescape(s); err == nil {
			s = dec
		}
	}
	if len(s) > 6 && strings.EqualFold(s[:6], "tei://") {
		return parseTEIURI(s[6:])
	}
	parts := strings.SplitN(s, ":", 4)
	if len(parts) != 4 {
		return TEI{}, false
	}
	if !strings.EqualFold(parts[0], "urn") || !strings.EqualFold(parts[1], "tei") {
		return TEI{}, false
	}
	t := strings.ToLower(parts[2])
	rest := parts[3]

	// The domain is everything up to the first colon of the remainder; the
	// unique identifier is the rest, colons and all.
	domain, id, ok := strings.Cut(rest, ":")
	if !ok || domain == "" || id == "" {
		return TEI{}, false
	}
	return TEI{Type: t, Domain: strings.ToLower(domain), ID: id}, true
}

// parseTEIURI parses what follows the `tei://` scheme: `<domain>/<type>/<id>`,
// where the id is a single path segment.
func parseTEIURI(rest string) (TEI, bool) {
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return TEI{}, false
	}
	id, err := url.PathUnescape(parts[2])
	if err != nil || id == "" {
		return TEI{}, false
	}
	t := strings.ToLower(parts[1])
	if t == "purl" {
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(id, "="))
		if err != nil || len(raw) == 0 {
			return TEI{}, false
		}
		id = string(raw)
	}
	return TEI{Type: t, Domain: strings.ToLower(parts[0]), ID: id}, true
}

// IsLocalDomain reports whether a TEI's domain part names this server's
// authority. Only TEIs in our own namespace can be resolved here; anything else
// is another publisher's identifier and is reported as unknown.
func IsLocalDomain(domain string) bool {
	switch domain {
	case Domain, "www." + Domain, "api." + Domain, "tea." + Domain:
		return true
	}
	return false
}

// Timestamp renders a millisecond epoch the way TEA documents carry dates, or
// "" when there is none.
func Timestamp(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05Z")
}
