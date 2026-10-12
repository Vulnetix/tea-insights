package teainsights

// The Insights object model.
//
// The Insights API (insights/readme.md) is "limited transparency": rather than
// making a consumer ingest whole SBOMs to answer "does product X use log4j and
// is it exposed to log4shell", it lets them ask that question directly and
// returns only the answer, as a CycloneDX fragment.
//
// That requires a queryable, CycloneDX-derived model of the tenant's software.
// This file builds one and caches it per tenant, in the same shape the
// specification's own CEL examples assume:
//
//	productId == 'XYZ' && component.type == 'third-party'
//	productId == 'XYZ' && component.licenseType == 'Open Source'
//	productId == 'XYZ' && component.vulnerabilities.size() > 0
//	productId == 'XYZ' && component.name == 'log4j' && component.vulnerabilities.contains('log4shell')
//	productId == 'XYZ' && component.cryptography != null
//
// So the evaluation unit is one (product, component) pair and the expression is
// a predicate over it. That is a much smaller thing than a general query
// language, and it is exactly what the examples describe.
//
// Size makes the whole approach viable: the reference tenant's inventory is
// ~5,400 components across 39 products — a few megabytes — so the model is
// built once per tenant and every query after that is in-memory. A query that
// had to touch the database per component would be unusable at any interesting
// expression complexity.

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

// teaInsightsTTL is how long an inventory is fresh. Longer than the TEA index
// TTL because the inventory is much more expensive to build and changes only
// when a new scan lands, not on every observation.
const teaInsightsTTL = 5 * time.Minute

// teaInsightsStaleFor is how long a past-TTL inventory is still served while a
// fresh one is built in the background. Building one is heavy for a large tenant
// (the vulnerability query alone reads every finding row the org has: 10 s warm,
// 22 s cold, 495k of 1.8M rows), and the Insights page asks for several at once,
// so the request that found the cache expired paid for it and the rest queued
// behind it. An hour-old inventory answers "what does this product contain" as
// well as a five-minute-old one; the refresh is what keeps it current.
const teaInsightsStaleFor = time.Hour

// teaInsightsBuildLimit bounds one build, which runs detached from the request.
const teaInsightsBuildLimit = 2 * time.Minute

// teaInsightsRetryAfter spaces background rebuilds of one org's inventory.
const teaInsightsRetryAfter = 30 * time.Second

var (
	teaInsightsCache  = newLRUCache(64, teaInsightsStaleFor)
	teaInsightsFlight singleflight.Group

	// BuildFunc builds an inventory; tests replace it.
	BuildFunc = BuildInventory

	// teaInsightsLastTry is when a background rebuild of an org's inventory last started.
	teaInsightsLastTry sync.Map
)

// Component is one component of one product, in CycloneDX terms.
type Component struct {
	// Identity
	BOMRef    string
	Name      string
	Group     string
	Version   string
	PURL      string
	CPE       string
	Type      string // CycloneDX component type: library | application | …
	Ecosystem string

	// Provenance within the product.
	//
	// There is deliberately no `thirdParty` field. TEA is a transparency log for
	// *all* software — open source and internal alike — and "third party" is a
	// reporting perspective, not a property of a component: the same library is
	// third-party to its consumer and first-party to the team that publishes it,
	// and both are legitimate views of the same record. Baking one of them into
	// the data would pick a side on the consumer's behalf and make the other
	// view unaskable.
	//
	// So the facts are published and the perspective is expressed by the query:
	// `component.origin == 'external'` is one reader's third-party, and
	// `component.isProduct` is the other reader's first-party.
	Scope       string // required | optional | excluded
	Direct      bool
	Development bool
	Transitive  bool

	// Relationship is "self" when the component *is* the product (its own
	// source tree), "dependency" when the product consumes it.
	Relationship string

	// Origin is "internal" when the component is published from a namespace
	// this tenant itself publishes, "external" otherwise. It is a statement
	// about publishing, not about licensing or trust.
	Origin string

	// IsProduct is true when this component is *also* a product in this
	// transparency log — the case TEA exists for. An open-source dependency
	// that the tenant also publishes is both at once.
	IsProduct  bool
	ProductRef string // the TEA product UUID, when IsProduct
	Publisher  string
	Supplier   string
	Author     string

	// Licensing
	Licenses    []string
	LicenseType string // Open Source | Commercial | Unknown

	// Findings that name this component, by every identifier a consumer might
	// know them as — the CVE, the advisory id, and any alias such as
	// "log4shell", which is what the specification's own example asks for.
	Vulnerabilities []string

	// Supply-chain evidence about the component, absent (null) when none is
	// held. Scorecard describes an open-source project's practices; provenance
	// and attestations describe how a specific artifact was built.
	Scorecard    map[string]any
	Provenance   []any
	Attestations []any

	// Cryptography and AI facets, present only on components that have them.
	// The examples test `component.cryptography != null`, so absence must be a
	// null rather than an empty object.
	Cryptography map[string]any
	AI           map[string]any

	// activation is the CEL view of this component, built once when the
	// inventory is built. A component is immutable for the inventory's
	// lifetime, so rebuilding this per request would allocate a map and two
	// slices for every component on every query — which was the dominant cost
	// of a static query before it was hoisted here.
	activation map[string]any
}

// Product is one product and everything queryable about it.
type Product struct {
	ID         string // the TEA product UUID — the identifier a consumer already holds
	Name       string // owner/repo
	PURL       string
	Components []*Component

	// ProcessAttestation is the SSDF / BSIMM / OWASP SAMM style claim the
	// examples query. It is nil unless the platform actually holds one; a
	// fabricated attestation in a machine-readable answer is worse than none.
	ProcessAttestation map[string]any

	// activation is the CEL view, built once with the inventory.
	activation map[string]any
}

// Inventory is the whole tenant model.
type Inventory struct {
	OrgID      string
	Products   []*Product
	ByID       map[string]*Product
	ByName     map[string]*Product
	ByPURL     map[string]*Product
	Components int
	BuiltAt    time.Time
}

// teaInsightsComponentsQuery loads the component set of each product's most
// recent composition scan.
//
// "Most recent" rather than "all": a product's inventory is what it is *now*,
// and unioning every scan it ever had would answer questions about versions
// nobody ships. DISTINCT ON gives the latest run per repository in one pass.
const teaInsightsComponentsQuery = `
	WITH latest AS (
	    SELECT DISTINCT ON (s."repoName") s."repoName" AS repo, s.uuid AS run
	      FROM "ScannerRun" s
	     WHERE s."orgId" = $1 AND s.category = 'SCA' AND s."repoName" IS NOT NULL
	     ORDER BY s."repoName", s."createdAt" DESC
	)
	SELECT l.repo,
	       d.name,
	       COALESCE(d."group", ''),
	       COALESCE(d.version, ''),
	       COALESCE(d.purl, ''),
	       COALESCE(d.cpe, ''),
	       COALESCE(d.license, ''),
	       COALESCE(d."packageEcosystem", ''),
	       COALESCE(d."componentType", ''),
	       COALESCE(c.scope, ''),
	       c."isDirect", c."isDev", c."isTransitive",
	       COALESCE(d.publisher, ''), COALESCE(d.supplier, ''), COALESCE(d.author, '')
	  FROM latest l
	  JOIN "CliScanDependency" c ON c."scannerRunUuid" = l.run
	  JOIN "Dependency" d ON d.key = c."dependencyKey"`

// teaInsightsVulnQuery maps each (product, component purl) to the identifiers
// of the findings that name it.
//
// Aliases are unioned in on purpose: the specification's worked example asks
// for `contains('log4shell')`, and "log4shell" is an alias, never a finding id.
// A model that only knew canonical ids would answer "no" to the one question
// the specification uses to motivate the whole API.
const teaInsightsVulnQuery = `
	SELECT "repoName", purl,
	       array_agg(DISTINCT "findingId") FILTER (WHERE "findingId" <> ''),
	       string_agg(DISTINCT COALESCE(aliases, ''), ',') FILTER (WHERE COALESCE(aliases, '') <> '')
	  FROM "Finding"
	 WHERE "orgId" = $1 AND purl IS NOT NULL AND purl <> '' AND "repoName" IS NOT NULL
	 GROUP BY 1, 2`

// teaInsightsCryptoQuery loads each product's cryptographic assets from its
// most recent CBOM.
const teaInsightsCryptoQuery = `
	WITH latest AS (
	    SELECT DISTINCT ON ("repoName") "repoName" AS repo, uuid
	      FROM "CbomScan"
	     WHERE "orgId" = $1 AND "repoName" IS NOT NULL
	     ORDER BY "repoName", "createdAt" DESC
	)
	SELECT l.repo, c.name, c.category, COALESCE(c."assetType", ''),
	       COALESCE(c.primitive, ''), COALESCE(c."pqcStatus", ''),
	       COALESCE(c.purl, ''), COALESCE(c."componentType", ''),
	       c."nistQuantumSecurityLevel"
	  FROM latest l
	  JOIN "CbomComponent" c ON c."cbomScanUuid" = l.uuid`

// teaInsightsScorecardQuery loads OpenSSF Scorecard results for the components
// in the tenant's inventory.
//
// Scorecard describes an open-source *project's* practices, so it attaches to a
// component by the repository that publishes it — which is the same subject the
// project's own transparency log would call a product. This is the clearest
// case for TEA holding one record per subject rather than one per perspective.
//
// The join decodes the percent-escaped namespace separators Go module purls
// carry: `pkg:golang/github.com%2Fmoby%2Fmoby@v1` names `github.com/moby/moby`.
// DISTINCT ON keeps the most recent assessment per repository.
// The subject set is scoped to each product's most recent scan, exactly as the
// component query is. Scoping to the org instead would read every dependency
// row the tenant has ever recorded — 6.3 million for the reference tenant, most
// of them historical — to answer a question about what it ships today.
const teaInsightsScorecardQuery = `
	WITH latest AS (
	    SELECT DISTINCT ON (s."repoName") s.uuid AS run
	      FROM "ScannerRun" s
	     WHERE s."orgId" = $1 AND s.category = 'SCA' AND s."repoName" IS NOT NULL
	     ORDER BY s."repoName", s."createdAt" DESC
	), subjects AS (
	    SELECT DISTINCT
	           replace(replace(
	             regexp_replace(split_part(substring(d.purl FROM 'pkg:[^/]+/(.*)'), '@', 1), '\?.*$', ''),
	             '%2F', '/'), '%2f', '/') AS repo_path
	      FROM latest l
	      JOIN "CliScanDependency" c ON c."scannerRunUuid" = l.run
	      JOIN "Dependency" d ON d.key = c."dependencyKey"
	     WHERE d.purl IS NOT NULL AND d.purl <> ''
	)
	SELECT DISTINCT ON (sc."repositoryName")
	       sc."repositoryName", sc."overallScore", sc."scorecardVersion",
	       sc."repositoryCommit", sc.date, sc.uuid
	  FROM "OpenSSFScorecard" sc
	  JOIN subjects s ON s.repo_path = sc."repositoryName"
	 ORDER BY sc."repositoryName", sc.date DESC`

// teaInsightsScorecardCheckQuery loads the individual checks behind those
// results. A bare overall score is not actionable; the checks are what a
// consumer asks about ("is this project signing its releases").
const teaInsightsScorecardCheckQuery = `
	SELECT ck."scorecardUuid", ck.name, ck.score, ck.reason
	  FROM "OpenSSFScorecardCheck" ck
	 WHERE ck."scorecardUuid" = ANY($1)`

// teaInsightsProvenanceQuery loads SLSA provenance and build attestations for
// the tenant's components, keyed by the dependency they describe.
// Driven from the provenance tables rather than from the dependency rows: there
// are a handful of provenance records and millions of dependency rows, so
// starting from the small side and confirming membership is orders of magnitude
// cheaper than the reverse.
const teaInsightsProvenanceQuery = `
	WITH latest AS (
	    SELECT DISTINCT ON (s."repoName") s.uuid AS run
	      FROM "ScannerRun" s
	     WHERE s."orgId" = $1 AND s.category = 'SCA' AND s."repoName" IS NOT NULL
	     ORDER BY s."repoName", s."createdAt" DESC
	)
	SELECT d.purl, 'slsa' AS kind, p."sourceRepository", p.commit, p.url, p.verified
	  FROM "DependencySLSAProvenance" p
	  JOIN "Dependency" d ON d.key = p."dependencyKey"
	 WHERE d.purl IS NOT NULL AND d.purl <> ''
	   AND EXISTS (SELECT 1 FROM latest l
	               JOIN "CliScanDependency" c ON c."scannerRunUuid" = l.run
	              WHERE c."dependencyKey" = p."dependencyKey")
	UNION ALL
	SELECT d.purl, a.type, COALESCE(a."sourceRepository", ''), COALESCE(a.commit, ''), a.url, a.verified
	  FROM "DependencyAttestation" a
	  JOIN "Dependency" d ON d.key = a."dependencyKey"
	 WHERE d.purl IS NOT NULL AND d.purl <> ''
	   AND EXISTS (SELECT 1 FROM latest l
	               JOIN "CliScanDependency" c ON c."scannerRunUuid" = l.run
	              WHERE c."dependencyKey" = a."dependencyKey")`

// teaInsightsAIQuery loads each product's AI assets from its most recent
// AI-BOM.
const teaInsightsAIQuery = `
	WITH latest AS (
	    SELECT DISTINCT ON ("repoName") "repoName" AS repo, uuid
	      FROM "AibomScan"
	     WHERE "orgId" = $1 AND "repoName" IS NOT NULL
	     ORDER BY "repoName", "createdAt" DESC
	)
	SELECT l.repo, c.name, c.category, COALESCE(c."componentType", ''),
	       COALESCE(c.version, ''), COALESCE(c.purl, ''), COALESCE(c.provider, ''),
	       COALESCE(c.family, ''), COALESCE(c.task, ''), COALESCE(c."modelArchitecture", '')
	  FROM latest l
	  JOIN "AibomComponent" c ON c."aibomScanUuid" = l.uuid`

// Querier is the one database method the inventory needs. Both services'
// db.Pool (a *pgxpool.Pool) satisfies it.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// ProductSeed is one product of the tenant's TEA catalogue: the TEA product
// UUID, the repository it projects, and that repository's purl.
type ProductSeed struct {
	ID   string // TEA product UUID
	Repo string // owner/repo
	PURL string
}

// Seeds is the catalogue an inventory is built over. vdb-site passes the
// products of its TEA index; a caller without one builds them with SeedsFor.
type Seeds struct {
	OrgID    string
	Products []ProductSeed
}

// LoadInventory returns the tenant's model, building it at most once per TTL
// across concurrent callers. An expired model is served while a fresh one is
// built behind it.
func LoadInventory(ctx context.Context, q Querier, seeds Seeds) (*Inventory, error) {
	saasOrgID := seeds.OrgID
	if saasOrgID == "" {
		return &Inventory{
			ByID:   map[string]*Product{},
			ByName: map[string]*Product{},
			ByPURL: map[string]*Product{},
		}, nil
	}
	if v, ok := teaInsightsCache.Get(saasOrgID); ok {
		inv := v.(*Inventory)
		if time.Since(inv.BuiltAt) >= teaInsightsTTL {
			// Past its TTL but still good: answer from it now, rebuild behind it. A
			// rebuild that failed is not retried for teaInsightsRetryAfter, so a sick
			// database is not asked for the heavy queries again by every request.
			if last, ok := teaInsightsLastTry.Load(saasOrgID); !ok || time.Since(last.(time.Time)) >= teaInsightsRetryAfter {
				teaInsightsLastTry.Store(saasOrgID, time.Now())
				go func() { _, _ = teaBuildShared(q, seeds, saasOrgID) }()
			}
		}
		return inv, nil
	}
	// No inventory at all: the caller waits for the build (shared with every other
	// caller), but the build is not tied to this caller's request, so one client
	// hanging up does not fail the others.
	ch := teaBuildSharedChan(q, seeds, saasOrgID)
	select {
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.(*Inventory), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// teaBuildSharedChan builds the org's inventory once however many callers ask, and
// caches it. The build runs on its own context, bounded by teaInsightsBuildLimit.
func teaBuildSharedChan(q Querier, seeds Seeds, saasOrgID string) <-chan singleflight.Result {
	return teaInsightsFlight.DoChan("insights:"+saasOrgID, func() (any, error) {
		bctx, cancel := context.WithTimeout(context.Background(), teaInsightsBuildLimit)
		defer cancel()
		inv, err := BuildFunc(bctx, q, seeds)
		if err != nil {
			log.Printf("[tea] insights inventory for %s: %v", saasOrgID, err)
			return nil, err
		}
		teaInsightsCache.Set(saasOrgID, inv)
		return inv, nil
	})
}

func teaBuildShared(q Querier, seeds Seeds, saasOrgID string) (*Inventory, error) {
	res := <-teaBuildSharedChan(q, seeds, saasOrgID)
	if res.Err != nil {
		return nil, res.Err
	}
	return res.Val.(*Inventory), nil
}

func BuildInventory(ctx context.Context, q Querier, seeds Seeds) (*Inventory, error) {
	saasOrgID := seeds.OrgID
	inv := &Inventory{
		OrgID:   saasOrgID,
		ByID:    map[string]*Product{},
		ByName:  map[string]*Product{},
		ByPURL:  map[string]*Product{},
		BuiltAt: time.Now().UTC(),
	}

	// Products come from the TEA index, so an Insights productId is the same
	// identifier the TEA endpoints publish. A consumer that discovered a
	// product through TEA can query it here without a second lookup.
	for _, p := range seeds.Products {
		prod := &Product{ID: p.ID, Name: p.Repo, PURL: p.PURL}
		inv.Products = append(inv.Products, prod)
		inv.ByID[prod.ID] = prod
		inv.ByName[strings.ToLower(prod.Name)] = prod
		inv.ByPURL[PURLBase(prod.PURL)] = prod
	}

	// The four loads are independent; the slowest sets the floor rather than
	// the sum.
	var (
		components []componentRow
		vulns      map[string][]string
		cryptos    map[string][]map[string]any
		ais        map[string][]map[string]any
		scorecards map[string]map[string]any
		provenance map[string][]any
	)
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() (err error) { components, err = teaQueryInsightsComponents(gctx, q, saasOrgID); return })
	g.Go(func() (err error) { vulns, err = teaQueryInsightsVulns(gctx, q, saasOrgID); return })
	g.Go(func() (err error) { cryptos, err = teaQueryInsightsCrypto(gctx, q, saasOrgID); return })
	g.Go(func() (err error) { ais, err = teaQueryInsightsAI(gctx, q, saasOrgID); return })
	g.Go(func() (err error) { scorecards, err = teaQueryInsightsScorecards(gctx, q, saasOrgID); return })
	g.Go(func() (err error) { provenance, err = teaQueryInsightsProvenance(gctx, q, saasOrgID); return })
	if err := g.Wait(); err != nil {
		return nil, err
	}

	for _, row := range components {
		prod := inv.ByName[strings.ToLower(row.Repo)]
		if prod == nil {
			continue // a scan for a repository the TEA index does not cover
		}
		c := &Component{
			BOMRef:       teaInsightsBOMRef(prod.ID, row),
			Name:         row.Name,
			Group:        row.Group,
			Version:      row.Version,
			PURL:         row.PURL,
			CPE:          row.CPE,
			Type:         teaInsightsCDXType(row.ComponentType),
			Ecosystem:    row.Ecosystem,
			Scope:        teaInsightsScope(row.Scope),
			Direct:       row.Direct,
			Development:  row.Dev,
			Transitive:   row.Transitive,
			Relationship: "dependency",
			Publisher:    row.Publisher,
			Supplier:     row.Supplier,
			Author:       row.Author,
		}
		// Is this component *also* something this log publishes? That is the
		// question TEA exists to make askable, and it is answered from the
		// catalogue rather than assumed: a dependency that the tenant also
		// ships is internal and external at once, and both readings are true.
		if owner := ResolveProduct(inv, row.PURL, row.Name); owner != nil {
			c.IsProduct = true
			c.ProductRef = owner.ID
			c.Origin = "internal"
		} else {
			c.Origin = "external"
		}
		if row.License != "" {
			c.Licenses = SplitLicenses(row.License)
		}
		c.LicenseType = LicenseType(c.Licenses)
		if row.PURL != "" {
			c.Vulnerabilities = vulns[row.Repo+"|"+row.PURL]
			base := PURLBase(row.PURL)
			c.Scorecard = scorecards[base]
			c.Provenance = provenance[base]
		}
		prod.Components = append(prod.Components, c)
		inv.Components++
	}

	// Cryptographic and AI assets are components in their own right: a
	// CycloneDX cryptographic-asset is a component, and the example query
	// `component.cryptography != null` only makes sense if they are in the same
	// component space as everything else.
	for repo, assets := range cryptos {
		prod := inv.ByName[strings.ToLower(repo)]
		if prod == nil {
			continue
		}
		for _, a := range assets {
			name, _ := a["name"].(string)
			c := &Component{
				BOMRef:       teaInsightsAssetRef(prod.ID, "crypto", name, a),
				Name:         name,
				Type:         "cryptographic-asset",
				Scope:        "required",
				LicenseType:  "Unknown",
				Cryptography: a,
			}
			if purl, _ := a["purl"].(string); purl != "" {
				c.PURL = purl
			}
			prod.Components = append(prod.Components, c)
			inv.Components++
		}
	}
	for repo, assets := range ais {
		prod := inv.ByName[strings.ToLower(repo)]
		if prod == nil {
			continue
		}
		for _, a := range assets {
			name, _ := a["name"].(string)
			cdxType, _ := a["componentType"].(string)
			c := &Component{
				BOMRef:      teaInsightsAssetRef(prod.ID, "ai", name, a),
				Name:        name,
				Type:        teaInsightsAIType(cdxType),
				Scope:       "required",
				LicenseType: "Unknown",
				AI:          a,
			}
			if v, _ := a["version"].(string); v != "" {
				c.Version = v
			}
			if purl, _ := a["purl"].(string); purl != "" {
				c.PURL = purl
			}
			prod.Components = append(prod.Components, c)
			inv.Components++
		}
	}

	// A total order over components keeps identical queries byte-identical,
	// which is what lets a response be cached and compared.
	for _, p := range inv.Products {
		sort.Slice(p.Components, func(i, j int) bool {
			a, b := p.Components[i], p.Components[j]
			if a.Name != b.Name {
				return a.Name < b.Name
			}
			if a.Version != b.Version {
				return a.Version < b.Version
			}
			return a.BOMRef < b.BOMRef
		})
	}
	inv.Prepare()
	return inv, nil
}

// Prepare freezes the CEL view of every product and component, so a query
// evaluates against prepared data. BuildInventory calls it; a caller that
// assembles an inventory by hand (a test, a fixture) must call it before
// Evaluate.
func (inv *Inventory) Prepare() {
	for _, p := range inv.Products {
		p.activation = ProductActivation(p)
		for _, c := range p.Components {
			c.activation = ComponentActivation(p, c)
		}
	}
}

// componentRow is one raw row of the component query.
type componentRow struct {
	Repo, Name, Group, Version, PURL, CPE, License, Ecosystem, ComponentType, Scope string
	Direct, Dev, Transitive                                                         bool
	Publisher, Supplier, Author                                                     string
}

// ResolveProduct answers "is this component also a product in this
// log". The purl is the join: a component published as pkg:github/owner/repo is
// the same subject as a product of that name, whoever is reading.
func ResolveProduct(inv *Inventory, purl, name string) *Product {
	if purl != "" {
		if p := inv.ByPURL[PURLBase(purl)]; p != nil {
			return p
		}
	}
	if name != "" {
		if p := inv.ByName[strings.ToLower(name)]; p != nil {
			return p
		}
	}
	return nil
}

// PURLBase strips the version and qualifiers, and decodes the
// percent-escaped namespace separators Go module purls carry, so
// `pkg:golang/github.com%2Fmoby%2Fmoby@v1` and `pkg:github/moby/moby` reduce to
// the same subject.
func PURLBase(purl string) string {
	s := purl
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '@'); i > 0 {
		s = s[:i]
	}
	s = strings.ReplaceAll(s, "%2F", "/")
	s = strings.ReplaceAll(s, "%2f", "/")
	// Reduce to the host-qualified path so purl types differ without changing
	// the subject: pkg:golang/github.com/moby/moby → github.com/moby/moby.
	if i := strings.IndexByte(s, '/'); i >= 0 {
		if rest := s[i+1:]; strings.HasPrefix(rest, "github.com/") {
			return strings.ToLower(rest)
		}
		if strings.HasPrefix(s, "pkg:github/") {
			return strings.ToLower("github.com/" + strings.TrimPrefix(s, "pkg:github/"))
		}
	}
	return strings.ToLower(s)
}

func teaQueryInsightsComponents(ctx context.Context, q Querier, saasOrgID string) ([]componentRow, error) {
	rows, err := q.Query(ctx, teaInsightsComponentsQuery, saasOrgID)
	if err != nil {
		return nil, fmt.Errorf("insights components: %w", err)
	}
	defer rows.Close()
	var out []componentRow
	for rows.Next() {
		var r componentRow
		if err := rows.Scan(&r.Repo, &r.Name, &r.Group, &r.Version, &r.PURL, &r.CPE,
			&r.License, &r.Ecosystem, &r.ComponentType, &r.Scope,
			&r.Direct, &r.Dev, &r.Transitive,
			&r.Publisher, &r.Supplier, &r.Author); err != nil {
			return nil, fmt.Errorf("insights components scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func teaQueryInsightsVulns(ctx context.Context, q Querier, saasOrgID string) (map[string][]string, error) {
	rows, err := q.Query(ctx, teaInsightsVulnQuery, saasOrgID)
	if err != nil {
		return nil, fmt.Errorf("insights vulnerabilities: %w", err)
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var repo, purl string
		var ids []string
		var aliases *string
		if err := rows.Scan(&repo, &purl, &ids, &aliases); err != nil {
			return nil, fmt.Errorf("insights vulnerabilities scan: %w", err)
		}
		set := map[string]struct{}{}
		add := func(s string) {
			s = strings.TrimSpace(s)
			if s != "" {
				set[s] = struct{}{}
			}
		}
		for _, id := range ids {
			add(id)
		}
		if aliases != nil {
			for _, a := range strings.Split(*aliases, ",") {
				add(a)
			}
		}
		merged := make([]string, 0, len(set))
		for s := range set {
			merged = append(merged, s)
		}
		sort.Strings(merged)
		out[repo+"|"+purl] = merged
	}
	return out, rows.Err()
}

func teaQueryInsightsCrypto(ctx context.Context, q Querier, saasOrgID string) (map[string][]map[string]any, error) {
	rows, err := q.Query(ctx, teaInsightsCryptoQuery, saasOrgID)
	if err != nil {
		return nil, fmt.Errorf("insights cryptography: %w", err)
	}
	defer rows.Close()
	out := map[string][]map[string]any{}
	for rows.Next() {
		var repo, name, category, assetType, primitive, pqc, purl, componentType string
		var nistLevel int
		if err := rows.Scan(&repo, &name, &category, &assetType, &primitive, &pqc,
			&purl, &componentType, &nistLevel); err != nil {
			return nil, fmt.Errorf("insights cryptography scan: %w", err)
		}
		out[repo] = append(out[repo], map[string]any{
			"name":                     name,
			"category":                 category,
			"assetType":                assetType,
			"primitive":                primitive,
			"pqcStatus":                pqc,
			"purl":                     purl,
			"componentType":            componentType,
			"nistQuantumSecurityLevel": int64(nistLevel),
		})
	}
	return out, rows.Err()
}

// teaQueryInsightsScorecards returns Scorecard results keyed by the repository
// path they describe.
func teaQueryInsightsScorecards(ctx context.Context, q Querier, saasOrgID string) (map[string]map[string]any, error) {
	rows, err := q.Query(ctx, teaInsightsScorecardQuery, saasOrgID)
	if err != nil {
		return nil, fmt.Errorf("insights scorecards: %w", err)
	}
	defer rows.Close()

	out := map[string]map[string]any{}
	byUUID := map[string]map[string]any{}
	var uuids []string
	for rows.Next() {
		var repoPath, version, commit, uuid string
		var score float64
		var date int64
		if err := rows.Scan(&repoPath, &score, &version, &commit, &date, &uuid); err != nil {
			return nil, fmt.Errorf("insights scorecards scan: %w", err)
		}
		card := map[string]any{
			"repository":       repoPath,
			"score":            score,
			"scorecardVersion": version,
			"commit":           commit,
			"date":             Timestamp(date),
			"checks":           []any{},
		}
		out[strings.ToLower(repoPath)] = card
		byUUID[uuid] = card
		uuids = append(uuids, uuid)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(uuids) == 0 {
		return out, nil
	}

	checkRows, err := q.Query(ctx, teaInsightsScorecardCheckQuery, uuids)
	if err != nil {
		// The overall scores are still useful without their checks, so a
		// failure here degrades the answer rather than failing the query.
		return out, nil
	}
	defer checkRows.Close()
	for checkRows.Next() {
		var uuid, name, reason string
		var score float64
		if err := checkRows.Scan(&uuid, &name, &score, &reason); err != nil {
			continue
		}
		card := byUUID[uuid]
		if card == nil {
			continue
		}
		checks, _ := card["checks"].([]any)
		card["checks"] = append(checks, map[string]any{
			"name": name, "score": score, "reason": reason,
		})
	}
	return out, nil
}

// teaQueryInsightsProvenance returns build provenance and attestations keyed by
// component purl.
func teaQueryInsightsProvenance(ctx context.Context, q Querier, saasOrgID string) (map[string][]any, error) {
	rows, err := q.Query(ctx, teaInsightsProvenanceQuery, saasOrgID)
	if err != nil {
		return nil, fmt.Errorf("insights provenance: %w", err)
	}
	defer rows.Close()

	out := map[string][]any{}
	for rows.Next() {
		var purl, kind, sourceRepo, commit, url string
		var verified bool
		if err := rows.Scan(&purl, &kind, &sourceRepo, &commit, &url, &verified); err != nil {
			return nil, fmt.Errorf("insights provenance scan: %w", err)
		}
		key := PURLBase(purl)
		out[key] = append(out[key], map[string]any{
			"type":             kind,
			"sourceRepository": sourceRepo,
			"commit":           commit,
			"url":              url,
			"verified":         verified,
		})
	}
	return out, rows.Err()
}

func teaQueryInsightsAI(ctx context.Context, q Querier, saasOrgID string) (map[string][]map[string]any, error) {
	rows, err := q.Query(ctx, teaInsightsAIQuery, saasOrgID)
	if err != nil {
		return nil, fmt.Errorf("insights ai: %w", err)
	}
	defer rows.Close()
	out := map[string][]map[string]any{}
	for rows.Next() {
		var repo, name, category, componentType, version, purl, provider, family, task, arch string
		if err := rows.Scan(&repo, &name, &category, &componentType, &version, &purl,
			&provider, &family, &task, &arch); err != nil {
			return nil, fmt.Errorf("insights ai scan: %w", err)
		}
		out[repo] = append(out[repo], map[string]any{
			"name":              name,
			"category":          category,
			"componentType":     componentType,
			"version":           version,
			"purl":              purl,
			"provider":          provider,
			"family":            family,
			"task":              task,
			"modelArchitecture": arch,
		})
	}
	return out, rows.Err()
}

// ── Normalisation ──────────────────────────────────────────────────────────

// teaInsightsCDXType maps a stored component type onto the CycloneDX enum. An
// unrecognised value becomes "library", which is the enum member that describes
// a dependency and keeps the emitted BOM schema-valid.
func teaInsightsCDXType(stored string) string {
	switch strings.ToLower(strings.TrimSpace(stored)) {
	case "application":
		return "application"
	case "framework":
		return "framework"
	case "container":
		return "container"
	case "operating-system", "operating_system":
		return "operating-system"
	case "device":
		return "device"
	case "file":
		return "file"
	case "firmware":
		return "firmware"
	case "platform":
		return "platform"
	case "machine-learning-model":
		return "machine-learning-model"
	case "data":
		return "data"
	case "cryptographic-asset":
		return "cryptographic-asset"
	default:
		return "library"
	}
}

func teaInsightsAIType(stored string) string {
	switch strings.ToLower(strings.TrimSpace(stored)) {
	case "machine-learning-model", "model":
		return "machine-learning-model"
	case "application":
		return "application"
	default:
		return "library"
	}
}

// teaInsightsScope maps onto CycloneDX's scope enum; anything else is dropped
// rather than guessed, since the schema constrains it.
func teaInsightsScope(stored string) string {
	switch strings.ToLower(strings.TrimSpace(stored)) {
	case "required", "runtime", "compile", "":
		return "required"
	case "optional", "dev", "development", "test":
		return "optional"
	case "excluded":
		return "excluded"
	default:
		return "required"
	}
}

// SplitLicenses splits a stored license expression into individual
// identifiers. Compound SPDX expressions ("MIT OR Apache-2.0") are kept whole
// as well as split, so a query for either member matches.
func SplitLicenses(stored string) []string {
	stored = strings.TrimSpace(stored)
	if stored == "" {
		return nil
	}
	set := map[string]struct{}{stored: {}}
	repl := strings.NewReplacer(" OR ", "\x00", " AND ", "\x00", " WITH ", "\x00",
		"(", "", ")", "", " or ", "\x00", " and ", "\x00")
	for _, part := range strings.Split(repl.Replace(stored), "\x00") {
		if p := strings.TrimSpace(part); p != "" {
			set[p] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// LicenseType answers the example query
// `component.licenseType == 'Open Source'`.
//
// A license is treated as open source when it carries an SPDX identifier that
// is not one of the proprietary markers. "Unknown" is returned rather than a
// guess when nothing was recorded — a component silently classified as open
// source because its license was missing would be a wrong answer to a
// compliance question.
func LicenseType(licenses []string) string {
	if len(licenses) == 0 {
		return "Unknown"
	}
	for _, l := range licenses {
		switch strings.ToUpper(strings.TrimSpace(l)) {
		case "", "NOASSERTION", "NONE", "UNKNOWN", "PROPRIETARY", "COMMERCIAL", "LICENSEREF-PROPRIETARY":
			continue
		default:
			return "Open Source"
		}
	}
	return "Commercial"
}

// teaInsightsBOMRef builds a bom-ref that is unique across the whole answer.
//
// The product is always part of it, even when a purl is available. CycloneDX
// requires the `components` array to hold distinct items, and the same library
// at the same version legitimately appears in several products — with a
// purl-only ref those entries serialise identically and the document is
// invalid. Scoping the ref by product keeps them distinguishable, which is also
// the more useful answer: it says *which product* each match came from.
func teaInsightsBOMRef(productID string, row componentRow) string {
	if row.PURL != "" {
		return productID + "/" + row.PURL
	}
	return productID + "/" + row.Name + "@" + row.Version
}

func teaInsightsAssetRef(productID, kind, name string, asset map[string]any) string {
	if purl, _ := asset["purl"].(string); purl != "" {
		return productID + "/" + kind + "/" + purl
	}
	return productID + "/" + kind + "/" + name
}
