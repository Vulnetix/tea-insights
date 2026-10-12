package teainsights

// The release keys a TEI uuid resolves against, and the components of one
// release.
//
// A TEA object UUID is derived, never stored (see tei.go), so resolving one
// means recomputing the candidates: every (repository, commit) the tenant has
// observed yields one product, one component and one release of each kind.
// IndexQuery is the statement that enumerates them. vdb-site builds its whole
// TEA object graph from it; vdb-api needs only the keys.

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// IndexQuery unions every source that observes a (repository, commit) pair,
// because a release exists as soon as anything was recorded about it. It reads
// $1 as the saas org id and returns, per pair: repo, commit, created_at,
// last_seen, head_committed_at, branch, default_branch, tag, observations.
const IndexQuery = `
	WITH scans AS (
	    SELECT s."repoName"                    AS repo,
	           e."gitCommit"                   AS commit,
	           s."createdAt"                   AS ts,
	           NULLIF(e."gitBranch", '')       AS branch,
	           NULLIF(e."ciDefaultBranch", '') AS def_branch,
	           NULL::bigint                    AS head_ts,
	           CASE WHEN e."ciRefType" = 'tag' THEN NULLIF(e."ciRefName", '') END AS tag
	      FROM "ScannerRun" s
	      JOIN "CliScanEnvironment" e ON e."scannerRunUuid" = s.uuid
	     WHERE s."orgId" = $1 AND s."repoName" IS NOT NULL AND e."gitCommit" IS NOT NULL
	    UNION ALL
	    SELECT "repoName", "commitSha", "createdAt", NULLIF("branchName", ''), NULL, NULL, NULL
	      FROM "CbomScan"
	     WHERE "orgId" = $1 AND "repoName" IS NOT NULL AND "commitSha" IS NOT NULL
	    UNION ALL
	    SELECT "repoName", "commitSha", "createdAt", NULLIF("branchName", ''), NULL, NULL, NULL
	      FROM "AibomScan"
	     WHERE "orgId" = $1 AND "repoName" IS NOT NULL AND "commitSha" IS NOT NULL
	    UNION ALL
	    SELECT "repoName", "commitSha", "createdAt", NULLIF("branchName", ''), NULL, "headCommittedAt", NULL
	      FROM "InsightsRun"
	     WHERE "orgId" = $1 AND "repoName" IS NOT NULL AND "commitSha" IS NOT NULL
	)
	SELECT repo,
	       commit,
	       MIN(ts)                       AS created_at,
	       MAX(ts)                       AS last_seen,
	       COALESCE(MAX(head_ts), 0)     AS head_committed_at,
	       COALESCE(MIN(branch), '')     AS branch,
	       COALESCE(MIN(def_branch), '') AS default_branch,
	       COALESCE(MIN(tag), '')        AS tag,
	       COUNT(*)                      AS observations
	  FROM scans
	 GROUP BY 1, 2`

// ReleaseKey is one observed (repository, commit) pair.
type ReleaseKey struct {
	Repo   string
	Commit string
}

// LoadReleaseKeys returns every release key of a tenant, ordered by repository
// then commit. Blank keys are dropped, as vdb-site's index drops them.
func LoadReleaseKeys(ctx context.Context, q Querier, saasOrgID string) ([]ReleaseKey, error) {
	if saasOrgID == "" {
		return nil, nil
	}
	rows, err := q.Query(ctx, IndexQuery, saasOrgID)
	if err != nil {
		return nil, fmt.Errorf("tea release keys: %w", err)
	}
	defer rows.Close()

	var keys []ReleaseKey
	for rows.Next() {
		var repo, commit, branch, defBranch, tag string
		var created, lastSeen, headTS int64
		var observations int
		if err := rows.Scan(&repo, &commit, &created, &lastSeen, &headTS,
			&branch, &defBranch, &tag, &observations); err != nil {
			return nil, fmt.Errorf("tea release keys scan: %w", err)
		}
		repo, commit = strings.TrimSpace(repo), strings.TrimSpace(commit)
		if repo == "" || commit == "" {
			continue
		}
		keys = append(keys, ReleaseKey{Repo: repo, Commit: commit})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Repo != keys[j].Repo {
			return keys[i].Repo < keys[j].Repo
		}
		return keys[i].Commit < keys[j].Commit
	})
	return keys, nil
}

// SeedsFor builds the inventory catalogue from release keys: one product per
// repository, with the same UUID and purl vdb-site's index gives it.
func SeedsFor(saasOrgID string, keys []ReleaseKey) Seeds {
	seen := map[string]bool{}
	s := Seeds{OrgID: saasOrgID}
	for _, k := range keys {
		if seen[k.Repo] {
			continue
		}
		seen[k.Repo] = true
		s.Products = append(s.Products, ProductSeed{
			ID:   ProductUUID(saasOrgID, k.Repo),
			Repo: k.Repo,
			PURL: RepoPURL(k.Repo, ""),
		})
	}
	return s
}

// SubjectKind names which TEA object a UUID identified.
type SubjectKind string

const (
	SubjectProduct          SubjectKind = "product"
	SubjectComponent        SubjectKind = "component"
	SubjectProductRelease   SubjectKind = "productRelease"
	SubjectComponentRelease SubjectKind = "componentRelease"
)

// Subject is what a TEA object UUID resolved to. Commit is empty for a product
// or a component, which name the repository's whole lineage.
type Subject struct {
	Kind   SubjectKind
	Repo   string
	Commit string
}

// IsRelease reports whether the subject pins one commit.
func (s Subject) IsRelease() bool { return s.Commit != "" }

// ResolveUUID finds the tenant object a UUID names, by recomputing each
// candidate's derived UUID. UUIDs compare case-insensitively.
func ResolveUUID(saasOrgID, id string, keys []ReleaseKey) (Subject, bool) {
	want := strings.ToLower(strings.TrimSpace(id))
	if saasOrgID == "" || want == "" {
		return Subject{}, false
	}
	repos := map[string]bool{}
	for _, k := range keys {
		if !repos[k.Repo] {
			repos[k.Repo] = true
			if ProductUUID(saasOrgID, k.Repo) == want {
				return Subject{Kind: SubjectProduct, Repo: k.Repo}, true
			}
			if ComponentUUID(saasOrgID, k.Repo) == want {
				return Subject{Kind: SubjectComponent, Repo: k.Repo}, true
			}
		}
		if ProductReleaseUUID(saasOrgID, k.Repo, k.Commit) == want {
			return Subject{Kind: SubjectProductRelease, Repo: k.Repo, Commit: k.Commit}, true
		}
		if ComponentReleaseUUID(saasOrgID, k.Repo, k.Commit) == want {
			return Subject{Kind: SubjectComponentRelease, Repo: k.Repo, Commit: k.Commit}, true
		}
	}
	return Subject{}, false
}

// ReleaseComponent is one dependency of one release, as recorded by the most
// recent composition scan of that commit.
type ReleaseComponent struct {
	Name      string
	Group     string
	Version   string
	PURL      string
	CPE       string
	Ecosystem string
}

// releaseComponentsQuery is teaInsightsComponentsQuery pinned to one commit: the
// latest SCA run of ($2 repository, $3 commit) for org $1.
const releaseComponentsQuery = `
	WITH run AS (
	    SELECT s.uuid
	      FROM "ScannerRun" s
	      JOIN "CliScanEnvironment" e ON e."scannerRunUuid" = s.uuid
	     WHERE s."orgId" = $1 AND s.category = 'SCA'
	       AND s."repoName" = $2 AND e."gitCommit" = $3
	     ORDER BY s."createdAt" DESC
	     LIMIT 1
	)
	SELECT d.name,
	       COALESCE(d."group", ''),
	       COALESCE(d.version, ''),
	       COALESCE(d.purl, ''),
	       COALESCE(d.cpe, ''),
	       COALESCE(d."packageEcosystem", '')
	  FROM run r
	  JOIN "CliScanDependency" c ON c."scannerRunUuid" = r.uuid
	  JOIN "Dependency" d ON d.key = c."dependencyKey"`

// ReleaseComponents returns the components of one release. A release with no
// composition scan has none, which is an empty answer rather than an error.
func ReleaseComponents(ctx context.Context, q Querier, saasOrgID, repo, commit string) ([]ReleaseComponent, error) {
	rows, err := q.Query(ctx, releaseComponentsQuery, saasOrgID, repo, commit)
	if err != nil {
		return nil, fmt.Errorf("tea release components: %w", err)
	}
	defer rows.Close()
	var out []ReleaseComponent
	for rows.Next() {
		var c ReleaseComponent
		if err := rows.Scan(&c.Name, &c.Group, &c.Version, &c.PURL, &c.CPE, &c.Ecosystem); err != nil {
			return nil, fmt.Errorf("tea release components scan: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
