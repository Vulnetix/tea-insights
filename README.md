# tea-insights

The data layer of the Vulnetix [Transparency Exchange API](https://github.com/CycloneDX/transparency-exchange-api) (TEA), shared by two services:

- **vdb-site** serves TEA (`/tea/v1/*`, `/.well-known/tea`) and Insights (`POST /insights/static`).
- **vdb-api** accepts a TEI or an Insights CEL expression as an input to its other endpoints, so a caller can ask for the defences, fixes or exploits that apply to "this release" or "every component this expression selects".

Both must give the same answer for the same identifier and the same expression. That is why the code lives here once.

## What is here

| File | Contents |
|------|----------|
| `tei.go` | Derived TEA object UUIDs (product, component, product release, component release, distribution), repository purls, and TEI parsing (`urn:tei:<type>:<domain>:<id>`) |
| `index.go` | `IndexQuery`, the statement that enumerates a tenant's releases; `LoadReleaseKeys`, `SeedsFor`, `ResolveUUID` and `ReleaseComponents` |
| `inventory.go` | The Insights inventory (products and their CycloneDX-shaped components), built from the saas database and cached per tenant, served stale while it is rebuilt |
| `cel.go` | The CEL environment (`productId`, `product`, `component`), compilation with a cache, and evaluation with a 3 second budget and a 5,000 match cap |

Rendering TEA objects and the CycloneDX answer stays in vdb-site.

## Rules

- **UUIDs are derived and never stored.** Each is a UUIDv5 over a per-type namespace and a natural key that includes the tenant's org id. Two tenants scanning the same repository get different UUIDs, and a UUID minted for one never resolves for another.
- **Only local TEIs resolve.** A TEI resolves only when its domain is `vulnetix.com` or its `www.`, `api.` or `tea.` subdomain. Any other domain belongs to another publisher and is reported unknown, never guessed.
- **Supported TEI types.** `uuid` and `purl` are resolvable here, and `swid` carries its own identity. `hash`, `eanupc`, `gtin`, `asin` and `udi` are valid TEI types this server does not mint.
- **Evaluation.** A CEL expression is a boolean predicate over one (product, component) pair. Absent facets are `null`, a per-item evaluation error is a non-match, and a non-boolean result is an error.
- **Database access.** The inventory and release keys read the saas database through the `Querier` interface. Both services' `db.Pool` wraps a `*pgxpool.Pool`, which satisfies it.

## Using it

Consumers reference it with a sibling `replace`, like the other shared modules:

```
replace github.com/Vulnetix/tea-insights => ../tea-insights
```

Container builds clone it beside `vdb-cyclonedx`.

```sh
go test ./...
```
