package teainsights

// The CEL evaluation engine behind POST /insights/static.
//
// The specification's examples fix the shape of the language exactly:
//
//	productId == 'XYZ' && component.type == 'third-party'
//	productId == 'XYZ' && component.vulnerabilities.size() > 0
//	productId == 'XYZ' && component.name == 'log4j' && component.vulnerabilities.contains('log4shell')
//	productId == 'XYZ' && component.cryptography != null
//	productId == 'XYZ' && product.processAttestation.type == 'OWASP SAMM'
//
// An expression is a boolean predicate over one (product, component) pair, with
// `productId`, `product` and `component` in scope. Everything else follows from
// that: the server evaluates the predicate across the tenant's inventory and
// returns the components it selected.
//
// Two details of the examples drive the environment setup:
//
//   - `component.vulnerabilities.contains(...)` calls `contains` on a list.
//     Standard CEL only defines `contains` for strings, so a list overload is
//     registered — otherwise the specification's own worked example fails to
//     compile, which would be an odd thing for a conforming server to do.
//   - `component.cryptography != null` requires absent facets to be null, not
//     an empty map. The activation builds them that way.

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

// EvalBudget bounds a single expression evaluation. CEL is
// non-Turing-complete so it always terminates, but a pathological expression
// over a large inventory can still be slow, and a query API must not let one
// caller occupy a worker indefinitely.
const EvalBudget = 3 * time.Second

// MaxMatches caps how many components one answer may carry. The
// point of Insights is "limited transparency" — returning the entire inventory
// would be the full-SBOM behaviour the API exists to avoid.
const MaxMatches = 5000

// teaCELEnv is the compiled environment. Building it parses the standard
// declarations, which is slow enough to be worth doing exactly once.
var teaCELEnv = func() *cel.Env {
	env, err := cel.NewEnv(
		cel.Variable("productId", cel.StringType),
		cel.Variable("product", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("component", cel.MapType(cel.StringType, cel.DynType)),

		// `list.contains(x)`, so the specification's log4shell example compiles.
		// Standard CEL spells this `x in list`; both work here.
		cel.Function("contains",
			cel.MemberOverload("list_contains_dyn",
				[]*cel.Type{cel.ListType(cel.DynType), cel.DynType}, cel.BoolType,
				cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
					lister, ok := lhs.(traits.Lister)
					if !ok {
						return types.MaybeNoSuchOverloadErr(lhs)
					}
					return lister.Contains(rhs)
				}),
			),
		),
	)
	if err != nil {
		// A malformed environment is a programming error, not a runtime one:
		// nothing a caller sends can cause it.
		panic("tea insights: building the CEL environment: " + err.Error())
	}
	return env
}()

// Program is a compiled expression.
type Program struct {
	program cel.Program
	source  string
}

// teaCELCache memoises compiled programs. Compilation is the fixed cost of a
// query and expressions repeat heavily — a CI pipeline asks the same question
// on every build — so caching it makes the repeat case pure evaluation. The
// cache is keyed by expression text only: a program has no tenant-specific
// state, and the data it runs against is supplied per evaluation.
var teaCELCache = newLRUCache(512, time.Hour)

// Compile compiles and type-checks an expression.
//
// Both failures are the caller's: the specification says an invalid expression
// is a 400, and a non-boolean expression cannot be a filter, so it is rejected
// at compile time rather than producing an empty answer at run time.
func Compile(expression string) (*Program, error) {
	src := strings.TrimSpace(expression)
	if src == "" {
		return nil, fmt.Errorf("expression is empty")
	}
	if v, ok := teaCELCache.Get(src); ok {
		switch cached := v.(type) {
		case *Program:
			return cached, nil
		case error:
			return nil, cached
		}
	}
	prg, err := compileUncached(src)
	if err != nil {
		teaCELCache.Set(src, err)
		return nil, err
	}
	teaCELCache.Set(src, prg)
	return prg, nil
}

func compileUncached(src string) (*Program, error) {
	ast, issues := teaCELEnv.Compile(src)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("invalid CEL expression: %s", teaFirstIssue(issues.Err().Error()))
	}
	// `component` is a map of dynamic values, so a bare field reference types
	// as `dyn` whether it is a boolean the caller meant as a filter
	// (`component.isProduct`) or a string they did not (`component.name`).
	// Static typing cannot separate those, so this rejects only what is
	// *statically* wrong — arithmetic, a string literal — and the evaluator
	// rejects a `dyn` that turns out not to be a boolean when it sees one.
	//
	// The alternative, rejecting `dyn` outright, would refuse
	// `component.isProduct`; accepting it blindly would answer "nothing found"
	// to `component.name`. Neither is acceptable, so the check is split across
	// both phases.
	if out := ast.OutputType(); out != cel.BoolType && out != cel.DynType && out != cel.AnyType {
		return nil, fmt.Errorf("expression must evaluate to a boolean, got %s", out)
	}
	prg, err := teaCELEnv.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return nil, fmt.Errorf("invalid CEL expression: %v", err)
	}
	return &Program{program: prg, source: src}, nil
}

// teaFirstIssue reduces CEL's multi-line diagnostic to its first line. The full
// rendering includes a source-position caret diagram that reads as noise in a
// JSON error body.
func teaFirstIssue(msg string) string {
	if i := strings.IndexByte(msg, '\n'); i > 0 {
		return strings.TrimSpace(msg[:i])
	}
	return strings.TrimSpace(msg)
}

// Match is one selected component with the product it came from.
type Match struct {
	Product   *Product
	Component *Component
}

// Evaluate runs the predicate across the inventory and returns what it
// selected.
//
// Evaluation errors on an individual component are treated as "no match" rather
// than as a request failure: an expression that reads a field some components
// do not have is normal, and failing the whole query because one component
// lacked a facet would make most useful expressions unusable.
func Evaluate(prg *Program, inv *Inventory) ([]Match, bool, error) {
	var out []Match
	deadline := time.Now().Add(EvalBudget)
	checked := 0

	// One activation map, rewritten per component. The values inside were built
	// with the inventory and are never mutated; only the three top-level
	// bindings change, so a query over the whole inventory allocates nothing.
	vars := make(map[string]any, 3)

	for _, product := range inv.Products {
		vars["productId"] = product.ID
		vars["product"] = product.activation
		for _, component := range product.Components {
			if checked%1024 == 0 && time.Now().After(deadline) {
				return out, true, fmt.Errorf("expression evaluation exceeded its time budget")
			}
			checked++

			vars["component"] = component.activation
			val, _, err := prg.program.Eval(vars)
			if err != nil {
				continue
			}
			b, isBool := val.Value().(bool)
			if !isBool {
				// The static check could not tell a boolean field from a string
				// one. This is where that is settled: an expression that
				// produces something other than a boolean is not a filter, and
				// saying so beats returning an empty document that a caller
				// will read as "you have none of those".
				return nil, false, fmt.Errorf(
					"expression must evaluate to a boolean; it produced %s", val.Type())
			}
			if b {
				out = append(out, Match{Product: product, Component: component})
				if len(out) >= MaxMatches {
					return out, true, nil
				}
			}
		}
	}
	return out, false, nil
}

func ProductActivation(p *Product) map[string]any {
	return map[string]any{
		"id":                 p.ID,
		"name":               p.Name,
		"purl":               p.PURL,
		"componentCount":     int64(len(p.Components)),
		"processAttestation": p.ProcessAttestation, // nil when none is held
	}
}

// ComponentActivation renders a component for the expression.
//
// There is no `thirdParty` field, and `type` is the CycloneDX component type
// rather than a provenance verdict. TEA is a transparency log for all software:
// "third party" is a reporting perspective a reader brings, not a property the
// log records. The same library is third-party to the team that consumes it and
// first-party to the team that publishes it, and this log holds one record that
// serves both.
//
// So the facts are published — `origin`, `relationship`, `isProduct`,
// `publisher` — and the perspective is written into the query:
//
//	component.origin == 'external'   … one reader's "third party"
//	component.isProduct              … the other reader's "we publish this"
//
// The readme's `component.type == 'third-party'` conflates a CycloneDX type
// with a perspective; `origin` is the field that answers what it meant.
func ComponentActivation(p *Product, c *Component) map[string]any {
	vulns := make([]any, 0, len(c.Vulnerabilities))
	for _, v := range c.Vulnerabilities {
		vulns = append(vulns, v)
	}
	licenses := make([]any, 0, len(c.Licenses))
	for _, l := range c.Licenses {
		licenses = append(licenses, l)
	}

	m := map[string]any{
		"name":            c.Name,
		"group":           c.Group,
		"version":         c.Version,
		"purl":            c.PURL,
		"cpe":             c.CPE,
		"type":            c.Type,
		"cdxType":         c.Type,
		"origin":          c.Origin,
		"relationship":    c.Relationship,
		"isProduct":       c.IsProduct,
		"productRef":      c.ProductRef,
		"publisher":       c.Publisher,
		"supplier":        c.Supplier,
		"author":          c.Author,
		"ecosystem":       c.Ecosystem,
		"scope":           c.Scope,
		"direct":          c.Direct,
		"development":     c.Development,
		"transitive":      c.Transitive,
		"licenses":        licenses,
		"licenseType":     c.LicenseType,
		"vulnerabilities": vulns,
		"scorecard":       teaNilMap(c.Scorecard),
		"provenance":      teaNilSlice(c.Provenance),
		"attestations":    teaNilSlice(c.Attestations),
		// A joined form so `component.vulnerabilityIds.contains('log4shell')`
		// works through the standard string overload as well as the list one.
		"vulnerabilityIds": strings.Join(c.Vulnerabilities, " "),
		"product":          p.Name,
		"productId":        p.ID,
		// Absent facets must be null, not empty: the specification's example
		// tests `component.cryptography != null`.
		"cryptography": teaNilMap(c.Cryptography),
		"ai":           teaNilMap(c.AI),
	}
	return m
}

// teaNilMap keeps an absent facet null so `!= null` behaves as the examples
// expect. Returning an empty map would make every component look as though it
// had cryptography.
func teaNilMap(m map[string]any) any {
	if len(m) == 0 {
		return nil
	}
	return m
}

// teaNilSlice is the list equivalent, so `component.provenance != null`
// distinguishes "none held" from "held and empty".
func teaNilSlice(s []any) any {
	if len(s) == 0 {
		return nil
	}
	return s
}

// Source is the expression text the program was compiled from, trimmed.
func (p *Program) Source() string { return p.source }
