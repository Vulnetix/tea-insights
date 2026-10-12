package teainsights

// Unit coverage for the Insights API's query engine and its output shape.
//
// The conformance suite exercises these endpoints against real data, but it
// cannot reach the parts that need no network — the CEL grammar, the model's
// output cleanup, the licence classification — and those are where the
// specification's own examples either work or do not.

import (
	"strings"
	"testing"
	"time"
)

// testInventory is a small hand-built inventory covering every facet the
// specification's examples query.
func testInventory() *Inventory {
	product := &Product{
		ID:   "09e8c73b-ac45-4475-acac-33e6a7314e6d",
		Name: "Acme/store",
		PURL: "pkg:github/Acme/store",
	}
	other := &Product{
		ID:   "1cb47b95-8bf8-4bad-a5a4-0d54d86e10ce",
		Name: "Acme/checkout",
		PURL: "pkg:github/Acme/checkout",
	}

	log4j := &Component{
		BOMRef: product.ID + "/pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		Name:   "log4j-core", Version: "2.14.1",
		PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		Type: "library", Ecosystem: "maven", Scope: "required",
		Direct: true, Relationship: "dependency", Origin: "external",
		Publisher: "Apache Software Foundation",
		Licenses:  []string{"Apache-2.0"}, LicenseType: "Open Source",
		Vulnerabilities: []string{"CVE-2021-44228", "log4shell"},
	}
	// A dependency that this log also publishes as a product. It is external to
	// nobody and internal to nobody in the abstract — it is simply recorded
	// once, and each reader decides what to call it.
	shared := &Component{
		BOMRef: product.ID + "/pkg:github/Acme/checkout@1.0.0",
		Name:   "acme-internal", Version: "1.0.0",
		PURL: "pkg:github/Acme/checkout@1.0.0",
		Type: "library", Scope: "required",
		Relationship: "dependency", Origin: "internal",
		IsProduct: true, ProductRef: other.ID,
		LicenseType: "Commercial", Licenses: []string{"Proprietary"},
	}
	aes := &Component{
		BOMRef: product.ID + "/crypto/AES-256",
		Name:   "AES-256", Type: "cryptographic-asset", Scope: "required",
		LicenseType: "Unknown",
		Cryptography: map[string]any{
			"name": "AES-256", "assetType": "algorithm", "primitive": "block-cipher",
			"pqcStatus": "quantum-safe", "nistQuantumSecurityLevel": int64(5),
		},
	}
	model := &Component{
		BOMRef: other.ID + "/ai/gpt-4o",
		Name:   "gpt-4o", Type: "machine-learning-model", Scope: "required",
		LicenseType: "Unknown",
		AI: map[string]any{
			"name": "gpt-4o", "category": "model", "provider": "openai", "task": "text-generation",
		},
	}

	product.Components = []*Component{log4j, shared, aes}
	other.Components = []*Component{model}

	inv := &Inventory{
		OrgID:    "test-org",
		Products: []*Product{product, other},
		ByID: map[string]*Product{
			product.ID: product, other.ID: other,
		},
		ByName: map[string]*Product{
			"acme/store": product, "acme/checkout": other,
		},
		Components: 4,
		BuiltAt:    time.Unix(1_700_000_000, 0).UTC(),
	}
	inv.Prepare()
	return inv
}

func runCEL(t *testing.T, expression string) []Match {
	t.Helper()
	prg, err := Compile(expression)
	if err != nil {
		t.Fatalf("compile %q: %v", expression, err)
	}
	matches, _, err := Evaluate(prg, testInventory())
	if err != nil {
		t.Fatalf("evaluate %q: %v", expression, err)
	}
	return matches
}

func TestInsightsSpecificationExamples(t *testing.T) {
	// The expressions the Insights readme uses to motivate the API. If one of
	// these cannot be answered, the implementation has missed the point of the
	// specification, whatever its schema conformance says.
	const productID = "09e8c73b-ac45-4475-acac-33e6a7314e6d"

	cases := []struct {
		name       string
		expression string
		wantNames  []string
	}{{
		// The readme writes this as `component.type == 'third-party'`, which
		// conflates a CycloneDX type with a reporting perspective. TEA records
		// no such property — "third party" is what a *reader* calls something —
		// so the perspective is written into the query instead, over the facts
		// the log does record.
		name:       "dependencies published by someone else (one reader's third-party)",
		expression: "productId == '" + productID + "' && component.relationship == 'dependency' && component.origin == 'external'",
		wantNames:  []string{"log4j-core"},
	}, {
		// The same log, the other perspective: a dependency that this log also
		// publishes as a product of its own. Both readings are true at once,
		// which is the case a `thirdParty` boolean could not express.
		name:       "dependencies this log also publishes (the other reader's first-party)",
		expression: "productId == '" + productID + "' && component.isProduct",
		wantNames:  []string{"acme-internal"},
	}, {
		// And the CycloneDX type keeps its own meaning, unconflated.
		name:       "components by CycloneDX type",
		expression: "productId == '" + productID + "' && component.type == 'cryptographic-asset'",
		wantNames:  []string{"AES-256"},
	}, {
		name:       "open-source dependencies of a product",
		expression: "productId == '" + productID + "' && component.licenseType == 'Open Source'",
		wantNames:  []string{"log4j-core"},
	}, {
		name:       "components with any vulnerability",
		expression: "productId == '" + productID + "' && component.vulnerabilities.size() > 0",
		wantNames:  []string{"log4j-core"},
	}, {
		// The specification's headline question, verbatim in shape: does the
		// product use log4j and is it exposed to log4shell?
		name:       "log4j exposed to log4shell",
		expression: "productId == '" + productID + "' && component.name == 'log4j-core' && component.vulnerabilities.contains('log4shell')",
		wantNames:  []string{"log4j-core"},
	}, {
		name:       "cryptographic algorithms of a product",
		expression: "productId == '" + productID + "' && component.cryptography != null",
		wantNames:  []string{"AES-256"},
	}, {
		name:       "process attestation query is answerable",
		expression: "productId == '" + productID + "' && product.processAttestation.type == 'OWASP SAMM'",
		wantNames:  nil, // no attestation is held, so the honest answer is none
	}, {
		name:       "AI components across the catalogue",
		expression: "component.ai != null",
		wantNames:  []string{"gpt-4o"},
	}, {
		// `in` is the standard CEL spelling; a generated client may use either.
		name:       "vulnerability membership using in",
		expression: "'CVE-2021-44228' in component.vulnerabilities",
		wantNames:  []string{"log4j-core"},
	}, {
		name:       "match a product by name rather than id",
		expression: "product.name == 'Acme/checkout'",
		wantNames:  []string{"gpt-4o"},
	}, {
		name:       "everything",
		expression: "true",
		wantNames:  []string{"AES-256", "acme-internal", "gpt-4o", "log4j-core"},
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches := runCEL(t, tc.expression)
			got := map[string]bool{}
			for _, m := range matches {
				got[m.Component.Name] = true
			}
			if len(got) != len(tc.wantNames) {
				t.Fatalf("selected %d components %v, want %v", len(got), keysOf(got), tc.wantNames)
			}
			for _, name := range tc.wantNames {
				if !got[name] {
					t.Errorf("expected %q to be selected; got %v", name, keysOf(got))
				}
			}
		})
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestInsightsRejectsUnusableExpressions(t *testing.T) {
	cases := []struct{ name, expression, expect string }{
		{"empty", "", "empty"},
		{"syntax error", "component.name ==", "invalid CEL expression"},
		{"unknown variable", "nonesuch == 1", "invalid CEL expression"},
		// Statically typed as an int, so the compiler settles it.
		{"arithmetic, not a predicate", "1 + 1", "must evaluate to a boolean"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compile(tc.expression)
			if err == nil {
				t.Fatalf("%q was accepted", tc.expression)
			}
			if !strings.Contains(err.Error(), tc.expect) {
				t.Errorf("error %q does not mention %q", err, tc.expect)
			}
		})
	}
}

func TestInsightsRejectsNonPredicatesAtEvaluation(t *testing.T) {
	// `component` holds dynamic values, so a bare field reference types as
	// `dyn` whether it is a boolean the caller meant as a filter or a string
	// they did not. The compiler cannot separate those; the evaluator can, and
	// must — an expression that yields a string is not a filter, and answering
	// it with an empty document would read as "you have none of those".
	prg, err := Compile("component.name")
	if err != nil {
		t.Fatalf("a dynamically-typed expression should compile: %v", err)
	}
	if _, _, err := Evaluate(prg, testInventory()); err == nil {
		t.Fatal("a non-boolean expression was evaluated as a filter")
	} else if !strings.Contains(err.Error(), "must evaluate to a boolean") {
		t.Errorf("error %q does not explain the problem", err)
	}

	// And the boolean field it could not be distinguished from still works.
	prg, err = Compile("component.isProduct")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	matches, _, err := Evaluate(prg, testInventory())
	if err != nil {
		t.Fatalf("a boolean field reference must be a usable filter: %v", err)
	}
	if len(matches) != 1 || matches[0].Component.Name != "acme-internal" {
		t.Errorf("component.isProduct selected %d components, want the one that is also a product", len(matches))
	}
}

func TestInsightsLicenseClassification(t *testing.T) {
	cases := []struct {
		licenses []string
		want     string
	}{
		{[]string{"Apache-2.0"}, "Open Source"},
		{[]string{"MIT"}, "Open Source"},
		{[]string{"MIT OR Apache-2.0", "MIT", "Apache-2.0"}, "Open Source"},
		{[]string{"Proprietary"}, "Commercial"},
		{[]string{"NOASSERTION"}, "Commercial"},
		// Nothing recorded must not become "Open Source" by default: that would
		// be a wrong answer to a compliance question.
		{nil, "Unknown"},
		{[]string{}, "Unknown"},
	}
	for _, tc := range cases {
		if got := LicenseType(tc.licenses); got != tc.want {
			t.Errorf("LicenseType(%v) = %q, want %q", tc.licenses, got, tc.want)
		}
	}
}

func TestInsightsSplitLicenses(t *testing.T) {
	got := SplitLicenses("MIT OR Apache-2.0")
	want := map[string]bool{"MIT": true, "Apache-2.0": true, "MIT OR Apache-2.0": true}
	if len(got) != len(want) {
		t.Fatalf("split produced %v", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected licence %q", g)
		}
	}
	if SplitLicenses("") != nil {
		t.Error("an empty licence produced entries")
	}
}

func TestInsightsEvaluationIsAllocationFree(t *testing.T) {
	// Evaluation walks the whole inventory, so anything allocated per component
	// is multiplied by the catalogue size. This is the guard that noticed the
	// original implementation building a fresh activation map per component,
	// which cost an order of magnitude in query latency.
	inv := testInventory()
	prg, err := Compile("component.licenseType == 'Open Source'")
	if err != nil {
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(20, func() {
		if _, _, err := Evaluate(prg, inv); err != nil {
			t.Fatal(err)
		}
	})
	// A handful for the result slice and CEL's own boxing; the failure this
	// guards against is proportional to the component count.
	if allocs > 200 {
		t.Errorf("evaluation allocated %.0f times over %d components; it should not scale with the inventory",
			allocs, inv.Components)
	}
}
