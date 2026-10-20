package scenario

import (
	"os"
	"testing"

	"github.com/let-the-dreamers-rise/peephole/check"
	"github.com/let-the-dreamers-rise/peephole/spec"
)

// TestSimpleFindings runs Vela's own sample app (app/simple) through the real
// executor. Expected: the comparison target leaks on the no-account error path
// (operator log + public error message) and, via unpadded result length plus
// publicly replayable balances, on equal-balance comparisons. Checks whose
// leak pattern the app does not have must stay silent. Needs apps/simple.wasm.
func TestSimpleFindings(t *testing.T) {
	const wasm = "../apps/simple.wasm"
	if _, err := os.Stat(wasm); err != nil {
		t.Skip("build apps/simple.wasm first (make apps)")
	}
	tr, err := simple(wasm)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := spec.Load("../specs/simple.json")
	if err != nil {
		t.Fatal(err)
	}
	byCheck := map[string]check.Finding{}
	for _, c := range check.Selected(pol) {
		for _, f := range c.Run(tr, pol) {
			byCheck[f.Check] = f
		}
	}
	for _, want := range []string{"guest-log-leak", "error-message-leak", "comparison-target"} {
		if f, ok := byCheck[want]; !ok || f.Field != "counterparty" {
			t.Errorf("expected a counterparty finding from %s, got %+v", want, f)
		}
	}
	// Every event goes to the requester, nothing is committed in clear, and
	// deposit/withdraw amounts are public by design: these must not fire.
	for _, quiet := range []string{"event-linkability", "operator-counterparty", "commitment-preimage", "amount-by-length"} {
		if f, ok := byCheck[quiet]; ok {
			t.Errorf("unexpected finding from %s: %s", quiet, f.Summary)
		}
	}
	if len(byCheck) != 3 {
		t.Errorf("expected exactly 3 checks to fire, got %d", len(byCheck))
	}
}
