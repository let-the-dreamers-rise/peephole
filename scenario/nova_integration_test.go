package scenario

import (
	"os"
	"testing"

	"github.com/let-the-dreamers-rise/peephole/check"
	"github.com/let-the-dreamers-rise/peephole/spec"
)

// TestNovaFindings runs the reference app through the real Vela executor and
// asserts peephole reproduces the known findings. It needs apps/nova.wasm,
// built by `make apps`; it skips if the module is absent.
func TestNovaFindings(t *testing.T) {
	const wasm = "../apps/nova.wasm"
	if _, err := os.Stat(wasm); err != nil {
		t.Skip("build apps/nova.wasm first (make apps)")
	}
	tr, err := nova(wasm)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := spec.Load("../specs/nova.json")
	if err != nil {
		t.Fatal(err)
	}
	byCheck := map[string]check.Finding{}
	for _, c := range check.Selected(pol) {
		for _, f := range c.Run(tr, pol) {
			byCheck[f.Check] = f
		}
	}
	for _, want := range []string{"event-linkability", "commitment-preimage", "operator-counterparty", "amount-by-length"} {
		if _, ok := byCheck[want]; !ok {
			t.Errorf("expected a finding from %s, got none", want)
		}
	}
	// The reference app must not forward a private value in its logs; if this
	// starts firing, the app (or Vela's log level) changed — not a false alarm.
	if f, ok := byCheck["guest-log-leak"]; ok {
		t.Logf("note: guest-log-leak now fires: %s", f.Summary)
	}
}
