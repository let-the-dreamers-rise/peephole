package scenario

import (
	"os"
	"testing"

	"github.com/let-the-dreamers-rise/peephole/check"
	"github.com/let-the-dreamers-rise/peephole/spec"
)

// TestTipjarLeakyThenHardened proves the suite is not a rubber stamp: the same
// example app fails in "leaky" mode and passes in "hardened" mode. Needs
// apps/tipjar.wasm (make apps); skips otherwise.
func TestTipjarLeakyThenHardened(t *testing.T) {
	const wasm = "../apps/tipjar.wasm"
	if _, err := os.Stat(wasm); err != nil {
		t.Skip("build apps/tipjar.wasm first (make apps)")
	}
	run := func(scen, policy string) int {
		tr, err := registry[scen](wasm)
		if err != nil {
			t.Fatal(err)
		}
		pol, err := spec.Load(policy)
		if err != nil {
			t.Fatal(err)
		}
		var n int
		for _, c := range check.Selected(pol) {
			n += len(c.Run(tr, pol))
		}
		return n
	}
	if n := run("tipjar-leaky", "../specs/tipjar-leaky.json"); n == 0 {
		t.Error("leaky mode: expected findings, got none")
	}
	if n := run("tipjar-hardened", "../specs/tipjar-hardened.json"); n != 0 {
		t.Errorf("hardened mode: expected a clean pass, got %d finding(s)", n)
	}
}
