package scenario

import (
	"fmt"
	"math/big"
	"os"

	"github.com/HorizenOfficial/vela/pkg/common"
	"github.com/let-the-dreamers-rise/peephole/engine"
	"github.com/let-the-dreamers-rise/peephole/trace"
)

func init() {
	Register("tipjar-leaky", func(w string) (*trace.Trace, error) { return tipjar(w, "leaky") })
	Register("tipjar-hardened", func(w string) (*trace.Trace, error) { return tipjar(w, "hardened") })
}

// tipjar drives the self-authored example app in one of its two modes. The tip
// amount and memo are declared private; the jar and tippers are public. In
// "leaky" mode peephole recovers both; in "hardened" mode (padded amount,
// salted commitment) it recovers neither — same app, same scenario.
func tipjar(wasmPath, mode string) (*trace.Trace, error) {
	wasm, err := os.ReadFile(wasmPath)
	if err != nil {
		return nil, err
	}
	tipper, err := engine.NewUser("tipper", true)
	if err != nil {
		return nil, err
	}
	deploy := fmt.Sprintf(`{"mode":%q,"salt":"s3cr3t-per-app-salt-kept-in-state"}`, mode)
	w, err := engine.NewWorld(wasm, []byte(deploy), []*engine.User{tipper})
	if err != nil {
		return nil, err
	}
	tr := &trace.Trace{Scenario: "tipjar-" + mode}

	// Fund the tipper (public deposit), then tip amounts of different magnitudes.
	w.Submit(engine.Request{Sender: tipper, Type: common.Process, Deposit: big.NewInt(100_000_000)})
	for _, amt := range []int64{1, 50, 9999, 7_000_000} {
		pl := fmt.Sprintf(`{"type":"tip","tip":{"amount":%d,"memo":"thanks"}}`, amt)
		o := w.Submit(engine.Request{Sender: tipper, Type: common.Process, Payload: []byte(pl)})
		tr.Add(fmt.Sprintf("tip amount=%d", amt), o,
			trace.Secret{Field: "amount", Kind: trace.KUint, Uint: big.NewInt(amt)})
	}
	// A tip whose memo+amount we try to recover from the public receipt.
	secret := int64(4321)
	pl := fmt.Sprintf(`{"type":"tip","tip":{"amount":%d,"memo":"coffee"}}`, secret)
	o := w.Submit(engine.Request{Sender: tipper, Type: common.Process, Payload: []byte(pl)})
	tr.Add("tip with memo", o,
		trace.Secret{Field: "amount", Kind: trace.KUint, Uint: big.NewInt(secret)},
		trace.Secret{Field: "memo", Kind: trace.KString, Str: "coffee"},
		trace.Secret{Field: "sender", Kind: trace.KAddress, Addr: tipper.Addr})
	return tr, nil
}
