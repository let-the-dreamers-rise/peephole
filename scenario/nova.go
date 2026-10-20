package scenario

import (
	"fmt"
	"math/big"
	"os"

	"github.com/HorizenOfficial/vela/pkg/common"
	ethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/let-the-dreamers-rise/peephole/engine"
	"github.com/let-the-dreamers-rise/peephole/trace"
)

func init() { Register("nova", nova) }

// nova exercises the Horizen reference confidential-payments app (vela-nova)
// the way its own tutorial does: register users, deposit publicly, make
// private transfers (some with an invoice receipt), withdraw, and hit an
// error path. Each private action declares the amount and counterparty it is
// meant to hide, so the checks have ground truth to test against.
func nova(wasmPath string) (*trace.Trace, error) {
	wasm, err := os.ReadFile(wasmPath)
	if err != nil {
		return nil, err
	}
	alice, err := engine.NewUser("alice", true)
	if err != nil {
		return nil, err
	}
	bob, err := engine.NewUser("bob", true)
	if err != nil {
		return nil, err
	}
	w, err := engine.NewWorld(wasm, []byte(`{"allowedTokens":[]}`), []*engine.User{alice, bob})
	if err != nil {
		return nil, err
	}
	var ethZero ethCommon.Address
	tr := &trace.Trace{Scenario: "nova"}

	// Public deposits. These are how an observer anchors each user's subtypes.
	for i := 0; i < 120; i++ {
		o := w.Submit(engine.Request{Sender: bob, Type: common.Process, Deposit: big.NewInt(1000)})
		tr.Add("bob public deposit", o)
	}
	o := w.Submit(engine.Request{Sender: alice, Type: common.Process, Deposit: big.NewInt(2_000_000_000_000_000_000)})
	tr.Add("alice public deposit", o)

	// A run of private transfers alice -> bob (counterparty private). Enough of
	// them that the linkability observer is tested on a real denominator.
	for i := 0; i < 40; i++ {
		pl := fmt.Sprintf(`{"type":"transfer","transfer":{"to":"%s","amount":"0x5"}}`, bob.Addr.Hex())
		o := w.Submit(engine.Request{Sender: alice, Type: common.Process, Payload: []byte(pl)})
		tr.Add("private transfer", o,
			trace.Secret{Field: "counterparty", Kind: trace.KAddress, Addr: bob.Addr})
	}

	// Private transfers of varying amounts (amount + counterparty private).
	amounts := []int64{5, 1000, 1_000_000, 500_000_000_000}
	for _, amt := range amounts {
		pl := fmt.Sprintf(`{"type":"transfer","transfer":{"to":"%s","amount":"0x%x"}}`, bob.Addr.Hex(), amt)
		o := w.Submit(engine.Request{Sender: alice, Type: common.Process, Payload: []byte(pl)})
		tr.Add(fmt.Sprintf("private transfer amount=%d", amt), o,
			trace.Secret{Field: "amount", Kind: trace.KUint, Uint: big.NewInt(amt)},
			trace.Secret{Field: "counterparty", Kind: trace.KAddress, Addr: bob.Addr})
	}

	// A transfer that attaches an invoice receipt (app-event commitment).
	secretAmt := big.NewInt(1_234_560_000) // 1,234.56 in 6-decimal units
	invoice := "INV-2026-042"
	pl := fmt.Sprintf(`{"type":"transfer","transfer":{"to":"%s","amount":"0x%x","invoice_id":"%s"}}`, bob.Addr.Hex(), secretAmt, invoice)
	o = w.Submit(engine.Request{Sender: alice, Type: common.Process, Payload: []byte(pl)})
	tr.Add("private transfer with invoice", o,
		trace.Secret{Field: "amount", Kind: trace.KUint, Uint: new(big.Int).Set(secretAmt)},
		trace.Secret{Field: "counterparty", Kind: trace.KAddress, Addr: bob.Addr},
		trace.Secret{Field: "invoiceId", Kind: trace.KString, Str: invoice},
		// Public values the commitment also hashes; an observer is assumed to
		// know these (the sender is public, the token is ETH/zero).
		trace.Secret{Field: "sender", Kind: trace.KAddress, Addr: alice.Addr},
		trace.Secret{Field: "token", Kind: trace.KAddress, Addr: ethZero})

	// Withdraw (destination + amount are public on-chain by design).
	pw := fmt.Sprintf(`{"type":"withdraw","withdraw":{"to":"%s","amount":"0x64"}}`, alice.Addr.Hex())
	o = w.Submit(engine.Request{Sender: alice, Type: common.Process, Payload: []byte(pw)})
	tr.Add("withdraw", o)

	return tr, nil
}
