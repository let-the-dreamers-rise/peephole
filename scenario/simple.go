package scenario

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/HorizenOfficial/vela/pkg/common"
	"github.com/let-the-dreamers-rise/peephole/engine"
	"github.com/let-the-dreamers-rise/peephole/trace"
)

func init() { Register("simple", simple) }

// simple exercises Vela's own sample app (third_party/vela/app/simple): ETH
// accounts funded by public deposits, public withdrawals, and a "compare my
// balance with X" request whose answer is an encrypted event to the requester
// only.
//
// What the app evidently keeps private is the comparison itself: the target
// address travels in the encrypted payload and the result sentence is
// encrypted to the requester; the target is never notified. Deposits (amount
// in clear calldata and a public "deposit_received" app event) and
// withdrawals (on-chain token/destination/amount) are public by design, so
// the per-user balance is not tagged as a secret.
//
// Each compare step tags the target as "counterparty" and the outcome as
// "compareResult" (ground truth computed from the scenario's own ledger and
// cross-checked against the decrypted event).
func simple(wasmPath string) (*trace.Trace, error) {
	wasm, err := os.ReadFile(wasmPath)
	if err != nil {
		return nil, err
	}
	// grace registers a key but never deposits, so she has no account.
	names := []string{"alice", "bob", "carol", "dave", "erin", "frank", "grace"}
	var users []*engine.User
	for _, n := range names {
		u, err := engine.NewUser(n, true)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	w, err := engine.NewWorld(wasm, []byte(`{"allowedTokens":[]}`), users)
	if err != nil {
		return nil, err
	}
	u := func(n string) *engine.User { return w.UserByName(n) }
	tr := &trace.Trace{Scenario: "simple"}
	bal := map[string]*big.Int{}
	for _, n := range names {
		bal[n] = new(big.Int)
	}
	eth := func(milli int64) *big.Int { // amounts in milli-ETH, as wei
		return new(big.Int).Mul(big.NewInt(milli), big.NewInt(1_000_000_000_000_000))
	}

	deposit := func(who string, amt *big.Int) error {
		o := w.Submit(engine.Request{Sender: u(who), Type: common.Process, Deposit: amt})
		if !o.OK {
			return fmt.Errorf("deposit %s %s: %s %s", who, amt, o.ErrorMsg, o.HarnessErr)
		}
		bal[who].Add(bal[who], amt)
		tr.Add(fmt.Sprintf("%s public deposit %s", who, amt), o)
		return nil
	}
	withdraw := func(who string, amt *big.Int, expectOK bool) error {
		pl := fmt.Sprintf(`{"type":"withdraw","withdraw":{"to":"%s","tokenAddress":"0x0000000000000000000000000000000000000000","amount":"0x%s"}}`,
			u(who).Addr.Hex(), amt.Text(16))
		o := w.Submit(engine.Request{Sender: u(who), Type: common.Process, Payload: []byte(pl)})
		if o.OK != expectOK {
			return fmt.Errorf("withdraw %s %s: ok=%v want %v (%s %s)", who, amt, o.OK, expectOK, o.ErrorMsg, o.HarnessErr)
		}
		if o.OK {
			bal[who].Sub(bal[who], amt)
		}
		label := fmt.Sprintf("%s public withdraw %s", who, amt)
		if !expectOK {
			label += " (insufficient balance)"
		}
		tr.Add(label, o)
		return nil
	}
	compare := func(from, to string) error {
		pl := fmt.Sprintf(`{"type":"compare_addresses","compare":{"targetAddress":"%s"}}`, u(to).Addr.Hex())
		o := w.Submit(engine.Request{Sender: u(from), Type: common.Process, Payload: []byte(pl)})
		if !o.OK || len(o.UserEvents) != 1 {
			return fmt.Errorf("compare %s->%s: %s %s", from, to, o.ErrorMsg, o.HarnessErr)
		}
		// Ground truth from our ledger, cross-checked against the decrypted event.
		var want string
		switch bal[to].Cmp(bal[from]) {
		case -1:
			want = "richer than"
		case 1:
			want = "poorer than"
		default:
			want = "as wealthy as"
		}
		var ev struct{ Sentence string }
		if err := json.Unmarshal(o.UserEvents[0].Plaintext, &ev); err != nil || !strings.Contains(ev.Sentence, " "+want+" ") {
			return fmt.Errorf("compare %s->%s: event %q disagrees with ledger (%s)", from, to, o.UserEvents[0].Plaintext, want)
		}
		tr.Add(fmt.Sprintf("%s compares with %s (%s)", from, to, want), o,
			trace.Secret{Field: "counterparty", Kind: trace.KAddress, Addr: u(to).Addr},
			trace.Secret{Field: "compareResult", Kind: trace.KString, Str: want})
		return nil
	}

	// Error path (also exercised by Vela's own system tests): comparing with an
	// address that has no account yet. The target is still the requester's
	// private query.
	compareMissing := func(from, to string) error {
		pl := fmt.Sprintf(`{"type":"compare_addresses","compare":{"targetAddress":"%s"}}`, u(to).Addr.Hex())
		o := w.Submit(engine.Request{Sender: u(from), Type: common.Process, Payload: []byte(pl)})
		if o.OK {
			return fmt.Errorf("compare %s->%s: expected failure", from, to)
		}
		tr.Add(fmt.Sprintf("%s compares with %s (no account)", from, to), o,
			trace.Secret{Field: "counterparty", Kind: trace.KAddress, Addr: u(to).Addr})
		return nil
	}

	steps := []func() error{
		// Funding: varied magnitudes, some users topping up several times.
		func() error { return deposit("alice", eth(1000)) },
		func() error { return deposit("bob", eth(250)) },
		func() error { return deposit("carol", eth(1000)) },
		func() error { return deposit("dave", eth(3)) },
		func() error { return deposit("erin", eth(42_000)) },
		func() error { return deposit("frank", big.NewInt(1)) },
		func() error { return deposit("bob", eth(750)) },
		func() error { return deposit("dave", eth(17)) },
	}
	// Round 1 of comparisons across many pairs (including equal balances:
	// alice=carol=bob=1000).
	pairs := [][2]string{
		{"alice", "bob"}, {"alice", "carol"}, {"alice", "dave"}, {"alice", "erin"}, {"alice", "frank"},
		{"bob", "carol"}, {"bob", "dave"}, {"carol", "erin"}, {"dave", "frank"}, {"erin", "frank"},
		{"frank", "alice"}, {"dave", "erin"},
	}
	for _, p := range pairs {
		p := p
		steps = append(steps, func() error { return compare(p[0], p[1]) })
	}
	steps = append(steps,
		func() error { return compareMissing("carol", "grace") },
		func() error { return withdraw("alice", eth(400), true) },
		func() error { return withdraw("erin", eth(41_000), true) },
		func() error { return withdraw("dave", eth(50), false) }, // error path
		func() error { return withdraw("bob", eth(1000), true) },
		func() error { return deposit("frank", eth(600)) },
		func() error { return deposit("dave", eth(580)) },
	)
	// Round 2 after balances moved: alice=600, bob=0, carol=1000, dave=600,
	// erin=1000, frank=600+1wei.
	pairs = [][2]string{
		{"alice", "bob"}, {"alice", "carol"}, {"alice", "dave"}, {"alice", "frank"},
		{"bob", "alice"}, {"carol", "erin"}, {"dave", "alice"}, {"dave", "frank"},
		{"erin", "carol"}, {"frank", "dave"}, {"carol", "bob"}, {"erin", "alice"},
	}
	for _, p := range pairs {
		p := p
		steps = append(steps, func() error { return compare(p[0], p[1]) })
	}
	// Round 3: a user repeatedly probes one target while moving their own
	// balance (the pattern a balance-guessing requester would use).
	for _, d := range []int64{100, 200, 50, 25, 12} {
		d := d
		steps = append(steps,
			func() error { return deposit("bob", eth(d)) },
			func() error { return compare("bob", "erin") })
	}
	for _, f := range steps {
		if err := f(); err != nil {
			return nil, err
		}
	}
	return tr, nil
}
