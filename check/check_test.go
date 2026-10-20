package check

import (
	"encoding/binary"
	"encoding/json"
	"math/big"
	"testing"

	ethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/let-the-dreamers-rise/peephole/engine"
	"github.com/let-the-dreamers-rise/peephole/spec"
	"github.com/let-the-dreamers-rise/peephole/trace"
	"golang.org/x/crypto/sha3"

	common "github.com/HorizenOfficial/vela/pkg/common"
)

var (
	alice = ethCommon.HexToAddress("0x00000000000000000000000000000000000000a1")
	bob   = ethCommon.HexToAddress("0x00000000000000000000000000000000000000b0")
	zero  ethCommon.Address
)

func sub(b byte) [32]byte { var s [32]byte; s[0] = b; return s }

// privatePolicy hides amount, counterparty and invoiceId from everyone but an auditor.
func privatePolicy(checks ...string) *spec.Policy {
	return &spec.Policy{
		App: "test",
		Fields: []spec.Visibility{
			{Field: "amount", VisibleTo: []spec.Audience{spec.Auditor}},
			{Field: "counterparty", VisibleTo: []spec.Audience{spec.Auditor}},
			{Field: "invoiceId", VisibleTo: []spec.Audience{spec.Auditor}},
		},
		Checks: checks,
	}
}

func TestLinkabilityPositiveAndNegative(t *testing.T) {
	// bob's deposit reveals subtype #7; a later transfer emits an event to bob
	// with the same subtype -> linked.
	tr := &trace.Trace{}
	tr.Add("bob deposit", engine.Observation{Sender: bob, Deposit: big.NewInt(100),
		UserEvents: []engine.UserEvent{{Subtype: sub(7), UserID: bob}}})
	tr.Add("alice->bob", engine.Observation{Sender: alice,
		UserEvents: []engine.UserEvent{
			{Subtype: sub(1), UserID: alice}, // sender's own event, not a counterparty
			{Subtype: sub(7), UserID: bob},   // recipient event, same tag as the deposit
		}},
		trace.Secret{Field: "counterparty", Kind: trace.KAddress, Addr: bob})

	if got := (linkability{}).Run(tr, privatePolicy()); len(got) != 1 || got[0].Severity != High {
		t.Fatalf("expected one high finding, got %+v", got)
	}
	// If the policy permits the public to see the counterparty, no finding.
	pub := privatePolicy()
	pub.Fields[1].VisibleTo = []spec.Audience{spec.Public}
	if got := (linkability{}).Run(tr, pub); len(got) != 0 {
		t.Fatalf("expected no finding when counterparty is public, got %+v", got)
	}
}

func TestAmountByLength(t *testing.T) {
	tr := &trace.Trace{}
	for _, a := range []int64{1, 1 << 20, 1 << 40} {
		n := len(big.NewInt(a).Bytes())
		tr.Add("t", engine.Observation{Sender: alice, PayloadLen: 100 + n,
			UserEvents: []engine.UserEvent{{Subtype: sub(byte(a)), UserID: bob, CipherLen: 200 + n}}},
			trace.Secret{Field: "amount", Kind: trace.KUint, Uint: big.NewInt(a)})
	}
	if got := (amountLength{}).Run(tr, privatePolicy()); len(got) != 1 {
		t.Fatalf("expected one finding, got %+v", got)
	}
	// Padded: identical observable length for every amount -> no finding.
	padded := &trace.Trace{}
	for _, a := range []int64{1, 1 << 20, 1 << 40} {
		padded.Add("t", engine.Observation{Sender: alice, PayloadLen: 128,
			UserEvents: []engine.UserEvent{{Subtype: sub(1), UserID: bob, CipherLen: 256}}},
			trace.Secret{Field: "amount", Kind: trace.KUint, Uint: big.NewInt(a)})
	}
	if got := (amountLength{}).Run(padded, privatePolicy()); len(got) != 0 {
		t.Fatalf("expected no finding when lengths are constant, got %+v", got)
	}
}

func TestOperatorCounterparty(t *testing.T) {
	tr := &trace.Trace{}
	tr.Add("t", engine.Observation{Sender: alice,
		UserEvents: []engine.UserEvent{{Subtype: sub(1), UserID: bob}}},
		trace.Secret{Field: "counterparty", Kind: trace.KAddress, Addr: bob})
	if got := (operatorCounterparty{}).Run(tr, privatePolicy()); len(got) != 1 {
		t.Fatalf("expected one finding, got %+v", got)
	}
	ok := privatePolicy()
	ok.Fields[1].VisibleTo = []spec.Audience{spec.Operator, spec.Auditor}
	if got := (operatorCounterparty{}).Run(tr, ok); len(got) != 0 {
		t.Fatalf("expected no finding when operator may see counterparty, got %+v", got)
	}
}

func TestGuestLogLeak(t *testing.T) {
	tr := &trace.Trace{}
	tr.Add("t", engine.Observation{Sender: alice,
		GuestLogs: []string{"ERR Wasm Guest [1]: transfer to " + bob.Hex() + " for 500"}},
		trace.Secret{Field: "counterparty", Kind: trace.KAddress, Addr: bob},
		trace.Secret{Field: "amount", Kind: trace.KUint, Uint: big.NewInt(500)})
	got := (guestLogLeak{}).Run(tr, privatePolicy())
	if len(got) < 1 {
		t.Fatalf("expected at least one finding, got %+v", got)
	}
	// No forwarded logs -> nothing to leak.
	clean := &trace.Trace{}
	clean.Add("t", engine.Observation{Sender: alice},
		trace.Secret{Field: "counterparty", Kind: trace.KAddress, Addr: bob})
	if got := (guestLogLeak{}).Run(clean, privatePolicy()); len(got) != 0 {
		t.Fatalf("expected no finding without logs, got %+v", got)
	}
}

func TestCommitmentPreimage(t *testing.T) {
	amount := big.NewInt(4_200_000)
	invoice := "INV-9"
	// Build the real receipt the way the reference app does.
	h := sha3.NewLegacyKeccak256()
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(invoice)))
	h.Write(lp[:])
	h.Write([]byte(invoice))
	h.Write(alice[:])
	h.Write(zero[:])
	var a32 [32]byte
	amount.FillBytes(a32[:])
	h.Write(a32[:])
	h.Write(bob[:])
	var subtype [32]byte
	copy(subtype[:], h.Sum(nil))

	tr := &trace.Trace{}
	// a prior step puts bob into the candidate recipient set
	tr.Add("seed", engine.Observation{Sender: bob})
	tr.Add("invoice transfer", engine.Observation{Sender: alice,
		AppEvents: []common.AppEvent{{EventSubType: subtype}}},
		trace.Secret{Field: "invoiceId", Kind: trace.KString, Str: invoice},
		trace.Secret{Field: "sender", Kind: trace.KAddress, Addr: alice},
		trace.Secret{Field: "token", Kind: trace.KAddress, Addr: zero})

	p := privatePolicy("commitment-preimage")
	p.CheckParams = map[string]json.RawMessage{"commitment-preimage": json.RawMessage(`{
      "hash":"keccak256",
      "fields":[
        {"kind":"lenPrefixedString","from":"secret:invoiceId"},
        {"kind":"address","from":"secret:sender"},
        {"kind":"address","from":"secret:token"},
        {"kind":"uint256","from":"brute:amount"},
        {"kind":"address","from":"brute:recipient"}],
      "brute":{"amountMin":0,"amountMax":5000000,"amountStep":100000,"recipients":"trace"}}`)}
	if got := (commitmentPreimage{}).Run(tr, p); len(got) != 1 || got[0].Severity != High {
		t.Fatalf("expected one high finding, got %+v", got)
	}
}
