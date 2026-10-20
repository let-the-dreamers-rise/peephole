package check

import (
	"encoding/json"
	"math/big"
	"testing"

	ethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/let-the-dreamers-rise/peephole/engine"
	"github.com/let-the-dreamers-rise/peephole/spec"
	"github.com/let-the-dreamers-rise/peephole/trace"
)

var carol = ethCommon.HexToAddress("0x00000000000000000000000000000000000000c0")

func comparePolicy() *spec.Policy {
	return &spec.Policy{
		App:    "test",
		Fields: []spec.Visibility{{Field: "counterparty"}, {Field: "compareResult", VisibleTo: []spec.Audience{spec.Public}}},
		CheckParams: map[string]json.RawMessage{"comparison-target": json.RawMessage(
			`{"outcomes":{"richer than":"lt","poorer than":"gt","as wealthy as":"eq"}}`)},
	}
}

// compareTrace: alice=100, bob=100, carol=7 (all public deposits), then
// comparisons whose event length is 221 for richer/poorer and eqLen for equal.
func compareTrace(eqLen int) *trace.Trace {
	tr := &trace.Trace{}
	for _, d := range []struct {
		a ethCommon.Address
		v int64
	}{{alice, 100}, {bob, 100}, {carol, 7}} {
		tr.Add("deposit", engine.Observation{Sender: d.a, OK: true, Deposit: big.NewInt(d.v),
			UserEvents: []engine.UserEvent{{CipherLen: 175, UserID: d.a}}})
	}
	cmp := func(from, to ethCommon.Address, res string, l int) {
		tr.Add("compare", engine.Observation{Sender: from, OK: true, Deposit: big.NewInt(0), PayloadLen: 129,
			UserEvents: []engine.UserEvent{{CipherLen: l, UserID: from}}},
			trace.Secret{Field: "counterparty", Kind: trace.KAddress, Addr: to},
			trace.Secret{Field: "compareResult", Kind: trace.KString, Str: res})
	}
	cmp(alice, bob, "as wealthy as", eqLen) // only bob equals alice -> re-identified
	cmp(alice, carol, "richer than", 221)   // lt/gt candidates = {carol} only -> re-identified
	cmp(carol, alice, "poorer than", 221)   // candidates {alice,bob} -> ambiguous
	return tr
}

func TestComparisonTargetPositive(t *testing.T) {
	got := (comparisonTarget{}).Run(compareTrace(223), comparePolicy())
	if len(got) != 1 || got[0].Field != "counterparty" || got[0].Audience != spec.Public {
		t.Fatalf("expected one public counterparty finding, got %+v", got)
	}
}

func TestComparisonTargetNegative(t *testing.T) {
	// Padded result: every outcome has the same length -> nothing to read.
	if got := (comparisonTarget{}).Run(compareTrace(221), comparePolicy()); len(got) != 0 {
		t.Fatalf("expected no finding with constant-length results, got %+v", got)
	}
	// Policy lets the public see the target -> not a violation.
	p := comparePolicy()
	p.Fields[0].VisibleTo = []spec.Audience{spec.Public}
	if got := (comparisonTarget{}).Run(compareTrace(223), p); len(got) != 0 {
		t.Fatalf("expected no finding when the target is public, got %+v", got)
	}
	// No outcome description in the policy -> the check does not run.
	p = comparePolicy()
	p.CheckParams = nil
	if got := (comparisonTarget{}).Run(compareTrace(223), p); len(got) != 0 {
		t.Fatalf("expected no finding without checkParams, got %+v", got)
	}
	// Balance model broken: carol's balance changed in a way the chain does
	// not show (e.g. a private transfer), so she really equals alice. The
	// observer's unique candidate (bob) is wrong for that step; the check must
	// stay silent rather than report a model it cannot trust.
	tr := compareTrace(223)
	tr.Add("compare", engine.Observation{Sender: alice, OK: true, Deposit: big.NewInt(0),
		UserEvents: []engine.UserEvent{{CipherLen: 223, UserID: alice}}},
		trace.Secret{Field: "counterparty", Kind: trace.KAddress, Addr: carol},
		trace.Secret{Field: "compareResult", Kind: trace.KString, Str: "as wealthy as"})
	if got := (comparisonTarget{}).Run(tr, comparePolicy()); len(got) != 0 {
		t.Fatalf("expected no finding when a guess disagrees with ground truth, got %+v", got)
	}
}

func TestErrorMessageLeak(t *testing.T) {
	p := &spec.Policy{App: "test", Fields: []spec.Visibility{{Field: "counterparty"}}}
	tr := &trace.Trace{}
	tr.Add("failed compare", engine.Observation{Sender: alice, ErrorCode: 1,
		ErrorMsg: "failed to process request: Account " + bob.Hex() + " does not exist!"},
		trace.Secret{Field: "counterparty", Kind: trace.KAddress, Addr: bob})
	if got := (errorMessageLeak{}).Run(tr, p); len(got) != 1 || got[0].Audience != spec.Public {
		t.Fatalf("expected one public finding, got %+v", got)
	}
	// The error names only the (public) sender -> no finding.
	clean := &trace.Trace{}
	clean.Add("failed withdraw", engine.Observation{Sender: alice, ErrorCode: 1,
		ErrorMsg: "Insufficient balance for account " + alice.Hex()},
		trace.Secret{Field: "counterparty", Kind: trace.KAddress, Addr: bob})
	if got := (errorMessageLeak{}).Run(clean, p); len(got) != 0 {
		t.Fatalf("expected no finding, got %+v", got)
	}
	// Policy allows the public to see it -> no finding.
	p.Fields[0].VisibleTo = []spec.Audience{spec.Public}
	if got := (errorMessageLeak{}).Run(tr, p); len(got) != 0 {
		t.Fatalf("expected no finding when public may see it, got %+v", got)
	}
}
