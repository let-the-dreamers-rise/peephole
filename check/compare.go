package check

import (
	"fmt"
	"math/big"
	"sort"

	ethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/let-the-dreamers-rise/peephole/observe"
	"github.com/let-the-dreamers-rise/peephole/spec"
	"github.com/let-the-dreamers-rise/peephole/trace"
)

func init() { register(comparisonTarget{}) }

// comparisonTarget models a chain-only observer against apps that answer a
// private "how does my balance compare with X?" query with an encrypted event
// to the requester. Two things combine:
//
//  1. In apps whose balances move only through public deposits and public
//     withdrawals, the observer can replay every account's balance exactly.
//  2. If the outcomes are encoded with different lengths (e.g. "as wealthy as"
//     vs "richer than") and the ciphertext is not padded, the event's length
//     reveals the outcome class.
//
// The observer then keeps only the accounts whose replayed balance is
// consistent with that outcome; when exactly one remains, the hidden target
// of the comparison is re-identified. The check is opt-in: the policy must
// describe the outcomes (checkParams), which asserts the public-flow balance
// model for this app. Every guess is scored against ground truth, and the
// check stays silent if any guess would be wrong.
type comparisonTarget struct{}

func (comparisonTarget) ID() string { return "comparison-target" }
func (comparisonTarget) Describe() string {
	return "re-identify a private comparison's target from result length + publicly replayed balances"
}

type comparisonCfg struct {
	// TargetField is the policy field of the hidden comparison target (default "counterparty").
	TargetField string `json:"targetField"`
	// ResultField is the trace field holding the outcome string (default "compareResult").
	ResultField string `json:"resultField"`
	// Outcomes maps each outcome string to the target's balance relative to
	// the requester's: "lt", "eq" or "gt".
	Outcomes map[string]string `json:"outcomes"`
}

func (comparisonTarget) Run(t *trace.Trace, p *spec.Policy) []Finding {
	var cfg comparisonCfg
	if err := p.Params("comparison-target", &cfg); err != nil || len(cfg.Outcomes) == 0 {
		return nil
	}
	if cfg.TargetField == "" {
		cfg.TargetField = "counterparty"
	}
	if cfg.ResultField == "" {
		cfg.ResultField = "compareResult"
	}
	vis, ok := p.Field(cfg.TargetField)
	if !ok || vis.Allows(spec.Public) {
		return nil
	}

	// Calibration: which outcomes each event length can encode. This is the
	// app's public, attested encoding; an observer learns it by running the
	// same module locally. Only the length -> outcome table is taken from the
	// trace, nothing about who compared with whom.
	lenOutcomes := map[int]map[string]bool{}
	for _, st := range t.Steps {
		if !st.Obs.OK || len(st.Obs.UserEvents) != 1 {
			continue
		}
		for _, s := range st.Secrets {
			if s.Field == cfg.ResultField && s.Kind == trace.KString {
				if _, known := cfg.Outcomes[s.Str]; !known {
					return nil // policy does not describe this outcome; refuse to guess
				}
				l := st.Obs.UserEvents[0].CipherLen
				if lenOutcomes[l] == nil {
					lenOutcomes[l] = map[string]bool{}
				}
				lenOutcomes[l][s.Str] = true
			}
		}
	}
	if len(lenOutcomes) < 2 {
		return nil // every outcome has the same length: nothing to read
	}

	pub := observe.ProjectAll(t, spec.Public)
	bal := map[ethCommon.Address]*big.Int{}
	var zeroTok ethCommon.Address
	var considered, right, wrong int
	var example string
	for i, v := range pub {
		// A comparison, as the observer sees it: an OK request with no deposit
		// and no withdrawal emitting one event whose length is a known outcome
		// encoding. Judge it against balances *before* this step.
		if v.OK && (v.Deposit == nil || v.Deposit.Sign() == 0) && len(v.Withdrawals) == 0 &&
			len(v.UserEvents) == 1 && lenOutcomes[v.UserEvents[0].CipherLen] != nil {
			rels := map[string]bool{}
			for o := range lenOutcomes[v.UserEvents[0].CipherLen] {
				rels[cfg.Outcomes[o]] = true
			}
			me := bal[v.Sender]
			if me == nil {
				me = new(big.Int)
			}
			var cands []ethCommon.Address
			for a, b := range bal {
				if a != v.Sender && rels[relation(b, me)] {
					cands = append(cands, a)
				}
			}
			considered++
			if len(cands) == 1 {
				truth, hasTruth := targetOf(t.Steps[i], cfg.TargetField)
				if hasTruth && truth == cands[0] {
					right++
					if example == "" {
						example = fmt.Sprintf("step %q: event length %d ⇒ outcome %v; only %s has a replayed balance consistent with it (correct hidden target)",
							v.Label, v.UserEvents[0].CipherLen, sortedKeys(lenOutcomes[v.UserEvents[0].CipherLen]), truth.Hex())
					}
				} else {
					wrong++
				}
			}
		}
		// Apply the step's public balance effects.
		if !v.OK {
			continue
		}
		if v.Deposit != nil && v.Deposit.Sign() > 0 && v.DepositTok == zeroTok {
			if bal[v.Sender] == nil {
				bal[v.Sender] = new(big.Int)
			}
			bal[v.Sender].Add(bal[v.Sender], v.Deposit)
		}
		for _, w := range v.Withdrawals {
			if w.Token != zeroTok || w.Amount == nil {
				continue
			}
			if bal[v.Sender] == nil {
				bal[v.Sender] = new(big.Int)
			}
			bal[v.Sender].Sub(bal[v.Sender], w.Amount)
		}
	}
	if right == 0 || wrong > 0 {
		return nil // nothing recovered, or the balance model does not hold for this app
	}
	return []Finding{{
		Check:    "comparison-target",
		Field:    cfg.TargetField,
		Audience: spec.Public,
		Severity: Medium,
		Summary: fmt.Sprintf("a chain-only observer re-identified the hidden target of %d of %d private balance comparisons",
			right, considered),
		Detail: fmt.Sprintf("The result event is unpadded and its outcomes have %d distinct lengths, so the length reveals the outcome class; every balance is replayable from public deposits and withdrawals, so the outcome pins the target whenever only one account is consistent with it. %s",
			len(lenOutcomes), example),
		Repro: "replay balances from public deposits/withdrawals; for each comparison, read the event ciphertext length and keep the accounts whose balance matches that outcome",
	}}
}

func relation(target, requester *big.Int) string {
	switch target.Cmp(requester) {
	case -1:
		return "lt"
	case 1:
		return "gt"
	}
	return "eq"
}

func targetOf(st trace.Step, field string) (ethCommon.Address, bool) {
	for _, s := range st.Secrets {
		if s.Field == field && s.Kind == trace.KAddress {
			return s.Addr, true
		}
	}
	return ethCommon.Address{}, false
}

func sortedKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
