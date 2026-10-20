package check

import (
	"fmt"
	"sort"

	"github.com/let-the-dreamers-rise/peephole/spec"
	"github.com/let-the-dreamers-rise/peephole/trace"
)

func init() { register(amountLength{}) }

// amountLength models a public observer that reads only the byte-length of the
// encrypted payload / events. Vela encrypts with AES-GCM and does not pad, so
// a larger integer produces a longer ciphertext. The observer therefore learns
// the magnitude class of an amount the policy marks private.
type amountLength struct{}

func (amountLength) ID() string       { return "amount-by-length" }
func (amountLength) Describe() string { return "infer a private amount's magnitude from ciphertext length" }

func (amountLength) Run(t *trace.Trace, p *spec.Policy) []Finding {
	vis, ok := p.Field("amount")
	if !ok || vis.Allows(spec.Public) {
		return nil
	}
	type point struct {
		amountBytes int
		obsLen      int
	}
	var pts []point
	for _, st := range t.Steps {
		var amtBytes int
		found := false
		for _, s := range st.Secrets {
			if s.Field == "amount" && s.Kind == trace.KUint && s.Uint != nil {
				amtBytes = len(s.Uint.Bytes())
				found = true
			}
		}
		if !found {
			continue
		}
		// Observable length: the largest user-event ciphertext, else the payload.
		obsLen := st.Obs.PayloadLen
		for _, e := range st.Obs.UserEvents {
			if e.CipherLen > obsLen {
				obsLen = e.CipherLen
			}
		}
		pts = append(pts, point{amtBytes, obsLen})
	}
	if len(pts) < 2 {
		return nil
	}
	// Is observable length a non-constant, monotone function of amount size?
	sort.Slice(pts, func(i, j int) bool { return pts[i].amountBytes < pts[j].amountBytes })
	buckets := map[int]bool{}
	monotone := true
	for i, pt := range pts {
		buckets[pt.obsLen] = true
		if i > 0 && pt.obsLen < pts[i-1].obsLen {
			monotone = false
		}
	}
	if len(buckets) < 2 {
		return nil // constant length: amounts are indistinguishable by length
	}
	sev := Medium
	note := ""
	if monotone {
		note = " Length rises monotonically with amount size, so the ordering of amounts also leaks."
	}
	return []Finding{{
		Check:    "amount-by-length",
		Field:    "amount",
		Audience: spec.Public,
		Severity: sev,
		Summary: fmt.Sprintf("a private amount's size is narrowed to one of %d distinguishable magnitude classes by ciphertext length",
			len(buckets)),
		Detail: fmt.Sprintf("AES-GCM output is not padded, so encoding length tracks the amount's byte-length. Across the run, %d distinct observable lengths appeared for %d amounts.%s",
			len(buckets), len(pts), note),
		Repro: "submit the same operation with amounts of different byte-lengths and compare the emitted ciphertext/calldata sizes",
	}}
}
