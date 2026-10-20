package check

import (
	"fmt"

	ethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/let-the-dreamers-rise/peephole/observe"
	"github.com/let-the-dreamers-rise/peephole/spec"
	"github.com/let-the-dreamers-rise/peephole/trace"
)

func init() { register(linkability{}) }

// linkability models a public, chain-only observer that tries to attribute
// each encrypted event to a real address using only the event's 32-byte
// subtype. Vela derives each user's subtypes from a fixed seed, so the
// anonymity set is bounded; a public action (a deposit) reveals one of the
// depositor's subtypes, and over time the observer learns enough of each
// user's set to re-identify them as the hidden counterparty of later events.
type linkability struct{}

func (linkability) ID() string       { return "event-linkability" }
func (linkability) Describe() string { return "re-identify an event's hidden owner from its subtype" }

func (linkability) Run(t *trace.Trace, p *spec.Policy) []Finding {
	vis, ok := p.Field("counterparty")
	if !ok || vis.Allows(spec.Public) {
		return nil // policy does not promise to hide the counterparty from the public
	}
	pub := observe.ProjectAll(t, spec.Public)

	// Build the attacker's table from public information only: in a step that
	// is a pure public deposit, every emitted subtype belongs to the depositor
	// (the public request sender).
	known := map[[32]byte]ethCommon.Address{}
	for _, v := range pub {
		if v.Deposit == nil || v.Deposit.Sign() == 0 || len(v.Withdrawals) > 0 {
			continue
		}
		for _, e := range v.UserEvents {
			known[e.Subtype] = v.Sender
		}
	}
	if len(known) == 0 {
		return nil
	}

	// Score against ground truth: a step's non-sender event owner is a hidden
	// counterparty. Ground truth owner is trace.Step.Obs.UserEvents[i].UserID,
	// which the public observer never sees.
	var hidden, linked int
	var example string
	for _, st := range t.Steps {
		for _, e := range st.Obs.UserEvents {
			truth := e.UserID
			if truth == st.Obs.Sender {
				continue // the submitter's own event does not reveal a counterparty
			}
			hidden++
			if guess, ok := known[e.Subtype]; ok && guess == truth {
				linked++
				if example == "" {
					example = fmt.Sprintf("step %q: event subtype %x… attributed to %s (correct hidden counterparty)",
						st.Label, e.Subtype[:4], truth.Hex())
				}
			}
		}
	}
	if linked == 0 {
		return nil
	}
	return []Finding{{
		Check:    "event-linkability",
		Field:    "counterparty",
		Audience: spec.Public,
		Severity: High,
		Summary: fmt.Sprintf("a chain-only observer re-identified the hidden counterparty in %d of %d events (%.0f%%)",
			linked, hidden, 100*float64(linked)/float64(hidden)),
		Detail: fmt.Sprintf("Event subtypes come from a bounded per-user set. Observing public deposits revealed %d subtype→address bindings, which then matched the subtypes of events the policy marks counterparty-private. %s",
			len(known), example),
		Repro: "collect subtypes from each address's public deposits, then match them against the subtypes of later encrypted events",
	}}
}
