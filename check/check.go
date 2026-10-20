// Package check holds the privacy checks. Each check models a specific
// outside observer and tries to recover a field the policy says that observer
// must not learn. A check reports a Finding only when it actually recovers the
// secret (verified against ground truth), with a reproduction, so there are no
// speculative warnings.
package check

import (
	"github.com/let-the-dreamers-rise/peephole/spec"
	"github.com/let-the-dreamers-rise/peephole/trace"
)

// Severity ranks a finding by how much it reveals.
type Severity string

const (
	High   Severity = "high"   // a private value is fully recovered
	Medium Severity = "medium" // a private value is substantially narrowed
	Low    Severity = "low"    // a private value is weakly narrowed
)

// Finding is one confirmed policy violation.
type Finding struct {
	Check    string        `json:"check"`
	Field    string        `json:"field"`
	Audience spec.Audience `json:"audience"`
	Severity Severity      `json:"severity"`
	Summary  string        `json:"summary"`
	Detail   string        `json:"detail"`
	Repro    string        `json:"repro"`
}

// Check is one observer model. Run returns the findings it confirmed, or nil.
type Check interface {
	ID() string
	// Describe is a one-line statement of what the check probes.
	Describe() string
	// Run is given the full recorded run (with ground truth) and the policy.
	// It must only use audience-visible data to attempt recovery, and verify
	// success against ground truth before reporting.
	Run(t *trace.Trace, p *spec.Policy) []Finding
}

// Registry is the set of available checks, keyed by id.
var Registry = map[string]Check{}

func register(c Check) { Registry[c.ID()] = c }

// Selected returns the checks named in the policy, or all of them if none named.
func Selected(p *spec.Policy) []Check {
	if len(p.Checks) == 0 {
		out := make([]Check, 0, len(Registry))
		for _, c := range Registry {
			out = append(out, c)
		}
		return out
	}
	var out []Check
	for _, id := range p.Checks {
		if c, ok := Registry[id]; ok {
			out = append(out, c)
		}
	}
	return out
}
