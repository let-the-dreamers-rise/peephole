package check

import (
	"fmt"
	"strings"

	"github.com/let-the-dreamers-rise/peephole/observe"
	"github.com/let-the-dreamers-rise/peephole/spec"
	"github.com/let-the-dreamers-rise/peephole/trace"
)

func init() { register(errorMessageLeak{}) }

// errorMessageLeak models a chain-only observer reading the error string of
// failed requests. When the guest returns an error, Vela's executor signs the
// (truncated to 100 bytes) message into the UpdatePayload that is posted
// on-chain, so anything an app formats into an error — e.g. a value it read
// from the encrypted payload — becomes public.
type errorMessageLeak struct{}

func (errorMessageLeak) ID() string { return "error-message-leak" }
func (errorMessageLeak) Describe() string {
	return "private values appear in the on-chain error message of a failed request"
}

func (errorMessageLeak) Run(t *trace.Trace, p *spec.Policy) []Finding {
	var out []Finding
	seen := map[string]bool{}
	pub := observe.ProjectAll(t, spec.Public)
	for i, v := range pub {
		if v.ErrorMsg == "" {
			continue
		}
		msg := strings.ToLower(v.ErrorMsg)
		for _, s := range t.Steps[i].Secrets {
			vis, ok := p.Field(s.Field)
			if !ok || vis.Allows(spec.Public) {
				continue
			}
			for _, nd := range secretNeedles(s) {
				if nd == "" || !strings.Contains(msg, nd) || seen[s.Field+nd] {
					continue
				}
				seen[s.Field+nd] = true
				out = append(out, Finding{
					Check:    "error-message-leak",
					Field:    s.Field,
					Audience: spec.Public,
					Severity: High,
					Summary:  fmt.Sprintf("the private %s appears verbatim in the on-chain error message of a failed request", s.Field),
					Detail:   fmt.Sprintf("step %q failed with public error %q", v.Label, v.ErrorMsg),
					Repro:    "submit the failing request and read ErrorMsg from the UpdatePayload the executor posts on-chain",
				})
			}
		}
	}
	return out
}
