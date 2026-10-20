package check

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/let-the-dreamers-rise/peephole/observe"
	"github.com/let-the-dreamers-rise/peephole/spec"
	"github.com/let-the-dreamers-rise/peephole/trace"
)

func init() {
	register(operatorCounterparty{})
	register(guestLogLeak{})
}

// operatorCounterparty models the Vela manager operator, who receives each
// encrypted user-event tagged with the recipient's clear address so it can be
// routed. If the policy says the counterparty is private from the operator,
// that routing address is a full disclosure.
type operatorCounterparty struct{}

func (operatorCounterparty) ID() string       { return "operator-counterparty" }
func (operatorCounterparty) Describe() string { return "operator reads the event recipient from routing metadata" }

func (operatorCounterparty) Run(t *trace.Trace, p *spec.Policy) []Finding {
	vis, ok := p.Field("counterparty")
	if !ok || vis.Allows(spec.Operator) {
		return nil
	}
	views := observe.ProjectAll(t, spec.Operator)
	var n int
	var example string
	for i, v := range views {
		for _, e := range v.UserEvents {
			// count any event whose cleartext recipient is a declared private counterparty
			for _, s := range t.Steps[i].Secrets {
				if s.Field == "counterparty" && s.Kind == trace.KAddress && s.Addr == e.Recipient {
					n++
					if example == "" {
						example = fmt.Sprintf("step %q: operator routes an event to %s, the declared-private counterparty", v.Label, e.Recipient.Hex())
					}
				}
			}
		}
	}
	if n == 0 {
		return nil
	}
	return []Finding{{
		Check:    "operator-counterparty",
		Field:    "counterparty",
		Audience: spec.Operator,
		Severity: High,
		Summary:  fmt.Sprintf("the manager operator learns the private counterparty of %d events in clear", n),
		Detail:   "The executor hands each encrypted user-event to the manager tagged with the recipient's plaintext address for routing. " + example,
		Repro:    "run the manager host and read the UserID field on each forwarded event",
	}}
}

// guestLogLeak models the operator reading the host log server. Vela forwards
// guest INF/WRN/ERR log lines out of the enclave at the default network level.
// If an app logs a value the policy marks private-from-operator, it leaks.
type guestLogLeak struct{}

func (guestLogLeak) ID() string       { return "guest-log-leak" }
func (guestLogLeak) Describe() string { return "private values appear in guest logs forwarded to the host" }

func (guestLogLeak) Run(t *trace.Trace, p *spec.Policy) []Finding {
	var out []Finding
	seen := map[string]bool{}
	for _, st := range t.Steps {
		if len(st.Obs.GuestLogs) == 0 {
			continue
		}
		blob := strings.ToLower(strings.Join(st.Obs.GuestLogs, "\n"))
		for _, s := range st.Secrets {
			vis, ok := p.Field(s.Field)
			if !ok || vis.Allows(spec.Operator) {
				continue
			}
			var needles []string
			switch s.Kind {
			case trace.KAddress:
				needles = []string{strings.ToLower(s.Addr.Hex())}
			case trace.KUint:
				if s.Uint != nil {
					needles = []string{s.Uint.String(), "0x" + s.Uint.Text(16), weiHint(s.Uint)}
				}
			case trace.KString:
				if s.Str != "" {
					needles = []string{strings.ToLower(s.Str)}
				}
			}
			for _, nd := range needles {
				if nd == "" {
					continue
				}
				if strings.Contains(blob, nd) && !seen[s.Field+nd] {
					seen[s.Field+nd] = true
					out = append(out, Finding{
						Check:    "guest-log-leak",
						Field:    s.Field,
						Audience: spec.Operator,
						Severity: High,
						Summary:  fmt.Sprintf("the private %s appears verbatim in a guest log line forwarded to the host", s.Field),
						Detail:   fmt.Sprintf("step %q logged: %q", st.Label, firstMatch(st.Obs.GuestLogs, nd)),
						Repro:    "read the Vela host log server output while the app runs an error path",
					})
				}
			}
		}
	}
	return out
}

func weiHint(u *big.Int) string { return "" } // reserved for unit-scaled matching

func firstMatch(lines []string, needle string) string {
	for _, l := range lines {
		if strings.Contains(strings.ToLower(l), needle) {
			return l
		}
	}
	return ""
}
