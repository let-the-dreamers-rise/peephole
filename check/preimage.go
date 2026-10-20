package check

import (
	"encoding/binary"
	"fmt"
	"math/big"

	ethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/let-the-dreamers-rise/peephole/spec"
	"github.com/let-the-dreamers-rise/peephole/trace"
	"golang.org/x/crypto/sha3"
)

func init() { register(commitmentPreimage{}) }

// commitmentPreimage models a public observer that inverts a low-entropy
// commitment emitted in clear as an app event. Many Vela apps emit a hash
// "receipt" (e.g. keccak(invoice‖sender‖token‖amount‖recipient)); if the
// hashed tuple has little real entropy — guessable invoice, public addresses,
// cent-aligned amount — the observer brute-forces the hidden fields. The
// tuple layout is declared in the policy's checkParams, so the check works for
// any app that documents its commitment, not just one.
type commitmentPreimage struct{}

func (commitmentPreimage) ID() string       { return "commitment-preimage" }
func (commitmentPreimage) Describe() string { return "invert a cleartext commitment to recover hidden fields" }

// layout describes the hashed tuple.
type layout struct {
	Hash   string      `json:"hash"` // "keccak256" (default) or "sha256"
	Fields []component `json:"fields"`
	Brute  bruteCfg    `json:"brute"`
}
type component struct {
	// Kind: "lenPrefixedString" | "address" | "uint256"
	Kind string `json:"kind"`
	// From: "secret:<field>" (ground truth the observer is assumed to guess),
	//       "brute:amount" | "brute:recipient" (searched).
	From string `json:"from"`
}
type bruteCfg struct {
	AmountMin  int64 `json:"amountMin"`
	AmountMax  int64 `json:"amountMax"`
	AmountStep int64 `json:"amountStep"`
	// Recipients: "trace" uses every address seen in the run as a candidate.
	Recipients string `json:"recipients"`
}

func (commitmentPreimage) Run(t *trace.Trace, p *spec.Policy) []Finding {
	var lo layout
	if err := p.Params("commitment-preimage", &lo); err != nil || len(lo.Fields) == 0 {
		return nil
	}
	// Candidate recipient set: every distinct address observed in the run.
	var recips []ethCommon.Address
	if lo.Brute.Recipients == "trace" {
		seen := map[ethCommon.Address]bool{}
		for _, st := range t.Steps {
			add := func(a ethCommon.Address) {
				if !seen[a] {
					seen[a] = true
					recips = append(recips, a)
				}
			}
			add(st.Obs.Sender)
			for _, e := range st.Obs.UserEvents {
				add(e.UserID)
			}
		}
	}

	var out []Finding
	for _, st := range t.Steps {
		// secrets the observer is assumed to know/guess (invoice id, sender, token)
		known := map[string]trace.Secret{}
		for _, s := range st.Secrets {
			known[s.Field] = s
		}
		for _, ae := range st.Obs.AppEvents {
			if ae.Data != nil && len(ae.Data) > 0 {
				continue // this check targets the empty-data commitment form
			}
			if found, amt, rcpt, tries := invert(lo, known, recips, ae.EventSubType); found {
				recovered := "amount " + amt.String()
				field := "amount"
				if usesBruteRecipient(lo) {
					recovered += " and recipient " + rcpt.Hex()
					field = "amount,counterparty"
				}
				out = append(out, Finding{
					Check:    "commitment-preimage",
					Field:    field,
					Audience: spec.Public,
					Severity: High,
					Summary:  fmt.Sprintf("inverted a cleartext commitment: recovered %s in %d hashes", recovered, tries),
					Detail:   fmt.Sprintf("step %q emitted an app-event whose 32-byte subtype hashes a low-entropy tuple with no secret blinding; brute force over the declared layout recovered the hidden field(s).", st.Label),
					Repro:    "hash every (guessed low-entropy input, public address, searched amount, candidate recipient) tuple and match against the app-event subtype",
				})
			}
		}
	}
	return out
}

func invert(lo layout, known map[string]trace.Secret, recips []ethCommon.Address, target [32]byte) (bool, *big.Int, ethCommon.Address, int) {
	min, max, step := lo.Brute.AmountMin, lo.Brute.AmountMax, lo.Brute.AmountStep
	if step <= 0 {
		step = 1
	}
	tries := 0
	for cents := min; cents <= max; cents += step {
		amt := big.NewInt(cents)
		for _, r := range recips {
			tries++
			if build(lo, known, amt, r) == target {
				return true, amt, r, tries
			}
		}
	}
	return false, nil, ethCommon.Address{}, tries
}

func build(lo layout, known map[string]trace.Secret, amount *big.Int, recipient ethCommon.Address) [32]byte {
	// Only keccak256 is implemented (what the Vela reference app uses); other
	// hashes would be added here.
	h := sha3.NewLegacyKeccak256()
	for _, c := range lo.Fields {
		switch c.Kind {
		case "lenPrefixedString":
			s := known[fieldOf(c.From)].Str
			var lp [4]byte
			binary.BigEndian.PutUint32(lp[:], uint32(len(s)))
			h.Write(lp[:])
			h.Write([]byte(s))
		case "address":
			if c.From == "brute:recipient" {
				h.Write(recipient[:])
			} else {
				a := known[fieldOf(c.From)].Addr
				h.Write(a[:])
			}
		case "uint256":
			var b [32]byte
			if c.From == "brute:amount" {
				amount.FillBytes(b[:])
			} else {
				known[fieldOf(c.From)].Uint.FillBytes(b[:])
			}
			h.Write(b[:])
		case "uint64":
			var b [8]byte
			if c.From == "brute:amount" {
				binary.BigEndian.PutUint64(b[:], amount.Uint64())
			} else {
				binary.BigEndian.PutUint64(b[:], known[fieldOf(c.From)].Uint.Uint64())
			}
			h.Write(b[:])
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// fieldOf strips the "secret:" prefix from a From spec.
func fieldOf(from string) string {
	const p = "secret:"
	if len(from) > len(p) && from[:len(p)] == p {
		return from[len(p):]
	}
	return from
}

// usesBruteRecipient reports whether the layout searches over recipients.
func usesBruteRecipient(lo layout) bool {
	for _, c := range lo.Fields {
		if c.From == "brute:recipient" {
			return true
		}
	}
	return false
}
