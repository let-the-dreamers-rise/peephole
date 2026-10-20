// Package trace is the recording of a scenario run: each step pairs what the
// enclave emitted (engine.Observation) with the ground-truth secrets that step
// was supposed to keep hidden. Checks read the observation as an outside
// observer would and test whether any secret is recoverable.
package trace

import (
	"math/big"

	ethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/let-the-dreamers-rise/peephole/engine"
)

// Kind classifies a secret so checks know how to search for it.
type Kind string

const (
	KAddress Kind = "address"
	KUint    Kind = "uint"
	KString  Kind = "string"
)

// Secret is a value a step was meant to keep from some audience, with the
// policy field label it corresponds to.
type Secret struct {
	Field string // matches spec.Visibility.Field
	Kind  Kind
	Addr  ethCommon.Address
	Uint  *big.Int
	Str   string
}

// Step is one request and everything it revealed, plus its secrets.
type Step struct {
	Label   string
	Obs     engine.Observation
	Secrets []Secret
}

// Trace is a full scenario run.
type Trace struct {
	Scenario string
	Steps    []Step
}

func (t *Trace) Add(label string, obs engine.Observation, secrets ...Secret) {
	t.Steps = append(t.Steps, Step{Label: label, Obs: obs, Secrets: secrets})
}
