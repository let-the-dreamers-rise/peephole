// Package spec defines the privacy policy a Vela app is checked against.
//
// A policy is a plain statement of intent: for each kind of information an
// app handles, who is allowed to learn it. Peephole never infers intent; the
// developer declares it, and peephole tries to violate it.
package spec

import (
	"encoding/json"
	"fmt"
	"os"
)

// Audience is a party that can observe a running app from outside the enclave.
type Audience string

const (
	// Public: anyone reading the chain (ProcessorEndpoint calldata + events).
	Public Audience = "public"
	// Operator: whoever runs the Vela manager host (sees cleartext routing
	// metadata and forwarded guest logs, but not enclave state or payloads).
	Operator Audience = "operator"
	// Auditor: a party registered in AuthorityRegistry, via deanonymization.
	Auditor Audience = "auditor"
	// Owner: the user the data belongs to. Always allowed; listed for clarity.
	Owner Audience = "owner"
)

// Visibility names who may learn a field. "private" means only the owner (and,
// where the app allows it, an auditor); anyone else learning it is a finding.
type Visibility struct {
	// Field is a human label, e.g. "transfer amount" or "counterparty".
	Field string `json:"field"`
	// VisibleTo lists audiences permitted to learn this field. Owner is implied.
	VisibleTo []Audience `json:"visibleTo"`
}

// Allows reports whether an audience is permitted to learn this field.
func (v Visibility) Allows(a Audience) bool {
	if a == Owner {
		return true
	}
	for _, x := range v.VisibleTo {
		if x == a {
			return true
		}
	}
	return false
}

// Policy is the full declared intent for one app.
type Policy struct {
	App         string       `json:"app"`
	Description string       `json:"description,omitempty"`
	Fields      []Visibility `json:"fields"`
	// Checks lists the check ids to run (empty = all registered checks).
	Checks []string `json:"checks,omitempty"`
	// CheckParams holds per-check configuration, keyed by check id. A check
	// that needs no configuration ignores it.
	CheckParams map[string]json.RawMessage `json:"checkParams,omitempty"`
}

// Params decodes this policy's parameters for a given check id into v.
// It is a no-op (returns nil) when the policy supplies none.
func (p Policy) Params(checkID string, v any) error {
	raw, ok := p.CheckParams[checkID]
	if !ok {
		return nil
	}
	return json.Unmarshal(raw, v)
}

// Field returns the declared visibility for a field label, or false.
func (p Policy) Field(label string) (Visibility, bool) {
	for _, f := range p.Fields {
		if f.Field == label {
			return f, true
		}
	}
	return Visibility{}, false
}

// Load reads a policy from a JSON file and validates it.
func Load(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("parse policy %s: %w", path, err)
	}
	if p.App == "" {
		return nil, fmt.Errorf("policy %s: missing \"app\"", path)
	}
	valid := map[Audience]bool{Public: true, Operator: true, Auditor: true, Owner: true}
	for _, f := range p.Fields {
		for _, a := range f.VisibleTo {
			if !valid[a] {
				return nil, fmt.Errorf("policy %s: field %q lists unknown audience %q", path, f.Field, a)
			}
		}
	}
	return &p, nil
}
