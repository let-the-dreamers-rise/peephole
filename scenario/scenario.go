// Package scenario drives a Vela app through a sequence of requests and
// records the result as a trace. A scenario is the "workload" peephole
// observes; real adoption would ship one scenario per app (or generate them).
package scenario

import (
	"fmt"
	"sort"

	"github.com/let-the-dreamers-rise/peephole/trace"
)

// Func builds a trace by driving the app at wasmPath.
type Func func(wasmPath string) (*trace.Trace, error)

var registry = map[string]Func{}

// Register adds a named scenario.
func Register(name string, f Func) { registry[name] = f }

// Get returns a scenario by name.
func Get(name string) (Func, bool) { f, ok := registry[name]; return f, ok }

// Names lists registered scenarios.
func Names() []string {
	var out []string
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ErrUnknown is returned for an unregistered scenario name.
func ErrUnknown(name string) error {
	return fmt.Errorf("unknown scenario %q; have %v", name, Names())
}
