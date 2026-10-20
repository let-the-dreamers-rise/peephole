// Package report renders the outcome of a peephole run.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/let-the-dreamers-rise/peephole/check"
)

// Report is the full result of running checks against one trace.
type Report struct {
	App      string          `json:"app"`
	Scenario string          `json:"scenario"`
	Steps    int             `json:"steps"`
	Ran      []string        `json:"checksRun"`
	Findings []check.Finding `json:"findings"`
}

// Passed is true when no findings were confirmed.
func (r Report) Passed() bool { return len(r.Findings) == 0 }

var sevRank = map[check.Severity]int{check.High: 0, check.Medium: 1, check.Low: 2}

// Sort orders findings most severe first.
func (r *Report) Sort() {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		return sevRank[r.Findings[i].Severity] < sevRank[r.Findings[j].Severity]
	})
}

// WriteText prints a human-readable report.
func (r Report) WriteText(w io.Writer) {
	fmt.Fprintf(w, "peephole — %s / scenario %q — %d steps, %d checks\n", r.App, r.Scenario, r.Steps, len(r.Ran))
	if r.Passed() {
		fmt.Fprintln(w, "\nPASS: no declared-private field was recovered by any observer.")
		return
	}
	fmt.Fprintf(w, "\nFAIL: %d privacy finding(s).\n", len(r.Findings))
	for i, f := range r.Findings {
		fmt.Fprintf(w, "\n[%d] %s  (%s, observer=%s, field=%s)\n", i+1, f.Summary, f.Severity, f.Audience, f.Field)
		fmt.Fprintf(w, "    check:  %s\n", f.Check)
		fmt.Fprintf(w, "    detail: %s\n", f.Detail)
		fmt.Fprintf(w, "    repro:  %s\n", f.Repro)
	}
}

// WriteJSON prints the report as JSON.
func (r Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
