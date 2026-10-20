// Command peephole runs a privacy-conformance check of a Vela app: it drives
// the app through a scenario using Horizen's real executor, then tests whether
// any field the policy declares private is recoverable by an outside observer.
//
// Exit code is 0 on PASS (nothing recovered) and 1 on FAIL, so it drops into CI.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/let-the-dreamers-rise/peephole/check"
	"github.com/let-the-dreamers-rise/peephole/report"
	"github.com/let-the-dreamers-rise/peephole/scenario"
	"github.com/let-the-dreamers-rise/peephole/spec"
)

func main() {
	var (
		policyPath = flag.String("policy", "", "path to the privacy policy JSON")
		appPath    = flag.String("app", "", "path to the app .wasm")
		scen       = flag.String("scenario", "", "scenario name (see -list)")
		asJSON     = flag.Bool("json", false, "emit the report as JSON")
		list       = flag.Bool("list", false, "list available scenarios and checks, then exit")
	)
	flag.Parse()

	if *list {
		fmt.Println("scenarios:", scenario.Names())
		fmt.Println("checks:")
		for id, c := range check.Registry {
			fmt.Printf("  %-22s %s\n", id, c.Describe())
		}
		return
	}
	if *policyPath == "" || *appPath == "" || *scen == "" {
		fmt.Fprintln(os.Stderr, "usage: peephole -policy p.json -app app.wasm -scenario name")
		os.Exit(2)
	}

	pol, err := spec.Load(*policyPath)
	if err != nil {
		fatal(err)
	}
	sf, ok := scenario.Get(*scen)
	if !ok {
		fatal(scenario.ErrUnknown(*scen))
	}
	tr, err := sf(*appPath)
	if err != nil {
		fatal(fmt.Errorf("run scenario: %w", err))
	}

	rep := report.Report{App: pol.App, Scenario: tr.Scenario, Steps: len(tr.Steps)}
	for _, c := range check.Selected(pol) {
		rep.Ran = append(rep.Ran, c.ID())
		rep.Findings = append(rep.Findings, c.Run(tr, pol)...)
	}
	rep.Sort()

	if *asJSON {
		_ = rep.WriteJSON(os.Stdout)
	} else {
		rep.WriteText(os.Stdout)
	}
	if !rep.Passed() {
		os.Exit(1)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "peephole:", err)
	os.Exit(2)
}
