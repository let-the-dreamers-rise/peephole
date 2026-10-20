# peephole

**A privacy-conformance harness for [Horizen Vela](https://docs.horizen.io/vela) apps.**

Vela runs your app's logic inside a TEE (an AWS Nitro enclave), so the *compute* is confidential. But privacy is not only about where code runs — it is about what the enclave *emits*: the on-chain events, the request calldata, the routing metadata the operator sees, the logs it forwards. Vela's own docs are explicit that this is on you:

> "Attestation shows which code ran… It does not prove the application's logic is correct, which remains the developer's responsibility."
> "The enclave can only include data the application has persisted… the developer decides what a report can reveal."

So every Vela app has a second, un-attested surface — everything that leaves the enclave — and today nothing checks it. peephole does.

You write a one-page **policy** saying what each field is *meant* to hide and from whom. peephole drives your real WASM app through Horizen's **real executor** across a scenario, then runs a battery of **observer models** — a chain-only observer, the manager operator, a log reader — and tries to recover each field the policy says they must not learn. It reports a finding only when it actually recovers the value, with a reproduction, and exits non-zero so it drops into CI.

```
$ make check
peephole — vela-nova (Horizen reference confidential payments) / scenario "nova" — 167 steps, 5 checks

FAIL: 4 privacy finding(s).

[1] a chain-only observer re-identified the hidden counterparty in 43 of 45 events (96%)  (high, observer=public, field=counterparty)
[2] inverted a cleartext commitment: recovered amount 1234560000 and recipient 0x292A…1691 in 246913 hashes  (high, observer=public, field=amount,counterparty)
[3] the manager operator learns the private counterparty of 5 events in clear  (high, observer=operator, field=counterparty)
[4] a private amount's size is narrowed to one of 5 distinguishable magnitude classes by ciphertext length  (medium, observer=public, field=amount)
```

Those four are real, reproduced against Horizen's **own reference payments app** (`vela-nova`, from its "first confidential app" tutorial), with the enclave behaving exactly as designed. They have been reported to Horizen privately first, and the detailed write-up will be published here once the Vela team has had time to respond; this repo frames them as "what a conformance tool catches", not "Vela is broken".

## How it works

```
your app.wasm ─▶ engine ─▶ Horizen StatelessExecutor + Wasmtime  (real Vela, in-process)
                   │              │
 scenario ────────▶│         emits: encrypted events + on-chain subtype, app events,
 (declares the     │                withdrawals, calldata size, routing metadata, guest logs
  secret values)   ▼
                 trace ──▶ observer projections ──▶ checks ──▶ report (pass/fail, repro)
 policy  ─────────────────────────────────────────────▶ (what each field may reveal, to whom)
```

- **engine/** runs the real `pkg/executor.StatelessExecutor` with the real Wasmtime runtime — no vsock, no Nitro — and records exactly what each request makes visible outside the enclave.
- **spec/** is the policy format: for each field, `visibleTo` lists the audiences allowed to learn it (`public`, `operator`, `auditor`; the owner is always allowed).
- **observe/** projects a run down to what one audience can actually see, so a check can never cheat by reading ground truth.
- **check/** holds the observer models. Each recovers a field or stays silent; it verifies recovery against ground truth before reporting, so there are no speculative warnings.
- **scenario/** drives an app and tags each step with the secret values it was supposed to hide.

## The checks

| id | observer | what it recovers |
|---|---|---|
| `event-linkability` | public (chain) | the hidden owner/counterparty of an encrypted event, from its bounded-set subtype |
| `commitment-preimage` | public (chain) | the amount + recipient inside a low-entropy cleartext hash "receipt" |
| `amount-by-length` | public (chain) | the magnitude class of a private amount, from unpadded ciphertext length |
| `operator-counterparty` | manager operator | the recipient of a "private" transfer, from cleartext routing metadata |
| `guest-log-leak` | manager operator | any private value an app writes to a forwarded log line |
| `error-message-leak` | public (chain) | any private value an app formats into a failed request's on-chain error message |
| `comparison-target` | public (chain) | the hidden target of a private balance comparison, from unpadded result length + balances replayed from public deposits/withdrawals (opt-in via `checkParams`) |

Each check documents the *leak pattern* it probes, not an app-specific bug, so it applies to any Vela app whose policy names the relevant field. The reference app passes `guest-log-leak` (it logs no private value) — the suite is not a rubber stamp; see the unit tests in `check/`.

## It confirms the fix, too

peephole is not just a failure-stamp. `examples/tipjar` is a tiny app (our own
code) with two modes — a natural "leaky" version and a "hardened" one (amount
padded to a fixed width, receipt commitment blinded with a per-app secret kept
in encrypted state). Same app, same scenario:

```
$ make demo
# leaky mode:
FAIL: 2 privacy finding(s).   # recovered the tip amount from the receipt + by length
# hardened mode:
PASS: no declared-private field was recovered by any observer.
```

So the loop a developer runs is: write policy → `peephole` fails → fix the emit
surface → `peephole` passes → wire it into CI so it stays fixed.

## Run it

Requires Go 1.24+, [TinyGo v0.39.0](https://github.com/tinygo-org/tinygo/releases/tag/v0.39.0) (the version Vela's CI pins), Docker not needed.

```bash
make vela     # fetch pinned Vela + vela-nova into third_party/, install the test shim
make apps     # compile the reference apps to WASM (TinyGo)
make test     # unit tests + the nova integration test
make check    # run the full suite against the reference payments app
make check-simple  # run it against Vela's own sample app (app/simple)
```

## Writing a policy for your app

```json
{
  "app": "my confidential app",
  "fields": [
    { "field": "amount",       "visibleTo": ["auditor"] },
    { "field": "counterparty", "visibleTo": ["auditor"] }
  ],
  "checks": ["event-linkability", "amount-by-length", "operator-counterparty"]
}
```

Then add a scenario that drives your app and tags each step's secret values (see `scenario/nova.go`). Roadmap: generate scenarios automatically from an app's request schema, and a `peephole attest` mode that emits a signed "privacy report" artifact.

## Status & license

Built against Vela **v0.2.0** (commit `335724c`). peephole is MIT (see `LICENSE`); it bundles no Horizen code — `make vela` downloads it for local testing under Vela's BSL evaluation grant (see `NOTICE`). Not affiliated with Horizen.
