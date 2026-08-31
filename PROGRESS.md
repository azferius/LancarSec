# LancarSec — Wave Progress

**Purpose.** This file is the handoff. If you are a new session or a different agent picking this
up, read this first, then `CLAUDE.md`, then `docs/AUDIT.md`. It tells you what is done, what is
next, and what will bite you.

**Keep it current.** Update this file at the end of every wave, in the same commit as the work.
A wave that landed but is not recorded here will be redone by whoever comes next.

Last updated: 2026-08-31 · HEAD when written: see `git log -1`

---

## Status at a glance

| Wave | Scope | Status |
| --- | --- | --- |
| 1 | Repo hygiene, secret purge, history rewrite | **DONE** |
| 2 | Toolchain 1.19→1.25, dependency graph, module path | **DONE** |
| 3 | Test harness, benchmark baseline, CI gates | **DONE** |
| 4 | Config load/reload unification, embed fingerprints, panics→errors | **DONE** |
| 5 | Secrets, token derivation, admin auth | **IN PROGRESS** |
| 6 | Client identity: trusted-proxy resolution, IPv6 | not started |
| 7 | Hot-path concurrency rewrite | not started |
| 8 | Upstream transport and response path | not started |
| 9 | Challenge rendering, XSS, middleware decomposition | not started |
| 10 | Wire-visible rebrand + legal notices (atomic, one commit) | not started |
| 11 | JA4 fingerprinting, stage-3 captcha redesign | **BLOCKED** — see below |

---

## How to verify you have not broken anything

These five are the CI gate. All must be green before a wave is considered done:

```bash
go build ./...
gofmt -l . | (! read)
go vet ./...
go test -race -count=1 ./...
go mod tidy && git diff --quiet go.mod go.sum
```

The hot-path benchmark is the sixth check, and the one wave 7 lives or dies by:

```bash
go test -run=XXX -bench=BenchmarkMiddleware -benchmem -count=1 ./core/server/
```

Compare against `core/server/BENCHMARK_BASELINE.md`. **Do not edit the numbers in that file** —
they are the "before". Update the citations if line numbers move; leave the measurements.

---

## The rule that matters most

**Tests pin TODAY'S behaviour, bugs included.** 63 defects are deliberately asserted as the current
contract, each with a comment naming the wave that flips it. When your wave fixes one, the test
failing is the design working.

> Flip the assertion, rewrite its comment, and say so in the commit. **Never weaken or delete a
> test to make it pass.**

And: **coverage lies.** The wave-3 suite hit 100% on `core/firewall` and passed `-race`, then 30 of
67 realistic mutations survived it. If you add tests, mutation-test them — apply the change you
fear, watch the test fail, revert, watch it pass.

---

## What each finished wave actually changed

Full detail is in `CLAUDE.md` under "Wave N outcome". Short version:

**Wave 1.** History rewritten (`git filter-repo`); every SHA changed and `origin/main` was
force-pushed — any clone predating `a09cc54` must be re-cloned, not pulled. Pack 312 MiB → 495 KiB.
A real RSA private key and 15 config.json blobs with live credentials left the history.

**Wave 2.** `go 1.25.0`, toolchain `go1.25.14`, module `github.com/azferius/lancarsec`.
govulncheck 20 reachable stdlib CVEs → zero. `gofilter` and `screen` vendored in-tree.
The Go 1.22 loop-variable change was proven inert here with `-gcflags=all=-d=loopvar=2` plus a
positive control — do not re-litigate it.

**Wave 3.** First tests. `core/firewall` 100%, `core/utils` 67.3%, `core/server` 46.1%.
Benchmark baseline committed. `hack/` holds the load and memory-growth harnesses.

**Wave 4.** First wave to change runtime behaviour. One config pipeline
(`parse → normalise → validate → build → publish`) with everything fallible before anything is
published. `reload` no longer disables the stage-2 proof-of-work, converges on the file, and
preserves live counters and attack state. No outbound call to Baloo infrastructure remains.
The `gofilter` `matches` panic is fixed in both `parser.go` and `parser.y`.

---

## Wave 11 is blocked on a decision, not on code

In Cloudflare mode `core/server/middleware.go` sets `tlsFp = "Cloudflare"` and
`browser = "Cloudflare"` for every client, so **TLS fingerprinting is entirely disabled** and the
unknown-fingerprint ratelimit (`if browser == ""`) never fires. Cloudflare terminates TLS; the
origin only ever sees Cloudflare's handshake.

So wave 11's value depends on deployment:

- **Behind Cloudflare** → spec-accurate JA4 is wasted effort. Do the `Cf-Ja3-Hash` passthrough
  (Enterprise add-on) and fix the GREASE asymmetry, nothing more.
- **Direct origin** → JA4 from the raw ClientHello is worth building, and may deserve to move up.

Ask the owner before starting wave 11.

There is a real bug there regardless of the decision, in `core/firewall/fingerprint.go`:
`CipherSuites[1:]` and `SupportedCurves[1:]` drop the first element to skip GREASE, but only
Chrome-family clients send GREASE — **Firefox loses a legitimate cipher and gets a wrong
fingerprint**. And `SupportedPoints[:1]` takes only the first element, the opposite of what its own
comment says.

---

## Traps that will cost you time

- **Check `git merge-base` before trusting a subagent's view of the tree.** Wave 4 lost time to
  three agents branching from before a commit they were told existed; one re-invented a design that
  had already been rejected.
- **Subagents must commit in their worktree before reporting.** Wave 3 lost eight verified tests
  because an agent returned a summary instead of the file, and the worktree was pruned. They were
  recovered from the transcript; do not rely on that working twice.
- **Never run `modernize -fix` or any repo-wide rewrite over `core/gofilter`.** It is vendored
  verbatim; its README documents byte-fidelity and the two allowed deviations. It rewrote 56 lines
  of the parser on the first attempt.
- **`transport` is a natural local identifier** and will shadow the `core/transport` package.
  Grep before assuming a file that gains that import compiles.
- **Wire tokens stay `__bProxy_v` / `/_bProxy/` / `baloo-Proxy` until wave 10.** Renaming the cookie
  invalidates every clearance cookie in flight and re-challenges every visitor at once, so it
  happens once, atomically, after the security work.
- **Docker image is unverified.** No daemon on the dev machine. Run `docker build` before a release.

---

## Decisions already made — do not relitigate

- **Product name is LancarSec.** One brand, not LancarProxy, not two. Owner decided 2026-08-31.
- **The rebrand stays in wave 10**, not pulled forward.
- Module path is `github.com/azferius/lancarsec` (lower-case; the module cache escapes upper-case
  as `!l!ancar!sec`).
- `core/gofilter` and `core/screen` are vendored, not dependencies.
- Alpine over distroless for the runtime image — the reasoning is in the Dockerfile header, and it
  is about `CAP_NET_BIND_SERVICE` and the stdin TUI, not about size.
