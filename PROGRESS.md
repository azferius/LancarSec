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
| 5 | Secrets, token derivation, admin auth | **DONE** |
| 6 | Client identity: trusted-proxy resolution, IPv6 | **DONE** |
| 7 | Hot-path concurrency rewrite | **IN PROGRESS** — request-path clock landed (`d8dffe6`) |
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

**Wave 5.** Secrets, tokens and admin auth. **Deploying this re-challenges every visitor once** —
three independent causes, any one sufficient: `Encrypt` became keyed BLAKE3 (was
`blake3(input+key)` concatenation), `EncryptSha` became HMAC-SHA256 (was `sha256(input+key)`,
length-extendable), and the access key changed shape.

- `utils.RandomString` and the new `utils.RandomIntN` draw from `crypto/rand` with rejection
  sampling. **`math/rand` is now absent from every non-vendored file.** The twelve `rand.Intn`
  calls generating the stage-3 captcha fell in the gap between two agents' scopes and were fixed
  separately: they place the answer, and captchas are served to anyone, so a linear PRNG there let
  a bot recover the state and predict where the secret half would be drawn.
- Challenge tokens are length-prefix encoded over `(v1, domain, ip, fingerprint, UA, hour, susLv)`.
  Previously bare concatenation: a UA ending in digits merged with the hour string, so an attacker
  could pre-mint a future hour's token, and a token minted on an idle domain cleared any other
  domain on the same proxy.
- `StageToString` no longer maps both susLv 0 and susLv >= 5 to `"5+"`. That collision was a full
  block bypass: a whitelisted request cached an empty token under the shared key, and the later
  blocked request found it, skipped the block, and hit a cookie check that degenerated to
  `strings.Contains(header, "__bProxy_v=")` — satisfied by any stale cookie.
- OTPs rotate on the **aligned UTC hour** through a single `atomic.Pointer` snapshot. They were
  plain globals written by a background goroutine and read on the hot path with no synchronisation.
- Stage-1 cookie is `HttpOnly`; cookies are validated by exact per-stage name lookup with
  `subtle.ConstantTimeCompare`; every `*__bProxy_v` cookie is stripped before forwarding upstream.
- Admin API: constant-time compare, 404 (not 403) on failure so endpoints are undiscoverable, an
  empty secret now denies everyone instead of matching `""`, and a capped failure delay.
  `/_bProxy/stats` and `/_bProxy/fingerprint` now require the secret — **any monitoring scraping
  them will break.**
- Deleted: `GET_IP_CACHE` (returned every live clearance token on the proxy), `FILL_IP_CACHE`
  (held the global write lock across ~20k iterations — one authenticated request was an outage).

**Decision that departed from the plan, recorded so it is not silently reverted:** the wave-4
design said to make the API `RELOAD` action actually work; the agent deleted it instead, on the
grounds that remote config reload is a lateral-movement primitive and the TUI `reload` covers the
operator need. If you want remote reload back, that is a deliberate re-add, not a bug fix.

**Wave 6.** Client identity. This closes the most directly exploitable finding in the whole audit:
`ip = request.Header.Get("Cf-Connecting-Ip")` from **any** peer, with no check. One header defeated
every ratelimit, every ban, and the token binding wave 5 had just hardened.

- New `core/trusted`: 22 Cloudflare prefixes `//go:embed`ed from `global/trusted/` (fetched
  2026-08-31, source URLs in that README), plus operator CIDRs from `proxy.trusted_proxies`.
  `IsTrusted` is 7-19 ns, 0 allocs. **An empty set trusts nobody** — deliberately, and there is no
  bundled default installed at init, so a pipeline that never calls `trusted.Load` degrades to
  "ignore all headers" rather than "believe everyone".
- `0.0.0.0/0` and `::/0` are **rejected** as config entries: a default route is not an allowlist,
  it is the absence of one.
- Two `net/netip` traps the agent found empirically rather than assuming: `Prefix.Contains` does
  **not** match an IPv4-mapped address (`::ffff:1.2.3.4`) against an IPv4 prefix — a dual-stack
  listener hands out exactly that form, so without `Unmap()` the entire IPv4 allowlist would be
  silently dead. And `Contains` returns false for **any** zoned address, so `fe80::1%eth0` never
  matches `fe80::/10`. Both handled and pinned by tests that fail if a Go release changes them.
- `realClientIP` is the single source of truth. `X-Forwarded-For` takes the **rightmost** element:
  the leftmost is whatever the client wrote, and taking it reintroduces the exact bug being fixed.
- IPv6 ratelimits key on the **/64**, not the address — a residential allocation is a /64 or
  larger, so per-address limiting is free rotation. Logs keep the full address; the key and the
  logged value are deliberately different things.
- `strings.Split(RemoteAddr, ":")[0]` is gone. It turned `[2001:db8::1]:443` into the key `"[2001"`,
  collapsing every IPv6 client sharing a first hextet into one bucket.
- Backend identity headers use `Set`, not `Add`, and inbound
  `X-Forwarded-For`/`X-Real-Ip`/`Forwarded`/`proxy-*` are `Del`eted first. `Add` appended, so a
  client-supplied `x-real-ip` survived and arrived **first**.
- `CONNECT` is refused with 405 (`httputil.ReverseProxy` forwards it verbatim, which turns a DDoS
  front end into an open relay running from the proxy's IP). Bodies are capped with
  `http.MaxBytesReader`.
- Firewall rules now evaluate **before** the ratelimits, so `action: 0` is a real whitelist.
  Previously the request was already counted and could already be blocked before its rule was read.

**Cost, measured, not estimated.** `BenchmarkMiddlewareDecisionPath` 429 → 525 ns/op serial and
1037 → 1274 ns/op parallel: roughly +22% for the trusted lookup and proper address parsing. Allocs
fell 80 → 64 B/op. Wave 7 should more than reclaim this; do not let it be attributed there.

**Caught in integration, worth knowing:** the config agent added
`proxy.cloudflare_enforce_origin` and the pipeline published it, but **nothing read it** — an
operator could switch on origin enforcement and get none. Wired separately with a four-case test.
A security option that silently does nothing is worse than an absent one, because it is believed.

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

## Wave 6, config half — MERGED

The seam described below was wired in commit `5b4a2d9`: `core/config/trusted.go` now
sets `var loadTrusted = trusted.Load` directly and the placeholder is gone. The
integration contract is kept here because it explains *why* the install runs in
**publish**, not build, and the config keys' defaults — do not undo either.

New keys, all defaulted in `normalise` and rejected in `validate`, single pipeline, no second path:

| Key | Default | Notes |
| --- | --- | --- |
| `proxy.trusted_proxies` | `[]` | Merged with the bundled Cloudflare ranges by `trusted.Load`. A bare address is accepted as its /32 or /128; prefixes are masked and deduplicated; an entry that will not parse is rejected **by name**. A zoned v6 address is refused rather than silently de-zoned. |
| `proxy.cloudflare_enforce_origin` | `false` | **Do not default this to true.** The check runs before any authentication, so turning it on before DNS is cut over — or before the operator's own address is in the trusted list — is a total, unrecoverable lockout from the origin. Consumed by the middleware; mirrored to `proxy.CloudflareEnforceOrigin`. |
| `proxy.max_body_size` | 10 MiB | Process-wide ceiling in bytes. `-1` is unlimited; `0` means "unset" and is replaced by the default. |
| `domains[].maxBodySize` | inherits `proxy.max_body_size` | Per-domain override, because an upload endpoint and a static site do not want the same number. Resolved in `normalise`, so `DomainSettings.MaxBodySize` is always final and never zero. |

`trusted.Load` runs in **publish**, not build. It both parses (fallible) and swaps a set the request
path reads (a publish), and the pipeline invariant does not allow both in build — a build that failed
after the swap would leave a refused configuration's trusted set running. So the halves are split
across the two stages that can each hold one: `validate` parses every entry with `netip.ParsePrefix`
and names the bad one, `publish` installs. A reload with a broken CIDR list is therefore refused
before `build` allocates anything, and the running trusted set survives untouched.

`hack/config.test.json` now trusts loopback so the load harnesses still resolve distinct subject IPs
from `Cf-Connecting-Ip`; see `hack/README.md`. `examples/config.json` shows the format using RFC 5737
/ RFC 3849 documentation prefixes only — a template must never ship a routable range, since trusting
a peer means believing its `Cf-Connecting-Ip`. Both files are decoded against the real structs by
`TestExampleConfigTemplate` / `TestHackTemplateStillLoads`, so a template that rots fails the build.

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
- **Wave 7 has started on `main`.** The request-path clock moved to atomics in
  `core/proxy/clock.go` (commit `d8dffe6`) — the clock goroutine is the only writer, everything
  else reads. Build on that, not on the old printStats globals.

---

## Decisions already made — do not relitigate

- **Product name is LancarSec.** One brand, not LancarProxy, not two. Owner decided 2026-08-31.
- **The rebrand stays in wave 10**, not pulled forward.
- Module path is `github.com/azferius/lancarsec` (lower-case; the module cache escapes upper-case
  as `!l!ancar!sec`).
- `core/gofilter` and `core/screen` are vendored, not dependencies.
- Alpine over distroless for the runtime image — the reasoning is in the Dockerfile header, and it
  is about `CAP_NET_BIND_SERVICE` and the stdin TUI, not about size.
