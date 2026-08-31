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
| 11 | Cf-Ja3-Hash passthrough, stage-3 captcha redesign | **UNBLOCKED** — owner decided 2026-08-31: deploy behind Cloudflare, see below |

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

## Independent audit 2026-08-31 — wave 8 and wave 9 scope (verified against `e3bb605`)

Every item below was confirmed in code by an independent audit pass. File:line is current HEAD.

### Wave 8 — upstream transport and response path

1. **Pooled-buffer aliasing (top priority, correctness + disclosure).** `core/transport/transport.go:48-52` —
   `defer bufferPool.Put(buffer)` returns the buffer while the error-page bodies (`:76-79`, `:117-122`)
   are still `bytes.NewReader(buffer.Bytes())` streaming to a client. Another request that grabs the
   buffer and `Reset()`s it corrupts the first client's response mid-stream — exactly during backend
   outages when error pages are served. Also a duplicated `resp.Body.Close()` at `:89` and `:117`.
2. **`InsecureSkipVerify: true`** at `transport.go:136` — any MITM between proxy and origin
   reads/injects all traffic. Add `backend_tls_verify` opt-out, default verify.
3. **Shared transport singleton** `transport.go:142-149` — `LoadOrStore` stores the same
   `defaultTransport` for every domain key; `MaxConnsPerHost: 10`, no `MaxIdleConnsPerHost`
   (default 2), no `ResponseHeaderTimeout`. Concurrency to the origin caps at 10 and 8/10
   connections re-dial under load.
4. **5xx masked as 200 + unescaped HTML** `transport.go:76-79, 119-122` — error pages respond
   StatusCode 200 and write raw `errMsg` into `srcdoc="` (`:104-106`); a `"` in a backend error
   breaks the attribute and attacker-flattened backend HTML/JS executes in the origin's error page.
   Escape it, return the real status, make error-body passthrough config-gated.
5. **No `BufferPool` on the ReverseProxy** — construction is now at `core/config/pipeline.go:385-389`
   (not `init.go:126-130` as the old audit says).
6. **Server TLS** `core/server/serve.go:64-68` — no `MinVersion` (TLS 1.0/1.1 negotiable); inert
   `Renegotiation` client-option on a server config (`:67`); `http2.ConfigureServer` on the plain
   :80 listeners (`:39, :72`) with discarded errors.
7. **Port-80 redirect** `serve.go:92` — `r.URL.Path+r.URL.RawQuery` with no `?`, and 301 is cached
   by browsers. Also the port-80 counter takes `firewall.Mutex.Lock()` on an unauthenticated path
   (`:86-90`) — DoS lever.
8. **Webhooks** `core/utils/discord.go:248-249` — `&http.Client{}` with no timeout, response
   discarded; `InitPlaceholders` indexes `RequestLogger[0]`/`[len-1]` unguarded (`:18-19`, panic on
   empty log); `quickchart-go` still in `go.mod` (`:201`).
9. **Fingerprint builder perf** `core/firewall/fingerprint.go:56-68` — per-element `fmt.Sprintf`
   into a Builder. (The GREASE `[1:]`/`[:1]` bug in the same file is being fixed separately.)
10. Minor: `GetCertificate` returns the address of a stack copy per handshake (`core/domains/util.go:16-24`).

### Wave 9 — challenge rendering, XSS, middleware decomposition

1. **Reflected XSS via interpolated IP is already dead** — wave 6 canonicalizes identity through
   `parseClientAddr`/`netip.ParseAddr` (`middleware.go:100-110, 583-584, 316-321`); payloads fail to
   parse. Do NOT claim to fix it. Still do the `html/template` move as defence-in-depth.
2. **Stage 3 is unsolvable for IPv6 clients (live bug).** The raw IPv6 address in the cookie name
   (`challengeCookieName`, `middleware.go:409-422`) contains `:`, which browsers reject in
   `document.cookie` names. Drop `ip` from the cookie name.
3. **CDN PoW supply chain (highest wave-9 priority).** `middleware.go:878` loads
   `cdn.jsdelivr.net/gh/41Baloo/balooPow@main` with no SRI, plus crypto-js 4.0.0 (predates
   CVE-2023-46233 fixed in 4.2.0). Repo owner or a jsDelivr outage neuter stage 2 for every
   challenged visitor mid-attack. Self-host the script; this is also the last outbound Baloo
   dependency (the CLAUDE.md rebrand map still cites it).
4. **Block/ratelimit/unknown-domain pages are cacheable 200s.** `SendResponse` never calls
   `WriteHeader` (`middleware.go:35-38`), so R1/R2/R3 (`:741/:748/:756`), forbidden-fp (`:775`),
   susLv block (`:811/:946`), and the unknown-domain 404 body (`:571-574`) are all cacheable
   200s — shared-CDN cache poisoning of block pages. Fix with real status codes + `Cache-Control:
   no-store` + `Retry-After`.
5. **Open redirect on stage 1 — LIVE** `middleware.go:872` — `http.Redirect(w, r,
   request.URL.RequestURI(), 302)`; a request line `//evil.com/` parses with `Host="evil.com"`,
   `Location: //evil.com/` is emitted verbatim, 302 from the protected site on first visit.
6. **No security headers on any proxy-generated page** — only `Content-Type`/`Cache-Control` on
   stage 2/3; nothing on stage 1 or block pages; captcha frameable.
7. **`err.Error()` to clients** `middleware.go:922/:926` (captcha encode failures).
8. **Middleware monolith** — `middleware.go:523-1031` (523 lines, not the old audit's 335);
   per-request field map `:691-726`; per-request admin-path concat `:996`. Decomposition targets
   should cite these lines.

### Already fixed — do not re-scope (waves 5/6)

Cookie substring check → exact-match + constant-time compare, stage-1 `HttpOnly`, cookie
stripping upstream, header Del-then-Set, CONNECT 405, body cap, rules-before-ratelimits.

One audit inaccuracy: the unknown-Host `%`-verb claim does not match current code — `serve.go:82`
is `fmt.Fprint` (verbatim). The page still 200s, echoes `r.Host`, and brands "balooProxy" (wave 10).

---

## Wave 11 was blocked on a decision — DECIDED 2026-08-31: behind Cloudflare

The owner confirmed LancarSec deploys **behind Cloudflare**. Cloudflare terminates TLS; the
origin only ever sees Cloudflare's handshake, so spec-accurate JA4 from the local ClientHello
is wasted effort and is **dropped from the plan**. Wave 11 is now:

- **Cf-Ja3-Hash passthrough** (Cloudflare Enterprise add-on): believe `Cf-Ja3-Hash` only from a
  trusted peer (same rules as wave 6's header trust), feed it the same fingerprint slot.
- **Stage-3 captcha redesign** — unaffected by the deployment mode, still in scope.
- The GREASE fingerprint bug below is fixed separately and earlier (it is real in either mode).
  **FIXED (wave 11 prep, GREASE fix):** the derivation now filters RFC 8701 GREASE values by
  pattern (0x?a?a) instead of blind `[1:]` slicing, and emits every non-GREASE
  `ec_point_format` instead of only the first. Chrome-family output is byte-identical, so the
  Chromium/Edge/Safari keys keep matching. The Firefox-family keys in
  `known_fingerprints.json` (Firefox, Firefox-Dev, both Tor builds) were regenerated to the new
  derivation in the same commit — without that, real Firefox-family traffic would slide into the
  unknown-fingerprint ratelimit (R3) and `ip.fingerprint` rules written against the old keys
  would go dead; `TestRegeneratedFirefoxFamilyKeysAreReachable` round-trips all four. Still owed
  on a live-traffic refresh (a rebuild, per the bundle's own rule): Dalvik, the bot table and the
  block list were generated from the old lossy output and their clients' true first elements are
  not recorded here, so those keys can only be regenerated from captured hellos.

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
  else reads. The CPU/RAM gauges followed in `core/proxy/usage.go` (commit `a7a3254`) — same
  pattern, `printStats` is the single writer via `SetCpuUsage`/`SetRamUsage`, readers (webhook
  literals, clearProxyCache eviction parse, admin API, discord placeholder substitution) are
  lock-free calls. Build on those, not on the old printStats globals. The remaining wave-7
  candidate, the self-disabling cache-eviction gate (AUDIT.md :4822 — `Alloc/Sys` plateaus so
  the `(cpu<15 && mem>25) || mem>95` test never fires under load), is deferred to wave 8 where
  the cache work lives.

---

## Decisions already made — do not relitigate

- **Product name is LancarSec.** One brand, not LancarProxy, not two. Owner decided 2026-08-31.
- **The rebrand stays in wave 10**, not pulled forward.
- Module path is `github.com/azferius/lancarsec` (lower-case; the module cache escapes upper-case
  as `!l!ancar!sec`).
- `core/gofilter` and `core/screen` are vendored, not dependencies.
- Alpine over distroless for the runtime image — the reasoning is in the Dockerfile header, and it
  is about `CAP_NET_BIND_SERVICE` and the stdin TUI, not about size.
