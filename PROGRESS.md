# LancarSec — Wave Progress

**Purpose.** This file is the handoff. If you are a new session or a different agent picking this
up, read this first, then `CLAUDE.md`, then `docs/AUDIT.md`. It tells you what is done, what is
next, and what will bite you.

**Keep it current.** Update this file at the end of every wave, in the same commit as the work.
A wave that landed but is not recorded here will be redone by whoever comes next.

Last updated: 2026-09-04 · HEAD when written: see `git log -1`

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
| 7 | Hot-path concurrency rewrite | **DONE** — clock `d8dffe6`, gauges `a7a3254` |
| 8 | Upstream transport and response path | **DONE** — HEAD `ee1daf2`, verified PASS |
| 9 | Challenge rendering, XSS, middleware decomposition | **DONE** — W1 `d1d62e9`, W2 `7767cf8`, W3 `1f9d878`, W4 `cdc269c`/`7b5b813`/`b3a417f` |
| 10 | Wire-visible rebrand + legal notices (atomic, one commit) | **DONE** — cutover `335ffd2`, fixes `de088a0`, docs `e7a7a58`/`e2c7982`, straggler `75e38f5` |
| 11 | Cf-Ja3-Hash passthrough, stage-3 captcha redesign, Go 1.26 | **DONE** — `edd8fc7`, `9c8b1cd`, `ff0a8fe`, `79b2ac9`, `ba82695` |
| 12 | Keyed-state sharding: firewall.Mutex off the request path | **DONE** — see below |
| 13 | Log cap, DSL rules that lie, graceful shutdown, headless spin | **DONE** — see below |

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

**Wave 7.** Hot-path concurrency rewrite, landed as two commits: the request-path clock moved to
atomics (`d8dffe6`) — ratelimit decisions no longer take the global lock — and the TUI display
gauges followed (`a7a3254`). Build on the atomic clock, not the old `printStats` globals. The one
deferred item, the eviction heuristic whose `(cpu<15 && mem>25) || mem>95` test never fires under
load, landed in wave 8 as a count-based gate.

**Wave 8.** Upstream transport and response path. Three worker branches (`9d2fd5e` transport,
`1c573ef` server, `98d2e1a` misc) merged to main at `ee1daf2`; independent verification PASS
(11 packages ok under `-race`, all CI gates green, adversarial probes passed).

- **Breaking:** backends are now TLS-verified by default. Self-signed origins must set the new
  `backend_tls_skip_verify: true` per-domain (default false = verify). Previously every upstream
  TLS connection ran `InsecureSkipVerify: true`.
- **Breaking:** backend 5xx responses now carry their real status code. They were masked as
  200s; anything monitoring for 200s will see 5xx it never saw before.
- **Breaking:** backend error-body passthrough is off by default; opt in per domain with
  `passBackendErrors: true`. The generic error page is html-escaped and the srcdoc injection
  (attacker-flattened backend HTML/JS) is closed.
- Per-domain transport registry replaces the shared singleton: `MaxIdleConnsPerHost` 100,
  `ResponseHeaderTimeout` 30s, `Configure`/`Reset` swept on config publish. Concurrency to the
  origin no longer caps at 10 connections with 8/10 re-dialing.
- Pooled-buffer aliasing fixed (the buffer went back to the pool while the response body was
  still being streamed from it) and a `BufferPool` is wired onto every `ReverseProxy` — the
  32 KiB-per-response alloc is gone.
- Server: TLS 1.2 floor on :443, `http2.ConfigureServer` once on the TLS listener only, port-80
  redirect is 307 with a proper query join (`/search?q=x` no longer redirects to `/searchq=x`,
  which browsers cached), and the redirect path takes no `firewall.Mutex.Lock`.
- Cache eviction is count-based (AUDIT.md:4822): caps `maxIpsCacheEntries`/`maxImgsCacheEntries`
  checked every 2 min, replacing the dead heap heuristic. Per-entry TTL still needs Store-site
  timestamps → wave 9.
- Misc: webhook 10s timeout + guarded body, `InitPlaceholders` empty-log placeholder (was a
  panic), fingerprint builder per-element `fmt.Sprintf` removed — output byte-identical, golden
  tests untouched.

**Deferred, recorded so it is not silently lost:** `GetCertificate` stack-copy (needs a
cert-cache design); per-entry cache TTL (wave 9 middleware decomposition); `quickchart-go`
removal (owner decision — replaceable with a direct `http.Post`).

---

## Independent audit 2026-08-31 — wave 8 and wave 9 scope (verified against `e3bb605`)

**Wave 8 status: LANDED 2026-08-31 at `ee1daf2`.** Items 1–9 below are fixed and verified; item
10 (`GetCertificate`) is deferred pending a cert-cache design. The item list is kept as the
written record of what wave 8 fixed; file:line refers to the pre-wave-8 tree.

Every item below was confirmed in code by an independent audit pass.

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

**W1 status: LANDED 2026-08-31 at `d1d62e9` (merge of `ad22800`).** Items 2–7 below are fixed and
verified (item 5's mechanism text is corrected in the outcome block); item 1 needs no fix; item 8
(decomposition) is the W2 slice. Verification: independent PASS — 13 checks incl. adversarial
probes (open-redirect target 400/no Location/no cookie, legit path still 302s with clearance
cookie, PoW assets first-party + immutable, proxied responses carry none of the new headers); all
CI gates green under `-race`.

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

### Wave 9 W1 outcome (2026-08-31, `ad22800`, merged `d1d62e9`)

- **Real status codes + `Cache-Control: no-store`** on every block/ratelimit/404/405 path
  (`SendResponseWithStatus`); R1/R2/R3 now send 429 with `Retry-After: 10`. Closes item 4.
- **`setProxyPageHeaders`** (nosniff, X-Frame-Options: DENY, Referrer-Policy: no-referrer) at each
  proxy-generated response site — deliberately never globally: `httputil.ReverseProxy` appends
  backend headers without clearing what the handler set. Closes item 6. No CSP by design: the
  challenge pages ARE inline script; a CSP with `'unsafe-inline'` would be security theater.
- **PoW assets served first-party** from the `global/pow` embeds (`/_bProxy/balooPow.min.js`,
  `/_bProxy/crypto-js.min.js`, immutable cache) before any bookkeeping; stage-2 page references
  them; CDN tags gone. Closes item 3 (and CVE-2023-46233's exposure).
- **Stage-3 cookie name** no longer embeds the client IP (IPv6 `:` made the challenge unsolvable);
  name derives from `challengeCookieName(3)`. **Breaks in-flight stage-3 cookies — one
  re-challenge at cutover.** Closes item 2.
- **Open redirect (item 5) — the mechanism text above was wrong.** `url.ParseRequestURI` parses
  `GET //evil.com/ HTTP/1.1` with `Host` EMPTY and `Path="//evil.com/"` (it never reads a
  scheme-less `//` as an authority); it is `http.Redirect`'s internal `url.Parse` that reads `//`
  as an authority and skips its relative-URL fixup, emitting `Location: //evil.com/` verbatim.
  The fix refuses any target with `URL.Host != ""` or `Path` starting `//` (400, no Location, no
  cookie). Mutation-tested: the weaker Host-only guard reproduces the 302 + cookie leak.
- **Captcha encode failures log instead of echoing `err.Error()`** (item 7). Interpolations into
  stage 2/3 go through new `escapeHTML`/`escapeJSString` helpers — a scoped defence-in-depth
  choice; the full `html/template` move stays deferred to W2 alongside item 8's decomposition.
- Item 1 confirmed dead (wave 6 canonicalization); not claimed as a fix.

### Re-audit folding (2026-08-31) — W2/W3/W4 slices

The ultracode re-audit (dated section at the tail of docs/AUDIT.md; 90 findings → 73 verified,
1 refuted, 5 already fixed by W1, completeness critic found nothing missed) folds into wave 9:

- **W2** (existing slice, +1 item): middleware decomposition + `html/template` move (item 8 /
  QUAL-03 — the monolith grew 335 → 509 lines) **plus the `debug` nil-proxy guard** (HTTP-03,
  new: `Host: debug` reaches a `DomainSettings` with nil `DomainProxy` and panics per
  connection, trace swallowed by `io.Discard`; ~3 lines).
- **W3 (new — config correctness)**: reject empty/short challenge secrets (AUTHZ-01/CRYPTO-02 —
  full challenge bypass, the re-audit's top security finding); ratelimits defaults + load
  warning when keys are absent (HTTP-05/QUAL-02 — threshold 0 currently blocks everyone after
  one monitor tick); wire the body limits that are currently dead (AUTHZ-06/QUAL-01/HTTP-02);
  republish OTP on reload (AUTHZ-02); redact the admin secret from LastLogs (HTTP-06/CRYPTO-06).
- **W4 (new — concurrency hardening)**: nil-window panic under `firewall.Mutex` without defer
  (CONC-01, critical — wave 7's claimed lazy bucket creation was never implemented, PERF-10);
  defer unlocks in supervised workers (CONC-03); window-map cardinality caps (CONC-04);
  synchronized config publish (CONC-02/AUTHZ-05/CRYPTO-04); unsupervised webhook goroutines
  (CONC-05); `Initialised` atomic (CONC-06); ReadLogs lock (CONC-07); coarse-lock decomposition
  (CONC-11); plus the re-audit's perf mediums/lows.

### Wave 9 W2 outcome (2026-09-01, `7767cf8`)

- **Decomposition (QUAL-03, item 8) — pure code motion.** The 1220-line monolith is now
  `middleware.go` ~490 lines (the decision pipeline: what is DECIDED) plus three owned files:
  `identity.go` (WHO the request is from: addr parsing, real IP, ratelimit keys, body cap,
  accessKey encoding), `response.go` (HOW the proxy answers: SendResponse/SendResponseWithStatus,
  proxy page headers, PoW assets, Proxy-Secret endpoint), `challenge.go` (what a challenged
  client is SENT: cookie names/suffix, strip, stage 1/2/3 pages and handlers). Seven moved
  functions verified byte-identical against `7767cf8~1`; the captcha generation block identical
  whitespace-normalized.
- **`html/template` migration.** Stage-2/stage-3 pages are `template.Must(...Parse(...))` with
  typed actions; `escapeHTML`/`escapeJSString` helpers deleted. Byte-preservation strategy:
  hex payloads are invisible to the escapers; the difficulty integer is `template.JS` of
  `strconv.Itoa` (digits-only, verbatim — `jsValEscaper` would pad with spaces and break the
  rendered-page pin); base64 captcha payloads do get re-escaped on the wire (`+`→`\u002b`,
  `/`→`\/`) — same decoded bytes, and the test-side extractor unescapes before decoding.
- **HTTP-03 nil-backend guard.** A request naming the `debug` pseudo-domain (registered by the
  config pipeline with a zero `DomainSettings`, `DomainProxy` nil) now gets 404 + no-store +
  text/plain instead of panicking per connection on `DomainProxy.ServeHTTP` (trace swallowed by
  `io.Discard`). Mutation-tested: guard disabled → the tripwire test fails with the exact
  nil-pointer panic; restored copy-verified with zero residue.
- **Verification: independent PASS, 13 checks over two verifier rounds** — CI gates green
  (`gofmt`/`go vet`/`go test -race` all 12 packages/`go mod tidy`), escape helpers gone,
  byte-equivalence, rendered-page pins load-bearing (exact `new BalooPow(...,5,...,!1)`, exact
  salts/challenge hex, captcha PNG decodes), guard mutation test.

### Wave 9 W4b outcome (2026-09-01, `185ac60`–`cdc269c`)

Solo batch, scoped disjoint from W3 (jim: `core/config/*`) and W4a (pam: firewall window maps,
middleware counting, monitor tick). jim/pam confirmed dead sessions (assignment envelopes
delivered 01:40, zero outbox activity by 03:30) — standups handled internally.

- **CONC-06 (`185ac60`)** `proxy.Initialised` was a plain bool written by the monitor goroutine
  (evaluateRatelimit, outside firewall.Mutex) and polled from main before the listener starts —
  data race under the Go memory model. Now an `atomic.Bool` (Store in `monitor.go`, Load in
  `main.go`). `atomic.Bool` contains `noCopy`, so the test fixture's snapshot-by-value is vet-
  rejected; fixtures now Store(false) at setup and in Cleanup.
- **CONC-07 (`199e9c6`)** lost-update in `utils.ReadLogs`: RLock'd snapshot → release → trim
  decision → Lock'd copy-back with the stale slice header, so entries AddLogs appended in between
  were silently dropped. Now snapshot + trim under one write Lock; terminal I/O loop stays
  outside (no hot-path stall).
- **CRYPTO-07 (`8fa0964`)** crash.log 0644 → 0600 — full stack traces can embed request material
  and it sits beside the 0600 secrets. Its only other entry point (dead `LogError`) deleted with it.
- **QUAL-09/CRYPTO-11 dead code (`8268a21`)** 13 symbols deleted, every one grep-verified
  caller-free before cutting, with their pin tests: utils SafeString/closestTo10/JsonEscape/
  PrintMutex, GetOwnIP (whole ip.go), LogHeapProfile/LogGoroutineProfile (whole debug.go),
  HashToInt + 5 tests, QuickchartResponse; pnc.LogError; domains.CacheResponse; firewall.RequestLog
  (whole requests.go); proxy.JSDifficulty. Excluded on purpose: `proxy.FailRequestRatelimit` (owner
  decision, W3/W4a). (The api.go RELOAD no-op was not reachable for this batch — it was
  deleted in an earlier wave and is pinned gone by `TestDeletedActionsAreGone`.)
- **PERF-11/12 (`cdc269c`)** the reserved-endpoint switch concatenated
  `"/_bProxy/"+AdminSecret+"/api/v1"` per request — one alloc on the hottest path. Cached keyed
  on the secret (reload/test-safe).
- **Stale entries corrected:** audit perf item 8's `InitPlaceholders` unguarded `RequestLogger[0]`/
  `[len-1]` was already fixed in wave 8 (renders "-"); item 10's `GetCertificate` stack-copy is
  real but its actual fix (store `*DomainSettings` in DomainsMap) is W3 config-publish territory —
  deferred, not forgotten. CONC-05 verified already fixed in wave 8 (`&http.Client{Timeout:10s}`).
- **Gates:** gofmt/vet/build/mod tidy clean; `go test -race ./...` all 12 packages ok.

### Wave 9 W4c outcome (2026-09-01, solo — pam fallback)

- **CONC-01 (critical)** the three per-request window writes
  (`WindowAccessIps`/`WindowUnkFps`/`WindowAccessIpsCookie` at middleware.go :191/:313/:406
  pre-fix) incremented a bucket only the monitor's 5 s prefill (evaluateRatelimit) ever created.
  If the prefill lagged past the 120 s horizon the write hit a nil inner map WHILE HOLDING
  firewall.Mutex, the bare Unlock was skipped, and every later request, Monitor and
  evaluateRatelimit blocked forever (net/http recovers the handler; `log.SetOutput(io.Discard)`
  ate the panic report — a silent total outage). The wave-7 comment claiming lazy creation was
  never implemented (AUDIT.md's exact point). Fix: `firewall.IncrWindow` — bucket created
  lazily on first increment; prefill demoted to advisory. The pin test
  `TestMiddlewareMissingWindowBucketPanicsAndWedgesMutex` (which required reproducing the panic
  AND hand-replacing the leaked mutex) flipped to
  `TestMiddlewareMissingWindowBucketIsCreatedLazily`: delete bucket → request serves 200 through
  the backend → bucket exists → mutex free.
- **CONC-04** same helper caps each 10-second bucket at 200k distinct keys
  (`firewall.windowKeyCap`). Every key is attacker-controlled (spoofed Cf-Connecting-Ip, rotated
  IPv6 source, raw TLS fp), so without a cap one connection rotating identities grows the maps
  until OOM (audit: ~50k req/s × 120 s retention ≈ millions of string keys). Past the cap NEW
  keys are dropped — the request still runs the rest of the pipeline; EXISTING keys keep
  counting, so a volume flood against one identity is still ratelimited. Four tests: lazy
  creation, cap drop, existing-key-still-counts, per-bucket independence.
- **Deferred in W4 scope:** CONC-03 (defer-Unlock sweep in supervised workers) — the concrete
  deadlock its evidence described was the CONC-01 nil-map panic, now structurally unreachable
  at the three window sites; the remaining bare Lock/Unlock pairs (monitor TUI `clrlogs`/`stage`
  sections, middleware :433 AddLogs section) wrap code that cannot panic. WindowUnkFps hashed
  keys (audit companion item) deferred to the PERF slice.
- **Gates:** gofmt/vet/build clean; `go test -race ./...` all 12 packages ok.

### Wave 9 W3 outcome (2026-09-01, solo — jim fallback)

Config-correctness batch. jim confirmed dead session (assignment envelope delivered 01:40, zero
outbox activity) — standups handled internally.

- **AUTHZ-01/CRYPTO-02 positive secret validation.** `validate()` was CHANGE_ME-only, and a
  missing `secrets` map indexed to `""` in the loop, so empty/missing/short secrets passed
  silently. Now every operator secret has a `minSecretLength = 16` floor (brute-forceable in
  hours below that) plus the CHANGE_ME hunt; the error names the offending key. Fixture,
  example-template and harness-template secrets lengthened to match. `hack/config.test.json`
  already carried ≥16-byte values — verified, not assumed.
- **AUTHZ-06 body-limit wiring (the finding was "config read by nobody").** The pipeline parsed,
  validated, normalised, built and published `Proxy.MaxBodySize` (default 10 MiB, per-domain
  resolve, `proxy.MaxBodySize` mirror) — and enforcement read `server.MaxRequestBodyBytes`, an
  atomic written only by `init()`, so an operator's `max_body_size` and its `-1` unlimited
  sentinel did nothing. Import direction is server→config (monitor.go imports config), so config
  cannot write server globals without a cycle: middleware now reads
  `domains.Config.Proxy.MaxBodySize` directly (same pattern as the existing
  `CloudflareEnforceOrigin` read; the racy-publish concern is the recorded CONC-02 debt). The
  obsolete atomic is deleted. **Deferred with reasoning:** per-domain `maxBodySize` override
  enforcement — the AUDIT finding was the process-wide dead knob, which this kills; per-domain
  plumbing is a new surface, not a fix of the recorded defect.
- **HTTP-06/CRYPTO-06 secret redaction in access logs.** `adminAPIPath()` builds
  `/_bProxy/<secret>/api/v1`, so every successful admin/API call — including the operator's own
  tooling — landed in `LastLogs` verbatim, readable from log viewers and the monitor TUI. Both
  secrets are redacted to `[redacted]` before `AddLogs`; empty-needle guards prevent
  `strings.ReplaceAll` splicing the marker between every character.
- **AUTHZ-02 OTP republish — closed MOOT, not forgotten.** Wave 7 deleted the
  CookieOTP/JSOTP/CaptchaOTP globals (proxy.go:103-105 comment); publish already republishes all
  secrets on load and reload (pipeline.go:527-533). There is nothing left to republish.
- **Verification:** gates green first — gofmt/vet/build/mod tidy clean, `go test -race ./...`
  all 12 packages ok; new tests (`TestMiddlewareRedactsSecretsFromAccessLogs`, three
  validate-reject cases) live. Independent scoped verifier returned **PASS** on all claims
  including adversarial probes (empty-secret redaction without corruption, both-secrets-empty
  verbatim logging, 16/15-byte secret boundary) and a fresh `-count=1` race suite; spot-checked
  (HEAD hash, tree clean, zero code references to the deleted atomic).

### Already fixed — do not re-scope (waves 5/6)

Cookie substring check → exact-match + constant-time compare, stage-1 `HttpOnly`, cookie
stripping upstream, header Del-then-Set, CONNECT 405, body cap, rules-before-ratelimits.

One audit inaccuracy: the unknown-Host `%`-verb claim does not match current code — `serve.go:82`
is `fmt.Fprint` (verbatim). The page still 200s, echoes `r.Host`, and brands "balooProxy" (wave 10).

---

## Wave 13 outcome (2026-09-05) — the log that never stopped growing, the rules that lied, and no way to stop the process

Five items, all of them defects an operator meets rather than internals.

### 1. The per-domain access log was unbounded (PERF-03)

`utils.AddLogs` appended on every bypassed request and the **only** trim was in `ReadLogs`, which
the TUI calls for `proxy.WatchedDomain` alone. Every other domain grew for the life of the
process — five strings per request — and headless (no TTY, so no TUI loop) so did the watched one.
It is also the last unbounded structure on the request path, and it grows under the write lock the
hot path takes.

Capped at append time at `utils.MaxDomainLogs` = 1000, dropping the oldest **half** when it
overflows: dropping one per request past the cap would memmove the whole slice on every request.
Capacity settles at the cap, and the dropped entries are zeroed so their strings can be collected.

### 2. Five DSL fields were registered and never supplied — rules that silently did nothing

`ip.country`, `ip.asn`, `ip.requests`, `http.headers` and `http.body` were registered with the rule
parser but never written into the message the middleware builds. gofilter answers false for a
missing key, so:

    (ip.country eq "CN")  action 5     compiled, listed in GET_FIREWALL_RULES, never fired
    (ip.country ne "ID")  action 0     matched EVERY request on earth — the natural way to write
                                       "only allow Indonesia" whitelisted the entire internet

The five names are gone from the registry, so such a rule is now refused **at config load** with
the field named. `core/firewall/filter.go` holds one `Fields` map as the single source of truth,
and three guards keep it honest in both directions:
`TestFieldsIsTheDocumentedVocabulary` (a literal list — removing a field is as much a break as
adding one), `TestRegisteredFieldsCompile`, and
`TestMiddlewareEveryRegisteredRuleFieldIsSupplied`, which drives a real request through
`Middleware` for every registered name.

**Breaking:** a `config.json` whose rules name one of the five stops loading. That is the point —
it was doing nothing before — but it means the proxy refuses to start until the rule is removed.

### 3. Bool rules were broken in the vendored parser (gofilter deviation 5)

Found while writing the guard above. `nodeEq.applyOne` has a case for every registered type except
`bool`, so every comparison against an `FT_BOOL` field fell through to `return false`:

    proxy.attack eq true     never matched, even under attack
    proxy.attack ne true     ALWAYS matched, since `ne` is parsed as not(eq)

All four bool fields LancarSec supplies were unusable in both directions. Fixed with a three-line
`case bool` in `core/gofilter/nodes.go`, pinned by `core/gofilter/bool_test.go`, recorded as
deviation 5 in that package's README. A bare field name stays a **presence** test (Wireshark
semantics) and is pinned as such.

`FieldType`, an exported alias for the unexported `ftenum`, is deviation 4 — one line, needed
because a caller cannot otherwise declare a map of field types, which is what makes `Fields` a
single source of truth.

**Breaking, quietly:** a rule using `ne` on a bool field used to match everything and now behaves.
Anyone who tuned around the broken behaviour sees a change.

### 4. Rule actions are parsed once, at config build

`EvalFirewallRule` re-derived the action per matching rule per request: `rule.Action[:1]` for the
operator and `fmt.Sscan` for the number — reflection and an allocation on the one path an attacker
drives as fast as they like — and printed a diagnostic to stdout on failure, which under a flood is
a log amplifier and, when stdout blocks, back-pressure into the request path.

`domains.ParseAction` is now the single definition of the syntax, used by both `validate` and
`build`; `domains.Rule` carries `Op`/`Value`; the eval switches on them. The unguarded
`Action[:1]` — which panicked the request goroutine the first time an empty-action rule MATCHED —
no longer exists. `" 7"` silently meaning something different from `"+7"` (Sscan skips whitespace)
is gone with it.

### 5. There was no way to stop the process cleanly

No `signal.Notify`, no `Shutdown`, no context: `main` blocked on a bare `select{}` and every
listener error path panicked. Every restart, redeploy and `docker stop` killed the proxy
mid-request — responses truncated, keep-alives reset, and a visitor part-way through the challenge
sent back to stage 1.

`server.Shutdown(ctx)` now drains every tracked listener in parallel; `main` waits for SIGINT or
SIGTERM and gives in-flight requests `shutdownGrace` = 20s, under systemd's and Docker's own 30s
before SIGKILL, exiting non-zero if the drain does not finish. `listenFatal` is what keeps
`http.ErrServerClosed` from turning a clean stop into a panic.

### 6. The TUI command loop spun a core when there was no terminal (CONC-10)

`commands()` was `for { if scanner.Scan() {...} }` with no else branch. With nothing on stdin —
systemd, `docker run` without `-i`, nohup, a closed pipe — `Scan` returns false immediately and
forever, so the goroutine burned a full core for the life of the process, in exactly the
deployments where nobody is watching a terminal to notice. On a mitigation proxy that is a core
taken from the request path. It returns on EOF now; the TUI's render loop is a different goroutine
and keeps printing stats.

### Also

README fixes: the removed fields are documented as removed, bool comparison is documented (it had
never worked, so it had never been documented correctly), the `matches` example used a
non-existent field name `http.header` with a PCRE lookahead RE2 cannot compile, and one example
said `http.engine` for `ip.engine`.

**Mutation-tested:** 13 mutations, 13 killed. The first pass killed 10 — the two survivors were
both holes in the new tests, not in the code: a log trim that keeps *nothing* passed a test that
only inspected the end state, and *removing* a field from the registry passed every guard that
iterates over the registry. Both are closed by tests that check the invariant rather than a
snapshot.

---

## Wave 12 outcome (2026-09-04) — keyed state off `firewall.Mutex`

This is PERF-01 / CONC-09 / CONC-04, the largest remaining item from the re-audit: the one global
`RWMutex` taken three to four times per request, twice for writing.

**What moved.** `core/firewall/shard.go` (new) puts the per-key ratelimit state on 16-way sharded
locks, key-hashed with an inline FNV-1a. `core/domains/counters.go` (new) puts the per-domain
request totals on lock-free atomics.

| Was | Is | Lock per request |
| --- | --- | --- |
| `AccessIps` + `WindowAccessIps` | `firewall.IPs` (`*counterSet`) | one shard |
| `AccessIpsCookie` + `WindowAccessIpsCookie` | `firewall.IPsCookie` | one shard |
| `UnkFps` + `WindowUnkFps` | `firewall.UnkFps` | one shard |
| `Connections map[string]string` | `firewall.Connections` (`*connSet`) | one shard |
| `DomainData.TotalRequests` / `.BypassedRequests` | `domains.AddDomainTotal` / `AddDomainBypassed` | none (`atomic.Int64`) |

`firewall.Mutex` keeps what is not per-client: `DomainsData`, the fingerprint tables, the
access-log append, the config publish. A request never holds two shard locks at once, so no cycle
is possible; `Sweep` takes every shard in index order and releases each before the next.

**The number.** Measured as a same-machine A/B against `9fdb563` from a clean worktree, because
the harness itself has drifted since wave 3 (`HarnessBaseline` 31.6 -> 93 ns) and cross-wave
absolute comparison is no longer valid. Full tables in `core/server/BENCHMARK_BASELINE.md`.

- `DecisionPathParallel` **-46% at 4 cores, -49.7% at 16** (1597 -> 862, 1582 -> 795 ns). The
  audit's inversion — slower with more cores — is gone even on the shared-key benchmark, which is
  the case sharding *cannot* help.
- New `BenchmarkMiddlewareDecisionPathParallelDistinctKeys` (a flood from many addresses, which is
  what this product is for): **1582 -> 272.6 ns at 16 cores, 5.8x**, and it now scales *down* with
  cores (1021 -> 393 -> 273).
- Serial is unchanged: **+1.8% median over n=12**, inside the run-to-run spread. The n=5 table
  shows +22..+72% across `-cpu` values on a benchmark that ignores GOMAXPROCS — that spread is the
  tell, and it was re-measured rather than explained away. Do not cite it as a regression.
- `144 B/op, 9 allocs/op` on both sides. This wave moved locks, not allocations.

**Bugs found in the wave-12 code itself, during verification.** The working tree was not green when
it was picked up; these were all live defects in the new code, not test breakage:

- **The CONC-04 memory cap was 16x too large.** `len(bucket) >= windowKeyCap` was checked against
  ONE SHARD's bucket, so the real bound was `shardCount * windowKeyCap` = 3.2M keys. Now
  `windowShardKeyCap = windowKeyCap / shardCount`, which makes the set-wide bound exactly
  `windowKeyCap`. **This mutation survived the first test pass** (every cap test fills one shard
  and compares against the same constant); `TestWindowKeyCapIsDividedAcrossShards` is what kills it.
- **`counterSet.Stats()` always reported 0 requests** — the range variable shadowed the named
  return (`for _, requests := range ...; requests += requests`). It feeds `GET_IP_REQUESTS`.
- **`WindowKeyCount()` returned the first shard that held the bucket**, not the total.
- **`TestOnStateChangeEvictionHoldsTheShard` self-deadlocked**: it holds a shard's write lock and
  then called `Connections.Get`, which re-takes that shard's RLock. It hung the whole `core/firewall`
  package for the full 10-minute timeout. `peekLocked` is the counterpart to `LockShard`.
- **`core/server` did not compile**: `monitor_test.go` still referenced `firewall.WindowAccessIps`.

**Tests flipped, per the rule.** CONC-01 (the nil-map panic that wedged `firewall.Mutex` forever) is
fixed by lazy bucket creation under a deferred unlock, so the four tests that pinned the panic as
current behaviour became `TestRatelimitMissingBucketWriteIsSafe` and
`TestRatelimitWriteBeyondPrefillHorizonIsSafe`. The prefill horizon is now an optimisation, not a
safety property.

**Deleted.** `DomainData.TotalRequests` and `.BypassedRequests` — after the move nothing in
production wrote or read them, and four tests were asserting on dead fields. `firewall.IncrWindow`
and the six package-level counter maps are gone with them.

**Mutation-tested**, as the wave-3 rule requires: 8 mutations, 8 killed (the cap divisor, the cap
check, an unlocked `connSet.Delete`, the `Stats` shadow, the one-shard `WindowKeyCount`, a missing
`DeleteDomainCounters` on converge, bypassed-counted-as-total, and a dropped window increment).
The first pass killed 7 of 8 — see the cap note above.

**Breaking for operators: nothing on the wire.** No config key, no header, no cookie, no path
changed. The one behavioural change an operator could notice: a domain removed from `config.json`
now also loses its request counters, so re-adding it starts from zero instead of resuming.

**Left open.** The two IP families (`IPs`, `IPsCookie`) hash the same `rateKey` separately, so the
request path computes FNV over it twice and takes two locks where one set with two counters per key
would take one. Measured cost is inside the noise today; revisit only with a benchmark that shows
it.

---

## Wave 11 was blocked on a decision — DECIDED 2026-08-31: behind Cloudflare

The owner confirmed LancarSec deploys **behind Cloudflare**. Cloudflare terminates TLS; the
origin only ever sees Cloudflare's handshake, so spec-accurate JA4 from the local ClientHello
is wasted effort and is **dropped from the plan**. Wave 11 is now:

- **Cf-Ja3-Hash passthrough** (Cloudflare Enterprise add-on): believe `Cf-Ja3-Hash` only from a
  trusted peer (same rules as wave 6's header trust), feed it the same fingerprint slot.
- **Stage-3 captcha redesign** — unaffected by the deployment mode, still in scope; the re-audit
  adds CRYPTO-03 (the PoW is an offline-verifiable exact preimage whose solution IS the clearance
  token) as design input.
- **Go toolchain bump** (re-audit DEPS-01): Go 1.25 has left upstream security support — move to
  the supported line in this wave.
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
- **The firewall DSL's vocabulary is `firewall.Fields`, and it is load-bearing** (wave 13). Adding
  a name there without supplying it in the middleware's message brings back the fail-open the wave
  removed; removing one breaks every config.json using it. Three tests guard both directions —
  read the failure message, it says what to do.
- **`firewall.Mutex` no longer guards the keyed state** (wave 12). Ratelimit counters, sliding
  windows and per-connection fingerprints are on 16-way shards in `core/firewall/shard.go`; the
  per-domain request totals are lock-free atomics in `core/domains/counters.go`. Do not add a
  `firewall.Mutex` acquisition around them, and do not call a `counterSet`/`connSet` method while
  already holding that structure's shard lock — `LockShard` has `peekLocked` for exactly that.
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
  Re-audit brand inventory (docs/AUDIT.md tail): **BRAND-01 is the critical note** — the BLAKE3
  KDF context embeds the module path `github.com/azferius/lancarsec`, so a rebrand that changes
  the module path rotates every derived token (clearance/OTP material): a deploy-time break of
  the same class as the W1 stage-3 cookie change. Plan the cutover accordingly.
- Module path is `github.com/azferius/lancarsec` (lower-case; the module cache escapes upper-case
  as `!l!ancar!sec`).
- `core/gofilter` and `core/screen` are vendored, not dependencies.
- **No container.** LancarSec ships as one standalone binary. The Dockerfile, `.dockerignore` and
  the dependabot docker ecosystem were deleted; `setcap cap_net_bind_service` and a systemd unit
  cover what the image was for (privileged ports and the stdin TUI). Owner decided 2026-09-07.
