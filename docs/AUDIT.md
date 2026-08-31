# LancarSec — Baseline Audit of the balooProxy Fork

Audit date: **2026-08-30**. Baseline commit: `4d4f128` (upstream balooProxy, Oct 2024).
Method: 4 architecture-mapping agents + 9 parallel audit dimensions, each dimension's findings
re-checked by an independent hostile verifier instructed to refute. 21 findings were refuted and
dropped; **171 survived**. A completeness critic then swept for what the 9 dimensions missed.

Every location below was verified against the source by a second agent. Severities are the
verifier's corrected values, not the finder's.

## Scoreboard

| Severity | Count |
|---|---|
| critical | 8 |
| high | 40 |
| medium | 80 |
| low | 42 |
| info | 1 |
| **total** | **171** |

| Dimension | Confirmed | Refuted |
|---|---|---|
| concurrency | 17 | 3 |
| security-crypto | 15 | 5 |
| security-http | 22 | 0 |
| security-authz | 21 | 0 |
| performance | 21 | 2 |
| quality-idiom | 18 | 3 |
| deps-toolchain | 18 | 5 |
| branding | 18 | 0 |
| ops-build | 21 | 0 |

---

## Roadmap

### Quick wins (do these first — trivial effort, real payoff)

- `fmt.Println` → `fmt.Printf` at core/firewall/eval.go:30 — one character class of fix that unblocks `go vet ./...` module-wide, which is currently red and therefore ungateable in CI
- Assign a shared `BufferPool` to every `httputil.ReverseProxy` (core/config/init.go:126-130, core/server/monitor.go:467-471) — five lines, removes a 32 KiB allocation per proxied response and by far the largest source of garbage in the process
- Add `Stage2Difficulty: domain.Stage2Difficulty` with the `== 0 { = 5 }` default to the reload path (core/server/monitor.go:507-526) — one line, and until it lands any `reload` prints the full valid stage-2 token in the challenge HTML
- `r.URL.Path + r.URL.RawQuery` → `r.URL.RequestURI()` at core/server/serve.go:99 — every query-bearing HTTP request is currently 301-redirected (and browser-cached) to a mangled URL
- `request.Header.Add` → `Set` for the four backend identity headers at core/server/middleware.go:358-361, with a `Del` of inbound `X-Real-Ip`/`X-Forwarded-For` first — stops the proxy laundering client-supplied IP spoofing to the backend
- Set `MinVersion: tls.VersionTLS12` and delete the inert `Renegotiation` field (core/server/serve.go:71-75) — the :443 listener currently negotiates TLS 1.0/1.1
- Delete `case "FILL_IP_CACHE"` (core/api/api.go:101-109) — one authenticated request freezes the entire proxy for ~1.76M math/rand calls under the global write lock
- Delete the `firewall.Mutex` lock/unlock and the unused `imgCachelen` range from `clearProxyCache` (core/server/monitor.go:539-570) — the caches are `sync.Map`s; this removes a periodic full-proxy stall every 120 s
- `return true` after the body-read error at core/api/api.go:25 — stops two JSON documents being written into one response
- Package-level `http.Client{Timeout: 5*time.Second}` plus `defer resp.Body.Close()` in core/utils/discord.go:243-249 — stops a leaked goroutine and socket per webhook, which fire most often during an attack
- Guard `commands()` on `term.IsTerminal` and add the missing loop exit (core/server/monitor.go:290-296) — reclaims a full CPU core on every systemd/docker/nohup deployment
- Drop the `github.com/boltdb/bolt` require (go.mod:6) — archived 2017, never imported
- Add `-trimpath -buildvcs=false -ldflags="-s -w"` to the Dockerfile and release build (Dockerfile:11, .github/workflows/release.yml) — stops shipping the builder's absolute paths and full DWARF in a security product
- Add `.dockerignore` (absent today) — stops the 312 MiB git history and the private key being copied into every image layer by `COPY . .`
- Remove the release fingerprint UUID from the comment at main.go:15 — publishing it lets anyone rebuild a modified proxy that reports as an official build

### Waves

#### Wave 1 — Repo hygiene, secret purge, history rewrite

*Why here:* This must be the literal first commit of the fork, before anything else, because two of its actions rewrite history (`git filter-repo`) and one renormalises every line ending in every .go file. Doing either after real work has landed forces every later branch to be rebased onto a rewritten history and buries genuine diffs under whole-file CRLF churn. It is also the only wave that must complete before the fork is pushed publicly: `assets/server/server.key` is a live CA-issued private key and `oryxBuildBinary` contains the un-rebranded proxy that makes every later `grep -ri baloo` verification useless.

- `git rm assets/server/server.key assets/server/server.crt` and treat the key as permanently compromised — it is a real ZeroSSL RSA key, not a dev placeholder (assets/server/server.key:1), and examples/config.json:34-35, :72-73, :110-111 currently point sample domains at it
- `git rm oryxBuildBinary` — 11 MB unstripped ELF built from /workspaces/balooProxy with the full pre-rebrand token set and 33 reachable stdlib vulns baked in (oryxBuildBinary, repo root)
- Purge both plus the 88 committed `main` blobs from history: `git filter-repo --path oryxBuildBinary --path main --path assets/server/server.key --path assets/server/server.crt --invert-paths --force` then `git gc --prune=now`; pack drops from 312 MiB (.gitignore:23 area — the ignore file covers `main` and `*.exe` but nothing else)
- Rewrite .gitignore as a deny-by-intent list: `config.json`, `config.*.json`, `*.key`, `*.pem`, `*.p12`, `*.db`, `crash.log`, `dist/`, `bin/`, `main`, `lancarsec`, `oryxBuildBinary` (.gitignore:9-24)
- Add `.gitattributes` with `* text=auto eol=lf` and `*.go text eol=lf`, then `git add --renormalize .` and `gofmt -w .` in one isolated commit — all 25 .go files are currently CRLF and fail `gofmt -l` (core/firewall/requests.go:1 and every other file)
- Add `.dockerignore` covering `.git`, `.github`, `*.md`, `assets/server/`, `config.json`, `oryxBuildBinary`, `main`, `dist/` — today Dockerfile:9 `COPY . .` copies the 312 MiB history and the private key into every image layer
- Point examples/config.json cert/key fields at non-repo paths (`/etc/lancarsec/tls/...`) so copy-paste deployment cannot pick up a bundled keypair (examples/config.json:34-35, :72-73, :110-111)
- Redact the real-shaped Discord webhook id in examples/config.json:39, :76, :114

**Exit criteria:** `git count-objects -vH` reports a pack under ~2 MiB; `gofmt -l .` prints nothing; `grep -ri baloo . | wc -l` returns a number that matches source hits only (no binary hits); `git log --all --diff-filter=A --name-only | grep -E 'server\.key|oryxBuildBinary'` is empty; `docker build .` context upload is under 5 MB.

#### Wave 2 — Toolchain, dependency graph, module path

*Why here:* Everything downstream depends on this: the `go 1.19` directive blocks `min`/`max`, `clear`, range-over-int, `sync.Map.Clear`, `errors.Join`, atomic types used idiomatically, and — critically for a concurrent proxy — leaves Go 1.22 per-iteration loop-variable semantics OFF, so any goroutine-in-a-loop written in wave 7 would silently capture a shared variable. The dependency bump is verified to be a zero-code-change upgrade, so there is no reason for it to sit behind anything. The module path rename (goProxy→lancarsec) is bundled here deliberately: it is category (a) internal-only, invisible on the wire, and a mechanical 37-line sed — doing it now means every later wave is written against the final import path, while the wire-visible tokens stay untouched until wave 10.

- Set `module lancarsec` (prefer a fetchable `github.com/<org>/lancarsec`) and `go 1.25` + `toolchain go1.25.13` in go.mod:1,3, then rewrite the 37 import lines across 11 files: `grep -rl '"goProxy/' --include='*.go' . | xargs sed -i 's#"goProxy/#"lancarsec/#g'`
- `go get -u ./... && go mod tidy` — clears 45 module-level advisories on the stale golang.org/x/* set (go.mod:9-11), including the x/net http2 infinite-loop DoS on the transport that terminates attack traffic
- Delete the `github.com/boltdb/bolt` require — archived since 2017 and never imported (go.mod:6)
- Replace `github.com/inancgumus/screen` (go.mod:22, used at core/server/monitor.go:17) with a six-line `core/screen/screen.go` doing `fmt.Print("\033[2J")` / `fmt.Print("\033[H")`; this is the sole reason golang.org/x/crypto and its 20 advisories are in the graph
- Vendor `github.com/kor44/gofilter` (go.mod:7 — untagged 2017 pseudo-version, no go.mod, personal repo) into `core/gofilter/` preserving its LICENSE, and rewrite the imports in core/firewall/filter.go, core/firewall/eval.go, core/config/init.go, core/server/monitor.go — this is the entire firewall rule engine and must not be deletable by a third party
- Multi-stage Dockerfile: `FROM golang:1.25-alpine AS build` (digest-pinned) → `CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/lancarsec .` → `FROM gcr.io/distroless/static-debian12:nonroot`, `USER nonroot` (Dockerfile:1-16)
- Release workflow: pin the third-party release action to a full commit SHA instead of `@latest`, bump `actions/setup-go@v2`→v5 with `go-version-file: go.mod`, add explicit job-level `permissions: contents: write` (.github/workflows/release.yml:20,33-35)
- Add `.github/dependabot.yml` for `gomod` + `github-actions`, weekly
- Replace `ioutil` with `io`/`os` in core/config/init.go:13 and the two other files; change the config-write mode from 0644 to 0600 at core/config/generate.go:53, generate.go:96, core/utils/domain.go:44
- Run `modernize -fix ./...` to sweep the now-unlocked constructs: hand-rolled min/max at core/server/monitor.go:118-123 and :73-78, counted loops at core/api/api.go:104, core/server/middleware.go:267, core/utils/image.go:45-46

**Exit criteria:** `go build ./... && go vet ./...` clean (after the eval.go:30 fix from wave 3's quick list, or land that fix here); `go list -m all | grep -E 'x/crypto|boltdb|inancgumus'` is empty; `govulncheck ./...` reports 0 module-level findings and only the known stdlib set; `docker build` produces an image under 20 MB that runs as non-root.

#### Wave 3 — Test harness, benchmark baseline, CI gates

*Why here:* This is the wave that makes waves 4-9 safe, and it must land before any of them. The repo has zero tests across 3098 lines, and the hot path being rewritten in wave 7 is a 335-line function that decides whether traffic is blocked. Two things are needed before that: golden-value tests that pin the current token-derivation output (so a refactor that silently changes a cookie value is caught, not discovered by every visitor being re-challenged), and a throughput/allocation baseline (so 'this made it faster' is a measurement, not a claim). `go vet` currently fails module-wide, so no CI gate can even be turned on until eval.go:30 is fixed.

- Fix `fmt.Println` with Printf directives at core/firewall/eval.go:30 → `fmt.Printf("[ ! ] [ Error Evaluating Rule %d : %s ]\n", index, err)`; the whole module fails `go vet` on this one line
- Table tests for `firewall.EvalFirewallRule` (core/firewall/eval.go:10) covering `+n`, `-n`, absolute, empty action (which panics today at eval.go:15 via `rule.Action[:1]`), and malformed `-abc`
- Golden tests for `utils.Encrypt` / `utils.EncryptSha` (core/utils/encryption.go:19,24) that capture today's exact outputs AND assert `Encrypt(a+b, k) != Encrypt(a, b+k)` — the second assertion fails today and is the wave-5 acceptance test
- Golden test for `utils.StageToString` (core/utils/text.go:176-189) pinning that susLv 0 and susLv>=5 both currently return "5+" — the wave-5 fix flips this assertion
- `firewall.Fingerprint` (core/firewall/fingerprint.go:52) fed synthetic `tls.ClientHelloInfo` values, pinning the current GREASE `[1:]` / `[:1]` strings so the wave-11 JA4 work is a deliberate, visible change
- httptest harness for `server.Middleware` (core/server/middleware.go:30): a stub backend plus a table asserting status, Set-Cookie and block-branch for stage 0/1/2/3, R1/R2/R3, forbidden fingerprint, and each `/_bProxy/*` reserved path
- `evaluateRatelimit` bucket arithmetic (core/server/monitor.go:576-636): create / expire / sum across a synthetic clock
- Benchmark baseline committed as a file: `BenchmarkMiddlewareHotPath` (ns/op, B/op, allocs/op) plus a `go test -run=X -bench=. -benchmem` snapshot, and a `-race` run of the httptest suite — expect the race detector to fire today on core/proxy/proxy.go:24-33 clock/OTP globals, which is the wave-5/7 acceptance signal
- External load harness under `hack/`: a stub origin plus a vegeta/hey profile at fixed concurrency recording req/s, p99 and peak RSS, and a second profile that sends a unique `Cf-Connecting-Ip` per request for 120 s to measure the unbounded-map growth rate that waves 6-7 must flatten
- New `.github/workflows/ci.yml` running `go build ./...`, `go vet ./...`, `gofmt -l . | (! read)`, `go test -race ./...`, `govulncheck ./...` on PRs, and make it a required prerequisite job for release.yml (today .github/workflows/codeql.yml:12-48 is the only CI and gates nothing)

**Exit criteria:** `go vet ./...` passes; `go test -race ./...` passes with the known pre-existing races documented as skipped/expected assertions; `go test -bench=. -benchmem ./core/server/` writes a baseline file committed to the repo; the load harness produces a recorded req/s + RSS number for the current binary that later waves diff against.

#### Wave 4 — Config load unification and startup independence

*Why here:* Placed before every behavioural fix because the reload path is a divergent copy-paste of the load path (core/server/monitor.go:401-531 vs core/config/init.go), so any fix landed in one and not the other silently regresses the moment an operator types `reload`. That divergence is not theoretical: it already zeroes Stage2Difficulty and disables the JS proof-of-work entirely. Unifying first means waves 5-9 each have exactly one place to change. This wave also cuts the two startup network dependencies on 41Baloo's GitHub, which is a prerequisite for the fork being deployable at all and removes a remote allow-list-injection channel into the firewall.

- Extract the shared body of `config.Load` and `ReloadConfig` into one exported `config.Apply(cfg *domains.Configuration) error`; delete the 131-line duplicate at core/server/monitor.go:401-531. Break the import cycle by moving the RoundTripper into its own package or registering a reload callback
- This kills the Stage2Difficulty divergence: today ReloadConfig's fresh literal at monitor.go:507-526 omits it, so `publicSalt := encryptedIP[:len(encryptedIP)-0]` at middleware.go:229 prints the complete valid token in the challenge HTML. Add a hard guard in middleware refusing to serve a stage-2 page when Stage2Difficulty < 1, and clamp to 1..len-1 (a negative or >64 value panics on that slice)
- Delete `utils.AddDomain` (core/utils/domain.go:11-48) and have the TUI `add` command at core/server/monitor.go:350 call the config package's single implementation — the utils copy silently writes stage2Difficulty absent
- Replace the network fingerprint fetch (core/config/init.go:104-106, function at core/config/generate.go:102-119) with `//go:embed` of the already-present global/fingerprints/{known,bot,malicious}_fingerprints.json, and make a load failure fatal and loud — today all three call sites discard the error and the proxy boots fail-open with empty maps, admitting every known-malicious fingerprint at middleware.go:137
- Delete `VersionCheck` and its call (core/config/init.go:224-226, :237-265) or stub it to return nil — today a GitHub outage panics the proxy at boot, it leaks every origin IP to GitHub on restart, and init.go:257 renders a remote-controlled download URL to the operator
- Convert the 22 `panic()` sites used for ordinary error handling to error returns, starting with core/server/monitor.go:407 — a config typo plus `reload` currently kills a live DDoS-mitigation proxy. Reload must validate into a fresh Configuration and swap only on success, keeping the running config on failure
- Make the RELOAD API action actually call the reload routine — core/api/api.go:110-112 is a lock immediately followed by an unlock, a documented action that silently no-ops
- Add `return true` after the body-read error response at core/api/api.go:25 — today a truncated body writes two JSON documents into one response
- Parse firewall rule actions once at load into a typed `Delta int` / `Absolute bool` on `domains.Rule` (filled in core/config/init.go:120-123 and the unified Apply), removing `fmt.Sscan` from core/firewall/eval.go:18,28,38 — 525 ns/op and 3 allocs each, 68x slower than the strconv equivalent, paid per matching rule per request

**Exit criteria:** A test asserts `config.Apply` produces byte-identical `domains.DomainsData` whether called from startup or from `reload`, including Stage2Difficulty; `reload` with a deliberately malformed config.json leaves the proxy running on the old config and prints an error; the binary starts with all outbound network blocked (`unshare -n ./lancarsec` or an egress-denied container) and serves traffic with fully populated fingerprint maps.

#### Wave 5 — Secrets, token derivation, and admin authentication

*Why here:* Comes after the config unification so each fix lands in exactly one place, and before the identity wave because the token derivation changes here (adding a domain, a delimiter, and an aligned time bucket) determine what the identity wave has to feed into. Every item is a total-bypass primitive: default builds ship identical secrets, an omitted config key disables admin auth entirely, and the StageToString collision lets a whitelist rule poison the cache so a susLv>=5 DROP is bypassable. All of these are cheap to fix and independently revertable, and none of them touch the concurrency model.

- Rewrite `utils.RandomString` to draw from crypto/rand (core/utils/encryption.go:30-38, `rand.Intn` at :35) — under the Go 1.19 toolchain the Dockerfile pins, every install generated by core/config/generate.go:23-34 gets AdminSecret `<derivable-admin-secret-withheld>` and APISecret `<derivable-api-secret-withheld>`. Keep math/rand out of that file entirely
- Validate every secret positively in the unified loader (core/config/init.go:40-63 today only rejects the literal "CHANGE_ME"): reject empty, reject <16 chars, reject a missing `secrets` map, and name the offending key. An omitted `apisecret` currently makes `"" != ""` false at core/api/api.go:17 and :155, opening the admin API to anonymous requests
- Fix `utils.StageToString` (core/utils/text.go:176-189): susLv 0 and susLv>=5 both map to "5+", so a whitelisted path caches `accessKey+"5+" -> ""` and a subsequent blocked request hits that cache entry, skips the block branch at core/server/middleware.go:199, and degenerates to `strings.Contains(cookie, "__bProxy_v=")`. Use `strconv.Itoa(susLv)` for the cache key, never cache the 0 or >=4 branches, and re-check susLv>=4 after the lookup
- Rebuild `accessKey` (core/server/middleware.go:184) as length-prefixed or delimiter-joined fields including the domain name and the stage — today `ua="Mozilla/5.0"+hour="15"` and `ua="Mozilla/5.01"+hour="5"` are byte-identical, letting an attacker pre-mint afternoon tokens in the morning, and the missing domain lets a token minted on an idle low-value domain be replayed on the domain under attack
- Move OTP derivation to an aligned bucket `time.Now().UTC().Format("2006-01-02-15")` published through a single `atomic.Pointer[otpSet]`, recomputed on an aligned ticker and called directly at the end of the reload path — today core/server/monitor.go:639-658 sleeps a fixed hour from process start (up to 59 min of drift, multi-node disagreement) and monitor.go:414-416 rewrites secrets that are not re-derived for up to an hour. Keep the previous bucket valid as a short grace window
- Validate the challenge cookie by parsing, not substring: `request.Cookie("_1__bProxy_v")` etc. per stage, compared with `subtle.ConstantTimeCompare` (core/server/middleware.go:214). Today any cookie name ending in the suffix, or any cookie whose *value* contains it, passes
- Set `HttpOnly` on the stage-1 cookie (core/server/middleware.go:225) and strip every `*__bProxy_v` cookie from the request before forwarding upstream at middleware.go:363
- Constant-time comparison for both API secrets (core/api/api.go:17, :155) and return 404 rather than falling through to the backend when auth fails; add a fixed ~200 ms failure delay and a peer-keyed failure counter logged to the TUI
- Delete `FILL_IP_CACHE` (core/api/api.go:101-109) — one authenticated request holds the global write lock across ~1.76M math/rand calls, freezing the whole proxy — and delete or redact `GET_IP_CACHE` (api.go:91-100), which returns every live challenge token in plaintext, plus `GET_IP_REQUESTS`/`GET_FINGERPRINT_REQUESTS` (api.go:72-81), which let encoding/json iterate a live map after the RLock is released — an uncatchable concurrent-map-iteration fatal error
- Gate `/_bProxy/stats` and `/_bProxy/fingerprint` (core/server/middleware.go:325-336) behind the API secret — unauthenticated they hand an attacker live bypassed-r/s, current stage, and his own susLv and ratelimit budget, which is a closed-loop tuning oracle
- Remove the release fingerprint UUID from the comment at main.go:15 — publishing it defeats the build-authenticity check it exists for

**Exit criteria:** The wave-3 golden test `Encrypt(a+b,k) != Encrypt(a,b+k)` now passes; a test asserts two secrets generated in separate processes differ; a config with `apisecret: ""` refuses to start with a message naming the key; a request with `Cookie: junk=__bProxy_v=<token>` is rejected; `curl /_bProxy/stats` without the secret returns 404; a stage-2 page served with Stage2Difficulty=0 is impossible (guard returns an error page instead).

#### Wave 6 — Client identity: trusted-proxy resolution and IPv6

*Why here:* Separated from the concurrency wave because it changes what the map *keys* are, and the sharding/capping work in wave 7 is only meaningful once the key space is bounded and correct. It also has to land after wave 5, since the token now binds to the resolved IP and the two changes together define the new cookie value. This is the single highest-impact security wave: in the documented Cloudflare deployment every per-IP control — R1, R2, ip.src rules, and the token binding — is read from a client-supplied header, and in origin mode every IPv6 client on the internet collapses into a handful of buckets.

- Bundle Cloudflare's published IPv4/IPv6 CIDR lists (plus operator extras) into a new `core/trusted` package as pre-parsed `[]netip.Prefix`, loaded at startup with no network fetch
- Rewrite the subject-IP resolution at core/server/middleware.go:59-71 into one `realClientIP(r)` helper: honour `Cf-Connecting-Ip` / `X-Real-Ip` / `X-Forwarded-For` only when `net.SplitHostPort(request.RemoteAddr)` parses to an address inside a trusted prefix; otherwise use the socket peer. This is the fix for the R1/R2 bypass, the targeted-DoS mirror attack (501 requests with a victim's IP blocks that victim for the window), and the botnet-portable token
- Add a `cloudflare_enforce_origin` config option that 403s any peer outside the allowlist when Cloudflare mode is on, so the origin cannot be hit directly at all
- Replace `strings.Split(request.RemoteAddr, ":")` at core/server/middleware.go:73 with `net.SplitHostPort` + `netip.ParseAddr` — today `[2001:db8::1]:54321` becomes the key `"[2001"`, so one IPv6 host exhausts the quota for a /16 of the internet, a token minted by one client is valid for every other in that prefix, and `net.ParseIP` at middleware.go:153 returns nil so every `ip.src` rule silently never matches IPv6. Also 2 allocs/request cheaper
- Normalise IPv6 sources to their /64 for ratelimit keying so rotation inside a routed prefix collapses into one bucket
- Use `request.Header.Set` (not `Add`) for the four backend identity headers and `Del` any inbound `X-Forwarded-For`/`X-Real-Ip`/`Forwarded`/`proxy-*` first (core/server/middleware.go:358-361) — today a client-supplied `X-Real-Ip: 127.0.0.1` arrives at the backend first, laundering IP spoofing through the proxy
- Evaluate firewall rules *before* the ratelimits and skip R1/R2/R3 plus the `WindowAccessIpsCookie` increment when susLv==0 (core/server/middleware.go:107-140, rule eval at :177) — today an `action: 0` whitelist cannot whitelist, and a cookieless whitelisted webhook accrues challenge failures until R1 hard-blocks it
- Reject `http.MethodConnect` with 405 at the top of Middleware and wrap the body once with `http.MaxBytesReader` (10 MiB, per-domain configurable); add `io.LimitReader` in core/api/api.go:21

**Exit criteria:** A test sends `Cf-Connecting-Ip: 1.2.3.4` from an untrusted peer and asserts the ratelimit key is the socket peer, then repeats from a trusted peer and asserts it is the header; a test asserts `[2001:db8::1]:443` and `[2001:db9::1]:443` land in different buckets while `[2001:db8::1]` and `[2001:db8::2]` share one; the wave-3 unique-header flood harness no longer produces one new bucket key per request; a whitelisted (`action: 0`) source survives 10k requests without being blocked.

#### Wave 7 — Hot-path concurrency rewrite

*Why here:* The single largest and riskiest wave, deliberately last among the behavioural ones, because it needs everything before it: the toolchain for the atomic types and loop semantics, the test harness and benchmark baseline to prove it did not regress, the unified config so there is one construction site, and the bounded key space from wave 6 so the sharded maps are sized sanely. It is also the wave that fixes the deadlock — a nil inner map at middleware.go:96 panics, net/http recovers, but `firewall.Mutex` was taken bare with no defer, so the write lock is never released and the entire mitigation layer silently stops forever (silently, because main.go:32 discards the panic report). Land it as one branch, but structure it as reviewable sub-commits: clock, counters, windows, connections, config pointer, logs.

- Move the clock out of the terminal renderer: a dedicated `time.Ticker` goroutine that does nothing but store `atomic.Int64` for `Last10SecondTimestamp`/`LastSecondTimestamp` and an `atomic.Pointer[string]` for the formatted strings (writers today at core/server/monitor.go:213-218, :94; readers unlocked at core/server/middleware.go:96, :184, :308). Today a blocked stdout — journald, a pipe, a slow console — freezes the ratelimit window and blocks all legitimate traffic within seconds
- Guard `commands()` with `term.IsTerminal(int(os.Stdin.Fd()))` and rewrite the loop as `for scanner.Scan()` plus an `scanner.Err()` check (core/server/monitor.go:290-296) — under systemd/docker/nohup it spins a full core forever and starves the goroutine that prefills the window buckets
- Replace the per-request copy-modify-write of `DomainData` with a `*DomainCounters` holding `atomic.Int64` fields: `ctr.Total.Add(1)` (core/server/middleware.go:97-99, :317-319, core/server/serve.go:93-97). Four full struct copies and two global write-lock acquisitions per request become two lock-free adds
- Shard the sliding-window counters across `runtime.NumCPU()` striped maps behind a `firewall.Incr(bucket, key)` helper that creates a missing bucket lazily (killing the nil-map panic outright) and enforces a `MaxBucketKeys` cap (~200k), dropping overflow keys from counting while still running the rest of the pipeline (core/firewall/general.go:10-25, callers at core/server/middleware.go:96, :130, :217)
- Key `WindowUnkFps` on a fixed 8/16-byte hash of the fingerprint rather than the 400-700 byte raw string (core/server/middleware.go:129-131)
- Make ratelimit decisions read the live window sums, not the 5-second snapshot rebuilt at core/server/monitor.go:576-636 and consumed at middleware.go:108, :115, :123 — today a single IP gets up to 5 s (250k requests at 50k rps) of completely unmetered traffic, and the rebuild itself reallocates millions of entries under the global write lock every 5 s. Maintain the aggregate incrementally by subtracting the evicted bucket
- Move `firewall.Connections` and the JA4 map to `sync.Map` (core/firewall/general.go:35,38-49, written at core/firewall/fingerprint.go:81-84, read at middleware.go:76-77) — today every TCP open/close takes the global write lock, so connection churn alone, with zero valid HTTP requests, starves request processing and makes the deadlock above more likely
- Publish the configuration through `atomic.Pointer[Configuration]` with one `LoadConfig()` snapshot per request (core/server/monitor.go:405-410 currently JSON-decodes into the live struct while handlers read it, so a request can observe `Cloudflare == false` mid-flip or a threshold of 0). Fold the loose scalars at monitor.go:444-447 into the same snapshot
- Replace `utils.AddLogs` (core/utils/text.go:22-26) with a fixed-capacity per-domain ring buffer trimmed at append time, independent of whether the TUI renders that domain — today only the watched domain is ever trimmed, and not even that when `helpMode` is true, so every other domain accumulates 7 strings per bypassed request forever
- Delete the `firewall.Mutex` acquisition and the unused `imgCachelen` range from `clearProxyCache` (core/server/monitor.go:539-570) — the caches are `sync.Map`s needing no external lock — and replace the CPU<15% eviction gate with per-entry TTL plus a hard entry cap swept on a ticker; the current gate is false by construction during the attack it exists for
- Buffer the TUI: one `bufio.Writer` flushed per frame instead of ~130 write(2) syscalls and ~600 allocations per second (core/utils/text.go:53-63, :92-97)
- Replace the 500 ms poll over an unsynchronised bool at main.go:43 with a `chan struct{}` closed by the ratelimit goroutine; thread a root context through every background loop and replace `select{}` at main.go:50 with `signal.NotifyContext` + `srv.Shutdown(ctx)`
- Stop discarding logs at main.go:32 so recovered handler panics are visible; fix core/pnc/panicHandler.go:17-30 (unreachable `log.Fatal` into a discarded logger, wrong timestamp layout, 4 MB alloc per panic — use `n := runtime.Stack(buf, false)` with 64 KB)

**Exit criteria:** `go test -race ./...` is clean including a new concurrent httptest run at high parallelism; the wave-3 benchmark shows the hot path improving with GOMAXPROCS instead of degrading (baseline: 43.7 ns/op at 1, 90.9 ns/op at 16); the load harness shows req/s scaling with cores and peak RSS flat under the unique-key flood for 10 minutes; a fault-injection test that forces a missing window bucket serves a normal response instead of deadlocking; killing the TUI's stdout (redirect to a full pipe) leaves ratelimiting functional.

#### Wave 8 — Upstream transport and response path

*Why here:* Independent of the concurrency wave and safe to land in either order, but placed after it so the throughput measurement is not confounded by two simultaneous changes to where time goes. The single largest allocation source in the whole proxy lives here — a fresh 32 KiB copy buffer per proxied response, 1.6 GB/s of garbage at 50k rps — and the sync.Pool aliasing bug serves one client's bytes to another, precisely during a backend outage.

- Give every `httputil.ReverseProxy` a shared `BufferPool` at construction (core/config/init.go:126-130 and the unified reload path) — a five-line type; this alone removes the dominant GC pressure in the process
- Fix the pooled-buffer aliasing in `RoundTrip` (core/server/serve.go:118-149, :189-192): acquire the buffer only inside the two error branches and copy out before Put (`append([]byte(nil), buffer.Bytes()...)`); today the deferred Put at :122 returns the buffer while `bytes.NewReader(buffer.Bytes())` at :148 is still streaming it to a client, and middleware.go:34-36 shares the same pool. Also remove the duplicate `resp.Body.Close()` at :187
- HTML-escape the backend error text before it goes into the iframe `srcdoc` attribute (core/server/serve.go:174-176) and stop relabelling 5xx as `http.StatusOK` (serve.go:190); gate verbose backend-error passthrough behind a config flag defaulting to off
- Build one `*http.Transport` per domain at config-load time and store the pointer on `DomainSettings`; delete `getTripperForDomain`/`transportMap`, which today store and return the same singleton for every domain (core/server/serve.go:198-219). Set `MaxIdleConnsPerHost`/`MaxConnsPerHost` in the hundreds (currently 10 total, with the default 2 idle per host — 8 of every 10 connections re-dialled), plus `ResponseHeaderTimeout` and `ExpectContinueTimeout`
- Drop `InsecureSkipVerify: true` (core/server/serve.go:206): set `ServerName` to the configured backend host and `MinVersion: tls.VersionTLS12`, with a per-domain `backend_tls_verify: false` opt-out and an optional `backendCA` for private CAs
- Set `MinVersion: tls.VersionTLS12`, an explicit AEAD-only CipherSuites list and deliberate `NextProtos` on the server TLS config, and delete the inert `Renegotiation: tls.RenegotiateOnceAsClient` (core/server/serve.go:71-75)
- Pass a tuned `&http2.Server{MaxConcurrentStreams: 100, MaxReadFrameSize: 16384, IdleTimeout: ..., MaxUploadBufferPerConnection: 1<<20}` and drop the no-op `ConfigureServer` calls on the plain :80 listeners (core/server/serve.go:46, :79-80); check its returned error
- Fix the :80→:443 redirect to use `r.URL.RequestURI()` (core/server/serve.go:99) — today `path + RawQuery` concatenates without `?`, so `/search?q=x` becomes `/searchq=x`, cached permanently by browsers because it is a 301 — and increment the counter atomically instead of taking the global write lock on an unauthenticated port-80 path
- Store `*domains.DomainSettings` in DomainsMap and assert to the pointer (core/server/middleware.go:145-146), add the missing `, ok`, and keep the certificate as a `*tls.Certificate` built once so `domains.GetCertificate` (core/domains/util.go:16-23) stops returning the address of a stack copy per handshake
- One package-level `http.Client{Timeout: 5*time.Second}` for webhooks with `defer resp.Body.Close()` + drain, behind a bounded 4-worker/256-deep pool that drops when saturated (core/utils/discord.go:243-249); guard the empty-slice indexing in `utils.InitPlaceholders` (discord.go:16-19), which currently panics the process via the re-panicking handler
- Replace the `quickchart-go` dependency with a direct `http.Post` using that same timeout-bearing client (core/utils/discord.go:201-207) and drop the require
- Replace the `+= fmt.Sprintf` loop in the fingerprint builder with `strconv.AppendUint` into a preallocated `[]byte` (core/firewall/fingerprint.go:62-79) — 8382 ns/op and 82 allocs today vs 388 ns/op and 2 allocs, on the TLS-handshake path

**Exit criteria:** Benchmark shows allocs/op on a successful proxied request dropping by the 32 KiB buffer plus the four header allocations; a concurrent test that forces 100 simultaneous backend failures asserts every client receives a byte-identical, well-formed error page (fails today); `openssl s_client -tls1_1` is refused; a backend with a self-signed cert is rejected unless `backend_tls_verify: false` is set; 1000 concurrent requests to one backend no longer queue behind a cap of 10.

#### Wave 9 — Challenge rendering, XSS, and middleware decomposition

*Why here:* Depends on wave 6 (the IP that gets interpolated is now the resolved one) and on wave 5 (the token semantics are final), and is best done after the hot path is stable so the 335-line function is split once, not twice. The reflected XSS at middleware.go:296 executes attacker JavaScript in the protected site's origin, and the stage-2 page currently loads its proof-of-work code from a mutable `@main` git ref with no SRI — whoever controls that repo can make `Solve()` return success for every visitor, disabling the escalation tier mid-attack.

- Move both multi-KB inlined HTML blobs (core/server/middleware.go:232 and :296) into `assets/html/`, load with `//go:embed` and parse with `html/template` once at init — that removes the interpolation of the client-controlled IP into the stage-3 page's JavaScript (middleware.go:296), which today turns `Cf-Connecting-Ip: ";alert(document.cookie);//` into origin-scoped script execution
- Drop `ip` from the stage-3 cookie name entirely — the value already binds to the IP via `encryptedIP`
- Self-host the PoW bundle and crypto-js: vendor into `assets/`, `//go:embed`, serve from a first-party path (core/server/middleware.go:232 currently pulls from `cdn.jsdelivr.net/gh/41Baloo/balooPow@main` with no `integrity`, which is both a supply-chain hole in the security control and an availability dependency — if jsDelivr is blocked, nobody can clear stage 2)
- Replace the `alert("... contact @ddosmitigation")` on navigator mismatch with an inline neutral message reported back to the proxy for logging (core/server/middleware.go:232)
- Add a response-header helper setting `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'; default-src 'none'; script-src 'self'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` on every proxy-generated response (core/server/middleware.go:230-231, :294-295) — without frame-ancestors the captcha can be framed and its solutions relayed
- Return real status codes on block paths: 429 for R1/R2/R3 (middleware.go:110, :117, :125) and 403 for the fingerprint and suspicion blocks (:138, :201, :300), each with `Cache-Control: no-store` and `Retry-After` — today they are cacheable 200s, so an attacker can get a block page stored in the shared CDN cache and served to every legitimate visitor
- Strip the `(R1)/(R2)/(R3)` discriminators and the numeric susLv/stage from response bodies and log them server-side instead; replace `err.Error()` rendered to the client at middleware.go:276, :280 with a generic message
- Fix the open redirect at core/server/middleware.go:226: normalise a leading `//` before redirecting and assert the parsed result has empty Scheme and Host — stage 1 is the default stage for every domain, so `https://victim//attacker.com/` is a 302 to a third party on a first visit
- Rewrite the unknown-Host response (core/server/serve.go:89) as a fixed 404 with no product identifier and no echo of `r.Host` — today it is a `fmt.Fprintf` with a concatenated format string, so `%` verbs in the Host header land in the format argument
- Split `Middleware` (core/server/middleware.go:30-364) into named steps: `resolveClient`, `applyRatelimits`, `evaluateRules`, `deriveTokens`, `serveChallenge`, `forward`; each independently testable against the wave-3 table
- Build the firewall DSL field map from the union of names the domain's compiled rules actually reference, populated from a pooled map, with `net.ParseIP` and `strings.ToLower` materialised lazily (core/server/middleware.go:150-177 — 891 ns/op, 1424 B/op, 9 allocs/op per request today, for data most rulesets never read)
- Precompute the admin API path string once at config load instead of concatenating it in a switch case per request (core/server/middleware.go:337)
- Delete `utils.SafeString` (core/utils/text.go:172 — actively dangerous, it sanitises nothing), the dead `closestTo10` at text.go:191, `core/firewall/requests.go` entirely, and the other unused exported symbols; wire up or remove `proxy.FailRequestRatelimit` so the documented `noRequestsSent` knob is not silently inert

**Exit criteria:** A test requesting the stage-3 page with `Cf-Connecting-Ip: ";alert(1);//` from a trusted peer asserts the payload appears escaped and no raw `"` reaches the script context; the challenge pages load with outbound network blocked; `curl -I` on every block path returns 429/403 with `Cache-Control: no-store`; a request to `//evil.com/` returns a relative Location; `staticcheck U1000` reports no unused exported symbols; the httptest stage table from wave 3 still passes unchanged.

#### Wave 10 — Wire-visible rebrand and legal notices (atomic)

*Why here:* Deliberately last among code waves and shipped as exactly one commit and one deploy. Every token here is protocol-visible, and two of them break live sessions: renaming the cookie family invalidates every issued clearance cookie, so at cutover 100% of active visitors are re-challenged simultaneously on a box that is by definition under attack. Worse, the stage-2/3 cookies are written by client-side JS while the check is in Go — rename one without the other and every visitor loops on the challenge forever. Dribbling these out across earlier waves would mean several such cutovers instead of one. The internal module path already moved in wave 2, so this wave is purely the wire surface plus the legal artifacts.

- Response header `baloo-Proxy: 1.5` → `LancarSec-Proxy` (core/server/middleware.go:102), value decoupled from `proxy.ProxyVersion` (core/proxy/proxy.go:6), plus a `hide_version_header` config flag defaulting to hidden — a mitigation product should not announce its exact version
- Cookie family `__bProxy_v` → `__lSec_v` at all four sites: the Go check (core/server/middleware.go:214), the stage-1 Set-Cookie (:225), and the client-side JS writers embedded at :232 and :296. Ship a transitional branch accepting either suffix for one release while only ever issuing the new name, then drop it. Deploy in a low-traffic window
- Path prefix `/_bProxy/` → `/_lancarsec/` at all 8 sites including core/api/api.go:159 and the `fetch("/_bProxy/verified")` callback inside the stage-3 page (core/server/middleware.go:296) — miss that one and no visitor can ever clear stage 3. Route both prefixes for one deprecation release if any API consumer exists
- Move the admin secret out of the URL path into an `Admin-Secret` header on a fixed `/_lancarsec/api/v1` route (core/server/middleware.go:337) — today it is logged by Cloudflare, the origin, browser history and any CDN, and it is rendered into the proxy's own log ring at middleware.go:307-314 and the TUI at core/utils/text.go:28-33
- Rename `BalooProxy` in the seven user-facing block/error pages (core/server/middleware.go:110, :117, :125, :138, :201, :276, :280, :300) and the unknown-Host page (core/server/serve.go:89)
- Credits endpoint (core/server/middleware.go:343-346): keep the route, rewrite the body to ADD LancarSec's identity while PRESERVING upstream's — project name, copyright holder, repo link, and the license statement. First resolve the contradiction that the code claims GPL v2 while LICENSE:2 is GPL v3, and make the string match whichever text actually ships. Never edit the LICENSE body
- Add a `NOTICE` file naming github.com/41Baloo/balooProxy as upstream, and an SPDX + copyright header on every .go file (main.go:1 and the other 24), enforced by `addlicense -check` in CI
- TUI `help` link (core/server/monitor.go:262) → LancarSec docs, or drop the URL; the inline command list at :263-267 is already complete
- examples/config.json: rewrite the three baloo.one/baloo.dog domains, set `"name": "LancarSec"`, and drop or self-host the `avatar` field — core/utils/discord.go:43-44 puts it straight into `avatar_url`, so a copy-paste operator posts attack alerts into their own Discord under upstream's name and GitHub avatar (examples/config.json:31, :38, :39, :69, :76, :107, :114)
- README.md rewrite (27 lines): the download link at :55 currently sends operators to upstream's releases to install upstream's binary; the Docker image name at :63-64; the header-based verification step at :68 must change in lockstep with the header rename; the SwaggerHub API link at :502 describes routes that no longer exist. Keep an explicit 'derived from balooProxy' attribution paragraph
- Add SECURITY.md (disclosure contact and window), CONTRIBUTING.md, and a Makefile with `build`/`docker`/`vet`/`test`/`lint`/`vuln` targets that the Dockerfile and CI both invoke, so there is one build command and the 1.19/1.23.1 divergence cannot recur
- Release workflow: tag-triggered only (`on: push: tags: ['v*']`), matrix build, `sha256sums.txt`, cosign signature, CycloneDX SBOM, and `actions/attest-build-provenance` (.github/workflows/release.yml:36-43) — today every commit silently overwrites a rolling `latest` prerelease with no checksum

**Exit criteria:** `grep -rniE 'baloo|bProxy|goProxy' --include='*.go' --include='*.json' --include='*.md' .` returns only the deliberate attribution strings in the credits endpoint, NOTICE, README and file headers; a browser session issued a cookie by the previous build still validates during the grace release, and a fresh session gets `__lSec_v`; the stage-3 fetch callback and the Go route agree (a manual captcha solve completes end to end); a tagged release produces a signed, checksummed, SBOM-bearing artifact.

#### Wave 11 — Deferred hard problems: fingerprinting and stage 3

*Why here:* Last because both are large, both change detection behaviour rather than fixing a defect, and both need the stable, tested, instrumented base the previous ten waves produce — tuning a detector on top of a hot path that is still being rewritten produces uninterpretable results. Neither blocks shipping the fork; both are what make the fork better than upstream rather than merely safe.

- Spec-accurate JA4/JA3 from the raw ClientHello — extension list, signature algorithms, ALPN — captured via a wrapping listener before the TLS stack consumes the bytes, replacing the current cipher/curve/point string (core/firewall/fingerprint.go:52-79). Filter GREASE by value pattern (0x?a?a) rather than blindly dropping index 0, which today loses a legitimate cipher for Firefox and makes two clients differing only in their first cipher indistinguishable. Fix the `[:1]` vs `[1:]` inconsistency for SupportedPoints, which contradicts the function's own comment, then regenerate the tables at fingerprint.go:12-49 (which are only 'correct' because they were captured from this same buggy code)
- Stop treating a known-browser fingerprint as a standalone ratelimit exemption (core/server/middleware.go:122-127): a utls client sets Chrome's exact ClientHello and gets `browser="Chromium"`, skipping the only control aimed at scripted clients. Require agreement with the User-Agent and an HTTP/2 SETTINGS fingerprint before the exemption applies
- Redesign or replace stage 3 (core/server/middleware.go:235-296, `utils.DrawTriangle` at core/utils/image.go:44-56, `basicfont.Face7x13` at image.go:18). Every pixel of the answer is shipped in captcha ∪ mask; the two decoys are separable by exact RGBA, the warp amplitude is under 2 px, and the answer is 6 hex glyphs from one fixed bitmap face — roughly 50 lines of Python solves it at ~100% accuracy. Prefer a proof-of-work tier or an external provider over a hand-rolled bitmap captcha
- Key the captcha image cache on the full token or a hash of it, not `encryptedIP[:6]` (core/server/middleware.go:235-292, cache at core/firewall/general.go:33) — 24 bits of entropy means collisions are likely above ~4000 concurrent stage-3 clients, and on collision client B is served a PNG containing client A's token material, which combined with the shared 6-character prefix hands B A's complete live token
- Add panic-recover and regex-complexity limits around `gofilter.Apply` (core/firewall/eval.go:13) now that the parser is vendored in-tree, plus `go test -fuzz` targets for `NewFilter` and `Apply` — an 8-year-old generated parser evaluating attacker-influenced input with no recovery is the last unguarded blast radius
- Bind stage-2/3 solutions to a server-set HttpOnly cookie: have the client POST its solution to an endpoint that sets the cookie server-side, instead of JavaScript writing the credential into `document.cookie` (core/server/middleware.go:232, :296)
- Cap how many requests one stage-1 token may carry before reissue (core/server/middleware.go:224-227) — today stage 1 is a pure echo of a server-issued value, so a three-line script passes it forever and one round trip per bot per hour buys unlimited access

**Exit criteria:** A recorded corpus of real ClientHellos (Chrome, Firefox, Safari, curl, python-requests, a utls Chrome mimic) produces JA4 strings that byte-match an external reference calculator, and the utls mimic is separated from real Chrome by the combined UA + h2 signal; a written solver against the new stage 3 fails to reach usable accuracy on 1000 samples; `go test -fuzz=FuzzApply -fuzztime=1h` finds no panic; captcha image cache collisions are impossible by construction (test asserts distinct tokens never share a key).

### Breaking changes

- Module path `goProxy` → `lancarsec` (go.mod:1 + 37 import lines): must land atomically or the build fails with `package X is not in std`. No runtime effect, no wire effect. Migration note: internal only; any downstream Go consumer importing `goProxy/core/...` must update, though the old path was never fetchable anyway.
- Response header `baloo-Proxy: 1.5` → `LancarSec-Proxy` (core/server/middleware.go:102), hidden by default behind `hide_version_header`. Migration note: README.md:68 documents this header as the install-verification step, and operator dashboards or uptime checks that grep for `baloo-proxy` will go blind. Announce before the rebrand deploy and give operators the config flag to re-enable emission if their monitoring needs it.
- Cookie family `__bProxy_v` → `__lSec_v` (core/server/middleware.go:214, :225, and the JS writers at :232 and :296). Migration note: this invalidates every issued clearance cookie — at cutover 100% of active visitors are re-challenged at once, on a box that is by definition under attack. Ship a one-release grace window that ACCEPTS either suffix while only ISSUING the new one, deploy in a low-traffic window, and remember the Go check and the client-side JS writer must change in the same commit or every visitor loops on the challenge forever.
- Reserved path prefix `/_bProxy/` → `/_lancarsec/` at 8 sites including core/api/api.go:159. Migration note: hard break for any API automation calling `/_bProxy/api/v2/...`, for CDN/WAF rules that exempt `/_bProxy/*` from caching, and — most dangerously — for the stage-3 page's own `fetch("/_bProxy/verified")` callback at middleware.go:296. Route both prefixes for one deprecation release.
- Admin secret moves from the URL path segment to an `Admin-Secret` header on a fixed route (core/server/middleware.go:337). Migration note: every admin bookmark, script and curl invocation changes shape. Also, auth failure now returns 404 instead of falling through to the backend, so a mistyped secret no longer lands the request (and the secret) in the customer's logs.
- Removed API actions: `GET_IP_CACHE` and `FILL_IP_CACHE` (core/api/api.go:91-109); `GET_IP_REQUESTS`/`GET_FINGERPRINT_REQUESTS` now return snapshots rather than live maps. Migration note: `RELOAD` changes from a silent no-op to an action that actually reloads — anyone who scripted it as a harmless health poke will now trigger real config reloads.
- Config validation now rejects empty, missing and <16-character secrets, not just the literal `CHANGE_ME` (core/config/init.go:40-63), and the same validation runs on `reload`. Migration note: hand-written configs that omit `apisecret` or a `secrets` entry currently boot fine and will now refuse to start — this is intentional (they are running with authentication disabled today) but operators must be told before upgrading, and `reload` now aborts and keeps the old config on a bad file rather than panicking the process.
- All five secrets must be rotated on upgrade. Migration note: any config generated by the official 1.19-toolchain build or Docker image has publicly derivable values (AdminSecret `<derivable-admin-secret-withheld>`, APISecret `<derivable-api-secret-withheld>`), so upgrading the binary without regenerating config.json leaves the deployment fully compromised. Ship this as a release-note blocker, and note that rotation now takes effect immediately rather than up to an hour later.
- New config keys with behavioural defaults: `cloudflare_enforce_origin`, `backend_tls_verify` (defaults ON), `hide_version_header` (defaults hidden), per-domain transport limits, per-domain method allowlist, body size cap. Migration note: `backend_tls_verify` defaulting on will break any domain whose origin uses a self-signed or private-CA certificate — those must set the per-domain opt-out or supply `backendCA` before upgrading.
- Server TLS minimum raised to 1.2 with an AEAD-only cipher list (core/server/serve.go:71-75). Migration note: clients stuck on TLS 1.0/1.1 lose access. Check access logs for pre-1.2 negotiation before deploying if the protected sites serve legacy embedded or enterprise clients.
- Block and ratelimit responses change from cacheable 200 OK to 429/403 with `Cache-Control: no-store` (core/server/middleware.go:110, :117, :125, :138, :201, :300). Migration note: monitoring that counts non-2xx as errors will see a step change in the error rate — it is the blocks becoming visible, not a regression. Conversely, this stops block pages being poisoned into the shared CDN cache.
- Ratelimits become instantaneous instead of reading a 5-second-stale snapshot (core/server/monitor.go:576-636). Migration note: configured thresholds that were effectively 5x-loose now bite as written. Expect `requests` and `challengeFailures` to fire on traffic that previously slipped through; review and retune per-domain values before deploying, and consider raising them on the first release to avoid blocking legitimate bursty clients.
- `Cf-Connecting-Ip`/`X-Real-Ip`/`X-Forwarded-For` are honoured only from trusted-proxy peers (core/server/middleware.go:59-71). Migration note: any deployment behind a load balancer that is not Cloudflare must add its CIDR to the trusted list or every client will be attributed to the balancer's address and instantly ratelimited. This is the one change most likely to cause a self-inflicted outage on upgrade — verify the trusted list before, not after.
- Firewall rules are now evaluated before the ratelimits so `action: 0` is a true bypass (core/server/middleware.go:107-140). Migration note: whitelists that operators wrote and assumed were working (they were not) now actually exempt traffic — anyone relying on a whitelisted source still being ratelimited will see more traffic reach the backend.
- Docker image base, name and user change (`golang:1.19-alpine` single-stage root → distroless non-root, image renamed to `lancarsec`), and releases move from a rolling `latest` prerelease to signed tagged artifacts. Migration note: the container no longer binds :80/:443 as root — grant `CAP_NET_BIND_SERVICE` or map host ports. Deployment scripts pulling `latest` must switch to a version tag, and `examples/config.json` cert paths no longer point inside the repo.
- `utils.AddDomain`, `utils.SafeString`, `core/firewall/requests.go` and twelve other unused exported symbols are deleted. Migration note: internal only, but `utils.SafeString` in particular should be called out — anyone who wrapped input in it believing it sanitised anything was already unprotected.

### Testing strategy

"Wave 3 exists solely to build the safety net, and no later wave may start until it has landed. In a codebase with zero tests the goal is not coverage, it is a tripwire on the five things that silently fail open.\n\nWhat to test first, in priority order. (1) Pure functions with security semantics, because they are trivial to pin and every one of them currently has a defect: `firewall.EvalFirewallRule` (core/firewall/eval.go:10) table-driven over `+n`/`-n`/absolute/empty/malformed — the empty case panics today via `rule.Action[:1]` at eval.go:15; `utils.StageToString` (core/utils/text.go:176-189) pinning the susLv 0 == susLv>=5 collision so wave 5 flips a visible assertion; `utils.Encrypt`/`EncryptSha` (core/utils/encryption.go:19,24) with golden values plus the failing-today assertion `Encrypt(a+b,k) != Encrypt(a,b+k)`; `firewall.Fingerprint` (core/firewall/fingerprint.go:52) fed synthetic `tls.ClientHelloInfo` so the GREASE change in wave 11 is deliberate rather than accidental. (2) The sliding-window arithmetic in `evaluateRatelimit` (core/server/monitor.go:576-636) driven by an injected clock — create, expire, sum — because wave 7 replaces it wholesale. (3) An httptest table over `server.Middleware` (core/server/middleware.go:30) with a stub backend, asserting status code, Set-Cookie and branch taken for each of: stage 0/1/2/3, R1/R2/R3, forbidden fingerprint, whitelisted `action: 0`, and every `/_bProxy/*` reserved path. This table is the contract the wave-9 decomposition must preserve unchanged.\n\nHow to verify the hot path did not regress. Capture three artifacts on the pre-change binary and commit them: a `go test -bench=. -benchmem` snapshot of the middleware hot path at GOMAXPROCS 1 and 16 (the audit's measurement — 43.7 ns/op at 1 degrading to 90.9 ns/op at 16 — is the negative-scaling signature wave 7 must invert); a load-harness run under `hack/` against a stub origin at fixed concurrency recording req/s, p99 latency and peak RSS; and a second harness profile that sends a unique `Cf-Connecting-Ip` per request for 120 seconds, recording the RSS slope, which is the direct measure of the unbounded-map DoS that waves 6 and 7 must flatten to zero. Diff all three after every wave that touches middleware, serve or firewall, and treat a regression in any as a blocker.\n\nRun `go test -race ./...` from wave 3 onward as a required CI gate. Expect it to fire immediately on the unsynchronised clock and OTP globals (core/proxy/proxy.go:24-33, written at core/server/monitor.go:213-218 and :653-655, read at core/server/middleware.go:184-198) — record those as expected failures in wave 3 and make their disappearance the acceptance criterion for waves 5 and 7 rather than trying to fix them early.\n\nThree things unit tests cannot catch, so test them by construction. The nil-map deadlock needs fault injection: a test that deliberately deletes the current window bucket before a request and asserts the request completes rather than hanging (today it panics, net/http recovers, and `firewall.Mutex` is never released because the `Lock()` at middleware.go:88 has no `defer`). The pooled-buffer aliasing needs concurrency: 100 simultaneous failing-backend requests asserting every client receives a byte-identical well-formed error page — this fails today and a single-threaded test will never show it. And startup independence needs isolation: run the binary with outbound network blocked and assert the fingerprint maps are fully populated and the challenge pages render, which catches both the GitHub fetch and the jsDelivr script dependency.\n\nFinally, wire `go build ./...`, `go vet ./...`, `gofmt -l . | (! read)`, `go test -race ./...` and `govulncheck ./...` into a `ci.yml` that is a required prerequisite for the release workflow. `go vet` cannot be turned on until eval.go:30 is fixed, so that one-line fix is the true first commit of the testing story."

---

## Findings


## CRITICAL

### Hot-path critical sections have no `defer Unlock`; a nil-map panic on line 96 permanently deadlocks the whole proxy

- **Dimension:** concurrency  
- **Location:** `core/server/middleware.go:88-100`  
- **Effort:** medium

**Evidence**

firewall.Mutex.Lock()
// Leaving this here for future reference. When the monitor thread that's supposed to prefill these maps lags
//behind for some reason, this will be come really messy. The mutex will be locked and never unlocked again,
//freezing the entire proxy
...
firewall.WindowAccessIps[proxy.Last10SecondTimestamp][ip]++
domainData = domains.DomainsData[domainName]
domainData.TotalRequests++
domains.DomainsData[domainName] = domainData
firewall.Mutex.Unlock()

**Impact**

`WindowAccessIps[ts]` is a `map[int]map[string]int`; if the bucket for the current `Last10SecondTimestamp` was never prefilled (evaluateRatelimit is starved for >120s, or the timestamp jumps — exactly the scenario the in-code comment describes), the inner map is nil and `nil[ip]++` panics with "assignment to entry in nil map". net/http recovers handler panics, so the process survives — but `firewall.Mutex` is a plain `Lock()` with no `defer`, so the write lock is never released. Every subsequent request, the Monitor loop, evaluateRatelimit and clearProxyCache block forever on that mutex: a total, silent outage of the DDoS mitigation layer. Silent because `main.go:32` does `log.SetOutput(io.Discard)`, so net/http's panic report is discarded. The same unprotected pattern exists at middleware.go:129-131 (`WindowUnkFps[...]`), 216-218 (`WindowAccessIpsCookie[...]`) and 306-320.

**Fix**

Replace every bare `firewall.Mutex.Lock()`/`Unlock()` pair in the request path with `defer`-released locks, or better: drop the map-of-maps entirely and use a `sync.Map` of `*atomic.Int64` (or a sharded counter) plus `LoadOrStore` so a missing bucket is created lazily instead of panicking. Also stop discarding logs in main.go so recovered handler panics are visible.

*Verifier:* Verified verbatim. middleware.go:88 `firewall.Mutex.Lock()`, :96 `firewall.WindowAccessIps[proxy.Last10SecondTimestamp][ip]++`, :100 bare Unlock, with the upstream author's own comment at :89-91 admitting the freeze. WindowAccessIps is `map[int]map[string]int{}` (general.go:20) and buckets are prefilled only by evaluateRatelimit (monitor.go:581-594), 12 buckets / 120s ahead of the timestamp it read. printStats advances proxy.Last10SecondTimestamp every second (monitor.go:216) from a goroutine that does NOT hold firewall.Mutex, so an NTP step / VM resume / >120s starvation of evaluateRatelimit yields a nil inner map and `nil[ip]++` panics. net/http's conn.serve recovers handler panics (process survives) and main.go:32 `log.SetOutput(io.Discard)` swallows the report, so the write lock is leaked silently and Monitor (monitor.go:88), evaluateRatelimit (:579), clearProxyCache (:539) and every later request block forever. Same bare Lock/Unlock at :129-131, :216-218, :306-320 confirmed. Critical stands.

### govulncheck: 20 stdlib vulnerabilities are symbol-reachable, several directly on the proxy request path

- **Dimension:** deps-toolchain  
- **Location:** `core/server/middleware.go:363`  
- **Effort:** small

**Evidence**

govulncheck ./... (golang.org/x/vuln v1.7.0, installed during this audit) reports:
"Your code is affected by 20 vulnerabilities from the Go standard library."
Examples with real traces into this codebase:
  Vulnerability #9: GO-2026-4976 "ReverseProxy forwards queries with more than urlmaxqueryparams parameters in net/http/httputil" — Found in net/http/httputil@go1.25.4, Fixed in go1.25.10 — trace: "core/server/middleware.go:363:38: server.Middleware calls httputil.ReverseProxy.ServeHTTP"
  Vulnerability #16: GO-2026-4341 "Memory exhaustion in query parameter parsing in net/url" — Fixed in go1.25.6 — same trace site
  Vulnerability #3: GO-2026-6089 "Apply ReadHeaderTimeout when doing unencrypted HTTP/2 check in net/http" — Fixed in go1.25.13 — trace: "core/server/serve.go:50:35: server.Serve calls http.Server.ListenAndServe"
  Vulnerability #14: GO-2026-4870 "Unauthenticated TLS 1.3 KeyUpdate record can cause persistent connection retention and DoS in crypto/tls" — Fixed in go1.25.9
The local toolchain is `go version go1.25.4 windows/amd64`.
Source line 363: `domainSettings.DomainProxy.ServeHTTP(writer, request)`

**Impact**

A DDoS-mitigation proxy built with go1.25.4 ships four separately-exploitable unauthenticated DoS primitives in its own hot path: an attacker sends a request with a huge query string (GO-2026-4341 / GO-2026-4976) and the origin-facing ReverseProxy amplifies it upstream; an attacker opens TLS 1.3 connections and floods KeyUpdate records (GO-2026-4870) to pin connections open indefinitely — precisely the resource-exhaustion class this product exists to stop. Note this is with the CURRENT local toolchain, not the go 1.19 directive: even after a naive `go build` on go1.25.4 the product is vulnerable.

**Fix**

Pin the toolchain forward, not just the language version: add `toolchain go1.25.13` (or newer) to go.mod alongside the `go` directive, set `go-version: '1.25.x'` / `check-latest: true` in .github/workflows/release.yml, and bump the Dockerfile base image. Add a `govulncheck ./...` step to CI that fails the build, so a stale toolchain cannot silently ship again. Re-run govulncheck after the bump; the 20 stdlib findings should drop to zero.

*Verifier:* Fully reproduced. I ran govulncheck (x/vuln, go1.25.4 windows/amd64) myself: 'Your code is affected by 20 vulnerabilities from the Go standard library.' The numbering matches exactly (#3 GO-2026-6089, #9 GO-2026-4976, #14 GO-2026-4870, #16 GO-2026-4341) and the traces are verbatim, including 'core/server/middleware.go:363:38: server.Middleware calls httputil.ReverseProxy.ServeHTTP'. middleware.go:363 is indeed `domainSettings.DomainProxy.ServeHTTP(writer, request)`. serve.go:50 is `if err := service.ListenAndServe(); err != nil {`. Highest fixed-in across all 20 is go1.25.13, so the proposed toolchain pin does clear them. One caveat on the fix: a bare `toolchain go1.25.13` line is only honored once the `go` directive is >=1.21, so it must be paired with the go.mod bump (which the companion finding supplies). Severity kept at critical: this is the single highest-value remediation in the set and the affected symbols sit on the request path of a DoS-mitigation product.

### One global RWMutex is acquired 3–4× per request (twice for writing), serializing the entire proxy onto one core

- **Dimension:** performance  
- **Location:** `core/server/middleware.go:88-100 (lock defined core/firewall/general.go:10)`  
- **Effort:** large

**Evidence**

middleware.go:88-100 —
	firewall.Mutex.Lock()
	firewall.WindowAccessIps[proxy.Last10SecondTimestamp][ip]++
	domainData = domains.DomainsData[domainName]
	domainData.TotalRequests++
	domains.DomainsData[domainName] = domainData
	firewall.Mutex.Unlock()

and core/firewall/general.go:10 — `Mutex = &sync.RWMutex{}` is the single lock guarding DomainsData, AccessIps, AccessIpsCookie, UnkFps, all three Window* maps, Connections, and the log slices. The same lock is also taken per TLS handshake (fingerprint.go:82-84) and per connection close (general.go:46-48).

**Impact**

Every request must serialize through one exclusive critical section that does two map-of-map writes plus a DomainData struct copy-in/copy-out. Benchmarked on this repo's exact shape (RLock+lookup, then Lock+window incr+struct RMW) with tiny maps: 43.7 ns/op at GOMAXPROCS=1 but 90.9 ns/op at 16 — negative scaling, throughput ceiling ~11M critical sections/s on an *empty* map. With a realistic WindowAccessIps bucket holding millions of IPs during an IP-randomized flood, the hashed write plus incremental map growth stretches hold time by an order of magnitude, and adding cores makes it worse, not better. At 50k req/s the proxy cannot use more than roughly one core's worth of the request path regardless of machine size; under attack the lock is the throughput limit rather than CPU.

**Fix**

Split by what is touched: make TotalRequests/BypassedRequests per-domain `atomic.Int64` (an atomic add benchmarked at 1.8 ns single-core / 12.6 ns at 16 threads vs 43-91 ns for the lock section); shard the sliding-window counters across N=runtime.NumCPU() striped maps keyed by hash(ip) so writers rarely collide; move `Connections` to a sync.Map (write-once-per-handshake, read-per-request); publish DomainsData through an atomic.Pointer to an immutable snapshot so the read path needs no lock at all.

*Verifier:* Verified. core/firewall/general.go:10 declares a single `Mutex = &sync.RWMutex{}` and it is the only lock guarding DomainsData, AccessIps/AccessIpsCookie/UnkFps, all three Window* maps, Connections and the log slices (62 acquisition sites repo-wide). middleware.go:40-42 RLock, :68-71 or :76-81 RLock, :88-100 Lock (window incr + DomainData copy-in/copy-out), :129-131 Lock, :216-218 Lock, :306-320 Lock — 3-4 acquisitions per request, 2+ exclusive. The same lock is taken per TLS handshake (fingerprint.go:82-84) and per connection close (general.go:46-48), exactly as claimed. Proposed fixes (atomic counters, sharded windows, sync.Map for Connections, atomic.Pointer snapshot) are all sound and do not break the existing semantics.

### Ratelimit decisions read maps refreshed only every 5 s, giving a 5-second unmetered burst window, and the refresh is an O(N) rebuild under the global write lock

- **Dimension:** performance  
- **Location:** `core/server/monitor.go:576-636 (consumed at core/server/middleware.go:69-70,78-80,108,115,123)`  
- **Effort:** large

**Evidence**

monitor.go:597-607 —
	firewall.AccessIps = map[string]int{}
	for windowTime, accessIPs := range firewall.WindowAccessIps {
		...
		for IP, requests := range accessIPs {
			firewall.AccessIps[IP] += requests
		}
	}
...
monitor.go:634 — `time.Sleep(5 * time.Second)`

Middleware reads only the aggregate: middleware.go:79 `ipCount = firewall.AccessIps[ip]` and enforces at :115 `if ipCount > proxy.IPRatelimit`.

**Impact**

A single IP that has 0 in the last aggregate can push unlimited requests for up to 5 s before its count is visible — at 50k req/s that is 250k unmetered requests per attacker IP per window, and an attacker who rotates IPs on a 5 s cadence is never rate-limited at all. Separately, the rebuild itself is O(12 windows × unique IPs) inside `firewall.Mutex.Lock()`: with a 120 s window at 50k req/s of unique IPs that is ~6M map entries reallocated and re-inserted into three fresh maps every 5 s, holding the lock that every request needs — a multi-hundred-millisecond total stall of the proxy, repeating forever.

**Fix**

Have the hot path sum the live per-bucket counters directly (12 lookups into the sharded Window* structures, or an incrementally maintained per-IP total updated on each Incr) so a ratelimit decision is instantaneous. Maintain the aggregate incrementally — subtract the bucket being evicted instead of rebuilding all three maps from scratch — and do the eviction under a per-shard lock, never a global one.

*Verifier:* Verified. evaluateRatelimit (monitor.go:576-637) rebuilds firewall.AccessIps (:597-607), AccessIpsCookie (:608-618) and UnkFps (:619-629) from scratch under firewall.Mutex.Lock() (:579) and then sleeps 5 s (:634). Middleware only ever reads those aggregates (middleware.go:69-70, :78-80) and enforces on them at :108, :115, :123 — it never reads the live Window* buckets, so a per-IP count is stale for up to 5 s and an IP absent from the last aggregate is unmetered for that whole interval. The rebuild is O(buckets x unique keys) with three fresh map allocations while holding the lock every request needs. Both the mechanism and the fix (sum live buckets / maintain incrementally under per-shard locks) check out.

### Cloudflare mode trusts Cf-Connecting-Ip from any peer: total identity spoofing, ratelimit and token-binding bypass

- **Dimension:** security-authz  
- **Location:** `core/server/middleware.go:59-71`  
- **Effort:** medium

**Evidence**

if domains.Config.Proxy.Cloudflare {

		ip = request.Header.Get("Cf-Connecting-Ip")

		tlsFp = "Cloudflare"
...
		ipCount = firewall.AccessIps[ip]
		ipCountCookie = firewall.AccessIpsCookie[ip]

There is no check anywhere that request.RemoteAddr belongs to a Cloudflare range (grep for RemoteAddr in Cloudflare mode returns nothing; the only other use is core/server/middleware.go:73 in the non-Cloudflare branch). The listener in this mode is plain :80 on all interfaces (core/server/serve.go:102 `Addr: ":80"`).

**Impact**

Attacker finds the origin IP (trivial: historical DNS, certificate transparency, or the proxy's own /_bProxy/stats). He then sends `GET / HTTP/1.1` directly to origin:80 with `Cf-Connecting-Ip: <random>` per request. Every per-IP control collapses at once: (1) R1 challenge-failure ratelimit (middleware.go:108), (2) R2 request ratelimit (middleware.go:115), (3) the identity the challenge token is bound to (accessKey at middleware.go:184 starts with `ip`), and (4) every `ip.src` firewall rule. One host produces unlimited apparent unique clients. The mirror attack is worse: send 501 requests with `Cf-Connecting-Ip: <victim's real IP>` and that victim is blocked by R2 for the whole 120 s ratelimit window — a 501-request targeted denial of service against any chosen user, or against Googlebot, or against a payment webhook source. If the header is simply omitted, ip is the empty string, so all such requests share one counter bucket and one challenge token.

**Fix**

Resolve the subject IP through a trusted-proxy allowlist: parse `request.RemoteAddr` with net.SplitHostPort, check membership in Cloudflare's published IPv4/IPv6 CIDRs (net/netip.Prefix.Contains over a preparsed []netip.Prefix), and only then honor Cf-Connecting-Ip; otherwise use the socket peer. Add a hard-reject mode that 403s any peer outside the allowlist when Cloudflare mode is on.

*Verifier:* Verified. middleware.go:59-71 takes `ip = request.Header.Get("Cf-Connecting-Ip")` with zero peer validation; `grep -rn RemoteAddr --include=*.go` returns only fingerprint.go:60, general.go:40, and middleware.go:73/77 (the non-CF branch), confirming no trusted-proxy check exists. The CF-mode listener is a plain `:80` on all interfaces. Spoofed ip feeds AccessIps/AccessIpsCookie lookups (69-70), the accessKey at :184, and `ip.src` in the rule message (:152). The victim-targeting variant is real too. Only citation error: the CF-mode `Addr: ":80"` is serve.go:42, not serve.go:102 (line 102 is `serviceH.Handler = ...`; serve.go:61 is the origin-mode redirect listener). Critical stands.

### All proxy secrets are generated with unseeded math/rand — every Docker/release build produces the identical AdminSecret, APISecret, cookie/JS/captcha secrets

- **Dimension:** security-crypto  
- **Location:** `core/utils/encryption.go:30-38 (rand.Intn at :35), core/config/generate.go:23-34, Dockerfile:1, .github/workflows/release.yml:20`  
- **Effort:** trivial

**Evidence**

core/utils/encryption.go:35 `res[i] = rnd[rand.Intn(len(rnd))]` (import "math/rand", line 6; no rand.Seed anywhere in the repo — `grep -rn "rand.Seed\|crypto/rand"` returns nothing).
core/config/generate.go:23-24 `AdminSecret: utils.RandomString(25), APISecret: utils.RandomString(30),` and :32-34 `"cookie": utils.RandomString(20), "javascript": utils.RandomString(20), "captcha": utils.RandomString(20),`.
Dockerfile:1 `FROM golang:1.19-alpine`; .github/workflows/release.yml:20 `go-version: "1.19"`.
On Go <=1.19 the top-level math/rand source is seeded with 1. Reproduced with the exact alphabet and call order (GODEBUG=randautoseed=0, which is the Go 1.19 behaviour):
  admin:   <derivable-admin-secret-withheld>
  api:     <derivable-api-secret-withheld>
  cookie:  <derivable-cookie-secret-withheld>
  js:      <derivable-js-secret-withheld>
  captcha: <derivable-captcha-secret-withheld>

**Impact**

Any config.json generated by the official container image or a 1.19-toolchain build has AdminSecret `<derivable-admin-secret-withheld>` and APISecret `<derivable-api-secret-withheld>`. An unauthenticated attacker GETs `/_bProxy/<derivable-admin-secret-withheld>/api/v1` with header `proxy-secret: <derivable-api-secret-withheld>` and owns the admin API on every default deployment. The three challenge secrets are equally fixed, so the attacker can compute CookieOTP/JSOTP/CaptchaOTP = sha256(secret||date) offline and mint valid challenge tokens for any IP — total bypass of stages 1-3. Even on Go 1.20+ (auto-seeded), math/rand is a linear generator: two observed outputs recover the state and predict all remaining secrets.

**Fix**

Rewrite utils.RandomString to draw from crypto/rand (`crypto/rand.Read` into a byte slice, then base64/hex-encode, or use `crypto/rand.Int` for unbiased index selection). Keep math/rand out of core/utils/encryption.go entirely. Ship a release note telling existing operators to rotate adminsecret/apisecret/secrets, since the current values are publicly derivable.

*Verifier:* Verified. core/utils/encryption.go:6 imports math/rand, :35 uses rand.Intn; no rand.Seed or crypto/rand anywhere (grep confirmed). generate.go:23,24,32,33,34 are exactly as quoted, and main.go:36 -> config.Load() -> Generate() is the first consumer of the global stream, so the call order is deterministic. I reproduced the claimed values byte-for-byte with the exact alphabet under GODEBUG=randautoseed=0 (Go 1.19 semantics): admin <derivable-admin-secret-withheld>, api <derivable-api-secret-withheld>, cookie <derivable-cookie-secret-withheld>, js <derivable-js-secret-withheld>, captcha <derivable-captcha-secret-withheld>. Dockerfile:1 (golang:1.19-alpine) and .github/workflows/release.yml:20 (go-version 1.19) pin a toolchain with no auto-seeding, so the official image and the released binary do produce these. ONE SUB-CLAIM IS WRONG: the finding elsewhere asserts GODEBUG defaults are keyed to the go.mod directive for randautoseed; I tested this and it is false — building this module (go 1.19 directive) with the local go1.25.4 produced different values on every run. The finding survives on the Dockerfile/CI 1.19 pin alone, so critical stands, but the 'even on Go 1.20+ two outputs recover the state' aside is theoretical and the go.mod-keying claim should be struck.

### ReloadConfig rebuilds DomainData without Stage2Difficulty, disabling the JS proof-of-work and printing the full valid token to the client

- **Dimension:** security-crypto  
- **Location:** `core/server/monitor.go:507-526`  
- **Effort:** trivial

**Evidence**

core/config/init.go:167-175 sets it on first load: `if domain.Stage2Difficulty == 0 { domain.Stage2Difficulty = 5 }` … `Stage2Difficulty: domain.Stage2Difficulty,`.
core/server/monitor.go:507-526 rebuilds the same struct after a `reload` and omits the field entirely: `domains.DomainsData[domain.Name] = domains.DomainData{ Name: domain.Name, Stage: 1, StageManuallySet: false, RawAttack: false, … }` — Stage2Difficulty takes its zero value.
core/server/middleware.go:229 `publicSalt := encryptedIP[:len(encryptedIP)-domainData.Stage2Difficulty]`.
Triggered by the operator command at core/server/monitor.go:375-379 `case "reload": … ReloadConfig()`.

**Impact**

After any `reload` (the documented way to apply config changes), Stage2Difficulty is 0 for every domain, so publicSalt == the complete encryptedIP. The stage-2 challenge page then renders the full valid token in the `publicSalt` div and in `document.cookie="_2__bProxy_v="+publicSalt+solution` — with zero work to do. Any bot that fetches the challenge page reads the token straight out of the HTML and replays it, so stage 2 (the JS challenge, the main anti-DDoS layer) becomes a no-op until the process is restarted. It is also a silent failure: the TUI still reports the domain as being at stage 2.

**Fix**

Add `Stage2Difficulty: domain.Stage2Difficulty,` plus the same `if domain.Stage2Difficulty == 0 { … = 5 }` default to ReloadConfig, and better, factor the DomainData construction into one shared function used by both config.Load and ReloadConfig so the two can never diverge again. Add a hard guard in middleware before slicing: refuse to serve a stage-2 page when Stage2Difficulty < 1.

*Verifier:* Verified exactly. core/config/init.go:167-175 defaults Stage2Difficulty to 5 and sets it in DomainData; core/server/monitor.go:507-526 rebuilds the identical struct and the field is simply absent (I printed lines 505-530 — Name, Stage, StageManuallySet, RawAttack, BypassAttack, LastLogs, counters, RequestLogger, and nothing else), so it becomes 0. middleware.go:229 slices encryptedIP[:len-0], making publicSalt the entire token, which is then printed into the page at :232 in the publicSalt div and in document.cookie="_2__bProxy_v="+publicSalt+solution, and validation at :214 is Contains(cookie, "__bProxy_v="+encryptedIP) — which publicSalt alone satisfies. Reached via the documented 'reload' command at monitor.go:375-379. Silent: the TUI still shows stage 2. Critical is justified for a fork whose whole value is stage 2.

### Cf-Connecting-Ip trusted with no trusted-proxy check — total ratelimit/ban bypass

- **Dimension:** security-http  
- **Location:** `core/server/middleware.go:61`  
- **Effort:** medium

**Evidence**

if domains.Config.Proxy.Cloudflare {

		ip = request.Header.Get("Cf-Connecting-Ip")
...
		ipCount = firewall.AccessIps[ip]
		ipCountCookie = firewall.AccessIpsCookie[ip]

There is no check anywhere in the repo that request.RemoteAddr belongs to a Cloudflare CIDR; grep for a trusted-proxy list returns nothing.

**Impact**

With `cloudflare: true` (the example config default, examples/config.json:3), every subject-IP decision in the proxy is taken from a client-supplied header. An attacker who reaches the origin IP directly (or any client, if Cloudflare does not overwrite the header on a path it does not proxy) sends `Cf-Connecting-Ip: <random>` on each request and gets a fresh ratelimit bucket every time, so `ipCount > proxy.IPRatelimit` (line 115) and `ipCountCookie > proxy.FailChallengeRatelimit` (line 108) never fire. The same value feeds `ip.src` in the firewall DSL (line 152) and the challenge token key (line 184), so custom IP-based block rules and per-IP challenge state are equally forgeable. The entire L7 mitigation is bypassed by one header.

**Fix**

Load the Cloudflare IPv4/IPv6 CIDR lists (and any operator-supplied extras) at startup into a []*net.IPNet, and only honour Cf-Connecting-Ip / X-Real-Ip / X-Forwarded-For when net.SplitHostPort(request.RemoteAddr) parses to an IP inside one of them; otherwise fall back to the socket peer. Add a `cloudflare_enforce_origin` option that returns 403 when the peer is not trusted, so the origin cannot be hit directly at all.

*Verifier:* Verified exactly. core/server/middleware.go:61 reads ip from request.Header.Get("Cf-Connecting-Ip") with no peer validation, and that value feeds firewall.AccessIps/AccessIpsCookie lookups (lines 69-70), the WindowAccessIps counter key (line 96), ip.src in the firewall DSL (line 152), and the challenge accessKey (line 184). A repo-wide grep for MinVersion|HttpOnly|MaxBytesReader|CIDR|ParseCIDR|trusted across all .go files returns zero hits, confirming no trusted-proxy list exists anywhere. examples/config.json:3 is "cloudflare": true. Critical severity stands: a single client-supplied header defeats every per-IP decision in the product.


## HIGH

### An 11MB unstripped ELF binary is committed, embedding /workspaces/balooProxy source paths and the credits string

- **Dimension:** branding  
- **Location:** `oryxBuildBinary (repo root)`  
- **Effort:** trivial

**Evidence**

$ file oryxBuildBinary
	oryxBuildBinary: ELF 64-bit LSB executable, x86-64, ... with debug_info, not stripped
$ git ls-files | grep -i oryx
	oryxBuildBinary
$ strings oryxBuildBinary | grep -iE 'baloo|goProxy'
	/workspaces/balooProxy/core/api/api.go
	/workspaces/balooProxy/core/config/init.go
	/workspaces/balooProxy/core/db/db.go
	/workspaces/balooProxy/core/server/middleware.go
	... BalooProxy; Lightweight http reverse-proxy https://github.com/41Baloo/balooProxy. Protected by GNU GENERAL PUBLIC LICENSE Version 2, June 1991
	... baloo-Proxy ... __bProxy_v= ... <script src="https://cdn.jsdelivr.net/gh/41Baloo/balooPow@main/balooPow.min.js">

**Impact**

Category (a)+(c), and it defeats the entire rebrand if left in place. This is a committed, unstripped, debug_info-bearing build artifact (11,250,895 bytes) from an Azure Oryx build of the UPSTREAM tree. Every branding token you are about to rename is frozen inside it: the `baloo-Proxy` header, the `__bProxy_v` cookie, the balooPow CDN URL, the full credits string, and the absolute build paths `/workspaces/balooProxy/core/...`. So `grep -ri baloo` will keep hitting after a clean source rename, and anyone who downloads the repo gets a runnable copy of the un-rebranded proxy. It also proves the tree once contained a `core/db/db.go` (the BoltDB store that assets/html/login.html:151 still references as `proxyData.db`) that no longer exists — the binary does not match the source. Shipping an opaque prebuilt binary in a SECURITY product's repo is independently a supply-chain smell: nobody can verify what is in it.

**Fix**

`git rm oryxBuildBinary` and add it to .gitignore (the existing .gitignore ignores `main` and `*.exe` but not this Oryx-specific name). Purge it from history with `git filter-repo --path oryxBuildBinary --invert-paths` before publishing the fork, otherwise it stays clonable and keeps 11MB in every clone. Re-run `grep -ri baloo .` after removal to confirm the source rename is actually complete — with this file present, that verification grep is useless.

*Verifier:* Fully verified. `git ls-files` tracks oryxBuildBinary; it is 11250895 bytes, `file` reports ELF 64-bit x86-64, dynamically linked, with debug_info, not stripped. `strings` confirms every claimed token: /workspaces/balooProxy/core/{api,config,db,domains,firewall,pnc,proxy,server,utils}/*.go build paths including core/db/db.go and core/db/init.go (packages absent from the tree), the full 'BalooProxy; Lightweight http reverse-proxy ... Version 2, June 1991' credits string, `baloo-Proxy`, `__bProxy_v=`, and the cdn.jsdelivr.net/gh/41Baloo/balooPow@main script tag. .gitignore does ignore `main` (line 23) and `*.exe` (line 9) but not this filename, as claimed. The point that its presence makes `grep -ri baloo` useless as a rename-completeness check is correct.

### Stage-2 proof-of-work challenge loads balooPow JS from cdn.jsdelivr.net/gh/41Baloo

- **Dimension:** branding  
- **Location:** `core/server/middleware.go:232`  
- **Effort:** medium

**Evidence**

core/server/middleware.go:232, inside the inlined stage-2 challenge HTML:
	<script src="https://cdn.jsdelivr.net/gh/41Baloo/balooPow@main/balooPow.min.js"></script>
	<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.0.0/crypto-js.min.js"></script>
	... new BalooPow("`+publicSalt+`",`+strconv.Itoa(domainData.Stage2Difficulty)+`,"`+hashedEncryptedIP+`",!1).Solve()

**Impact**

Category (d) external dependency on Baloo infrastructure — and a live supply-chain hole in the security control itself. The stage-2 JS PoW is the escalation tier the proxy switches to when the cookie challenge is being bypassed, i.e. mid-attack. It cannot execute unless every visitor's browser successfully loads a script from `cdn.jsdelivr.net` pinned to `@main` — a MUTABLE git ref, not a version or an SRI hash. Consequences: (1) whoever controls the 41Baloo/balooPow repo can push JS that runs in the browser of every visitor to every LancarSec-protected site, and can trivially make `Solve()` return a valid-looking solution for all clients, disabling stage 2 entirely; (2) if jsDelivr is blocked (common in CN/RU/corporate egress filters) or down, affected visitors can never clear stage 2 and are permanently locked out of the protected site; (3) every visitor's IP is disclosed to jsDelivr and to cdnjs. There is no `integrity=` attribute on either script tag, so even a CDN-level tamper is undetected.

**Fix**

Self-host. Vendor balooPow.min.js and crypto-js into `assets/` and `//go:embed` them, serving from a first-party path like `/_lancarsec/pow.js`. This removes the third-party dependency, the mutable-ref risk, and the IP disclosure in one move, and it is strictly faster (same connection, no extra DNS+TLS handshake) on the challenge path that matters most. If a CDN must be kept as an interim step, at minimum pin an immutable tag instead of `@main` and add `integrity="sha384-..." crossorigin="anonymous"`. Note the class name `BalooPow` is invoked in the same script block — rename the constructor when you vendor it, or the branding survives in the page source.

*Verifier:* The code claim is verified: core/server/middleware.go:232 loads `https://cdn.jsdelivr.net/gh/41Baloo/balooPow@main/balooPow.min.js` and crypto-js from cdnjs, both with no `integrity=`, on a mutable `@main` ref, and instantiates `new BalooPow(...)`. But enumerated consequence (1) is FALSE and is the one the 'critical' rating leans on: a hostile balooPow build canNOT 'trivially make Solve() return a valid-looking solution ... disabling stage 2 entirely'. Clearance is validated server-side at middleware.go:214 against `encryptedIP`, and the client is only ever given `publicSalt = encryptedIP[:len-Stage2Difficulty]` (middleware.go:229) plus `hashedEncryptedIP`; it never learns the withheld suffix, so a lying library cannot forge a passing `_2__bProxy_v` cookie. Consequences (2) CDN-block lockout and (3) IP disclosure to jsDelivr/cdnjs are real, as is arbitrary attacker JS running in every visitor's browser (including exfiltration of a legitimately-solved clearance cookie). Downgraded one level for the false core claim.

### Startup version check phones home to 41Baloo's GitHub and can hard-panic the proxy

- **Dimension:** branding  
- **Location:** `core/config/init.go:224-226 (VersionCheck at :237-265)`  
- **Effort:** trivial

**Evidence**

core/config/init.go:238:
	resp, err := http.Get("https://raw.githubusercontent.com/41Baloo/balooProxy/main/global/proxy/version.json")
core/config/init.go:224-226:
	vcErr := VersionCheck()
	if vcErr != nil {
		panic("[ " + utils.PrimaryColor("!") + " ] [ " + vcErr.Error() + " ]")
core/config/init.go:257 (message names upstream's download URL):
	"... Consider Downloading The New Version From Github Or " + proxyVersions.Download + " ]"
global/proxy/version.json:4:
	"download": "https://github.com/41Baloo/balooProxy/releases/download/1.5/main"

**Impact**

Category (d) external dependency + availability. Unlike the fingerprint fetch, this error is NOT discarded — it is escalated to `panic` at init.go:225. So a DDoS-mitigation proxy REFUSES TO BOOT if GitHub is down, DNS is blocked, or the host is in an egress-restricted network. That is a hard availability dependency on a third party's infrastructure for a product whose entire job is staying up. It also leaks every deployment's origin IP to GitHub on every restart — an attacker who can observe that traffic, or the repo owner, learns where your origins are. And init.go:257 prints a message telling YOUR operators to download a NEW VERSION from the upstream author's release page (`proxyVersions.Download`, sourced from JSON the upstream controls) — a remote-controlled string that could be pointed anywhere.

**Fix**

Delete `VersionCheck` and its call at init.go:224 outright, or stub it to return nil with a TODO pointing at a future LancarSec-owned endpoint. If retained: never `panic` on it (log and continue), never render a remote-supplied download URL to the operator, and run it asynchronously off the boot path. Also rewrite global/proxy/version.json:4's `download` field away from the 41Baloo releases URL. Nothing breaks by removing it — nothing else in the codebase reads the result.

*Verifier:* Verified end to end. core/config/init.go:224-226 does `vcErr := VersionCheck(); if vcErr != nil { panic(...) }`; VersionCheck at :237 does `http.Get("https://raw.githubusercontent.com/41Baloo/balooProxy/main/global/proxy/version.json")` at :238 and returns an error on any transport failure. The panic is genuinely fatal — pnc.PanicHndl (core/pnc/panicHandler.go:23-32) writes crash.log and then re-panics at line 30, so the process exits; the boot-blocking availability claim holds. init.go:257 does render the remote-controlled `proxyVersions.Download` to the operator, and global/proxy/version.json:4 is the 41Baloo releases URL. Nothing consumes VersionCheck's result beyond that panic, so removal is safe as claimed. Severity confirmed at high.

### TLS fingerprint database fetched from raw.githubusercontent.com/41Baloo at every startup, with errors discarded

- **Dimension:** branding  
- **Location:** `core/config/init.go:104-106 (function core/config/generate.go:102-119)`  
- **Effort:** small

**Evidence**

core/config/init.go:104-106:
	GetFingerprints("https://raw.githubusercontent.com/41Baloo/balooProxy/main/global/fingerprints/known_fingerprints.json", &firewall.KnownFingerprints)
	GetFingerprints("https://raw.githubusercontent.com/41Baloo/balooProxy/main/global/fingerprints/bot_fingerprints.json", &firewall.BotFingerprints)
	GetFingerprints("https://raw.githubusercontent.com/41Baloo/balooProxy/main/global/fingerprints/malicious_fingerprints.json", &firewall.ForbiddenFingerprints)

core/config/generate.go:102-105:
	func GetFingerprints(url string, target *map[string]string) error {
		resp, err := http.Get(url)
		if err != nil {
			return errors.New("failed to fetch fingerprints: " + err.Error())

**Impact**

Category (d) external dependency on Baloo infrastructure — the single worst item in this inventory, on three axes. (1) AVAILABILITY: `GetFingerprints` returns an `error` and all three call sites DISCARD it. If GitHub is unreachable, rate-limits the origin IP, or 41Baloo deletes/renames the repo, the three maps stay empty and the proxy boots with NO fingerprint intelligence — `firewall.ForbiddenFingerprints[tlsFp]` at middleware.go:137 returns "" so every known-malicious client is admitted, and `browser == ""` for everyone, driving all traffic down the unknown-FP ratelimit path at middleware.go:122. It fails OPEN and silently, and it does so precisely when the box is under attack and outbound calls are slowest. (2) SUPPLY CHAIN: whoever controls that GitHub repo controls, unauthenticated over a plain `http.Get`, which TLS fingerprints your proxy blocks and allows. An upstream repo compromise is a remote allow-list injection into every deployment. (3) BRANDING: it is a hard runtime dependency on the upstream author's namespace that survives every cosmetic rename.

**Fix**

Delete the network fetch entirely. `global/fingerprints/{known,bot,malicious}_fingerprints.json` already exist in the tree (verified present, 2085/4726/3515 bytes) — read them from disk with `os.ReadFile`, or better `//go:embed` them into the binary so there is no filesystem dependency either. Change the call sites to `if err := LoadFingerprints(path, &target); err != nil { panic(...) }` so a load failure is loud and fatal instead of a silent fail-open. If a remote update channel is genuinely wanted later, make it opt-in, signed, and cached — never a blocking unauthenticated GET on the startup path.

*Verifier:* Verified precisely, including the function span: GetFingerprints is core/config/generate.go:102-119 (exact), and core/config/init.go:104-106 call it three times discarding the returned error. The three JSON files exist locally at the claimed sizes (known 2085, bot 4726, malicious 3515 bytes). Two corrections. (1) 'unauthenticated over a plain http.Get' is misleading — the URLs are https://, so transport is TLS-authenticated to GitHub; the real defect is that the CONTENT is unsigned and unpinned, which is what the supply-chain argument actually rests on. (2) 'It fails OPEN' is only half right. Empty ForbiddenFingerprints does fail open (middleware.go:137 `forbiddenFp` is always ""). But empty KnownFingerprints makes `browser = firewall.KnownFingerprints[tlsFp]` (middleware.go:84) empty for EVERY client, which pushes all legitimate traffic into the stricter unknownFingerprint bucket at middleware.go:122 — that fails CLOSED and mass-blocks real users. Also note both effects are inert in Cloudflare mode, where middleware.go:63-65 hardcodes tlsFp/browser to "Cloudflare". Downgraded one level from critical: startup-time degradation of one control layer, not proxy compromise.

### One global `firewall.Mutex` serialises every request, every TLS handshake and every connection close

- **Dimension:** concurrency  
- **Location:** `core/firewall/general.go:10`  
- **Effort:** large

**Evidence**

core/firewall/general.go:10: `Mutex = &sync.RWMutex{}` — the only lock in the program.
Per request Middleware takes it up to six times: RLock at middleware.go:40-42, RLock at 68-71 (or 76-81), Lock at 88-100, Lock at 129-131, Lock at 216-218, Lock at 306-320.
It also guards `domains.DomainsData` in the :80 redirect handler (serve.go:83-97), the TLS handshake hook (`firewall.Fingerprint`, fingerprint.go:82-84), the connection-close hook (`OnStateChange`, general.go:46-48), the Monitor loop (monitor.go:88-92), the cache sweeper (monitor.go:539-570) and the admin API (api.go:73-112).

**Impact**

Four write-lock acquisitions per request on a single global RWMutex means the request path is fully serialised — the proxy cannot use more than roughly one core for mitigation decisions no matter how many are available. This is the exact opposite of what a DDoS-mitigation front end needs: throughput collapses precisely when load is highest, and each of the four sections does a full copy-modify-write of the ~15-field `DomainData` struct while holding the lock (middleware.go:97-99, 317-319, serve.go:94-96).

**Fix**

Split by ownership and remove the lock from the hot path entirely: per-domain counters as `atomic.Int64` fields behind a `*DomainCounters` pointer (no struct copy, no lock); the sliding-window buckets in their own `sync.Map`/sharded mutex; `Connections`/`JA4` in a `sync.Map`; the config behind `atomic.Pointer[Configuration]`. Keep a mutex only for the terminal UI state.

*Verifier:* Location verified: core/firewall/general.go:10 is `Mutex = &sync.RWMutex{}`, and every cited holder checks out — middleware.go:40-42, 68-71, 76-81, 88-100, 129-131, 216-218, 306-320; the :80 redirect handler serve.go:83-97; firewall.Fingerprint fingerprint.go:82-84; OnStateChange general.go:46-48; Monitor monitor.go:88-92; clearProxyCache monitor.go:539-570; api.go:73-112. The full-struct copy-modify-write of the 15-field DomainData under the lock is confirmed at middleware.go:97-99, 317-319 and serve.go:94-96 (domains.DomainData, domain.go:70-92). Two evidence inaccuracies that do not change the verdict: it is not 'the only lock in the program' (PrintMutex at monitor.go:30 and utils.PrintMutex at text.go:17 also exist), and a typical bypassed request takes 2 write locks (:88, :306), not 4 — :129 only fires for unknown fingerprints and :216 only when the challenge cookie is absent. The serialisation of the hot path on one global RWMutex is real and high for a mitigation front end.

### RoundTrip returns a response body that aliases a `sync.Pool` buffer it has already returned to the pool

- **Dimension:** concurrency  
- **Location:** `core/server/serve.go:120-149`  
- **Effort:** small

**Evidence**

buffer := bufferPool.Get().(*bytes.Buffer)
buffer.Reset()
defer bufferPool.Put(buffer)
...
	buffer.WriteString(`<!DOCTYPE html>...`)
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(buffer.Bytes())),
	}, nil

Same pattern again at serve.go:189-192. The consumer of that Body is `httputil.ReverseProxy.copyResponse`, which runs *after* RoundTrip has returned — i.e. after the deferred `bufferPool.Put(buffer)` has already published the buffer for reuse.

**Impact**

`bytes.NewReader(buffer.Bytes())` aliases the pooled buffer's backing array. The moment RoundTrip returns, the deferred Put makes that buffer available to any other request goroutine, which does `bufferPool.Get()` + `buffer.Reset()` + `WriteString(...)` (middleware.go:34-36, serve.go:120-121) — writing into the array a different connection is still streaming to its client. Result: a data race, truncated/garbled error pages, and cross-request content bleed (one client can receive bytes generated for another client's response). Because the error path only fires when the backend is down or 5xx, this shows up exactly during an incident. My short race-detector run did not catch it (sync.Pool's per-P caching makes the collision window narrow with few concurrent connections), but the use-after-Put is unambiguous from the code.

**Fix**

Do not put a pooled buffer into a returned `http.Response.Body`. Either copy the bytes out (`body := append([]byte(nil), buffer.Bytes()...)`) before the Put, or hand back a `Body` whose `Close()` is what returns the buffer to the pool instead of a `defer` in RoundTrip.

*Verifier:* Confirmed use-after-Put. serve.go:120-122 does Get / Reset / `defer bufferPool.Put(buffer)`, then :146-149 returns `Body: io.NopCloser(bytes.NewReader(buffer.Bytes()))`, and the identical pattern is at :189-192. bytes.NewReader aliases the pooled buffer's backing array, and httputil.ReverseProxy.copyResponse drains that Body only after RoundTrip returns — i.e. after the deferred Put has republished the buffer. The RoundTripper is genuinely wired in: core/config/init.go:130 and core/server/monitor.go:471 both set `dProxy.Transport = &RoundTripper{}`. The bleed is worse than described: the racing consumer is usually Middleware's own pooled buffer (middleware.go:34-36), which is where the stage-2/3 challenge HTML containing another client's encryptedIP/hashedEncryptedIP is written (middleware.go:232, 296), so a challenge token can leak into another client's error page. Note Middleware's own Get/defer-Put pair is correct — only RoundTrip's is broken. High stands.

### Sliding-window maps are keyed by fully attacker-controlled values with no cardinality cap

- **Dimension:** concurrency  
- **Location:** `core/server/middleware.go:96`  
- **Effort:** medium

**Evidence**

middleware.go:96:  firewall.WindowAccessIps[proxy.Last10SecondTimestamp][ip]++
middleware.go:130: firewall.WindowUnkFps[proxy.Last10SecondTimestamp][tlsFp]++
middleware.go:217: firewall.WindowAccessIpsCookie[proxy.Last10SecondTimestamp][ip]++

where `ip = request.Header.Get("Cf-Connecting-Ip")` (middleware.go:61 — a raw request header, with no trusted-proxy check anywhere in the file) and `tlsFp` is the cipher/curve string built from the client's own ClientHello (fingerprint.go:62-79).

The aggregation maps are rebuilt from these every 5s with no cap either: `firewall.AccessIps = map[string]int{}` … `firewall.AccessIps[IP] += requests` (monitor.go:597-607).

**Impact**

With `RatelimitWindow` defaulting to 120s there are 12 live buckets. An attacker sending a distinct `Cf-Connecting-Ip` header per request (or, in origin mode, rotating an IPv6 /64, or varying the ClientHello to produce a unique `tlsFp` string of ~500 bytes) inserts one new map entry per request per bucket, plus one in the aggregate map. At even 50k req/s that is millions of live entries within the window; each `WindowUnkFps` key is a long string. Memory grows until OOM, and every insert happens under the single global write lock, so the GC pressure and rehashing also stall every other request. The mitigation layer is the DoS vector.

**Fix**

Cap each bucket (e.g. refuse new keys past a `MaxBucketKeys` limit and treat overflow as "unknown, apply default suspicion"), and normalise the key: hash the fingerprint to a fixed 8/16 bytes instead of storing the raw string, and collapse IPv6 sources to their /64. Only honour `Cf-Connecting-Ip` when the socket peer is a trusted proxy.

*Verifier:* Verified. middleware.go:96, :130, :217 insert into WindowAccessIps / WindowUnkFps / WindowAccessIpsCookie keyed on attacker-controlled values: middleware.go:61 is literally `ip = request.Header.Get("Cf-Connecting-Ip")` with no trusted-peer check anywhere in the file, and tlsFp is the raw `0x%x,`-concatenated cipher/curve/point string built from the client's own ClientHello (fingerprint.go:62-79). proxy.RatelimitWindow = 120 (core/proxy, line 45) and evaluateRatelimit prefills 12 buckets (monitor.go:581), so 12 live buckets, each uncapped. The aggregation maps are rebuilt with no cap either (monitor.go:597-607, 608-618, 619-629). Every insert happens under the single global write lock, so the rehash cost compounds finding #4. This is the mitigation layer being the memory-exhaustion vector; high is correct.

### `CacheIps`/`CacheImgs` eviction is gated on a CPU/RAM heuristic that is guaranteed false during an attack

- **Dimension:** concurrency  
- **Location:** `core/server/monitor.go:551-569`  
- **Effort:** medium

**Evidence**

// Only clear if proxy isnt under attack / memory is running out
if (proxyCpuUsage < 15 && proxyMemUsage > 25) || proxyMemUsage > 95 {
	firewall.CacheIps.Range(func(key, value any) bool {
		firewall.CacheIps.Delete(key)
		return true
	})
}

Entries are stored per request at middleware.go:196 and 204 with key `accessKey + susLvStr`, where `accessKey := ip + tlsFp + reqUa + proxy.CurrHourStr` (middleware.go:184) — `reqUa` is `request.UserAgent()`, i.e. arbitrary attacker-supplied text. `proxyMemUsage` is `Alloc/Sys*100` (monitor.go:238).

**Impact**

There is no TTL and no size bound; the only eviction path requires CPU < 15%, which is exactly what is not true while the proxy is being flooded — the comment even says so. An attacker varying only the User-Agent header creates one permanent `CacheIps` entry (plus a second for the hashed value) per request. Combined with the 2-minute sleep between sweeps, the cache grows monotonically until the process is OOM-killed. Two `CacheImgs` PNG blobs (base64) per unique captcha secret compound it.

**Fix**

Give the caches a real TTL and a hard entry cap (an LRU or a sharded map with per-entry expiry swept every few seconds), independent of CPU/RAM heuristics. Key on a hash of the identity tuple, not on raw attacker text.

*Verifier:* Verified verbatim at monitor.go:551-557 (and the duplicate gate at :564-569 for CacheImgs): `if (proxyCpuUsage < 15 && proxyMemUsage > 25) || proxyMemUsage > 95`. proxy.RamUsage is Alloc/Sys*100 (monitor.go:238), a ratio that sits well under 95 for a normally-growing heap, so under load neither clause is satisfiable — the first requires idle CPU, the second essentially never trips. Insert side confirmed: middleware.go:184 `accessKey := ip + tlsFp + reqUa + proxy.CurrHourStr` with reqUa = request.UserAgent() (:148), stored unconditionally at :204 and additionally at :196, plus a base64 PNG pair per unique secretPart at :287. No TTL, no size bound, 2-minute sleep between sweeps (monitor.go:571). Unbounded growth from a varied User-Agent header until OOM. High stands.

### `LastLogs` grows without bound for every domain that is not the one shown in the terminal

- **Dimension:** concurrency  
- **Location:** `core/utils/text.go:22-26`  
- **Effort:** small

**Evidence**

// Only run in locked thread
func AddLogs(entry domains.DomainLog, domainName string) {
	domainData := domains.DomainsData[domainName]
	domainData.LastLogs = append(domainData.LastLogs, entry)
	domains.DomainsData[domainName] = domainData
}

called for every bypassed request at middleware.go:307-315. The only trim is in `ReadLogs` (text.go:42-51):
	logOverflow := len(domainData.LastLogs) - proxy.MaxLogLength
	if logOverflow > 0 { domainData.LastLogs = domainData.LastLogs[logOverflow:] ... }
and `ReadLogs` is reached from exactly one place: `utils.ReadLogs(proxy.WatchedDomain)` (monitor.go:280), inside the final `else` branch of printStats.

**Impact**

With N configured domains only one is trimmed. Every other domain accumulates a `DomainLog` struct (7 strings: IP, UA, path, full TLS fingerprint…) per bypassed request, forever — hundreds of MB per hour on a busy domain, unbounded. Even the watched domain stops being trimmed whenever `helpMode` is true or the domain is not found, because `ReadLogs` is not called on those branches. The re-slice at text.go:47 also never releases the head of the backing array, so trimming does not return memory either.

**Fix**

Make the log buffer a fixed-capacity ring buffer owned per domain, trimmed at append time (in `AddLogs`), completely independent of whether the TUI is rendering that domain.

*Verifier:* Verified. utils.AddLogs (text.go:22-26) appends to domainData.LastLogs for every bypassed request via middleware.go:307-315, for whatever domain the request hit. The only trim is text.go:42-51, inside ReadLogs, and a repo-wide grep confirms ReadLogs has exactly one caller: monitor.go:280 `utils.ReadLogs(proxy.WatchedDomain)`, inside the final else branch of printStats — so the help-mode branch (:259) and the domain-not-found branch (:246) skip it too. DomainLog is 7 strings (domain.go:60-68) including the full TLS fingerprint and User-Agent. Every non-watched domain accumulates forever. The re-slice caveat is also correct: `domainData.LastLogs = domainData.LastLogs[logOverflow:]` (text.go:47) keeps the original backing array alive. High stands.

### `commands()` spins at 100% CPU forever when stdin is not interactive (systemd, docker, nohup)

- **Dimension:** concurrency  
- **Location:** `core/server/monitor.go:290-296`  
- **Effort:** trivial

**Evidence**

scanner := bufio.NewScanner(os.Stdin)
for {
	if scanner.Scan() {
		...
	}
}

Measured on the race-instrumented binary started with redirected stdio, with the proxy otherwise idle:
  PS> Get-Process proxy_race | ... => cpu_seconds=254.33  elapsed_s=260.82
i.e. 97.5% of a full core consumed with essentially no traffic.

**Impact**

`bufio.Scanner.Scan()` returns false immediately and permanently once stdin hits EOF or is closed. The loop has no `break`, no sleep and no error check, so it becomes a tight infinite loop. Any non-interactive deployment — `systemd` without a TTY, `docker run` without `-it`, `nohup`, a supervisor — burns one entire CPU core from startup. On a DDoS mitigation box that is a core stolen from mitigation, and it also starves the `evaluateRatelimit` goroutine that must prefill the window buckets (see the nil-map deadlock finding).

**Fix**

Check the scanner's terminal state at startup (`term.IsTerminal(int(os.Stdin.Fd()))`) and return from `commands()` when stdin is not a TTY; regardless, `for scanner.Scan() { ... }` plus an explicit `scanner.Err()` check so the loop terminates on EOF.

*Verifier:* Verified verbatim at monitor.go:290-292: `scanner := bufio.NewScanner(os.Stdin)` then `for { if scanner.Scan() {` — no else, no break, no scanner.Err() check, no sleep, and the closing brace at :397-398 confirms the for has no other exit. bufio.Scanner.Scan returns false permanently after EOF or error, so a non-interactive stdin (systemd's default StandardInput=null, docker without -it, nohup) turns this into an unbounded tight loop from startup. I cannot independently confirm the 97.5%-of-a-core measurement, but it is the arithmetically expected result and the code alone is conclusive. Given the fork's own deployment is a systemd unit, this is a guaranteed hit, not a hypothetical. High stands.

### Client IP is extracted by splitting RemoteAddr on ':' instead of net.SplitHostPort

- **Dimension:** deps-toolchain  
- **Location:** `core/server/middleware.go:73`  
- **Effort:** trivial

**Evidence**

core/server/middleware.go:73, the non-Cloudflare branch of the request hot path:
```go
ip = strings.Split(request.RemoteAddr, ":")[0]
```
The value is then used as the ratelimit key at middleware.go:79-80 and :96:
```go
ipCount = firewall.AccessIps[ip]
ipCountCookie = firewall.AccessIpsCookie[ip]
...
firewall.WindowAccessIps[proxy.Last10SecondTimestamp][ip]++
```
`net.SplitHostPort` has been in the standard library since Go 1.0 and handles the bracketed IPv6 form.

**Impact**

`http.Server` sets RemoteAddr to `[2001:db8::1]:54321` for IPv6 peers. Splitting on ':' yields `"[2001"` — the same key for every address in `2001::/16`. Every IPv6 client on the internet collapses into a handful of ratelimit buckets, so a single IPv6 host can exhaust the per-IP quota for an entire prefix (self-inflicted DoS on legitimate traffic) while an attacker rotating within one prefix is metered as one address. For a product whose core function is per-IP ratelimiting, this silently disables it for IPv6.

**Fix**

`host, _, err := net.SplitHostPort(request.RemoteAddr); if err != nil { host = request.RemoteAddr }; ip = host`. Consider normalising through `netip.ParseAddr` and, for IPv6, keying the ratelimit on the /64 rather than the full address — but first stop conflating /16s.

*Verifier:* Confirmed and, if anything, understated. middleware.go:73 is exactly `ip = strings.Split(request.RemoteAddr, ":")[0]` in the non-Cloudflare branch, and that value keys the ratelimit reads at :79-80 and the sliding-window write at :96 `firewall.WindowAccessIps[proxy.Last10SecondTimestamp][ip]++`. http.Server sets RemoteAddr to the bracketed form for IPv6 peers, so every such client collapses to '[2001' (or its first hextet) — per-IP ratelimiting is silently non-functional for IPv6 in origin mode, which is the product's core function. I found a second consequence the finding missed that strengthens it: middleware.go:184 builds `accessKey := ip + tlsFp + reqUa + proxy.CurrHourStr` and that key mints the challenge cookie at :192-198, so two IPv6 clients sharing a first hextet, browser and TLS fingerprint also share a valid challenge token. Severity raised one level to high. The net.SplitHostPort fix is correct.

### Dockerfile builds on golang:1.19-alpine, an image whose Go toolchain reached end-of-life in August 2023

- **Dimension:** deps-toolchain  
- **Location:** `Dockerfile:1`  
- **Effort:** small

**Evidence**

Dockerfile in full:
```
FROM golang:1.19-alpine
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o main .
EXPOSE 80 443
CMD ["./main"]
```
The local toolchain is go1.25.4 and govulncheck already finds 20 reachable stdlib vulns at 1.25.4 — Go 1.19 predates every one of those fixes plus roughly two additional years of net/http, crypto/tls and net/url security releases.
It is also a single-stage image: the final container ships the full Go toolchain, module cache and source tree, and runs as root by default.

**Impact**

Containers built from this Dockerfile are the worst-case artifact: an internet-facing TLS-terminating reverse proxy compiled with a toolchain that has been unsupported for over two years, so none of the HTTP/2 rapid-reset, CONTINUATION-flood, net/url, or crypto/tls fixes are present. The single-stage layout multiplies the attack surface by shipping a compiler and the source into production.

**Fix**

Multi-stage: `FROM golang:1.25-alpine AS build` with `RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /lancarsec .`, then `FROM gcr.io/distroless/static-debian12` (or `alpine:3.21`) copying only the binary plus `global/` and `assets/`. `modernc.org`-free pure-Go build means CGO_ENABLED=0 is safe. Add `USER 65532:65532` and grant CAP_NET_BIND_SERVICE at runtime rather than running as root.

*Verifier:* The Dockerfile is quoted verbatim and correctly (16 lines; line 1 is `FROM golang:1.19-alpine`; single stage; `go build -o main .` with no -trimpath, no CGO_ENABLED, no USER directive, so the final image ships the toolchain, module cache and source and runs as root). Go 1.19 reached EOL in Aug 2023, and since govulncheck already finds 20 reachable stdlib vulns at go1.25.4, a 1.19 build necessarily predates all of them plus the HTTP/2 rapid-reset and CONTINUATION-flood fixes. The multi-stage/distroless fix is sound. One cosmetic defect in the fix text: the sentence "`modernc.org`-free pure-Go build means CGO_ENABLED=0 is safe" references a package that does not appear anywhere in this tree — the correct justification is simply that no dependency here uses cgo. Severity high retained.

### Release workflow uses Go 1.19, a deprecated setup-go@v2, and an unpinned third-party action with repo write token

- **Dimension:** deps-toolchain  
- **Location:** `.github/workflows/release.yml:33`  
- **Effort:** small

**Evidence**

.github/workflows/release.yml:16-20:
```yaml
      - name: "Set up Go"
        uses: actions/setup-go@v2
        with:
          go-version: "1.19"
```
.github/workflows/release.yml:26-27:
```yaml
      - name: "Build with UUID"
        run: go build -ldflags "-X 'main.Fingerprint=${{ env.uuid }}'" -o dist/main
```
.github/workflows/release.yml:29-33:
```yaml
      - name: "Release"
        uses: marvinpinto/action-automatic-releases@latest
        with:
          repo_token: "${{ secrets.GITHUB_TOKEN }}"
```
There is no `go vet`, `go test`, `staticcheck` or `govulncheck` step anywhere in the workflow, and no `go mod verify`.

**Impact**

Three compounding supply-chain problems on the workflow that produces the binaries users download. (1) `@latest` is a mutable Git ref on a third-party action — whoever controls that repo can push new code that executes in a job holding `secrets.GITHUB_TOKEN` and can rewrite the `latest` release artifact; this is the exact shape of the tj-actions/changed-files compromise. (2) `actions/setup-go@v2` runs on a retired Node runtime and is long superseded by v5. (3) Every published prerelease binary is compiled by an EOL Go 1.19, and nothing gates the release on vet or vulnerability status. The build also omits `-trimpath`, so the builder's absolute filesystem paths are embedded in every shipped binary.

**Fix**

Pin third-party actions to a full commit SHA (`uses: <owner>/<action>@<40-char-sha> # v1.2.3`) or replace the release step with `gh release create` via the official CLI. Bump to `actions/setup-go@v5` with `go-version-file: go.mod` and `check-latest: true` so the toolchain tracks go.mod instead of a hardcoded string. Add `-trimpath -buildvcs=false` to the build. Insert required steps: `go vet ./...`, `go mod verify`, and `govulncheck ./...` before the release step, and set `permissions: contents: write` explicitly at job level rather than inheriting the default token scope.

*Verifier:* All three quoted blocks are verbatim correct: release.yml:17-20 is `actions/setup-go@v2` with `go-version: "1.19"`; line 30 is the build with -ldflags and no -trimpath/-buildvcs; and the Release step uses `marvinpinto/action-automatic-releases@latest` with `repo_token: ${{ secrets.GITHUB_TOKEN }}`, automatic_release_tag 'latest'. I confirmed the workflow contains no go vet, go test, staticcheck, govulncheck or go mod verify step, and that codeql.yml runs only `build-mode: autobuild` (line 48). A mutable `@latest` ref on a third-party action inside a job holding GITHUB_TOKEN is a genuine high — it is the tj-actions/changed-files shape, and the fixes (SHA pinning, setup-go@v5 with go-version-file, explicit job permissions, added gates) all work. Location off by one: the `uses:` line the finding describes is release.yml:33, not :32 (:32 is `- name: "Release"`).

### Dockerfile is single-stage on EOL golang:1.19-alpine, runs as root, no strip, no digest pin

- **Dimension:** ops-build  
- **Location:** `Dockerfile:1-16`  
- **Effort:** small

**Evidence**

Whole file: `Dockerfile:1` `FROM golang:1.19-alpine`; `:5` `COPY go.mod go.sum ./`; `:9` `COPY . .`; `:11` `RUN go build -o main .`; `:13` `EXPOSE 80 443`; `:15` `CMD ["./main"]`. There is no second stage, no `USER`, no `HEALTHCHECK`, no image digest, and no build flags.

**Impact**

The published image is the ~350 MB golang builder itself: it ships the full Go toolchain, compiler, module cache and complete source into production, so any RCE in the proxy lands in a container with `go build`, `git` and a package manager available. The process runs as uid 0 with no capability drop. `golang:1.19-alpine` reached end of life in Aug 2023 and receives no Go security backports, and the floating tag means two builds a month apart are not the same image. The binary is unstripped, so the shipped container also leaks the build paths and symbols.

**Fix**

Multi-stage: `FROM golang:1.25-alpine AS build` (pinned by digest) → `RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/lancarsec .` → `FROM gcr.io/distroless/static-debian12:nonroot`, `COPY --from=build /out/lancarsec /lancarsec`, `USER nonroot`, `ENTRYPOINT ["/lancarsec"]`. Bind :80/:443 via `CAP_NET_BIND_SERVICE` or a host port map rather than root.

*Verifier:* Verified line for line: Dockerfile:1 `FROM golang:1.19-alpine`, :5 `COPY go.mod go.sum ./`, :9 `COPY . .`, :11 `RUN go build -o main .`, :13 `EXPOSE 80 443`, :15 `CMD ["./main"]` (with a commented alternate CMD on :16). There is no second FROM, no USER, no HEALTHCHECK, no digest pin and no build flags anywhere in the file. Severity high stands: this is multi-factor — the production image is the builder itself (full Go toolchain, compiler and module cache reachable after any RCE), the process is uid 0 with no capability drop, and golang:1.19-alpine is EOL since Aug 2023 so the shipped runtime carries the same unpatched net/http and crypto/tls set govulncheck flags. The multi-stage + distroless nonroot fix is correct; the CAP_NET_BIND_SERVICE caveat for :80/:443 is the right accompanying note.

### No .dockerignore: the 312 MiB .git history and the private key are copied into the image

- **Dimension:** ops-build  
- **Location:** `Dockerfile:9`  
- **Effort:** trivial

**Evidence**

`ls .dockerignore` → "No such file or directory". `Dockerfile:9` is `COPY . .` with no exclusions, and the build context root contains `.git` (`git count-objects -vH` → "size-pack: 311.91 MiB"), `oryxBuildBinary` (11,250,895 bytes) and `assets/server/server.key`. README:63 instructs: "start by executing the ./main file to generate a config.json. Next, build the Docker image by running docker build -t baloo-proxy ." — i.e. generate the secrets file first, then `COPY . .` it in.

**Impact**

Every image layer contains the real `baloo.dog` private key, the full git history with 91 committed binaries, and — following the README literally — the freshly generated `config.json` with the admin/API/challenge secrets. `docker save | tar x` on any published image recovers all of it. Build context upload alone is ~325 MB per build.

**Fix**

Add a `.dockerignore` with `.git`, `.github`, `*.md`, `assets/server/`, `config.json`, `oryxBuildBinary`, `main`, `dist/`, `examples/`. Combine with the multi-stage build so only the compiled binary and the fingerprint JSON reach the final layer, and mount certs/config at runtime as volumes or secrets.

*Verifier:* Verified. `ls .dockerignore` → no such file; Dockerfile:9 is an unqualified `COPY . .`; and the context root demonstrably contains .git at 311.91 MiB (git count-objects -vH), oryxBuildBinary at 11,250,895 bytes, and assets/server/server.key (confirmed a real, modulus-matching ZeroSSL private key). README:63 does read "start by executing the ./main file to generate a config.json. Next, build the Docker image by running docker build -t baloo-proxy ." — so an operator following the documented order has the freshly written config.json (mode 0644, all secrets) sitting in the context when COPY runs. Severity high stands: a published image layer containing a live private key and the operator's admin/API/challenge secrets is recoverable by anyone with `docker save`. The .dockerignore + multi-stage fix is correct.

### Release workflow hands GITHUB_TOKEN to a third-party action pinned to a mutable @latest tag

- **Dimension:** ops-build  
- **Location:** `.github/workflows/release.yml:33-35`  
- **Effort:** small

**Evidence**

`.github/workflows/release.yml:33` `uses: marvinpinto/action-automatic-releases@latest` with `:35` `repo_token: "${{ secrets.GITHUB_TOKEN }}"`. The workflow has no top-level or job-level `permissions:` block (`.github/workflows/release.yml:8-13` jumps straight from `jobs:` to `runs-on`). `:18` still uses `actions/setup-go@v2`. Trigger is `:3-6` `on: push: branches: - "main"`.

**Impact**

`@latest` is a mutable ref: whoever controls that third-party repo can push new code that runs on every push to main with a token that has default (often write) permissions on contents, releases and packages — a one-step supply-chain takeover of the release channel for a security product. `actions/setup-go@v2` is a deprecated Node16 action that will stop running.

**Fix**

Pin every third-party action to a full commit SHA (`uses: marvinpinto/action-automatic-releases@<sha>`), or drop it for `softprops/action-gh-release` pinned by SHA / plain `gh release create`. Add explicit `permissions: contents: write` at job level (and `contents: read` at workflow level), and bump to `actions/setup-go@v5` with `go-version-file: go.mod`.

*Verifier:* Verified. .github/workflows/release.yml:33 is `uses: marvinpinto/action-automatic-releases@latest` and :35 passes `repo_token: "${{ secrets.GITHUB_TOKEN }}"`. `grep -n permissions .github/workflows/release.yml` exits rc=1 — there is no permissions block at workflow or job level; lines 8-13 go jobs: → pre-release: → name: → runs-on: → steps: exactly as described. :18 is `uses: actions/setup-go@v2` and the trigger at :3-6 is push to main. Severity high stands: `@latest` is a mutable git ref, so the third-party repo owner can execute arbitrary code on every push to main holding a token that must have contents/releases write (the job would otherwise fail to publish) — a one-step takeover of the release channel of a security product. Pinning to a full SHA plus explicit least-privilege permissions is the correct fix; setup-go@v5 with go-version-file: go.mod also resolves the version drift in go-1-19-toolchain-eol.

### `assets/server/server.key` is a genuine RSA private key for a real ZeroSSL certificate, not a dev cert

- **Dimension:** ops-build  
- **Location:** `assets/server/server.key:1`  
- **Effort:** small

**Evidence**

`head -3 assets/server/server.key` → "-----BEGIN RSA PRIVATE KEY-----\nMIIEow<key-body-withheld>...". `openssl rsa -in assets/server/server.key -noout -check` → "RSA key ok". `openssl x509 -in assets/server/server.crt -noout -subject -issuer -dates` → "subject=CN=baloo.dog / issuer=C=AT, O=ZeroSSL, CN=ZeroSSL RSA Domain Secure Site CA / notBefore=Dec 17 00:00:00 2022 GMT / notAfter=Mar 17 23:59:59 2023 GMT". Modulus MD5 of cert and key match exactly (`1c977d47666d329b468c416b27fc8333` both). Added in commit 1fcb542 "Cleaned Code, Added Caching, Added Install Helper".

**Impact**

This is a publicly-trusted CA-issued keypair for a real domain, published in a public repo — not a self-signed placeholder as the path `assets/server/` implies. The cert is expired so live impersonation is blocked by clients, but the private key remains valid for decrypting any archived TLS session recorded under an RSA key-exchange cipher and for signing anything else the key was reused for. Worse operationally: `examples/config.json:34-35`, `:72-73`, `:110-111` point every sample domain at `"certificate": "assets/server/server.crt", "key": "assets/server/server.key"`, so a copy-paste deployment serves production traffic with a world-known private key.

**Fix**

`git rm` both files, purge them from history in the same `git filter-repo` pass as the binaries, and treat the key as permanently compromised (notify upstream). Ship no keypair at all: have `config.Generate` mint a self-signed cert at first run, or document `openssl req -x509 -newkey ...`. Point `examples/config.json` at `/etc/lancarsec/tls/…` paths that do not exist in the repo.

*Verifier:* Verified in full. `head -3 assets/server/server.key` shows a BEGIN RSA PRIVATE KEY header; `openssl rsa -noout -check` returns "RSA key ok"; the cert is subject=CN=baloo.dog, issuer=C=AT, O=ZeroSSL, CN=ZeroSSL RSA Domain Secure Site CA, notBefore=Dec 17 2022, notAfter=Mar 17 2023; and the modulus MD5 of cert and key match at 1c977d47666d329b468c416b27fc8333 exactly as stated. examples/config.json:34-35, :72-73 and :110-111 do all point every sample domain at these two files (grep confirms exactly six references). Note this matters extra for the fork: CLAUDE.md describes assets/server/ as a 'dev self-signed cert+key', which is wrong. Severity lowered one level: the cert expired over three years ago so no live impersonation is possible, and the key belongs to the upstream author's domain, not to LancarSec — the residual risks (retrospective decryption of RSA-kex sessions captured in 2022-23, and copy-paste deployments serving a world-known key) are serious but not the immediate, exploitable-today exposure 'critical' implies. The fix is correct; add that upstream should be notified.

### Backend transport is capped at 10 connections with only 2 idle conns per host (the unset default), forcing constant re-dial

- **Dimension:** performance  
- **Location:** `core/server/serve.go:198-219`  
- **Effort:** small

**Evidence**

serve.go:198-210 —
var defaultTransport = &http.Transport{
	...
	IdleConnTimeout:     90 * time.Second,
	MaxIdleConns:        10,
	MaxConnsPerHost:     10,
}

`MaxIdleConnsPerHost` is never set, so net/http uses DefaultMaxIdleConnsPerHost = 2 ($GOROOT/src/net/http/transport.go:60). `getTripperForDomain` (serve.go:212-219) stores the *same* `defaultTransport` for every domain, so the per-domain sync.Map is pure per-request overhead with no benefit.

**Impact**

MaxConnsPerHost:10 is a hard concurrency cap on the backend: at 50k req/s each of the 10 connections would need to sustain 5,000 req/s, so in practice requests block in the transport's connection queue and latency explodes — this alone caps real throughput far below what the rest of the proxy could do. Worse, with only 2 idle connections retained, 8 of every 10 finished connections are closed and must be re-dialed (TCP handshake + TLS handshake at serve.go:206), producing tens of thousands of TIME_WAIT sockets per second and potential ephemeral-port exhaustion on the origin.

**Fix**

Set MaxIdleConns to several thousand, MaxIdleConnsPerHost equal to (or above) the expected concurrency, and either raise MaxConnsPerHost far above expected in-flight count or set it to 0 (unlimited); add ForceAttemptHTTP2 and larger Read/WriteBufferSize. Give each domain its own *http.Transport at config load and store the pointer in DomainSettings so the per-request sync.Map lookup in getTripperForDomain disappears.

*Verifier:* Verified. serve.go:198-210 sets IdleConnTimeout 90s, MaxIdleConns 10, MaxConnsPerHost 10 and never sets MaxIdleConnsPerHost; the local toolchain confirms net/http/transport.go:60 `const DefaultMaxIdleConnsPerHost = 2`, so at most 2 idle conns per host are retained. getTripperForDomain (serve.go:212-219) LoadOrStores the identical `defaultTransport` pointer for every domain, so the per-request sync.Map lookup buys nothing. MaxConnsPerHost bounds total (active+idle) connections per host, so 10 is a hard backend concurrency cap and 8 of every 10 completed connections must be re-dialled — both claimed consequences follow directly. Fix (raise the pool limits, per-domain transports stored in DomainSettings) is sound.

### CacheIps/CacheImgs are unbounded sync.Maps whose only eviction path is disabled precisely when under attack

- **Dimension:** performance  
- **Location:** `core/firewall/general.go:27-33; eviction core/server/monitor.go:552,564`  
- **Effort:** medium

**Evidence**

general.go:27-29 —
	//"cache" encryption result of ips for 2 minutes in order to have less load on the proxy
	CacheIps = sync.Map{}

monitor.go:552 —
	if (proxyCpuUsage < 15 && proxyMemUsage > 25) || proxyMemUsage > 95 {
		firewall.CacheIps.Range(func(key, value any) bool { firewall.CacheIps.Delete(key) ... })

**Impact**

The comment claims a 2-minute TTL; there is none. Entries are only dropped when CPU is under 15% — i.e. never during the DDoS this product exists to survive — until RAM hits 95%, at which point the whole cache is dumped and every subsequent request pays a full blake3 recompute. Each entry costs a ~700-byte key plus a 64-char value plus sync.Map entry overhead (~124 B/3 allocs measured for the store alone), so a unique-per-request attack adds roughly 1 KB × 50k/s = 50 MB/s of live heap. sync.Map is also the wrong structure here: it is optimised for read-mostly workloads, and a stream of misses (each miss does a Store of a brand-new key) forces repeated dirty-map promotions that copy the entire map — an O(n) stall that grows with the leak.

**Fix**

Replace with a bounded sharded LRU or a two-generation map rotated on a real timer (swap current→previous every 60 s, drop previous), capped at a configured max entries. Eviction must be independent of CPU/mem heuristics, and the rotation must never touch the global request lock.

*Verifier:* Verified. general.go:27-29 carries the '2 minutes' comment with no TTL mechanism anywhere; the only eviction is monitor.go:552-557 (CacheIps) and :564-569 (CacheImgs), both gated on `(proxyCpuUsage < 15 && proxyMemUsage > 25) || proxyMemUsage > 95`, i.e. disabled while the CPU is busy — precisely during an attack. Entries are stored per unique ip+tlsFp+ua+hour+susLv (middleware.go:204) plus a second entry keyed on encryptedIP (:196), so a unique-per-request flood grows the map without bound, and when the condition finally trips the whole cache is dumped at once. Note proxyMemUsage is Alloc/Sys (monitor.go:238), a heap-utilisation ratio rather than machine RAM, which makes the >95 escape hatch even less reliable than the finding assumes.

### Every bypassed request appends to an unbounded per-domain log slice while holding the global write lock

- **Dimension:** performance  
- **Location:** `core/utils/text.go:22-26 (caller core/server/middleware.go:306-320)`  
- **Effort:** small

**Evidence**

utils/text.go:22-26 —
func AddLogs(entry domains.DomainLog, domainName string) {
	domainData := domains.DomainsData[domainName]
	domainData.LastLogs = append(domainData.LastLogs, entry)
	domains.DomainsData[domainName] = domainData
}

Trimming only ever happens in utils.ReadLogs (text.go:42-51), which monitor.go:280 calls for `proxy.WatchedDomain` only, and only in the else-branch of printStats. Any domain that is not the currently watched one never trims.

**Impact**

DomainLog is 7 strings (112 B of headers plus the IP/UA/path payload). At 50k req/s that is 50k appends/s ≈ 5.6 MB/s of permanently retained headers plus the string bodies — several hundred MB per hour per unwatched domain, ending in OOM. Worse for latency: append's growth step reallocates and memmoves the whole slice *inside* `firewall.Mutex.Lock()`, so once the slice reaches 100 MB every doubling stalls every in-flight request for the duration of a 100 MB copy. The struct copy-in/copy-out on lines 23 and 25 also copies the whole DomainData value twice per request.

**Fix**

Replace with a fixed-size ring buffer of cap = proxy.MaxLogLength (or a small constant like 256) per domain, guarded by its own per-domain mutex, so append is O(1) with no reallocation and no global lock. Better still, make the terminal log a lossy channel with a non-blocking send that the Monitor goroutine drains, so the request path never touches a shared slice.

*Verifier:* Code verified verbatim: core/utils/text.go:22-26 appends to domainData.LastLogs with a full struct copy-in/copy-out, called at middleware.go:307-315 inside the Lock taken at :306. Trimming exists only in ReadLogs (text.go:42-51), reached only via printStats' final else-branch (monitor.go:280) and only for proxy.WatchedDomain, so every non-watched domain grows without bound; ClearLogs (text.go:68-73) is manual-command only. Severity lowered one level: the default single-domain deployment sets WatchedDomain = Domains[0] (config/init.go:233) and is therefore trimmed each second, so the unbounded case needs multiple domains or an unset/invalid WatchedDomain — real, but not universally reachable. The append-realloc-inside-the-global-lock cost is real regardless.

### ReverseProxy has no BufferPool, so every proxied response allocates a fresh 32 KiB copy buffer

- **Dimension:** performance  
- **Location:** `core/config/init.go:126-130 and core/server/monitor.go:467-471`  
- **Effort:** trivial

**Evidence**

config/init.go:126-130 —
		dProxy := httputil.NewSingleHostReverseProxy(&url.URL{
			Scheme: domain.Scheme,
			Host:   domain.Backend,
		})
		dProxy.Transport = &server.RoundTripper{}

No `dProxy.BufferPool` is ever assigned. In $GOROOT/src/net/http/httputil/reverseproxy.go:645-657, `copyResponse` uses `p.BufferPool` if set, otherwise falls through to `buf = make([]byte, 32*1024)`.

**Impact**

One 32 KiB heap allocation per successfully proxied response. At 50k req/s that is 1.6 GB/s of allocation — by far the largest single source of garbage in the whole proxy, enough to keep the GC running continuously and to dominate every other cost listed here. It is invisible in the proxy's own code, which is why it survives.

**Fix**

Assign a shared `BufferPool` backed by a sync.Pool of 32 KiB (or 16 KiB) byte slices to every ReverseProxy at construction in both config/init.go:130 and monitor.go:471. This is a five-line type implementing Get() []byte / Put([]byte).

*Verifier:* Verified. config/init.go:126-130 and monitor.go:467-471 construct the ReverseProxy and set only Transport; a repo-wide grep for `BufferPool` returns zero hits. The local toolchain confirms httputil/reverseproxy.go:645-647 uses p.BufferPool when non-nil and reverseproxy.go:657 otherwise does `buf = make([]byte, 32*1024)` per copyResponse, i.e. one 32 KiB allocation per proxied response. The five-line sync.Pool BufferPool fix is correct and must be applied in both construction sites.

### ReloadConfig is a 131-line divergent copy-paste of config.Load

- **Dimension:** quality-idiom  
- **Location:** `core/server/monitor.go:401-531`  
- **Effort:** medium

**Evidence**

monitor.go:400 carries the admission: '// This would ideally be in package config, however import cycles seem to not allow this.' Lines 412-447 and 449-528 are near-verbatim copies of init.go:38-100 and init.go:108-193 (same timeout blocks, same SetColor, same four Ratelimits lookups, same domain/firewall-rule/cert/DomainsMap construction). The copies have already drifted: ReloadConfig omits the five CHANGE_ME secret guards (init.go:41-63), omits the RatelimitWindow<10 clamp (init.go:92-95), and omits the Stage2Difficulty==0 default of 5 (init.go:167-169), so DomainData written at monitor.go:507 has no Stage2Difficulty field set at all.

**Impact**

After an operator runs the 'reload' command, every domain's Stage2Difficulty becomes 0. middleware.go:229 then computes publicSalt := encryptedIP[:len(encryptedIP)-0], i.e. the full string, and emits a stage-2 proof-of-work with difficulty 0 - the JS challenge becomes free to solve. Reload also skips secret validation, so a config edited to CHANGE_ME is accepted at runtime.

**Fix**

Extract the shared body into one exported function in package config (e.g. config.Apply(cfg *domains.Configuration) error) and have both Load and the reload command call it. Break the import cycle by moving the RoundTripper into its own package, or by having server register a reload callback with config rather than importing it.

*Verifier:* Verified line by line and the security consequence is real. monitor.go:400 carries the stated comment; ReloadConfig spans 401-531 (131 lines); 412-447 mirrors init.go:38-100 and 449-528 mirrors init.go:108-193. All three claimed omissions are confirmed: no CHANGE_ME guards (cf. init.go:41-63), no RatelimitWindow<10 clamp (cf. init.go:92-95 — ReloadConfig does not touch proxy.RatelimitWindow at all), and no Stage2Difficulty default (cf. init.go:167-169). Decisively, the domains.DomainData literal at monitor.go:507-526 has no Stage2Difficulty field whatsoever, so after any reload every domain's value is the zero value. middleware.go:229 then computes `publicSalt := encryptedIP[:len(encryptedIP)-0]`, i.e. the whole token, and middleware.go:232 hands BalooPow a literal difficulty of "0". The stage-2 proof-of-work costs nothing: the full cookie value is printed in the challenge page and any script can set it. ReloadConfig is reachable from the 'reload' command (monitor.go:379) and also from 'add' (monitor.go:356), so a routine operator action silently disarms stage 2 until the next full restart. High is correct.

### Zero test files in the repository; five functions need coverage before any refactor

- **Dimension:** quality-idiom  
- **Location:** `core/server/middleware.go:30`  
- **Effort:** large

**Evidence**

$ find . -name '*_test.go' => 0 results. $ go test ./... reports '[no test files]' for all nine packages and 'FAIL goProxy/core/firewall [build failed]'. go.sum lists github.com/stretchr/testify v1.8.1 as an indirect dependency, so a test framework is already available but unused.

**Impact**

Every finding above is a silent regression risk: the Stage2Difficulty divergence between the two AddDomain copies, the [:1]/[1:] fingerprint slip, and the '-' branch Println bug are all exactly the class of defect a single table test would have caught. Refactoring a 335-line Middleware with no safety net is how a mitigation proxy starts failing open.

**Fix**

Highest-value five: (1) firewall.EvalFirewallRule (eval.go:10) - it decides block/allow, already has the vet bug at line 30, and panics on an empty rule.Action via rule.Action[:1] at line 15; table-test +/-/absolute actions and malformed input. (2) server.Middleware (middleware.go:30) - the entire security decision path; use httptest to assert each stage's status, Set-Cookie, and rate-limit branch. (3) firewall.Fingerprint (fingerprint.go:52) - feed synthetic tls.ClientHelloInfo values and pin expected strings so the GREASE rule is locked down. (4) evaluateRatelimit (monitor.go:576) - the sliding-window bucket create/expire/sum arithmetic that every rate-limit decision reads. (5) utils.Encrypt/EncryptSha (encryption.go:19,24) - the challenge-token derivation; assert that Encrypt(a+b, k) differs from Encrypt(a, b+k), which the current 'input + key' concatenation does not guarantee. Add utils.InitPlaceholders (discord.go:16-19) as a sixth: it indexes RequestLogger[0] and [len-1] with no empty-slice guard.

*Verifier:* Verified. `find . -name '*_test.go'` returns nothing and `git ls-files` tracks no test file anywhere. My `go test ./...` run reports '[no test files]' for all nine tracked packages (goProxy, core/api, core/config, core/domains, core/pnc, core/proxy, core/server, core/utils) plus 'FAIL goProxy/core/firewall [build failed]', matching the finding exactly. go.mod does carry github.com/stretchr/testify v1.8.1 as an indirect dependency. I also checked each of the six targets the fix nominates and every one is correctly located and correctly characterised: firewall.EvalFirewallRule at eval.go:10 with the vet bug at :30 and the genuine empty-Action panic at :15 (""[:1] is a slice-bounds panic, and nothing validates Action at config-load time); server.Middleware at middleware.go:30; firewall.Fingerprint at fingerprint.go:52; evaluateRatelimit at monitor.go:576; utils.Encrypt/EncryptSha at encryption.go:19/24 — and the ambiguity claim is right, since both hash `input + key`, so Encrypt("ab","c") == Encrypt("a","bc"); utils.InitPlaceholders at discord.go:16-19 does index RequestLogger[0] and [len-1] with no empty-slice guard. High is justified for a security product where three separate findings in this same audit (the Stage2Difficulty divergence, the [:1]/[1:] slip, the '-' branch Println) are precisely what a table test would have caught.

### panic() used for ordinary, recoverable error handling at 22 sites, including the runtime reload path

- **Dimension:** quality-idiom  
- **Location:** `core/server/monitor.go:407`  
- **Effort:** medium

**Evidence**

22 panic() call sites across the tree. The runtime-triggered ones are the worst: monitor.go:407 panics if config.json cannot be opened during 'reload'; monitor.go:458 panics on a bad firewall-rule expression; monitor.go:478 panics on a bad cert path. These run inside commands() (monitor.go:286), a goroutine started at monitor.go:51, whose only recover is 'defer pnc.PanicHndl()' at monitor.go:288 - and PanicHndl re-panics at panicHandler.go:30. serve.go:51,108,113 likewise panic on ListenAndServe returning, and utils/text.go:162 JsonEscape panics on a json.Marshal error.

**Impact**

An operator typo in config.json plus the 'reload' command terminates the whole DDoS-mitigation proxy: PanicHndl writes crash.log then re-panics, killing the process and dropping every domain it fronts. For a product whose job is staying up under attack, config validation errors must never be fatal.

**Fix**

Convert these to error returns. ReloadConfig should validate into a fresh Configuration and swap it in only on success, printing the error to the TUI and keeping the running config on failure. Reserve panic for genuinely unrecoverable programmer errors.

*Verifier:* Verified. My grep finds 24 panic() call sites, not 22 — the count is off by two — but every location the finding actually cites is correct: monitor.go:407 (config open during reload), monitor.go:458 (bad firewall-rule expression), monitor.go:478 (bad cert path), serve.go:51/108/113 (ListenAndServe), utils/text.go:162 (JsonEscape). The termination chain is exactly as described and I traced all of it: `go commands()` at monitor.go:51 -> commands() at monitor.go:286 with only `defer pnc.PanicHndl()` at monitor.go:288 -> PanicHndl at panicHandler.go:23 recovers, writes crash.log, then re-panics at panicHandler.go:30. An unrecovered panic in a goroutine kills the process. So an operator typo in config.json plus 'reload' genuinely takes down the whole proxy and every domain it fronts. I also found an unclaimed instance of the same class: monitor.go:530 `proxy.WatchedDomain = domains.Domains[0]` panics with index-out-of-range if the reloaded config has zero domains. High stands for a product whose value proposition is staying up.

### All five proxy secrets are generated with unseeded math/rand under the pinned Go 1.19 toolchain, making them identical on every install

- **Dimension:** security-authz  
- **Location:** `core/utils/encryption.go:30-38`  
- **Effort:** trivial

**Evidence**

func RandomString(length int) string {
	var rnd = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	res := make([]rune, length)
	for i := range res {
		res[i] = rnd[rand.Intn(len(rnd))]
	}
	return string(res)
}

Import is `"math/rand"` (core/utils/encryption.go:6). `grep -rn "rand.Seed\|crypto/rand" --include=*.go .` returns nothing — the global source is never seeded. Consumers (core/config/generate.go:23-34):
			AdminSecret: utils.RandomString(25),
			APISecret:   utils.RandomString(30),
...
			Secrets: map[string]string{
				"cookie":     utils.RandomString(20),
				"javascript": utils.RandomString(20),
				"captcha":    utils.RandomString(20),
The shipped build pins the toolchain where math/rand's global source is seeded with the constant 1: Dockerfile:1 `FROM golang:1.19-alpine`, go.mod:3 `go 1.19`.

**Impact**

Under Go 1.19 (the pinned toolchain and the only one the Dockerfile builds with), the top-level math/rand functions run off a source seeded with 1 unless rand.Seed is called, which it never is. Generate() is the first thing that consumes randomness in the process, so every operator who runs the first-launch wizard gets the identical adminsecret, apisecret, cookie, javascript, and captcha secrets. An attacker runs `docker build . && ./main` once locally, answers the wizard, and reads config.json — he now holds the admin secret and API secret for every default install, plus the three challenge secrets, which lets him compute utils.Encrypt(ip+tlsFp+ua+hour, EncryptSha(secret, date)) offline and forge a valid stage-1/2/3 cookie for any client, on any domain, without ever solving a challenge. I verified with go1.25.4 that a modern toolchain does auto-seed (output differed across runs), so the determinism is toolchain-specific — but math/rand remains a non-cryptographic generator whose internal state is recoverable from a handful of outputs, which is unfit for an admin credential regardless of seeding.

**Fix**

Replace RandomString with crypto/rand: read n bytes via crypto/rand.Read and hex/base64-encode them, or use the rejection-sampling form over the alphabet. This function is the only randomness source for every secret in the product; math/rand must not appear in that path at all. Also bump the go directive off 1.19 so no build ever lands on the constant-seed semantics.

*Verifier:* Code verified: core/utils/encryption.go:6 imports math/rand, :30-38 is RandomString, no rand.Seed or crypto/rand anywhere in the repo, and generate.go:23-33 uses it for AdminSecret/APISecret/cookie/javascript/captcha. Dockerfile:1 is `FROM golang:1.19-alpine` and go.mod:3 is `go 1.19`, so the shipped Docker artifact does get the constant seed 1 and identical secrets on every install (AskBool/AskInt consume no randomness, so the rand call order is fixed). I empirically tested the modern-toolchain caveat the finding raises: a module with `go 1.19` in go.mod built by the local go1.25.4 still auto-seeds (three runs gave three different 25-char strings), so the GODEBUG go-directive defaulting does NOT restore randautoseed=0. Downgraded one level: the catastrophic 'identical on every install' outcome exists only on the Go 1.19 build path this fork is explicitly abandoning (task item 4), and the secondary argument (math/rand state recoverable from outputs) does not apply because these outputs are never published.

### Challenge token is not bound to the domain or path, so stage-2/3 tokens can be pre-minted on an idle endpoint and replayed during the flood

- **Dimension:** security-authz  
- **Location:** `core/server/middleware.go:184-198`  
- **Effort:** medium

**Evidence**

accessKey := ip + tlsFp + reqUa + proxy.CurrHourStr
encryptedCache, encryptedExists := firewall.CacheIps.Load(accessKey + susLvStr)
...
		case 2:
			encryptedIP = utils.Encrypt(accessKey, proxy.JSOTP)
...
		case 3:
			encryptedIP = utils.Encrypt(accessKey, proxy.CaptchaOTP)

The domain name is absent from accessKey, and proxy.JSOTP / proxy.CaptchaOTP are process-global, not per-domain (core/proxy/proxy.go:25-33, set once in core/server/monitor.go:653-655). The shipped example config forces stage 3 on a fixed path for every domain: examples/config.json `{"expression": "(http.path eq \"/captcha\")", "action": "3"}` and `{"expression": "(http.path eq \"/js\")", "action": "2"}`.

**Impact**

Step 1: while the target is calm (stage 1, no attack), the attacker requests https://target/captcha from each of his bot IPs with a fixed User-Agent. The firewall rule forces susLv=3, so the proxy mints and serves a stage-3 captcha for that exact (ip, fp, ua, hour) tuple. Step 2: he solves it once per bot (see finding captcha-answer-recoverable — the answer is machine-readable). Step 3: he now holds a valid `_3__bProxy_v` cookie. Step 4: he starts the flood against `/`. The proxy escalates to stage 3, but every bot already presents the exact token stage 3 demands, so `strings.Contains(cookie, "__bProxy_v="+encryptedIP)` (middleware.go:214) passes and every request is proxied to the backend. The proxy's stage escalation — its entire defense — is a no-op against an attacker who spent one cheap request per bot beforehand. Because the domain is not in accessKey, the same holds across tenants: a token minted on a low-value domain on the same proxy is valid on the domain under attack.

**Fix**

Include the domain name and the stage in the hashed input, not just in the cache key: accessKey = strings.Join([]string{domainName, ip, tlsFp, reqUa, susLvStr, timeBucket}, "\x00"). Use per-domain OTP secrets derived with HKDF from the global secret and the domain name. Additionally, mint the escalated token only when the domain is actually at that stage, so an idle-path rule cannot be used as a token vending machine.

*Verifier:* Verified. accessKey at middleware.go:184 is `ip + tlsFp + reqUa + proxy.CurrHourStr` — no domain, no path, no stage. JSOTP/CaptchaOTP are process-global (core/proxy/proxy.go:25-33, assigned once in monitor.go:653-655), so a token minted on domain A is byte-identical on domain B. examples/config.json does ship `(http.path eq "/captcha") -> 3` and `(http.path eq "/js") -> 2` on every domain, and EvalFirewallRule (core/firewall/eval.go:35-44) treats a bare "3" as a hard set-and-return, so the idle path really is a token vending machine. Downgraded one level: the pre-minting chain is contingent on the operator shipping such a static-stage rule (or on a second domain already sitting at stage 3), and tokens still expire hourly via CurrHourStr, so the bot fleet must re-mint each hour. Cross-domain token portability is unconditional and is the solid half of this finding.

### Challenge-failure and request ratelimits read a snapshot refreshed every 5 s, giving an unbounded burst window for challenge brute force

- **Dimension:** security-authz  
- **Location:** `core/server/monitor.go:596-634`  
- **Effort:** medium

**Evidence**

		// Delete outdated records & calculate requests for every ip
		firewall.AccessIps = map[string]int{}
		for windowTime, accessIPs := range firewall.WindowAccessIps {
...
		firewall.AccessIpsCookie = map[string]int{}
...
		firewall.Mutex.Unlock()
		proxy.Initialised = true
...
		time.Sleep(5 * time.Second)
The hot path reads only the derived snapshot, never the live window (core/server/middleware.go:69-70 and :79-80):
		ipCount = firewall.AccessIps[ip]
		ipCountCookie = firewall.AccessIpsCookie[ip]
and decides on it at middleware.go:108 `if ipCountCookie > proxy.FailChallengeRatelimit` and :115 `if ipCount > proxy.IPRatelimit`. Requests are written to WindowAccessIps (middleware.go:96) and WindowAccessIpsCookie (middleware.go:217) but those writes are invisible to the decision for up to 5 s.

**Impact**

The configured `challengeFailures: 40` limit does not bound anything within a 5-second window — a single IP can submit an unlimited number of wrong challenge answers, and the counter only catches up on the next sweep. Paired with /_bProxy/verified (core/server/middleware.go:333-336), which returns the literal string "verified" only when the cookie check at line 214 passed and never touches the backend, the attacker has a free, cheap, backend-free oracle for testing candidate tokens at line rate. The same 5 s blindness applies to the main `requests` ratelimit: an attacker gets a full 5 s of unmetered flood per IP before R2 engages, which for a DDoS mitigation product is the entire point of the control. In Cloudflare mode, where the IP is spoofable per request, the window never engages at all.

**Fix**

Have the hot path sum the live sliding-window buckets (WindowAccessIps / WindowAccessIpsCookie for the timestamps inside the ratelimit window) rather than a periodically rebuilt snapshot, and use atomic counters so the read is lock-free. Keep the sweeper only for evicting expired buckets.

*Verifier:* Verified at the cited lines. monitor.go:596-634 rebuilds AccessIps/AccessIpsCookie/UnkFps from scratch each pass and then sleeps 5 s at :634, while the hot path reads only those snapshots (middleware.go:69-70, 79-80) and decides on them at :108 and :115. Writes go to WindowAccessIps (:96) and WindowAccessIpsCookie (:217) and are invisible until the next sweep. For a DDoS-mitigation product this is the core control being blind for up to 5 s per IP, and in CF mode the spoofable key means it never engages at all. High stands. One caveat on the impact text: /_bProxy/verified (:333-336) is a real pass/fail oracle, but brute-forcing a 256-bit blake3 token through it is not feasible, so the oracle argument adds nothing — the unmetered burst window is the finding.

### Config validation only rejects the literal "CHANGE_ME": empty or missing secrets yield an unauthenticated admin API and attacker-computable challenge tokens

- **Dimension:** security-authz  
- **Location:** `core/config/init.go:40-63`  
- **Effort:** trivial

**Evidence**

	proxy.CookieSecret = domains.Config.Proxy.Secrets["cookie"]
	if strings.Contains(proxy.CookieSecret, "CHANGE_ME") {
		panic(...)
	}
...
	proxy.APISecret = domains.Config.Proxy.APISecret
	if strings.Contains(proxy.APISecret, "CHANGE_ME") {
		panic("[ " + utils.PrimaryColor("!") + " ] [ API Secret Contains 'CHANGE_ME'. Refusing To Load ]")
	}
There is no length or emptiness check. `strings.Contains("", "CHANGE_ME")` is false, so an absent JSON key (which decodes to "") passes validation. The authentication comparisons are then core/api/api.go:17 `if request.Header.Get("proxy-secret") != proxy.APISecret` and api.go:155 `if r.Header.Get("Proxy-Secret") != proxy.APISecret`.

**Impact**

Two separate total compromises from one omitted config key. (1) Omit `apisecret` (or set it to ""): a request that carries no Proxy-Secret header makes Header.Get return "", so `"" != ""` is false and the guard passes. Every admin action is then open to anyone on the internet — `curl https://target/_bProxy/api/v2/GET_IP_CACHE` dumps all challenge tokens, `curl https://target/_bProxy/api/v2/FILL_IP_CACHE` stalls the proxy. (2) Omit `secrets.cookie` / `javascript` / `captcha`: proxy.CookieOTP becomes EncryptSha("", "2026-08-30") = sha256 of the current date alone (core/server/monitor.go:653-655), which any attacker computes. Combined with accessKey = ip+tlsFp+ua+hour, where in Cloudflare mode tlsFp is the literal string "Cloudflare" and the other three are attacker-chosen, he forges a valid cookie for any IP at any stage with no network interaction. Hand-written configs routinely omit keys, and the operator gets no warning — the proxy boots and reports itself healthy.

**Fix**

Validate each secret positively at load: reject empty, reject shorter than ~16 chars, reject the CHANGE_ME placeholder, and reject a missing `secrets` map entirely. Panic with a message naming the specific key. Do the same for adminsecret.

*Verifier:* Verified at core/config/init.go:40-63: five `strings.Contains(..., "CHANGE_ME")` panics and nothing else — no emptiness, length, or key-presence check. `strings.Contains("", "CHANGE_ME")` is false, so a missing JSON key decodes to "" and sails through. The auth comparisons at api.go:17 and api.go:155 are plain `!=` against proxy.APISecret, so an empty APISecret makes a request with no Proxy-Secret header authenticate ("" != "" is false). CookieOTP/JSOTP/CaptchaOTP would become EncryptSha("", date) (monitor.go:653-655), computable by anyone. Downgraded one level: this requires an operator to hand-write a config that omits keys — the shipped generator (generate.go:23-33) always populates all five, and the shipped examples/config.json carries CHANGE_ME placeholders that correctly panic. It is a missing-validation hardening gap, not a default-configuration compromise.

### GET_IP_CACHE returns every live challenge token for every client on the proxy

- **Dimension:** security-authz  
- **Location:** `core/api/api.go:91-100`  
- **Effort:** trivial

**Evidence**

	case "GET_IP_CACHE":
		cacheIps := make(map[string]interface{})
		firewall.CacheIps.Range(func(key, value any) bool {
			cacheIps[fmt.Sprint(key)] = value
			return true
		})

		APIResponse(writer, true, map[string]interface{}{
			"IP_CACHE": cacheIps,
		})
CacheIps holds exactly the challenge material — core/server/middleware.go:196 `firewall.CacheIps.Store(encryptedIP, hashedEncryptedIP)` and middleware.go:204 `firewall.CacheIps.Store(accessKey+susLvStr, encryptedIP)`, where accessKey is `ip + tlsFp + reqUa + proxy.CurrHourStr` (middleware.go:184).

**Impact**

This is the answer to "what can an attacker who guesses the API secret do". One request — `curl -H 'Proxy-Secret: <secret>' https://target/_bProxy/api/v2/GET_IP_CACHE` — returns a map whose keys are `<clientIP><tlsFingerprint><userAgent><hour><stage>` and whose values are the verified tokens those clients are currently presenting. The attacker instantly (a) obtains a valid stage-3 cookie for every IP in the cache, so his botnet replays real users' tokens and sails past every challenge tier, and (b) harvests a full roster of the site's active visitors with their IP, TLS fingerprint, and User-Agent. There is no need to solve a single challenge, and no rotation until the top of the hour. The same endpoint is reachable via v2 with only the header secret (core/api/api.go:155) — the admin path secret is not required.

**Fix**

Delete GET_IP_CACHE, or at minimum have it return only counts and never the token values. Nothing operational needs the plaintext tokens. While you are there, GET_IP_REQUESTS (api.go:72-81) similarly dumps every client IP with its request count.

*Verifier:* Verified at api.go:91-100. CacheIps genuinely holds token material: middleware.go:204 stores accessKey+susLvStr -> encryptedIP and :196 stores encryptedIP -> hashedEncryptedIP, with accessKey = ip+tlsFp+reqUa+hour (:184). Both key and value are dumped verbatim by fmt.Sprint over Range. ProcessV2 (api.go:153-157, routed at middleware.go:350-355) does reach handleProxyActions with only the Proxy-Secret header, so the admin path secret is not needed. GET_IP_REQUESTS at api.go:72-81 does dump AccessIps/AccessIpsCookie as claimed. Downgraded one level: this is gated behind the highest-privilege credential in the product, and reaching it also requires passing the current challenge tier (the reserved-path switch is at :324, after the :214 cookie gate). The genuine escalation is that an API-secret holder who does NOT hold config.json can impersonate every live visitor — real, but not unauthenticated on its own.

### Stage-3 captcha answer is fully recoverable from the two images the server ships to the client

- **Dimension:** security-authz  
- **Location:** `core/server/middleware.go:235-296 (DrawTriangle is core/utils/image.go:44-56, not 87-98; basicfont.Face7x13 is image.go:18, not :61)`  
- **Effort:** large

**Evidence**

			secretPart := encryptedIP[:6]
			publicPart := encryptedIP[6:]
...
				utils.AddLabel(captchaImg, 0, 18, publicPart[6:], color.RGBA{61, 140, 64, 20})
				utils.AddLabel(captchaImg, rand.Intn(90), rand.Intn(30), publicPart[:6], color.RGBA{255, randomColor, randomColor, 100})
				utils.AddLabel(captchaImg, rand.Intn(25), rand.Intn(20)+10, secretPart, color.RGBA{61, 140, 64, 255})
...
				amplitude := float64(rand.Intn(10)+10) / 10.0
Both images go to the client (middleware.go:296): `captcha_image.src="data:image/png;base64,`+captchaData+`"` and `mask_image.src="data:image/png;base64,`+maskData+`"`. The mask is not an overlay — DrawTriangle moves the pixels out of the captcha and into the mask (core/utils/image.go:87-98): `dst.Set(x+i+shift, y+j, src.At(x+i, y+j))` followed by `src.Set(x+i, y+j, color.RGBA{0, 0, 0, 0})`. The glyphs are a fixed 7x13 bitmap font (core/utils/image.go:61 `Face: basicfont.Face7x13`).

**Impact**

Every pixel of the answer is present in captcha ∪ mask, so nothing is actually hidden. A solver: (1) base64-decode both PNGs from the HTML; (2) shift the mask back by the slider offset and composite; (3) keep only pixels whose RGBA is exactly (61,140,64,255) — the two decoys are distinguishable by construction, one is alpha 20 (invisible) and the other is red-tinted at alpha 100, so this isolates the answer with zero ambiguity; (4) undo the sinusoidal warp, whose amplitude is at most 1.9 px; (5) template-match against the 16 glyph bitmaps of basicfont.Face7x13, since the answer is 6 hex characters from a blake3 hex digest. That is roughly 50 lines of Python and ~100% accuracy — no ML, no OCR service. Stage 3 is the proxy's last line of defense and it costs an attacker microseconds per bot. The image is also cached (middleware.go:287), so the CPU cost of generating it falls on the proxy while the solve cost falls on nobody.

**Fix**

Stop shipping the removed pixels to the client — the mask must be additive noise generated independently of the answer, never a carrier for the answer's own pixels. Render the answer with randomized per-glyph color, rotation, and scale so no exact-color filter isolates it, and use a variable font rather than one fixed 7x13 bitmap face. Better: replace this with a proof-of-work or an external captcha provider; a hand-rolled 6-hex-char bitmap captcha cannot be made robust.

*Verifier:* Substance verified, citations partly fabricated. middleware.go:235-296 is correct: secretPart = encryptedIP[:6] drawn at exactly color.RGBA{61,140,64,255} (:248), decoys at alpha 20 (:246) and R=255 red-tinted alpha 100 (:247) so an exact-color filter isolates the answer unambiguously; both PNGs are shipped as data: URIs (:296); warp amplitude is at most 1.9 px (:250). DrawTriangle does move pixels out of the captcha into the mask and clear the source — but it is at core/utils/image.go:44-56, NOT image.go:87-98, and `Face: basicfont.Face7x13` is image.go:18, NOT image.go:61; that file is only 56 lines long, so both supporting line cites are invented. WarpImg (image.go:24-42) samples nearest-neighbour, preserving the exact RGBA values the filter keys on, which if anything strengthens the claim. Severity high stands: this is not the generic 'captchas are weak' argument but a concrete design break — the mask is a carrier for the answer's own pixels.

### `reload` command resets Stage2Difficulty to 0, making the stage-2 challenge page print the exact cookie value it demands

- **Dimension:** security-authz  
- **Location:** `core/server/monitor.go:507-527`  
- **Effort:** trivial

**Evidence**

ReloadConfig builds DomainData without the field:
		domains.DomainsData[domain.Name] = domains.DomainData{
			Name:             domain.Name,
			Stage:            1,
			StageManuallySet: false,
			RawAttack:        false,
			BypassAttack:     false,
			LastLogs:         []domains.DomainLog{},
...
(no Stage2Difficulty). `grep -rn Stage2Difficulty` shows it is assigned only at core/config/init.go:175. The consumer is core/server/middleware.go:229:
			publicSalt := encryptedIP[:len(encryptedIP)-domainData.Stage2Difficulty]
and the page then emits it verbatim (middleware.go:232): `<div class=placeholder id=publicSalt ...><span>`+publicSalt+`</span>` and `document.cookie="_2__bProxy_v=`+publicSalt+`"+e.solution`.

**Impact**

Any operator who types `reload` in the TUI (the documented way to apply a config change without downtime) silently disables stage 2 for every domain until the process is restarted. With Stage2Difficulty=0, publicSalt = encryptedIP[:64-0] = the complete 64-hex-char token. The challenge page hands the attacker the full answer in the HTML body. Attack: `curl -s https://target/ | grep -o 'id=publicSalt[^<]*<span>[0-9a-f]\{64\}'`, extract the token T, then replay every subsequent request with `Cookie: _2__bProxy_v=T`. Cost: one request. Stage 2 — the proof-of-work tier the proxy escalates to at 75 bypassing rps — provides zero protection, and the operator sees stage 2 active in the TUI with no indication that it is inert.

**Fix**

Copy the whole surviving DomainData rather than rebuilding a fresh literal in ReloadConfig, or at minimum add `Stage2Difficulty: domain.Stage2Difficulty` with the same `if == 0 { = 5 }` default that core/config/init.go:167-169 applies. Separately, hard-fail in middleware if Stage2Difficulty < 1 instead of emitting a full-token salt, and clamp it to a sane range (1..len(encryptedIP)-1) — a negative or >64 value currently panics on the slice at middleware.go:229.

*Verifier:* Verified exactly at the cited lines. monitor.go:507-527 rebuilds the DomainData literal with no Stage2Difficulty field (zero value 0), while core/config/init.go:167-175 applies the `if == 0 { = 5 }` default only on first load. `grep -rn Stage2Difficulty` confirms init.go:175 is the sole assignment. ReloadConfig is invoked from the TUI `reload` command (monitor.go:375-379) and from `add` (monitor.go:356). With 0, middleware.go:229 yields publicSalt = encryptedIP[:64] = the whole blake3 hex token (utils.Encrypt returns hex.EncodeToString of a 32-byte blake3 sum), which is printed verbatim in the page body and satisfies the `strings.Contains(cookie, "__bProxy_v="+encryptedIP)` check at :214. Downgraded one level: the token leaked is bound to that same (ip, fp, ua, hour) client, so this removes the PoW cost rather than leaking a cross-client credential, and PoW at difficulty 5 is only ~5e5 hashes to begin with.

### AdminSecret is embedded in the request URL path, leaking through access logs, Referer, and any upstream cache

- **Dimension:** security-crypto  
- **Location:** `core/server/middleware.go:337 (logged at :307-314, rendered at core/utils/text.go:28-33)`  
- **Effort:** small

**Evidence**

core/server/middleware.go:337 `case "/_bProxy/" + proxy.AdminSecret + "/api/v1":` — the switch is over `request.URL.Path` (line 324 `switch request.URL.Path {`).
The same request is also logged verbatim: core/server/middleware.go:307-315 `utils.AddLogs(domains.DomainLog{ … Path: request.RequestURI, }, domainName)`, rendered to the terminal by core/utils/text.go:30-32.

**Impact**

The long-lived admin credential travels in the URL. It is written into the proxy's own log ring (visible to anyone with GET_LOGS on the API or shoulder-access to the TUI), into Cloudflare's HTTP logs when deployed in the documented Cloudflare mode, into any browser history/Referer header when an admin clicks a link from that page, and into CDN/intermediary caches. One leaked log line is a permanent admin compromise, and the secret is static (never rotated).

**Fix**

Move the admin credential to a header, exactly as the v1 API already does for APISecret (`request.Header.Get("proxy-secret")`), and serve the admin API on a fixed path such as `/_bProxy/api/v1`. Compare with crypto/subtle.ConstantTimeCompare. Add an explicit no-store/no-referrer response header on the admin route.

*Verifier:* Verified verbatim. core/server/middleware.go:326 switches on request.URL.Path and :337 is `case "/_bProxy/" + proxy.AdminSecret + "/api/v1":`. The same request is logged with Path: request.RequestURI at middleware.go:307-314 (AddLogs, utils/text.go:21-25) and rendered to the TUI by utils.FormatLogs at text.go:28-33, so the secret lands in the in-process log ring that GET_LOGS and the terminal both expose. In the documented Cloudflare mode (serve.go:35-52) it also transits Cloudflare's logs. The secret is static and there is no rotation path (ReloadConfig never re-reads AdminSecret). High is fair.

### In Cloudflare mode every input the token binds to is attacker-supplied, making solved challenges portable across a botnet

- **Dimension:** security-crypto  
- **Location:** `core/server/middleware.go:59-71 and :184 (ratelimit keys at :96, :217; listener at core/server/serve.go:37-43)`  
- **Effort:** medium

**Evidence**

core/server/middleware.go:59-66 `if domains.Config.Proxy.Cloudflare { ip = request.Header.Get("Cf-Connecting-Ip"); tlsFp = "Cloudflare"; browser = "Cloudflare"; botFp = ""; fpCount = 0` — the header is read with no check that the socket peer is actually a Cloudflare address, and the TLS fingerprint is a constant.
core/server/middleware.go:184 `accessKey := ip + tlsFp + reqUa + proxy.CurrHourStr` — so the binding reduces to (attacker-chosen header, constant, attacker-chosen UA, current hour).
The same `ip` is the ratelimit key: core/server/middleware.go:96 `firewall.WindowAccessIps[proxy.Last10SecondTimestamp][ip]++` and :217 for the challenge-failure counter.

**Impact**

Any host that can reach the origin directly (the deployment listens on :80 for the whole internet in this mode — core/server/serve.go:37-43) forges `Cf-Connecting-Ip`. One node solves the JS or captcha challenge once; because the token is a pure function of the spoofed IP, the fixed UA string and the hour, every other node in the botnet replays the same cookie for the rest of the hour without solving anything. Rotating the forged header additionally resets the per-IP ratelimit and the challenge-failure counter at will, so the R1/R2 thresholds never trigger.

**Fix**

Only honour Cf-Connecting-Ip / X-Forwarded-For when the socket peer (request.RemoteAddr) is inside Cloudflare's published CIDR list, bundled locally and refreshed out of band; otherwise fall back to RemoteAddr. Add an opt-in mode that rejects non-Cloudflare peers outright. Bind the token to something the client cannot choose (peer address, plus the domain name) rather than to headers.

*Verifier:* Verified line by line. middleware.go:59-71 takes ip straight from the Cf-Connecting-Ip header with no peer check, hard-codes tlsFp/browser to "Cloudflare" and fpCount to 0; there is no CIDR check anywhere in the repo. middleware.go:184 therefore reduces accessKey to (spoofable header, constant, spoofable UA, hour), and OTPs rotate only daily (monitor.go:651-655), so one solved token is replayable across a botnet for the rest of the hour. The same spoofable ip is the ratelimit key at :96 and the challenge-failure key at :217, and the rate lookups at :69-70 read those maps, so rotating the header resets R1 and R2. serve.go:35-52 confirms Cloudflare mode listens on :80 for the whole internet with no origin enforcement. High is correct.

### Secret validation only rejects the literal "CHANGE_ME"; a missing or empty apisecret/adminsecret silently disables authentication

- **Dimension:** security-crypto  
- **Location:** `core/config/init.go:40-63, core/api/api.go:17, core/api/api.go:155, core/server/middleware.go:337`  
- **Effort:** trivial

**Evidence**

core/config/init.go:60-63 `proxy.APISecret = domains.Config.Proxy.APISecret` / `if strings.Contains(proxy.APISecret, "CHANGE_ME") { panic(...) }` — an absent JSON key leaves the string "", which does not contain "CHANGE_ME" and passes. Same pattern for AdminSecret (:55-58), CookieSecret (:40-43), JSSecret (:45-48), CaptchaSecret (:50-53).
core/api/api.go:17 `if request.Header.Get("proxy-secret") != proxy.APISecret { return false }` — `Header.Get` on an absent header returns "", so "" != "" is false and the check passes.
core/api/api.go:155 has the identical check for the v2 API.
core/server/middleware.go:337 `case "/_bProxy/" + proxy.AdminSecret + "/api/v1":` becomes the literal path `/_bProxy//api/v1` when AdminSecret is "".

**Impact**

An operator who hand-writes config.json (or copies a partial one) and omits `apisecret` gets a proxy whose admin API authenticates every anonymous request: `POST /_bProxy//api/v1` with no headers reaches api.Process and can dump the IP cache, read firewall rules and logs, and drive handleProxyActions. An empty `secrets.cookie` likewise makes the challenge OTP sha256(""||date) — a value any attacker can compute.

**Fix**

In config.Load (and in ReloadConfig), reject each secret unless it is non-empty and of a minimum length: `if len(proxy.APISecret) < 16 { panic(...) }`, plus the existing CHANGE_ME check. Also require a non-empty header before comparing in api.Process/ProcessV2, so a misconfiguration fails closed.

*Verifier:* Verified. core/config/init.go:40-63 contains only strings.Contains(x,"CHANGE_ME") panics for cookie/js/captcha/admin/api — an absent JSON key leaves "" and passes all five. core/api/api.go:17 `request.Header.Get("proxy-secret") != proxy.APISecret` and core/api/api.go:155 `r.Header.Get("Proxy-Secret") != proxy.APISecret` both compare "" to "" and fall through when the header is absent. middleware.go:337 collapses to the literal path "/_bProxy//api/v1", which net/http hands to the handler uncleaned (the Handler is set directly at serve.go:48/:103, no ServeMux). Only caveat, which does not change the verdict: reaching :337 still requires passing the stage-1/2 cookie check at :214 first, and stage 1 is a trivially scriptable cookie+redirect (:225-226). High is right.

### StageToString maps susLv 0 and susLv >=5 to the same key "5+", poisoning the token cache with an empty token that lets blocked requests through

- **Dimension:** security-crypto  
- **Location:** `core/server/middleware.go:183-214 and core/utils/text.go:176-189`  
- **Effort:** small

**Evidence**

core/utils/text.go:176-189 `func StageToString(stage int) string { switch stage { case 1: return "1" … case 4: return "4" default: return "5+" } }` — susLv 0 falls into `default` and yields "5+", exactly like susLv 5, 6, 7…
core/server/middleware.go:183-185 `susLvStr := utils.StageToString(susLv)` / `accessKey := ip + tlsFp + reqUa + proxy.CurrHourStr` / `encryptedCache, encryptedExists := firewall.CacheIps.Load(accessKey + susLvStr)`.
core/server/middleware.go:189-204: `case 0: //whitelisted` leaves encryptedIP == "" and then unconditionally `firewall.CacheIps.Store(accessKey+susLvStr, encryptedIP)`.
core/server/middleware.go:214 `if !strings.Contains(request.Header.Get("Cookie"), "__bProxy_v="+encryptedIP) {`.
README.md:451 documents action `0` as Allow and README.md:469 "Every request with a susLv of 4 or higher will be blocked"; core/firewall/eval.go:42-43 shows a rule action of "0" or "5" sets susLv absolutely.

**Impact**

A config with any allow rule (action "0") plus any block path (action "5", or stage 3 plus a stacking "+2" rule) is bypassable. The attacker first hits the whitelisted path, which caches `accessKey+"5+" -> ""`. He then hits the blocked path from the same IP/TLS-fingerprint/User-Agent: the cache hit at line 185 short-circuits the `default:` block branch at line 199, so encryptedIP stays "", and line 214 degenerates to `strings.Contains(cookie, "__bProxy_v=")` — satisfied by a self-set header `Cookie: a=__bProxy_v=`. The request is proxied to the backend, defeating a susLv>=5 DROP rule entirely.

**Fix**

Make StageToString total and injective for cache keys — use strconv.Itoa(susLv) for the cache key, or key the cache on the tuple with an explicit separator. Never store a cache entry for the non-challenged (0) or blocked (>=4) branches, and re-check `susLv >= 4` after the cache lookup so a cache hit can never skip a block decision. Treat an empty encryptedIP as "no valid token" instead of a match.

*Verifier:* Code verified: utils.StageToString is at core/utils/text.go:176-189 exactly as quoted and maps 0 to the default branch "5+", identical to 5+. middleware.go:183-185 builds the cache key as accessKey+susLvStr, :189-190 case 0 leaves encryptedIP empty, :204 stores it unconditionally (the >=4 default branch at :199-202 returns before the Store, so only the whitelist branch can poison the key), and :214 then degenerates to Contains(cookie,"__bProxy_v="), satisfiable with a self-set header. firewall/eval.go:36-44 confirms a bare action value sets susLv absolutely, so action "0" and "5" are both reachable. The bypass is real. Severity trimmed one level because it is config-conditional, not a default-config bypass: with no custom rules susLv equals domainData.Stage (1-3) and neither 0 nor >=4 is ever produced, so the operator must have both an action "0" allow rule and a >=4 block path, and the attacker must hit them in that order within the same ip+fingerprint+UA+hour.

### Backend 5xx response body injected raw into an iframe srcdoc attribute

- **Dimension:** security-http  
- **Location:** `core/server/serve.go:174-176`  
- **Effort:** small

**Evidence**

buffer.WriteString(`</h1><p>Sorry, the backend returned this error.</p><iframe width="100%" height="25%" style="border:1px ridge lightgrey; border-radius: 5px;"srcdoc="`)
buffer.WriteString(errMsg)
buffer.WriteString(`"></iframe><a onclick="location.reload()">Reload page</a></div></div></body></html>`)

errMsg is `string(errBody)` read straight off the upstream response (serve.go:155-166) with no escaping.

**Impact**

Any 5xx body containing a double quote closes the srcdoc attribute and injects arbitrary HTML/JS into a page served from the protected domain's own origin — e.g. a backend that echoes the request path in its 500 page turns `GET /"><script>...</script>` into stored-in-response XSS delivered by the proxy. The proxy also relabels the response `StatusCode: http.StatusOK` (serve.go:190), so caches and monitoring see a successful 200 for the injected page. Because `_1__bProxy_v` is not HttpOnly, the injected script can harvest challenge tokens for the whole domain.

**Fix**

HTML-escape errMsg with html.EscapeString before writing it into the attribute (or drop the iframe and render the upstream error as opaque text), preserve the upstream status code instead of rewriting it to 200, and gate verbose backend error passthrough behind a config flag that defaults to off.

*Verifier:* Verified. core/server/serve.go:174 writes the srcdoc=" opener, line 175 writes errMsg unescaped, line 176 closes it. errMsg is string(errBody) read straight off the upstream 5xx body at serve.go:156-163 with no sanitisation. An iframe srcdoc document inherits the embedder's origin, so injected script executes on the protected domain. serve.go:190 does rewrite the status to http.StatusOK as claimed. Exploitation as XSS depends on the backend reflecting input into a >=500 body, but the injection sink itself is unconditional and any quote in a normal HTML error page breaks the attribute.

### Backend identity headers are Added, not Set — client-supplied x-real-ip survives and arrives first

- **Dimension:** security-http  
- **Location:** `core/server/middleware.go:358-361`  
- **Effort:** trivial

**Evidence**

//Allow backend to read client information
request.Header.Add("x-real-ip", ip)
request.Header.Add("proxy-real-ip", ip)
request.Header.Add("proxy-tls-fp", tlsFp)
request.Header.Add("proxy-tls-name", browser+botFp)

**Impact**

`Add` appends; it does not overwrite. A client that sends `X-Real-Ip: 127.0.0.1` gets both values forwarded, and the backend sees `X-Real-Ip: 127.0.0.1, <real ip>` (or, with Go's Header.Get semantics on the receiving side, only the client-supplied first value). Backends routinely trust X-Real-Ip for admin allowlists, audit logs and their own ratelimiting, so this turns the proxy into a laundering service for IP spoofing. The same applies to `proxy-tls-fp`/`proxy-tls-name`: a client can forge a "Chromium" fingerprint label for any backend logic that keys off it.

**Fix**

Use `request.Header.Set(...)` for all four headers, and explicitly `request.Header.Del(...)` any inbound `X-Forwarded-For`/`X-Real-Ip`/`Forwarded`/`proxy-*` before setting the trusted values, so nothing client-supplied survives.

*Verifier:* Verified verbatim at core/server/middleware.go:358-361: four consecutive request.Header.Add calls for x-real-ip, proxy-real-ip, proxy-tls-fp, proxy-tls-name. Add appends, so a client-supplied X-Real-Ip stays at index 0 and any backend using Header.Get reads the forged value. The proxy is httputil.NewSingleHostReverseProxy (core/config/init.go:126), which manages only X-Forwarded-For and hop-by-hop headers and never touches X-Real-Ip. Nothing Dels inbound values. High stands given how routinely backends trust X-Real-Ip for allowlists and audit logs.

### Reflected XSS: client-controlled IP string interpolated into the stage-3 captcha page's JavaScript

- **Dimension:** security-http  
- **Location:** `core/server/middleware.go:296`  
- **Effort:** small

**Evidence**

document.cookie="`+ip+`_3__bProxy_v="+a+"`+publicPart+`; SameSite=Lax; path=/; Secure"

`ip` is `request.Header.Get("Cf-Connecting-Ip")` (middleware.go:61) in Cloudflare mode. It is written into a JS string literal with no escaping; the response is sent with `writer.Header().Set("Content-Type", "text/html")` (middleware.go:294).

**Impact**

A request carrying `Cf-Connecting-Ip: ";alert(document.cookie);//` while the domain is at stage 3 (or matched by a firewall rule with action "3") returns a page that executes attacker JavaScript in the protected site's origin. Because the challenge cookies are not HttpOnly (middleware.go:225) the payload can read `__bProxy_v` and hand a working bypass token to a botnet, and it can act on any session cookie the protected site sets. The victim can be driven to the page with a plain link since the header is settable by anyone hitting the origin directly.

**Fix**

Never interpolate request-derived data into the challenge HTML. Render both challenge pages with html/template (or text/template plus template.JSEscapeString) so contextual escaping is applied, and drop `ip` from the cookie name entirely — the cookie value already binds to the IP through `encryptedIP`.

*Verifier:* Verified. core/server/middleware.go:296 contains document.cookie="`+ip+`_3__bProxy_v=" inside a raw Go backtick string, with Content-Type text/html set at line 294 and no escaping of ip anywhere. In Cloudflare mode ip is the raw Cf-Connecting-Ip header (line 61), and Go's header parser permits double quotes and semicolons in header values. Reachability is stronger than the finding claimed: core/server/monitor.go:169 escalates domainData.Stage to 3 automatically during a bypass attack, so this is not operator-only. High stands.

### Sliding-window ratelimit maps are unbounded and keyed by an attacker-controlled header

- **Dimension:** security-http  
- **Location:** `core/server/middleware.go:96`  
- **Effort:** medium

**Evidence**

firewall.WindowAccessIps[proxy.Last10SecondTimestamp][ip]++
...
(line 217) firewall.WindowAccessIpsCookie[proxy.Last10SecondTimestamp][ip]++

Buckets are pre-created for a 120s horizon in core/server/monitor.go:582-594 and only reaped after proxy.RatelimitWindow seconds (monitor.go:598-602). No cap on the number of keys per bucket exists.

**Impact**

In Cloudflare mode `ip` is `request.Header.Get("Cf-Connecting-Ip")` (middleware.go:61), so a single attacker on a single connection can insert an unbounded number of distinct keys. At ~50k req/s with a unique header value per request and a 120s retention window, the maps hold millions of string keys across 12 buckets; the proxy OOMs. The same primitive works in origin mode over IPv6 by rotating source addresses. This is a memory-exhaustion DoS against the DDoS-mitigation appliance itself.

**Fix**

Cap each window bucket (e.g. 200k keys) and drop counting — but not the rest of the request pipeline — for overflow keys; validate that the resolved IP parses with net.ParseIP before it is ever used as a map key; and normalise IPv6 to a /64 prefix so rotation inside a routed prefix collapses into one bucket.

*Verifier:* Verified. core/server/middleware.go:96 does firewall.WindowAccessIps[proxy.Last10SecondTimestamp][ip]++ and line 217 does the same for WindowAccessIpsCookie, both with no key cap. core/server/monitor.go:580-594 pre-creates buckets across a 120s horizon and the reap loop at 596-606 only deletes a bucket once utils.TrimTime(windowTime)+proxy.RatelimitWindow < LastSecondTimestamp. Combined with finding 1 the key is attacker-chosen per request, so key cardinality is unbounded. High is correct.

### sync.Pool buffer returned to the pool while it still backs the response body

- **Dimension:** security-http  
- **Location:** `core/server/serve.go:122,148`  
- **Effort:** trivial

**Evidence**

buffer := bufferPool.Get().(*bytes.Buffer)
buffer.Reset()
defer bufferPool.Put(buffer)
...
return &http.Response{
	StatusCode: http.StatusOK,
	Body:       io.NopCloser(bytes.NewReader(buffer.Bytes())),
}, nil

**Impact**

`buffer.Bytes()` aliases the pool buffer's backing array. The deferred `bufferPool.Put(buffer)` runs at `return`, i.e. before httputil.ReverseProxy has copied the body to the client. Concurrently another goroutine can `Get` the same buffer, `Reset()` and `WriteString` into it (serve.go:120-122, and middleware.go:34-36 shares the same pool), overwriting bytes that are still being streamed to a different client. Under a backend outage — precisely the condition this code path exists for — every request takes this branch, so garbled or cross-request content is served at scale. The identical pattern repeats at serve.go:187-192 for the 5xx path.

**Fix**

Copy the bytes out before releasing the buffer: `body := append([]byte(nil), buffer.Bytes()...)` (or build the error page into a fresh bytes.Buffer that is not pooled) and only then `bufferPool.Put(buffer)`. Also populate `Header`, `ContentLength` and `Request` on the synthesized http.Response.

*Verifier:* Verified use-after-put. core/server/serve.go:120-122 gets the pooled buffer and registers defer bufferPool.Put(buffer); serve.go:146-149 returns a Response whose Body is io.NopCloser(bytes.NewReader(buffer.Bytes())), aliasing the pooled backing array. The defer fires at return, before httputil.ReverseProxy copies the body to the client. serve.go:189-192 repeats it. The pool is package-level (serve.go:24-28) and shared with core/server/middleware.go:33, so a concurrent Get+Reset+WriteString overwrites bytes still being streamed. High is correct.


## MEDIUM

### Build fingerprint identifying official upstream builds is exposed unauthenticated at /_bProxy/stats

- **Dimension:** branding  
- **Location:** `core/server/middleware.go:325-328 (also main.go:15, core/proxy/proxy.go:6, .github/workflows/release.yml:30)`  
- **Effort:** small

**Evidence**

main.go:15:
	var Fingerprint string = "S3LF_BU1LD_0R_M0D1F13D" // 455b9300-0a6f-48f1-82ee-bb1f6cf43500
core/proxy/proxy.go:5-7:
	const (
		ProxyVersion float64 = 1.5
	)
.github/workflows/release.yml:
	run: go build -ldflags "-X 'main.Fingerprint=${{ env.uuid }}'" -o dist/main
core/server/middleware.go:325-327:
	case "/_bProxy/stats":
		SendResponse("Stage: "+...+"\nProxy Fingerprint: "+proxy.Fingerprint, buffer, writer)

**Impact**

Category (c) user-visible string / upstream identity marker. `main.Fingerprint` is injected at release time by upstream's CI with a random UUID, and the default literal `S3LF_BU1LD_0R_M0D1F13D` plus the hardcoded UUID in the trailing comment are upstream's scheme for distinguishing official builds from forks — precisely the marker a rebrand must not inherit. It is then published at `/_bProxy/stats` (middleware.go:326) alongside stage, total/bypassed request counts and RPS, with NO secret check on that case arm — any client that clears the challenge can read it. Combined with `ProxyVersion 1.5` at proxy.go:6, that endpoint hands an attacker your mitigation stage and live bypass rate, which is direct feedback on whether their attack is working.

**Fix**

Replace the sentinel with a LancarSec-appropriate default and drop the upstream UUID from the comment; wire your own CI to inject a build ID via `-ldflags -X`. More importantly, gate `/_lancarsec/stats` behind the admin secret the way api.go:17 gates v1 (`request.Header.Get("proxy-secret") != proxy.APISecret`) — stage, bypassed-RPS and build ID are operator telemetry, not public data. Same applies to the adjacent `/_bProxy/fingerprint` arm at middleware.go:329-331, which echoes the caller's IP, susLv and TLS fingerprint back unauthenticated.

*Verifier:* Every cite verified. main.go:15 is `var Fingerprint string = "S3LF_BU1LD_0R_M0D1F13D" // 455b9300-0a6f-48f1-82ee-bb1f6cf43500`, assigned to proxy.Fingerprint at main.go:19. core/proxy/proxy.go:5-7 declares `ProxyVersion float64 = 1.5`. .github/workflows/release.yml:30 injects it: `go build -ldflags "-X 'main.Fingerprint=${{ env.uuid }}'" -o dist/main` with the UUID generated at :27. middleware.go:325-328 publishes Stage, TotalRequests, BypassedRequests, both RPS figures and proxy.Fingerprint with no secret check on that case arm — and the switch sits at :326, after the challenge block ends and after BypassedRequests++ at :319, so any client that clears the challenge reads it, exactly as claimed. The adjacent /fingerprint arm at :329-331 is likewise ungated. The fix's reference point is accurate: api.go:17 gates v1 on `request.Header.Get("proxy-secret") != proxy.APISecret` and api.go:155 gates v2 on `Proxy-Secret`. Severity medium is right.

### Challenge cookie family `__bProxy_v` — renaming force-rechallenges every live session

- **Dimension:** branding  
- **Location:** `core/server/middleware.go:214 (live stage-3 writer is middleware.go:296, not assets/html/captcha.html:199)`  
- **Effort:** small

**Evidence**

core/server/middleware.go:214:
	if !strings.Contains(request.Header.Get("Cookie"), "__bProxy_v="+encryptedIP) {
core/server/middleware.go:225:
		writer.Header().Set("Set-Cookie", "_1__bProxy_v="+encryptedIP+"; SameSite=Lax; path=/; Secure")
core/server/middleware.go:232 (inlined stage-2 JS):
	document.cookie="_2__bProxy_v=`+publicSalt+`"+e.solution+"; SameSite=Lax; path=/; Secure"
assets/html/captcha.html:199:
	document.cookie = "`+ip+`_3__bProxy_v=" + t + "`+publicPart+`; SameSite=Lax; path=/; Secure"

**Impact**

Category (b) wire-visible protocol token, and the most operationally disruptive rename in the whole inventory. Three cookie variants (`_1__bProxy_v`, `_2__bProxy_v`, `<ip>_3__bProxy_v`) all share the `__bProxy_v=` suffix, which is what the single validation check at middleware.go:214 substring-matches. Renaming to `__lSec_v` invalidates every already-issued clearance cookie: at cutover 100% of active visitors are re-challenged simultaneously — a self-inflicted thundering herd on a box that is by definition under attack. Worse, the stage-2/stage-3 cookies are written by CLIENT-SIDE JS embedded in the challenge pages, so the Go-side check and the JS-side writer must be renamed in the same deploy or verification silently fails forever (client sets `__lSec_v`, server keeps looking for `__bProxy_v`) and every visitor loops on the challenge.

**Fix**

Rename all four sites to `__lSec_v` in one atomic commit. Because the writer is JS and the reader is Go, add a transitional grace period: accept either `__lSec_v=` or `__bProxy_v=` in the middleware.go:214 check for one release, while only ever ISSUING the new name — then drop the legacy branch. Deploy during a low-traffic window regardless. Also note middleware.go:214 uses `strings.Contains` on the raw Cookie header rather than `request.Cookie(name)`, so a renamed token stays substring-matchable; keep that in mind when adding the dual-accept branch so an attacker cannot smuggle the old name inside another cookie's value.

*Verifier:* Locations verified verbatim: middleware.go:214 (`strings.Contains(request.Header.Get("Cookie"), "__bProxy_v="+encryptedIP)`), :225 (`_1__bProxy_v=`), :232 (inlined JS `_2__bProxy_v=`), assets/html/captcha.html:199 (`_3__bProxy_v=`). The Go-reader/JS-writer atomicity point is correct, and the live stage-3 writer is actually the inlined copy at middleware.go:296, not captcha.html:199 — captcha.html is dead (no Go source references it, confirmed by grep), so citing it as a required rename site is a location error. The headline impact is overstated: encryptedIP derives from proxy.CookieOTP/JSOTP/CaptchaOTP, which monitor.go:649-655 regenerates from `currTime.Format("2006-01-02")` — a DATE bucket. Every issued clearance cookie already becomes invalid for 100% of visitors at every UTC midnight, so the claimed 'self-inflicted thundering herd' is an event the proxy inflicts on itself daily by design. The rename adds one extra occurrence of a routine event.

### Credits endpoint claims GPL v2 but the shipped LICENSE is GPL v3

- **Dimension:** branding  
- **Location:** `core/server/middleware.go:346 vs LICENSE:2`  
- **Effort:** small

**Evidence**

core/server/middleware.go:343-347:
	//Do not remove or modify this. It is required by the license
	case "/_bProxy/credits":
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("BalooProxy; Lightweight http reverse-proxy https://github.com/41Baloo/balooProxy. Protected by GNU GENERAL PUBLIC LICENSE Version 2, June 1991", buffer, writer)

LICENSE:1-2:
	                    GNU GENERAL PUBLIC LICENSE
	                       Version 3, 29 June 2007

(LICENSE is 674 lines; `grep -nE "Version 3|Version 2" LICENSE` matches only line 2.)

**Impact**

Category (e) legal — and a factual contradiction that must be resolved BEFORE the fork ships, not after. The fork brief and the project's own notes describe this as a GPL v2 project, and the credits string the code calls license-mandatory says "Version 2, June 1991" — but the actual LICENSE file in the repo is GPL **v3** (29 June 2007), verified as the only version string in all 674 lines. The two licenses have materially different obligations: v3 adds the anti-Tivoization installation-information clause (§6), the patent grant (§11), and different termination-cure terms (§8). Copying upstream's v2 assumption into LancarSec means the fork may be distributing under, and asserting compliance with, the wrong license. GPL v3 §7 also lets an author add a preservation-of-attribution requirement — which is exactly what the `//Do not remove or modify this` comment is asserting about this endpoint.

**Fix**

Resolve the discrepancy first: determine which license upstream actually granted (check the upstream repo's headers/README at the commit you forked, since a v2-vs-v3 mismatch between LICENSE and in-code claims is upstream's bug that you inherit). Then (1) keep LICENSE byte-identical to whichever GPL text applies — never edit the license body; (2) fix the credits string's version number to MATCH the LICENSE file; (3) keep the endpoint present and reachable. See the separate finding on what the credits text may and may not be changed to.

*Verifier:* The factual discrepancy is verified: LICENSE line 2 reads 'Version 3, 29 June 2007' and `grep -nE "Version 3|Version 2" LICENSE` matches only that line, while core/server/middleware.go:346 asserts 'GNU GENERAL PUBLIC LICENSE Version 2, June 1991'. The git history corroborates upstream churn here (commits 'Removed Outdated License', 'Updated License', 'Readded License'). Severity is inflated by two levels: this is an inherited documentation inconsistency in a plain-text response body with no runtime, availability, or exploitability dimension, sitting in the same 'critical' bucket as an unpinned third-party script in the security control. It is real and must be resolved before the fork ships, but it is medium at most.

### Module path `goProxy` and 37 import lines across 11 files

- **Dimension:** branding  
- **Location:** `go.mod:1`  
- **Effort:** small

**Evidence**

go.mod:1 `module goProxy`
main.go:5-8:
	"goProxy/core/config"
	"goProxy/core/pnc"
	"goProxy/core/proxy"
	"goProxy/core/server"
core/server/monitor.go:22-26:
	"goProxy/core/domains"
	"goProxy/core/firewall"
	"goProxy/core/pnc"
	"goProxy/core/proxy"
	"goProxy/core/utils"

**Impact**

Category (a) module/import path. 38 total hits (1 in go.mod + 37 import lines). Nothing breaks at runtime — the module path is never emitted on the wire — but every import line must change atomically. A partial rename produces `package X is not in std` build failures, and any downstream Go consumer that does `import "goProxy/core/firewall"` breaks. `goProxy` is also not a valid remote-fetchable path (no domain), so `go get` never worked for this module anyway.

**Fix**

Set `module lancarsec` in go.mod, then `gofmt -w` after a mechanical rewrite: `grep -rl '"goProxy/' --include='*.go' . | xargs sed -i 's#"goProxy/#"lancarsec/#g'`. Prefer a fully-qualified path (`github.com/<org>/lancarsec`) so the module is actually fetchable. Verify with `go build ./... && go vet ./...`. Do NOT use `gorename`/`gopls rename` for this — it does not touch go.mod.

*Verifier:* Verified exactly. go.mod:1 is `module goProxy`. `grep -rn 'goProxy' --include='*.go'` returns exactly 37 hits across exactly the 11 files listed, and every cited import range matches byte-for-byte (main.go:5-8, api.go:6-9, generate.go:7-8, init.go:8-12, eval.go:5, middleware.go:6-10, monitor.go:22-26, serve.go:8-11, discord.go:7-9, domain.go:6, text.go:7-9). The fix works and the caveat that gopls rename does not touch go.mod is correct. Severity is inflated: the finding itself concedes nothing is emitted on the wire and nothing breaks at runtime; this is a mechanical, compiler-verified rename with zero security or availability impact, so medium.

### Reserved URL path prefix `/_bProxy/` — 8 endpoints including the admin API

- **Dimension:** branding  
- **Location:** `core/server/middleware.go:325-350 (plus core/api/api.go:159, core/server/middleware.go:296)`  
- **Effort:** small

**Evidence**

core/server/middleware.go:325-350:
	case "/_bProxy/stats":
	case "/_bProxy/fingerprint":
	case "/_bProxy/verified":
	case "/_bProxy/" + proxy.AdminSecret + "/api/v1":
	case "/_bProxy/credits":
	if strings.HasPrefix(request.URL.Path, "/_bProxy/api/v2") {
core/api/api.go:159:
	path := strings.TrimPrefix(r.URL.Path, "/_bProxy/api/v2/")
assets/html/captcha.html:199 (client JS):
	fetch("https://" + location.hostname + "/_bProxy/verified")

**Impact**

Category (b) wire-visible protocol token. Renaming to `/_lancarsec/` breaks: (1) every deployed API client that calls `/_bProxy/api/v2/...` — this is a hard break for automation, the v2 path is the documented admin surface; (2) the stage-3 captcha's own `fetch("/_bProxy/verified")` callback, which is written into the browser page — if the Go route is renamed and the inlined JS is not, captcha verification returns 404 through to the backend and no visitor can ever clear stage 3; (3) any backend WAF/CDN rule that exempts `/_bProxy/*` from caching. Note the v1 route at middleware.go:337 embeds `proxy.AdminSecret` in the URL PATH, so the secret lands in access logs and `Referer` — worth moving to a header while you are touching this line anyway.

**Fix**

Rename to `/_lancarsec/` at all 8 sites in one commit, including the inlined client JS at assets/html/captcha.html:199 and the equivalent inlined copy in middleware.go:296. Route both prefixes for one deprecation release if any API consumer exists. Take the opportunity to move the v1 admin secret from the path segment (middleware.go:337) into an `Admin-Secret` request header, matching what api.go:155 already does for v2 via `Proxy-Secret`.

*Verifier:* All 8 cited locations verified verbatim: middleware.go:325 /stats, :329 /fingerprint, :333 /verified, :337 /_bProxy/+proxy.AdminSecret+/api/v1, :344 /credits, :350 HasPrefix /_bProxy/api/v2, api/api.go:159 TrimPrefix, captcha.html:199 fetch. The title's '8 endpoints' is wrong — there are 6 distinct endpoints plus one TrimPrefix and one dead-file reference. Impact (2) is also mis-anchored: the captcha fetch that actually runs is the inlined copy at middleware.go:296 (assets/html/captcha.html is unreferenced by any Go file), which the fix text does correctly call out. api.go:155 does gate v2 on `Proxy-Secret`, so that part of the fix is accurate. Severity downgraded — this is a coordinated rename with breakage risk, not a vulnerability.

### Response header `baloo-Proxy: 1.5` emitted on every proxied request

- **Dimension:** branding  
- **Location:** `core/server/middleware.go:102`  
- **Effort:** trivial

**Evidence**

core/server/middleware.go:102:
	writer.Header().Set("baloo-Proxy", "1.5")

**Impact**

Category (b) wire-visible protocol token. This header is set on EVERY response that reaches the middleware, so it is the single loudest branding leak — anyone can `curl -I` a protected site and learn it runs balooProxy 1.5, then look up known bypasses for that exact version. README.md:68 even instructs operators to verify their install by searching for the `baloo-proxy` header in DevTools, so third-party monitoring/health-check scripts written against this project may key off it. Renaming breaks any such external checker.

**Fix**

Rename to `LancarSec-Proxy` and decouple the value from the upstream `1.5` (which is `proxy.ProxyVersion` in core/proxy/proxy.go:6). Better: make emission opt-out via a `hide_version_header` config flag and default it to hidden — a DDoS-mitigation product should not self-identify its exact version to attackers. Breaks: README.md:68's verification instructions and any operator dashboard grepping for `baloo-proxy`.

*Verifier:* Verified. core/server/middleware.go:102 is exactly `writer.Header().Set("baloo-Proxy", "1.5")`, unconditional, on every request that reaches Middleware (which is the handler for :443 in origin mode and :80 in Cloudflare mode, serve.go:48 and :103). README.md:68 does instruct operators to verify the install by looking for a `baloo-proxy` response header, so the documented verification step breaks on rename. Note the value "1.5" is a hardcoded literal here, NOT `proxy.ProxyVersion` as the fix text implies — proxy.ProxyVersion (core/proxy/proxy.go:6) is a separate float64 used only by VersionCheck. Severity downgraded: this is version/product disclosure, not an exploitable weakness.

### Seven user-facing block/error pages hardcode 'BalooProxy'

- **Dimension:** branding  
- **Location:** `core/server/middleware.go:110, :117, :125, :138, :201, :276, :280, :300`  
- **Effort:** trivial

**Evidence**

core/server/middleware.go:110:
	SendResponse("Blocked by BalooProxy.\nYou have been ratelimited. (R1)", buffer, writer)
core/server/middleware.go:117:
	SendResponse("Blocked by BalooProxy.\nYou have been ratelimited. (R2)", buffer, writer)
core/server/middleware.go:125:
	SendResponse("Blocked by BalooProxy.\nYou have been ratelimited. (R3)", buffer, writer)
core/server/middleware.go:138:
	SendResponse("Blocked by BalooProxy.\nYour browser "+forbiddenFp+" is not allowed.", buffer, writer)
core/server/middleware.go:201:
	SendResponse("Blocked by BalooProxy.\nSuspicious request of level "+susLvStr+" (base "+strconv.Itoa(domainData.Stage)+")", buffer, writer)
core/server/middleware.go:276 / :280:
	SendResponse("BalooProxy Error: Failed to encode captcha: "+err.Error(), buffer, writer)
	SendResponse("BalooProxy Error: Failed to encode captchaMask: "+err.Error(), buffer, writer)
core/server/middleware.go:300:
	SendResponse("Blocked by BalooProxy.\nSuspicious request of level "+susLvStr, buffer, writer)

**Impact**

Category (c) user-visible string. These are the pages an actual blocked visitor sees, so they are the most-read branding surface after the response header. They also leak defensive internals to the attacker who triggered them: the R1/R2/R3 suffixes disclose WHICH of the three ratelimit buckets fired (challenge-failure vs per-IP vs unknown-fingerprint), and `susLv`/`stage` disclose the exact suspicion score and current mitigation stage — free feedback for an attacker tuning a bypass. Lines 276/280 render `err.Error()` straight to the client, which can surface internal encoder state.

**Fix**

Rename to `LancarSec` at all 8 sites (`sed -i 's/BalooProxy/LancarSec/g' core/server/middleware.go` catches all of them, but review the credits line at :346 first — exclude it per the legal finding). While renaming, strip the diagnostic detail from what is sent to the client: drop the `(R1)/(R2)/(R3)` discriminators and the numeric susLv/stage from the response body and log them server-side instead, and replace `err.Error()` at :276/:280 with a generic message. Nothing breaks — these are plain-text response bodies with no known machine consumer.

*Verifier:* All eight cited lines verified verbatim (110 R1, 117 R2, 125 R3, 138 forbidden-fp, 201 susLv+stage, 276/280 `BalooProxy Error: Failed to encode captcha[Mask]: `+err.Error(), 300 susLv). Title says 'Seven' but eight sites are listed and eight exist — count error in the title only. The secondary info-leak claims check out: R1/R2/R3 do map to distinct buckets (challenge-failure at :109, per-IP at :116, unknown-fingerprint at :123), and :276/:280 do render err.Error() to the client. The proposed sed catches all eight and will NOT collide with `BalooPow` at :232 (different token), but does hit the credits string at :346 as the finding warns.

### All domains share one `http.Transport` with `MaxConnsPerHost: 10`, capping backend concurrency globally

- **Dimension:** concurrency  
- **Location:** `core/server/serve.go:198-219`  
- **Effort:** small

**Evidence**

var defaultTransport = &http.Transport{
	...
	IdleConnTimeout:     90 * time.Second,
	MaxIdleConns:        10,
	MaxConnsPerHost:     10,
}

func getTripperForDomain(domain string) *http.Transport {
	transport, ok := transportMap.Load(domain)
	if !ok {
		transport, _ = transportMap.LoadOrStore(domain, defaultTransport)
	}
	return transport.(*http.Transport)
}

No `ResponseHeaderTimeout` and no per-request deadline are set anywhere.

**Impact**

`getTripperForDomain` stores and returns the *same* `defaultTransport` for every domain, so `transportMap` is dead weight and the limits are global: at most 10 concurrent connections to any single backend, 10 idle total across all backends. Request 11 blocks inside `Transport.RoundTrip` waiting for a free connection, holding its handler goroutine, its pooled buffer and its inbound connection. A backend that merely gets slow (no error, no timeout — `ResponseHeaderTimeout` is unset) therefore converts into a total front-end stall: I observed exactly this shape in testing, where requests to a non-responsive backend hung indefinitely rather than erroring. For a proxy whose job is to absorb load, a hard cap of 10 upstream connections is a self-inflicted bottleneck.

**Fix**

Build one `*http.Transport` per domain at config-load time with sane, configurable limits (`MaxIdleConnsPerHost`, `MaxConnsPerHost` in the hundreds), set `ResponseHeaderTimeout` and `ExpectContinueTimeout`, and store the real per-domain transport in the map instead of the shared singleton.

*Verifier:* Verified. serve.go:198-210 defines the single defaultTransport with MaxIdleConns: 10 and MaxConnsPerHost: 10, no ResponseHeaderTimeout and no ExpectContinueTimeout; getTripperForDomain (:212-219) does `transportMap.LoadOrStore(domain, defaultTransport)` and so returns the same shared singleton for every domain, making transportMap dead weight exactly as claimed. Only Dialer.Timeout (5s) and TLSHandshakeTimeout (10s) exist, so a backend that accepts the connection and then stalls before sending headers hangs the handler goroutine indefinitely — holding its inbound connection and, per finding #6, a pooled buffer. One precision note: MaxConnsPerHost is keyed per host:port, so it is 10 per backend rather than 10 globally; MaxIdleConns: 10 is the genuinely global one. The finding's body already states this correctly even though its title says 'globally'. Medium stands.

### Confirmed data race: the ratelimit clock (`Last10SecondTimestamp`, `LastSecondTimeFormated`, `CurrHourStr`) is written by the terminal-UI goroutine and read unlocked by request goroutines

- **Dimension:** concurrency  
- **Location:** `core/server/monitor.go:213-218`  
- **Effort:** small

**Evidence**

Race-detector output from the running proxy:

WARNING: DATA RACE
Read at 0x000140b499b8 by goroutine 2662:
  goProxy/core/server.Middleware() ... middleware.go:96
Previous write at 0x000140b499b8 by goroutine 19:
  goProxy/core/server.printStats() ... monitor.go:216

WARNING: DATA RACE
Read at ... middleware.go:217 / Previous write at monitor.go:216
WARNING: DATA RACE
Read at ... middleware.go:184 / Previous write at monitor.go:218 (proxy.CurrHourStr)
WARNING: DATA RACE
Read at ... middleware.go:308 / Previous write at monitor.go:214 (proxy.LastSecondTimeFormated)

Writer: `proxy.LastSecondTimestamp = int(proxy.LastSecondTime.Unix()); proxy.Last10SecondTimestamp = utils.TrimTime(proxy.LastSecondTimestamp)` (monitor.go:215-216, called from Monitor under PrintMutex only)
Reader: `firewall.WindowAccessIps[proxy.Last10SecondTimestamp][ip]++` (middleware.go:96, under firewall.Mutex)

**Impact**

The writer holds PrintMutex; the readers hold firewall.Mutex — two different locks, so there is no synchronisation at all. Beyond UB, the correctness consequence is direct: the sliding-window bucket key can be read stale or torn, so requests get counted into a bucket that evaluateRatelimit is about to delete (undercounting an attacker) or into a bucket that does not exist (the nil-map panic in the previous finding). `proxy.CurrHourStr` feeding `accessKey` at middleware.go:184 means a torn read produces a cookie that will never validate.

**Fix**

Make the clock its own concern: an `atomic.Int64` for the timestamps updated by a dedicated `time.Ticker` goroutine (not the UI loop), and an `atomic.Pointer[string]`/`atomic.Value` for the formatted strings. Nothing in the request path should depend on the terminal renderer running.

*Verifier:* Verified. printStats writes proxy.LastSecondTime/LastSecondTimeFormated/LastSecondTimestamp/Last10SecondTimestamp/CurrHour/CurrHourStr at monitor.go:213-218, called from Monitor at :94 while holding only PrintMutex (:67/:96); readers at middleware.go:96 and :217 hold firewall.Mutex, :184 and :308 hold nothing — genuinely disjoint locks, no happens-before. The string-tearing argument is actually strongest for the variable the finding treats as an aside: proxy.CurrHourStr is `strconv.Itoa(hour)` (monitor.go:218), so it flips between 1-byte and 2-byte strings at the 9->10 and 23->0 transitions, where a torn read genuinely reads past the string and yields a bad accessKey. Downgraded one level because the two headline consequences are weak: proxy.Last10SecondTimestamp is an aligned int (no tearing on any supported arch), and a stale read cannot land on a missing bucket since evaluateRatelimit prefills 120s ahead (monitor.go:581) — the nil-map panic needs the >120s stall of the separate finding, not this race.

### Every TCP connection open/close takes the global write lock — an attacker-controlled contention amplifier

- **Dimension:** concurrency  
- **Location:** `core/firewall/general.go:38-49`  
- **Effort:** medium

**Evidence**

func OnStateChange(conn net.Conn, state http.ConnState) {
	remoteAddr := conn.RemoteAddr().String()
	switch state {
	case http.StateNew:
	case http.StateHijacked, http.StateClosed:
		Mutex.Lock()
		delete(Connections, remoteAddr)
		Mutex.Unlock()
	}
}

and core/firewall/fingerprint.go:82-84:
	Mutex.Lock()
	Connections[remoteAddr] = fingerprint
	Mutex.Unlock()
(installed as `ConnState: firewall.OnStateChange` and `GetConfigForClient: firewall.Fingerprint`, serve.go:60/69/72)

**Impact**

An attacker does not need to send a single valid HTTP request to hurt the proxy: opening and immediately closing TCP connections (or starting TLS handshakes) forces a global write-lock acquisition per event, on the same mutex the request path needs four times per request. A connection-churn flood — the cheapest possible attack, and one that bypasses all of the challenge machinery — directly starves legitimate request processing and the Monitor/ratelimit goroutines. It also makes the nil-map deadlock above far more likely by starving `evaluateRatelimit`.

**Fix**

Move `Connections` (and the fingerprint map) to a `sync.Map` keyed by remote address, or better, attach the fingerprint to the connection via a `context.Context` value / a wrapping `net.Conn` so no shared map is touched at all. Never let a connection-lifecycle hook contend with the request path.

*Verifier:* Code verified verbatim: general.go:38-49 takes Mutex.Lock to `delete(Connections, remoteAddr)` on StateHijacked/StateClosed, fingerprint.go:82-84 takes Mutex.Lock to write Connections[remoteAddr], and both are installed at serve.go:60/69 (ConnState) and :72 (GetConfigForClient). Downgraded one level for two reasons the finding omits. First, it is mode-conditional: the Cloudflare listener (serve.go:37-44) sets neither ConnState nor a TLSConfig, so this amplifier does not exist at all in the deployment mode the fork actually runs. Second, each critical section is a single map delete/insert — real added contention on the one mutex the request path needs, but a contributing factor to the coarse-lock finding rather than an independent high, and the claim that it 'makes the nil-map deadlock far more likely by starving evaluateRatelimit' would require >120s of writer starvation, which Go's sync.Mutex starvation mode (1ms handoff) makes implausible.

### The cache sweeper holds the global write lock across three full `sync.Map` range passes

- **Dimension:** concurrency  
- **Location:** `core/server/monitor.go:539-570`  
- **Effort:** trivial

**Evidence**

firewall.Mutex.Lock()
... strconv.ParseFloat(proxy.CpuUsage, 32) ...
if (proxyCpuUsage < 15 && proxyMemUsage > 25) || proxyMemUsage > 95 {
	firewall.CacheIps.Range(func(key, value any) bool { firewall.CacheIps.Delete(key); return true })
}
imgCachelen := 0
firewall.CacheImgs.Range(func(key, value any) bool { imgCachelen++; return true })
if ... { firewall.CacheImgs.Range(func(key, value any) bool { firewall.CacheImgs.Delete(key); return true }) }
firewall.Mutex.Unlock()

**Impact**

`CacheIps` and `CacheImgs` are `sync.Map`s (general.go:29,33) — they need no external lock at all, yet the sweeper takes the one mutex the request path needs four times per request and holds it across a full iteration of a cache that this same code path lets grow to millions of entries. Every 2 minutes the entire proxy stops serving for as long as the range takes. The `imgCachelen` counter computed at line 559-563 is then never used, so a full range over the image cache is paid unconditionally on every sweep. `proxy.CpuUsage`/`proxy.RamUsage` are also read here while printStats writes them unlocked (monitor.go:222-238) — another unsynchronised pair.

**Fix**

Delete the `firewall.Mutex` acquisition entirely (sync.Map is already safe), drop the unused `imgCachelen` pass, and replace bulk eviction with per-entry TTL so the sweep is incremental and bounded.

*Verifier:* Verified verbatim at monitor.go:539-570. firewall.Mutex.Lock() at :539 wraps strconv.ParseFloat of proxy.CpuUsage/RamUsage and all three sync.Map range passes, released only at :570. CacheIps and CacheImgs are sync.Map (general.go:29, 33) and need no external lock, so the acquisition is pure contention on the mutex the request path needs. The dead-code claim checks out: imgCachelen is incremented at :559-563 and never read — the gate at :564 tests proxyCpuUsage/proxyMemUsage, not imgCachelen — so a full unconditional range over an unbounded image cache is paid under the global write lock every 2 minutes. The unsynchronised read of proxy.CpuUsage/RamUsage here against printStats' writes at :222-238 is also correct. Medium stands; note the two bulk-delete ranges are gated by the condition finding #8 shows is almost never true, so in practice it is the unconditional imgCachelen pass that does the stalling.

### The entire ratelimit window clock is advanced by the terminal-rendering goroutine

- **Dimension:** concurrency  
- **Location:** `core/server/monitor.go:94`  
- **Effort:** small

**Evidence**

Monitor's loop: `utils.ClearScreen(proxy.MaxLogLength)` … `printStats()` … `PrintMutex.Unlock(); time.Sleep(1 * time.Second)` (monitor.go:85-97), and printStats is what advances the clock:
	proxy.LastSecondTime = time.Now()
	proxy.LastSecondTimestamp = int(proxy.LastSecondTime.Unix())
	proxy.Last10SecondTimestamp = utils.TrimTime(proxy.LastSecondTimestamp)  (monitor.go:213-216)
printStats also does blocking work first: `cpu.Percent(0, false)` (monitor.go:220), `runtime.ReadMemStats` (monitor.go:235) and dozens of `fmt.Println` writes to stdout.

**Impact**

`evaluateRatelimit` decides which buckets to expire by comparing against `proxy.LastSecondTimestamp` (monitor.go:599, 610, 621), and Middleware indexes buckets by `Last10SecondTimestamp`. If stdout blocks (piped to a consumer that stopped reading, a slow serial console, a full journal socket) or `runtime.ReadMemStats` stalls the world, the clock freezes: every request piles into one frozen bucket that never expires, `AccessIps` grows monotonically, and within seconds every client exceeds `IPRatelimit` — the proxy blocks all legitimate traffic. Conversely `time.Sleep(1s)` plus the render cost means the "per second" window actually drifts longer than a second, so the advertised ratelimit window is not the configured one.

**Fix**

Drive the clock from a dedicated `time.Ticker` goroutine that does nothing but store atomics; let the TUI read those atomics. The mitigation path must not depend on rendering.

*Verifier:* Verified. Monitor's loop is `utils.ClearScreen` (:85) ... `printStats()` (:94) ... `PrintMutex.Unlock(); time.Sleep(1 * time.Second)` (:96-97), and printStats advances the entire ratelimit clock at :213-218 before doing blocking work: `cpu.Percent(0, false)` at :220, `runtime.ReadMemStats(&ramStats)` at :235 (a stop-the-world pause), then dozens of fmt.Println writes to stdout at :223-283. Consumers confirmed: evaluateRatelimit compares against proxy.LastSecondTimestamp at :599/:610/:621 and prefills from proxy.Last10SecondTimestamp at :581; Middleware indexes buckets by it at :96/:130/:217. A blocked stdout therefore freezes the mitigation clock. The drift point is also correct — sleep(1s) plus render time means the window is longer than configured. Medium is right; this is the architectural root of findings #1 and #3 rather than an independent high.

### `ReloadConfig` JSON-decodes into the live `domains.Config` struct while request goroutines read it unlocked

- **Dimension:** concurrency  
- **Location:** `core/server/monitor.go:405-410`  
- **Effort:** medium

**Evidence**

file, err := os.Open("config.json")
...
json.NewDecoder(file).Decode(&domains.Config)

Readers, with no lock at all:
middleware.go:59  `if domains.Config.Proxy.Cloudflare {`
middleware.go:169 `"proxy.cloudflare":    domains.Config.Proxy.Cloudflare,`
Writers that follow, also unlocked: monitor.go:412-447 (`proxy.Cloudflare`, `proxy.CookieSecret`, `proxy.IPRatelimit`, `proxy.FPRatelimit`, `proxy.FailChallengeRatelimit` …), read on the hot path at middleware.go:108, 115, 123.

**Impact**

`domains.Config` is a non-nil `*Configuration`, so `encoding/json` decodes *into the existing struct* rather than allocating a fresh one — fields and the `Domains` slice header are mutated in place while handler goroutines are reading them. Concretely: during an operator `reload` (issued from the `commands` goroutine) a request can observe `Proxy.Cloudflare == false` mid-flip and take the origin branch, reading `request.RemoteAddr` as the client IP for a Cloudflare-fronted deployment — every request in that window is attributed to one Cloudflare edge IP and instantly trips the IP ratelimit. Ratelimit thresholds read at middleware.go:108/115/123 can likewise be observed as 0 (block everything) between the zero-write and the new value.

**Fix**

Build a brand new `*Configuration` from the file, then publish it with `atomic.Pointer[Configuration].Store(newCfg)`; have Middleware do one `cfg := domains.LoadConfig()` at entry and use that snapshot for the whole request. Same for the derived `proxy.*` scalars — group them into the config snapshot instead of loose package globals.

*Verifier:* Location and mechanism verified: monitor.go:405-410 opens config.json and calls `json.NewDecoder(file).Decode(&domains.Config)`, and domains.Config is declared `Config *Configuration` (core/domains/domain.go:17). encoding/json's indirect() follows a non-nil pointer rather than allocating, so it does decode into the live struct in place. Unlocked readers confirmed at middleware.go:59 and :169; the derived scalars at monitor.go:412-447 are read unlocked at middleware.go:108/115/123. Downgraded one level because the flagship impact is overstated: json.Decode assigns a bool field with a single SetBool, it does not zero-then-write, so there is no transient `Proxy.Cloudflare == false` unless the operator genuinely flips the setting. The real transient windows are the reference types — `domains.Domains = []string{}` at monitor.go:403 before repopulation at :450 (read unlocked by printStats at :253) and the freshly allocated Ratelimits map. Real race, operator-triggered and rare.

### Every golang.org/x/* module is ~2 years stale, carrying 45 module-level advisories; a plain `go get -u ./...` fixes all of them with zero code changes

- **Dimension:** deps-toolchain  
- **Location:** `go.mod:9-10`  
- **Effort:** trivial

**Evidence**

`go list -m -u all` current -> latest:
```
golang.org/x/crypto v0.24.0 [v0.55.0]
golang.org/x/image  v0.17.0 [v0.45.0]
golang.org/x/net    v0.26.0 [v0.58.0]
golang.org/x/sys    v0.21.0 [v0.47.0]
golang.org/x/term   v0.21.0 [v0.45.0]
golang.org/x/text   v0.16.0 [v0.41.0]
```
govulncheck module-level advisory counts against the pinned versions: x/crypto 20, x/net 13, x/image 10, x/text 1, x/sys 1 = 45.
Notable x/net entries since v0.26.0: GO-2026-4918 (HTTP/2 infinite loop, fixed v0.53.0 — symbol-reachable here), GO-2026-5026 (idna Punycode label bypass, v0.55.0), GO-2025-3503 (HTTP proxy bypass via IPv6 zone IDs, v0.36.0), GO-2025-3595 (x/net XSS, v0.38.0), GO-2024-3333 (non-linear case-insensitive HTML parsing, v0.33.0), GO-2026-4441 (infinite parsing loop, v0.45.0).
x/image (captcha rendering, utils/image.go:7-9): GO-2026-6222 (VP8L memory blowup), GO-2026-5066/5062 (tiff strip-offset panic, unbounded tile sizes), GO-2024-2937 (palette-image panic).
Verified in a scratch copy: `go get -u ./... && go mod tidy && go build ./...` upgraded 10 modules (blake3 v0.2.3->v0.2.4, x/crypto ->v0.55.0, x/image ->v0.45.0, x/net ->v0.58.0, x/sys ->v0.47.0, x/term ->v0.45.0, x/text ->v0.41.0, cpuid ->v2.4.0, go-sysconf ->v0.4.0, numcpus ->v0.12.0) and built cleanly with **zero source edits**.

**Impact**

45 published advisories against a product sold on its security posture, one of them a remotely-triggerable infinite loop on the backend transport. The upgrade cost is provably zero — no API in use has changed — so the only thing standing between the fork and a clean scan is running one command.

**Fix**

`go get -u ./... && go mod tidy && go build ./... && go vet ./...` as the very first commit of the fork (verified to succeed). Then combine with the screen-vendoring and http2 fixes above: in a scratch copy those three changes together dropped govulncheck's module-level count from 52 to 11 and package-level from 6 to 4, and removed x/crypto and x/net from the graph entirely.

*Verifier:* The verifiable core is exact. `go list -m -u all` reproduces all six current->latest pairs verbatim (crypto v0.24.0->v0.55.0, image v0.17.0->v0.45.0, net v0.26.0->v0.58.0, sys v0.21.0->v0.47.0, term v0.21.0->v0.45.0, text v0.16.0->v0.41.0), and `grep -c 'Module: golang.org/x/<m>$'` on govulncheck -show verbose gives crypto 20, net 13, image 10, text 1, sys 1 = 45 exactly. I reproduced the fix in a scratch copy: `go get -u ./... && go mod tidy && go build ./...` upgraded precisely the ten listed modules (including blake3 v0.2.3->v0.2.4, cpuid ->v2.4.0, go-sysconf ->v0.4.0, numcpus ->v0.12.0) with zero source edits and exit 0. go.mod:9-10 are indeed x/image and x/net. Two corrections. (1) 'one of them a remotely-triggerable infinite loop on the backend transport' repeats the GO-2026-4918 misattribution: govulncheck's trace for that advisory runs through net/http@go1.25.4, not x/net, and it reports zero *called* non-stdlib vulnerabilities. (2) The x/image advisories cited (VP8L, tiff strip-offsets, palette panics) are decoder bugs; this tree imports only x/image/font, font/basicfont and math/fixed (utils/image.go:7-9) and never decodes untrusted images. So all 45 are unreachable SBOM noise. Severity dropped one level; the recommended action remains correct and free.

### Startup synchronisation is a 500ms polling loop over an unsynchronised bool written from another goroutine

- **Dimension:** deps-toolchain  
- **Location:** `main.go:43`  
- **Effort:** small

**Evidence**

core/proxy/proxy.go:59 declares `Initialised = false` (plain `bool`, no atomic, no mutex).
core/server/monitor.go:631 writes it from the `evaluateRatelimit` goroutine:
```go
firewall.Mutex.Unlock()
proxy.Initialised = true
```
main.go:42-47 reads it from the main goroutine:
```go
go server.Monitor()
for !proxy.Initialised {
	time.Sleep(500 * time.Millisecond)
}

go server.Serve()
```
Note the write at monitor.go:631 happens *after* `firewall.Mutex.Unlock()`, so it is not covered by that mutex either.

**Impact**

An unsynchronised read/write of a shared `bool` across goroutines is a data race by the Go memory model — `go build -race` will flag it, and on a weakly-ordered target the main goroutine is not guaranteed to observe the store at all, or may observe it before the initialisation it is meant to signal is visible. Practically it also delays listener startup by up to 500ms for no reason, and main.go:50 then parks forever on `select {}` with no signal handling, so there is no graceful shutdown path.

**Fix**

Replace the bool with a `chan struct{}` closed by `evaluateRatelimit` (or `sync.WaitGroup.Done`) and have main.go block on `<-proxy.Ready`; that is both race-free and instantaneous. If a flag is genuinely wanted, use `atomic.Bool` (Go 1.19, already available). While there, replace `select {}` at main.go:50 with `signal.NotifyContext` + `server.Shutdown(ctx)`.

*Verifier:* Verified line by line. proxy/proxy.go:59 declares `Initialised = false` as a plain bool inside the var block with no atomic or mutex. monitor.go:630-631 is `firewall.Mutex.Unlock()` immediately followed by `proxy.Initialised = true`, so the write is genuinely outside the mutex, inside the evaluateRatelimit goroutine. main.go:42-45 is the quoted `go server.Monitor()` / `for !proxy.Initialised { time.Sleep(500 * time.Millisecond) }`, and main.go:50 is `select {}` with no signal handling. Unsynchronised bool shared across goroutines is a data race under the Go memory model, the up-to-500ms startup delay is real, and the channel/atomic.Bool fix plus signal.NotifyContext is correct. Minor wording nit: -race reports this at runtime under load, not at build time. Severity medium is right.

### Zero test files in 3098 lines, and the only linter that would catch this is not wired into CI

- **Dimension:** deps-toolchain  
- **Location:** `go.mod:15`  
- **Effort:** medium

**Evidence**

`find . -name '*_test.go' | wc -l` -> `0` across all 25 .go files.
Consequently go.mod:15 `github.com/stretchr/testify v1.8.1 // indirect` is inherited purely from gopsutil's own test tree — `go mod why -m github.com/stretchr/testify`:
```
goProxy/core/server
github.com/shirou/gopsutil/cpu
github.com/shirou/gopsutil/cpu.test
github.com/stretchr/testify/assert
```
.github/workflows/release.yml has steps for checkout, setup-go, `go mod download`, uuidgen, `go build`, release — and no `go test`, `go vet`, or vulnerability step. .github/workflows/codeql.yml runs CodeQL with `build-mode: autobuild` only.
Meanwhile `go vet ./...` currently FAILS (eval.go:30) and `staticcheck ./...` reports 4 issues — neither is blocking anything.

**Impact**

Every finding in this audit — the vet failure, the deprecated imports, the dead `closestTo10`, and any future regression in the firewall DSL evaluator at eval.go:13 or the ratelimit window rotation at monitor.go:575-633 — can ship to a `latest` prerelease without anything objecting. For a security product with a hand-written rule-evaluation engine and a sliding-window ratelimiter, the absence of even one table test around `EvalFirewallRule` and `TrimTime` is the largest quality gap in the toolchain story.

**Fix**

Add a `test` job to release.yml running `go vet ./...`, `go test ./...`, `staticcheck ./...` and `govulncheck ./...` as required checks before the build/release job. Seed the suite with the two highest-value targets: table tests for `firewall.EvalFirewallRule` (eval.go:10) covering `+n`, `-n`, absolute and malformed actions, and a fuzz target `FuzzNewFilter` over `gofilter.NewFilter` — which, once the DSL is vendored per the gofilter finding, is the only way to gain confidence in an 8-year-old generated parser.

*Verifier:* Verified. `find . -name '*_test.go'` returns 0 across all 25 .go files (3098 lines total, matching the stated size). go.mod:15 is `github.com/stretchr/testify v1.8.1 // indirect` and `go mod why -m` reproduces the quoted four-line trace through `github.com/shirou/gopsutil/cpu.test`, so it is 100% inherited. release.yml contains only checkout, setup-go, go mod download, uuidgen, go build and the release step — no test, vet, staticcheck, govulncheck or go mod verify — and codeql.yml:48 is `build-mode: autobuild`. I independently confirmed `go vet ./...` currently exits 1 and `staticcheck ./...` reports the 4 issues, so neither is gating anything today. The suggested seeds (table tests around EvalFirewallRule at eval.go:10 and a fuzz target over gofilter.NewFilter) are the right two targets. Severity medium is appropriate.

### `go vet ./...` fails: firewall rule-evaluation error path uses fmt.Println with Printf directives

- **Dimension:** deps-toolchain  
- **Location:** `core/firewall/eval.go:30`  
- **Effort:** trivial

**Evidence**

`go vet ./...` output, in full:
```
# goProxy/core/firewall
core\firewall\eval.go:30:6: fmt.Println call has possible Printf formatting directive %d
```
eval.go:26-31:
```go
case "-":
	var actionInt int
	_, err := fmt.Sscan(rule.Action[1:], &actionInt)
	if err != nil {
		fmt.Println("[ ! ] [ Error Evaluating Rule %d : %s ]\n", index, err.Error())
```
The sibling `+` branch (eval.go:20) and `default` branch (eval.go:40) correctly use `fmt.Printf`.

**Impact**

The whole module fails `go vet`, so vet can never be a CI gate until this is fixed. Functionally, when an operator writes a malformed subtractive firewall rule (`-abc`), the diagnostic prints literally `[ ! ] [ Error Evaluating Rule %d : %s ]` followed by a space-joined dump of the index and error — the rule number is unreadable, and since eval.go:31 deliberately swallows the error and continues, a silently-broken deny rule looks identical to a working one.

**Fix**

Change eval.go:30 to `fmt.Printf("[ ! ] [ Error Evaluating Rule %d : %s ]\n", index, err)`. Add `go vet ./...` as a required step in .github/workflows/release.yml so the module cannot regress.

*Verifier:* Reproduced exactly. `go vet ./...` on this tree emits precisely one diagnostic and exits 1: 'core\firewall\eval.go:30:6: fmt.Println call has possible Printf formatting directive %d'. eval.go:30 is `fmt.Println("[ ! ] [ Error Evaluating Rule %d : %s ]\n", index, err.Error())` inside the `case "-":` branch, and the sibling `+` branch (eval.go:20) and `default` branch (eval.go:40) both correctly use fmt.Printf. The swallow-and-continue at eval.go:31 is real, so a malformed subtractive rule silently no-ops with an unreadable diagnostic. The proposed one-line fix is correct and makes vet gateable. Severity medium is appropriate.

### github.com/kor44/gofilter is a 2017 pseudo-version with no tags and no go.mod, and it is the entire firewall rule engine

- **Dimension:** deps-toolchain  
- **Location:** `go.mod:7`  
- **Effort:** medium

**Evidence**

go.mod:7 `github.com/kor44/gofilter v0.0.0-20171111115139-75787865c72c`
`go list -m -json github.com/kor44/gofilter@latest` -> `"Version": "v0.0.0-20171111115139-75787865c72c", "Time": "2017-11-11T11:51:39Z"` — the pinned commit IS the tip; there has been no commit in 8 years.
`go list -m -versions github.com/kor44/gofilter` returns the module name and no versions at all — zero tags, ever.
`Test-Path <modcache>/go.mod` -> False — pre-modules package; the .mod in the download cache is synthesized by the go tool.
It is load-bearing on every request: firewall/filter.go:1-30 registers all 26 DSL fields in `init()`, config/init.go:76 `gofilter.NewFilter(fwRule.Expression)` compiles them at load, and firewall/eval.go:13 `if rule.Filter.Apply(variables)` runs the parsed AST per request per rule.
The upstream package is generated code: filter_main.go carries `//go:generate ragel -Z lexer.rl` and `//go:generate yacc -o parser.go -p filter parser.y` — a goyacc/Ragel parser (parser.go 18KB, lexer.go 13KB, nodes.go 14KB) that no one has audited since 2017.

**Impact**

The single most security-critical component of LancarSec — the Wireshark-style rule evaluator that decides whether traffic is blocked — is an untagged 2017 snapshot from a personal repo with no releases, no CI, no security contact, and a yacc/Ragel-generated parser nobody maintains. If the GitHub account is deleted or the repo force-pushed, builds break; if a `matches` regex path has a catastrophic-backtracking or panic bug, there is no upstream to fix it and firewall/eval.go:13 has no recover around `Apply`.

**Fix**

Vendor it. Copy the seven source files plus LICENSE into `core/gofilter/` under the fork (the repo carries a permissive LICENSE file — verify and preserve it), rewrite the import in firewall/filter.go, firewall/eval.go, config/init.go and server/monitor.go, and drop the go.mod require. That freezes the supply chain, makes the parser auditable and fuzzable in-tree (`go test -fuzz` against `NewFilter` and `Apply`), and lets LancarSec add the panic-recover and regex-complexity limits the rule evaluator needs. Vendoring is preferable to a `replace` directive because it survives upstream deletion.

*Verifier:* Substance holds. go.mod:7 is the quoted 2017 pseudo-version; `go list -m -versions github.com/kor44/gofilter` returns the module name with no versions at all; there is no go.mod in the module cache directory; filter.go registers exactly 26 fields in init() (9 ip.*, 10 http.*, 7 proxy.*); eval.go:13 is `if rule.Filter.Apply(variables)`; filter_main.go:1-3 carry the ragel and yacc go:generate lines; parser.go 18489 B, lexer.go 13488 B, nodes.go 14667 B; the LICENSE is MIT (so vendoring is permitted, as the finding asks). Attacker-controlled data really does reach it every request (middleware.go:160-166 feeds http.user_agent, http.query, http.path, http.cookie into the Message). Two defects to correct. (1) Location error inside the evidence: `gofilter.NewFilter(fwRule.Expression)` is at core/config/init.go:115, not init.go:76 — init.go:76 is `proxy.ReadTimeout = ...`; the second call site is monitor.go:456. (2) The fix's import-rewrite list is incomplete: core/server/middleware.go:22 also imports gofilter. Also note the 'catastrophic-backtracking' hypothetical is impossible as stated — nodes.go:6 / parser.go:745 use Go's regexp (RE2), which has no backtracking. Severity dropped one level: this is a supply-chain and auditability risk with no demonstrated defect.

### go.mod pins the language at `go 1.19`, five releases of language and GODEBUG defaults behind the toolchain

- **Dimension:** deps-toolchain  
- **Location:** `go.mod:3`  
- **Effort:** trivial

**Evidence**

go.mod:1-3:
```
module goProxy

go 1.19
```
Local toolchain: `go version go1.25.4 windows/amd64`.
Verified: I copied the tree to a scratch dir, changed only `go 1.19` -> `go 1.25.4`, and ran `go mod tidy && go build ./...` — exit 0, no output, no source changes required.

**Impact**

The `go` directive gates language features and per-release GODEBUG defaults. At 1.19 the compiler refuses `min`/`max` builtins (1.21), `for i := range n` (1.22), `clear()` (1.21), range-over-func (1.23), and — most importantly for a concurrent proxy — the Go 1.22 per-iteration loop variable semantics are OFF. Any future `go func()` closure over a range variable (serve.go:105 is already the only goroutine-in-a-loop-adjacent site) silently gets 1.19 shared-variable capture. It also means every reviewer and linter treats the module as legacy and `gopls`/`modernize` refuses to suggest the newer stdlib.

**Fix**

Set `go 1.25.4` in go.mod (verified to build unchanged) and add an explicit `toolchain go1.25.13` line so builds are reproducible across machines. Then run `go run golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@latest -fix ./...` to sweep the now-unlocked constructs.

*Verifier:* go.mod:1-3 is exactly `module goProxy` / blank / `go 1.19`. I independently reproduced the fix: copied the tree to scratch, changed only the directive to `go 1.25.4`, ran `go mod tidy && go build ./...` — exit 0, zero source edits (and tidy also dropped boltdb). The language-gate claims are all correct. However the stated impact is entirely hypothetical: I grepped and there is no `go func()` closing over a range variable anywhere in the tree (serve.go:105 is a bare `go func(){}` not inside a loop), so no loopvar bug exists today. Severity dropped one level to medium. Note the finding actually understates a real consequence it never mentions: `go list -f '{{.DefaultGODEBUG}}'` on this module resolves to tls10server=1, tls3des=1, tlssha1=1, tlsrsakex=1, rsa1024min=0, httpmuxgo121=1 — the 1.19 directive is silently re-enabling weakened TLS defaults on a TLS-terminating proxy.

### golang.org/x/crypto (20 known vulns) is linked in solely because inancgumus/screen calls ssh/terminal for a function this code never uses

- **Dimension:** deps-toolchain  
- **Location:** `core/server/monitor.go:17`  
- **Effort:** small

**Evidence**

monitor.go:17 `"github.com/inancgumus/screen"` — the only importer.
`go mod why -m golang.org/x/crypto`:
```
goProxy/core/server
github.com/inancgumus/screen
golang.org/x/crypto/ssh/terminal
```
`go list -deps ./...` confirms `golang.org/x/crypto/ssh/terminal` is genuinely compiled into the binary.
The module's dimensions.go is the culprit and is 16 lines:
```go
import (
	"os"
	"golang.org/x/crypto/ssh/terminal"
)
func Size() (int, int) { w, h, err := terminal.GetSize(int(os.Stdout.Fd())) ... }
```
`screen.Size()` is never called — this code uses `term.GetSize` from golang.org/x/term directly at monitor.go:68.
govulncheck attributes 20 advisories to golang.org/x/crypto@v0.24.0 (`grep -c "  Module: golang.org/x/crypto$"` = 20), e.g. GO-2026-6303, GO-2026-5023 (VerifiedPublicKeyCallback permissions skip), GO-2026-5021 (auth bypass via unenforced @revoked in knownhosts), GO-2024-3321.

**Impact**

The two functions actually used from `screen` are `Clear()` and `MoveTopLeft()` — six lines of ANSI escape printing (`fmt.Print("\033[2J")` / `fmt.Print("\033[H")`). In exchange the binary links the entire x/crypto SSH stack and inherits 20 advisories, every one of which will appear on a customer's dependency scan of a security appliance. It also blocks any "zero known CVEs" claim for the fork.

**Fix**

Create `core/screen/screen.go` with the two six-line functions (the non-Windows path is literally `fmt.Print("\033[2J")` and `fmt.Print("\033[H")`; keep the kernel32 path from clear_windows.go if Windows console support matters) and swap monitor.go:17 to `"lancarsec/core/screen"`. Verified in a scratch copy: after this substitution `go mod tidy && go build ./...` succeeds and golang.org/x/crypto disappears from `go list -m all` entirely.

*Verifier:* Verified end to end. monitor.go:17 is the sole `github.com/inancgumus/screen` import; `go mod why -m golang.org/x/crypto` returns exactly the quoted three-line chain through ssh/terminal; the module-cache dimensions.go is byte-for-byte as quoted (16 lines); `go list -deps ./...` does contain `golang.org/x/crypto/ssh/terminal`; monitor.go:68 uses `term.GetSize` directly; grep confirms screen.Size() is never called and screen.Clear/MoveTopLeft are the only uses (monitor.go:39-40, 80-81, 342-343, 348-349, 351-352, 358-359, 376-377, 384-385, 390-391 — all ten pairs correct); `grep -c 'Module: golang.org/x/crypto$'` on -show verbose = 20. I reproduced the fix: vendored a 6-line core/screen and repointed the import — builds clean, x/crypto gone from go.mod's require block and from `go list -deps` (0 hits). One evidentiary overreach in the fix text: x/crypto does NOT disappear from `go list -m all` (it lingers at v0.24.0 in the wider module graph even though `go mod why` then says the main module does not need it). Severity dropped one level: all 20 advisories are SSH/knownhosts issues in code that is never called (govulncheck reports zero called non-stdlib vulns) — the impact is SBOM/compliance noise, not exploitability, which the finding itself concedes.

### io/ioutil, deprecated since the go.mod's own Go 1.19, is still imported in three files

- **Dimension:** deps-toolchain  
- **Location:** `core/config/init.go:13`  
- **Effort:** trivial

**Evidence**

`staticcheck ./...` output:
```
core\config\generate.go:9:2: "io/ioutil" has been deprecated since Go 1.19 ... (SA1019)
core\config\init.go:13:2: "io/ioutil" has been deprecated since Go 1.19 ... (SA1019)
core\utils\domain.go:7:2: "io/ioutil" has been deprecated since Go 1.19 ... (SA1019)
core\utils\text.go:191:6: func closestTo10 is unused (U1000)
```
Call sites: config/generate.go:53 and :96 `ioutil.WriteFile("config.json", jsonConfig, 0644)`, generate.go:109 `ioutil.ReadAll(resp.Body)`, config/init.go:244 `ioutil.ReadAll(resp.Body)`, utils/domain.go:44 `ioutil.WriteFile("config.json", jsonConfig, 0644)`.
(staticcheck v0.x was already installed locally at ~/go/bin/staticcheck.exe; govulncheck was NOT installed and I installed golang.org/x/vuln/cmd/govulncheck@latest -> v1.7.0 to run it.)

**Impact**

Three of five ioutil calls write `config.json` — the file holding `AdminSecret`, `APISecret` and the cookie/JS/captcha secrets (generate.go:23-24, 31-35) — at mode 0644, world-readable. Moving to `os.WriteFile` is the moment to fix the mode to 0600. The deprecated import also blocks adopting `golangci-lint` with SA1019 enabled.

**Fix**

Mechanical: `ioutil.ReadAll` -> `io.ReadAll`, `ioutil.WriteFile` -> `os.WriteFile`, and drop the import. While editing, change the two config-writing sites (generate.go:53, generate.go:96, utils/domain.go:44) from 0644 to 0600. Also delete the dead `closestTo10` at utils/text.go:191 that staticcheck flags.

*Verifier:* Reproduced exactly. `staticcheck ./...` emits precisely the four quoted diagnostics (generate.go:9, init.go:13, domain.go:7 SA1019; text.go:191 closestTo10 U1000) and exits 1. All five call sites verified: generate.go:53 and :96 are `ioutil.WriteFile("config.json", jsonConfig, 0644)`, generate.go:109 and init.go:244 are `ioutil.ReadAll(resp.Body)`, domain.go:44 is the third 0644 WriteFile. config.json really does hold AdminSecret and APISecret (generate.go:23-24) and the cookie/javascript/captcha secrets (generate.go:31-35), so the 0644 observation is a legitimate secondary finding, not padding — a world-readable secret file on a shared host is the actual risk here, more than the deprecation. text.go:191 `func closestTo10(n int) int` is confirmed dead. The mechanical fix is correct.

### .gitignore does not cover config.json, private keys, or build output paths

- **Dimension:** ops-build  
- **Location:** `.gitignore:9-24`  
- **Effort:** trivial

**Evidence**

`git check-ignore -v config.json` returns nothing (not ignored); `git check-ignore -v oryxBuildBinary; echo rc=$?` → "rc=1" (not ignored). The whole ignore file is a stock toptal template — `.gitignore:9-14` (`*.exe`, `*.dll`, `*.so`, `*.dylib`, `*Cache.db*`), `.gitignore:23-24` (`main`, `crash.log`) — with no entry for `config.json`, `*.key`, `*.pem`, `*.crt`, `dist/`, or `*.db`. Meanwhile `core/config/init.go:27` opens `config.json` and `examples/config.json:5-11` shows what it holds: `"adminsecret": "CHANGE_ME", "apisecret": "CHANGE_ME", "secrets": {"captcha": ..., "cookie": ..., "javascript": ...}`.

**Impact**

The single most secret-laden file the proxy produces — admin secret, API secret, and the three HMAC secrets that back the cookie/JS/captcha challenges, plus Discord webhook URLs — sits unignored in the working directory. One `git add -A` by an operator publishes the keys that let anyone mint valid challenge-bypass cookies for every protected domain. The same gap already let two different binaries be committed.

**Fix**

Replace the template with a deny-by-intent list: `config.json`, `config.*.json`, `*.key`, `*.pem`, `*.p12`, `*.db`, `dist/`, `bin/`, `main`, `lancarsec`, `oryxBuildBinary`, `crash.log`. Add a pre-commit hook or `gitleaks` CI job so a PEM header can never be committed again.

*Verifier:* Verified. `git check-ignore -v config.json` returns nothing and `git check-ignore -v oryxBuildBinary` exits rc=1 — neither is ignored. The file is the stock toptal template: .gitignore:9-14 are *.exe/*.exe~/*.dll/*.so/*.dylib/*Cache.db*, .gitignore:23-24 are main and crash.log, with no config.json, *.key, *.pem, *.crt, dist/ or *.db entry anywhere in its 51 lines. core/config/init.go:27 opens config.json and examples/config.json:5-11 shows adminsecret, apisecret and the captcha/cookie/javascript secrets. Severity lowered one level: the impact requires an operator mistake (`git add -A`) to materialise — it is a latent exposure, not an active one, and the secrets are not currently in any tracked object. The deny-by-intent list plus a gitleaks gate is the right fix.

### 11 MB unstripped ELF binary `oryxBuildBinary` is committed and leaks full build provenance

- **Dimension:** ops-build  
- **Location:** `oryxBuildBinary`  
- **Effort:** small

**Evidence**

`git ls-files` lists `oryxBuildBinary` (last line). `file oryxBuildBinary` → "ELF 64-bit LSB executable, x86-64 ... dynamically linked ... with debug_info, not stripped", 11,250,895 bytes. `go version -m oryxBuildBinary` prints: "oryxBuildBinary: go1.23.1 / path goProxy / mod goProxy (devel)", the complete dependency list with h1: hashes, and build settings `CGO_ENABLED=1`, `GOOS=linux`, `GOAMD64=v1`, `vcs=git`, `vcs.revision=1ba331b98f44016c99c9a50ab544e742a0c328a8`, `vcs.time=2024-07-12T17:40:45Z`, `vcs.modified=false`, plus a full `DefaultGODEBUG=asynctimerchan=1,...,tls10server=1,tls3des=1,tlsrsakex=1,...`. `strings` recovers build-machine paths `/go/pkg/mod/github.com/...` and `/usr/local/go/src/...`. The filename identifies Microsoft Oryx (Azure App Service / Codespaces build system) as the producer.

**Impact**

An attacker downloading the repo gets the exact source commit, Go version, and CGO/GODEBUG posture of an official build of a DDoS-mitigation proxy — enough to pick matching stdlib CVEs (see the binary vuln finding) and to reconstruct the deploy pipeline. The `debug_info`/symbol table also makes reversing the challenge/PoW logic trivial. It is also 11 MB of dead weight in every clone.

**Fix**

`git rm --cached oryxBuildBinary`, add it plus `main`, `dist/`, `*.elf` to `.gitignore`, and purge it from history with `git filter-repo --path oryxBuildBinary --path main --invert-paths` before the LancarSec fork is published. Never commit build output; publish releases as CI artifacts instead.

*Verifier:* Verified. `git ls-files` lists oryxBuildBinary as its last entry; `file` reports "ELF 64-bit LSB executable, x86-64 ... with debug_info, not stripped" at 11,250,895 bytes; `go version -m` prints go1.23.1 / path goProxy / mod goProxy (devel), the full h1: dep list, and build settings CGO_ENABLED=1, GOOS=linux, GOAMD64=v1, vcs.revision=1ba331b98f44016c99c9a50ab544e742a0c328a8, vcs.time=2024-07-12T17:40:45Z, vcs.modified=false, DefaultGODEBUG=asynctimerchan=1,...,tls10server=1,tls3des=1,tlsrsakex=1,.... All exactly as claimed. Severity lowered one level: the 'leaks provenance' and 'makes reversing the challenge/PoW logic trivial' impact is thin for a GPL project whose full source (including the PoW and OTP logic) is already public in the same repo — the commit hash and dep list add nothing an attacker cannot read from the tree. The genuine, verified cost is a committed 11 MB build artifact and repo bloat, which is ops hygiene, not a high-severity security exposure. Fix is sound.

### CI runs CodeQL only — no build, vet, gofmt, lint, or test gate; `go vet` currently fails

- **Dimension:** ops-build  
- **Location:** `.github/workflows/codeql.yml:12-48`  
- **Effort:** medium

**Evidence**

`ls -R .github` → only `workflows/codeql.yml` and `workflows/release.yml`. codeql.yml is the unmodified GitHub template (`:12` `name: "CodeQL"`, `:48` `build-mode: autobuild`), and release.yml does no verification before publishing. `git ls-files | grep -c "_test.go"` → `0`. And `go vet ./...` fails today: `core\firewall\eval.go:30:6: fmt.Println call has possible Printf formatting directive %d`, from `core/firewall/eval.go:30` `fmt.Println("[ ! ] [ Error Evaluating Rule %d : %s ]\n", index, err.Error())`.

**Impact**

A DDoS-mitigation proxy with zero tests ships on every push to main, and a bug `go vet` catches for free — firewall rule-evaluation errors printing literal `%d : %s` instead of the rule index and error — has survived into releases, so operators debugging a broken firewall rule get no usable diagnostics. Nothing prevents a non-compiling or non-formatted commit reaching the `latest` release.

**Fix**

Add a `ci.yml` running `go build ./...`, `go vet ./...`, `gofmt -l . | tee /dev/stderr | (! read)`, `go test -race ./...` and `govulncheck ./...` on PRs and as a prerequisite job for the release workflow. Fix eval.go:30 to `fmt.Printf("[ ! ] [ Error Evaluating Rule %d : %s ]\n", index, err)`. Start tests with the firewall DSL evaluator and the challenge/OTP helpers.

*Verifier:* Verified on every claim. .github/workflows contains only codeql.yml and release.yml; codeql.yml is the unmodified template (:12 name: "CodeQL", :48 build-mode: autobuild) and release.yml runs no verification before publishing. `git ls-files | grep -c _test.go` → 0. And `go vet ./...` does fail today with exactly `core\firewall\eval.go:30:6: fmt.Println call has possible Printf formatting directive %d`, matching core/firewall/eval.go:30 `fmt.Println("[ ! ] [ Error Evaluating Rule %d : %s ]\n", index, err.Error())` — so firewall rule-evaluation errors really do print the literal format string instead of the rule index. Medium is right. The proposed fix `fmt.Printf("...%d : %s ]\n", index, err)` is valid Go (%s formats an error via its Error method) and vet-clean.

### Generated config.json holding all proxy secrets is written mode 0644

- **Dimension:** ops-build  
- **Location:** `core/config/generate.go:53`  
- **Effort:** trivial

**Evidence**

`core/config/generate.go:53` `err = ioutil.WriteFile("config.json", jsonConfig, 0644)`; same mode at `core/config/generate.go:96` and `core/utils/domain.go:44` (`err = ioutil.WriteFile("config.json", jsonConfig, 0644)`). The file contains `adminsecret`, `apisecret` and the captcha/cookie/javascript secrets per `examples/config.json:5-11`.

**Impact**

On a shared host every local user can read the proxy's admin secret, API secret and challenge HMAC keys — enough to forge Stage 1/2/3 bypass tokens and to drive the admin API. Deployments that run the proxy as root (the documented systemd/screen pattern in README:60) leave the file readable by every unprivileged account on the box.

**Fix**

Write with `0600` and `os.WriteFile`, and `os.Chmod("config.json", 0600)` on load if the mode is wider; refuse to start (or log loudly) when the config file is group/world-readable, the way ssh does for private keys.

*Verifier:* Verified verbatim at all three sites: core/config/generate.go:53 and :96 and core/utils/domain.go:44 are each `err = ioutil.WriteFile("config.json", jsonConfig, 0644)` (grep -n WriteFile over core/ returns exactly these three lines). The file marshalled at those points is domains.Config, whose shape per examples/config.json:5-11 carries adminsecret, apisecret and the three challenge HMAC secrets, and README:60 documents running the proxy under systemd or screen as the deploying user. Severity medium is correct — local-only exposure requiring an existing unprivileged account on the box. The 0600 + os.WriteFile fix works and does not break anything; the ssh-style startup warning on a wide mode is a good addition.

### Git history contains 91 committed binaries totalling ~992 MB; pack is 312 MiB

- **Dimension:** ops-build  
- **Location:** `.gitignore:23`  
- **Effort:** medium

**Evidence**

`git rev-list --objects --all | git cat-file --batch-check ... | awk '$1=="blob" && $2>1000000'` → "big blobs: 91 total bytes: 992538556"; by name: 88 × `main`, 3 × `oryxBuildBinary`, largest 13,914,867 bytes. `git count-objects -vH` → "in-pack: 1689 / packs: 2 / size-pack: 311.91 MiB" for a 3,098-line codebase. `.gitignore:23` only added `main` after the fact, so the 88 historical copies remain.

**Impact**

Every clone of the LancarSec fork downloads 312 MiB to get ~100 KB of Go source; CI checkouts, Docker build contexts and mirrors all pay it. Deleting the working-tree files does nothing — the objects stay reachable forever, and each of those 88 `main` blobs is an unstripped binary carrying its own build provenance and stdlib CVE set.

**Fix**

Before the fork's first public push, run `git filter-repo --path main --path oryxBuildBinary --invert-paths --force` (or start a fresh history with a single squashed commit, keeping the upstream repo link for GPL attribution), then `git gc --prune=now --aggressive` and force-push. Verify with `git count-objects -vH` afterwards.

*Verifier:* Verified exactly. The awk census over `git rev-list --objects --all` returns "count: 91  bytes: 992538556", and `git count-objects -vH` returns "in-pack: 1689 / packs: 2 / size-pack: 311.91 MiB" for a repo with 45 tracked files. .gitignore:23 is `main`, confirming it was added after the fact. Severity lowered one level: this is a real and expensive repository-hygiene problem (312 MiB clone for ~100 KB of source, paid by every CI checkout and Docker build context) but it is not itself a security weakness — the secret-bearing objects it also preserves are covered by real-private-key-committed. The filter-repo + gc + force-push fix works, and doing it before the fork's first public push is the correct sequencing.

### Neither the Dockerfile nor the release workflow uses -trimpath, -buildvcs=false, or -ldflags='-s -w'

- **Dimension:** ops-build  
- **Location:** `Dockerfile:11`  
- **Effort:** trivial

**Evidence**

`Dockerfile:11` `RUN go build -o main .`; `.github/workflows/release.yml:30` `run: go build -ldflags "-X 'main.Fingerprint=${{ env.uuid }}'" -o dist/main` — no `-trimpath`, no `-buildvcs=false`, no `-s -w`. Measured on this tree with go1.25.4: plain `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build` → 11,741,039 bytes; adding `-trimpath -buildvcs=false -ldflags="-s -w"` → 8,097,976 bytes (31% smaller).

**Impact**

Released binaries embed the builder's absolute source paths, the git revision and dirty-state, and a full symbol table + DWARF — exactly the leakage already demonstrated by `go version -m oryxBuildBinary`. Builds are also not byte-reproducible, so no one can verify that a published release corresponds to the tagged source of a security product.

**Fix**

Standardise on `CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -X main.Version=$TAG"` in a Makefile used by both the Dockerfile and CI, and publish `sha256sum` output alongside each artifact.

*Verifier:* Verified, including the measurement. Dockerfile:11 is `RUN go build -o main .` and .github/workflows/release.yml:30 is `run: go build -ldflags "-X 'main.Fingerprint=${{ env.uuid }}'" -o dist/main` — neither carries -trimpath, -buildvcs=false or -s -w. I reproduced the size figures on this tree with go1.25.4 byte-for-byte: plain GOOS=linux GOARCH=amd64 CGO_ENABLED=0 build → 11,741,039 bytes; with -trimpath -buildvcs=false -ldflags="-s -w" → 8,097,976 bytes (31.0% smaller). The leakage claim is corroborated by the committed artifact's own `go version -m` output (vcs.revision, vcs.time, vcs.modified all embedded). Medium is right — a supply-chain verifiability and hygiene gap, not a directly exploitable one. The single-Makefile fix is sound.

### No dependabot config; direct deps are ~2 years stale with known advisories, including the http2 stack in use

- **Dimension:** ops-build  
- **Location:** `go.mod:9-11`  
- **Effort:** small

**Evidence**

`ls .github/dependabot.yml` → "No such file or directory". `go.mod:9-11` pins `golang.org/x/image v0.17.0`, `golang.org/x/net v0.26.0`; `:16` `golang.org/x/text v0.16.0`; `:27` `golang.org/x/crypto v0.24.0`. `x/net` is used directly for the server's HTTP/2: `core/server/serve.go:19` `"golang.org/x/net/http2"`, `:46` and `:79-80` `http2.ConfigureServer(service, &http2.Server{})`. `govulncheck -show=verbose ./...` reports for these modules: "GO-2026-4918 Infinite loop in HTTP/2 transport when given bad SETTINGS_MAX_FRAME_SIZE ... Found in: golang.org/x/net@v0.26.0 Fixed in: golang.org/x/net@v0.53.0", "GO-2026-5026 ... golang.org/x/net/idna ... Fixed in v0.55.0", "GO-2026-5970 Infinite loop on invalid input in golang.org/x/text ... Fixed in v0.39.0", "GO-2026-6222 Excessive memory allocation during VP8L decoding in golang.org/x/image ... Fixed in v0.45.0", "GO-2026-6303 ... golang.org/x/crypto/ssh ... Fixed in v0.55.0".

**Impact**

The HTTP/2 library that terminates attack traffic is 27 minor versions behind and carries an infinite-loop DoS advisory; x/image is what the captcha generator depends on and has a memory-exhaustion advisory. For a product whose whole job is absorbing hostile traffic, unpatched DoS bugs in the parsing layer are the worst possible place to be stale, and nothing in the repo will ever tell the maintainer a fix shipped.

**Fix**

Add `.github/dependabot.yml` with `package-ecosystem: gomod` (weekly) plus `github-actions` (weekly), run `go get -u ./... && go mod tidy` now to land x/net ≥0.55.0, x/text ≥0.39.0, x/image ≥0.45.0, x/crypto ≥0.55.0, and gate merges on `govulncheck ./...`.

*Verifier:* Verified. `ls .github/dependabot.yml` → no such file. go.mod:9-10 are golang.org/x/image v0.17.0 and golang.org/x/net v0.26.0, :16 is golang.org/x/text v0.16.0, :27 is golang.org/x/crypto v0.24.0. x/net is imported directly for HTTP/2 at core/server/serve.go:19, and http2.ConfigureServer is called at :46 and again at :79-80. I re-ran the scan and every advisory reproduces: GO-2026-4918 x/net@v0.26.0 → fixed v0.53.0, GO-2026-5026 x/net@v0.26.0 → fixed v0.55.0, GO-2026-5970 x/text@v0.16.0 → fixed v0.39.0, GO-2026-6222 x/image@v0.17.0 → fixed v0.45.0, GO-2026-6303 x/crypto@v0.24.0 → fixed v0.55.0. One impact correction: govulncheck places GO-2026-6222 (VP8L decoding) in the not-called bucket — the captcha generator draws images rather than decoding WebP, so that particular advisory is not currently reachable; the x/net HTTP/2 ones are the reachable half. Medium stands and the dependabot + go get -u + govulncheck-gate fix is correct.

### Releases go to a rolling `latest` prerelease tag with no checksum, signature, or SBOM

- **Dimension:** ops-build  
- **Location:** `.github/workflows/release.yml:36-43`  
- **Effort:** medium

**Evidence**

`.github/workflows/release.yml:36-38` `automatic_release_tag: "latest"` / `prerelease: true` / `title: "Prerelease ${{ env.uuid }}"`, `:39-40` `files: | dist/main`, `:42` `body: | This is an automatic build that might have bugs.` The workflow fires on every push to main (`:3-6`) and builds one `linux/amd64` artifact only. README:55 tells operators: "To start, download the latest version of balooProxy ... or compile it from source."

**Impact**

Every commit silently overwrites the artifact users are told to download, with no version tag, no `sha256` file, no cosign signature and no SBOM. An operator cannot tell which source produced the binary they are running, and a compromised runner or the unpinned action above can swap the artifact undetected — the classic distribution-channel attack against a security appliance.

**Fix**

Release on `on: push: tags: ['v*']` only, build a matrix (linux/amd64+arm64), emit `sha256sums.txt`, sign with `cosign sign-blob --yes`, attach a CycloneDX SBOM (`cyclonedx-gomod`), and enable GitHub artifact attestations (`actions/attest-build-provenance`).

*Verifier:* Verified. .github/workflows/release.yml:36-38 are `automatic_release_tag: "latest"` / `prerelease: true` / `title: "Prerelease ${{ env.uuid }}"`, :39-40 are `files: | dist/main`, and :42 is the `This is an automatic build that might have bugs.` body. The trigger at :3-6 is every push to main, only one linux/amd64 artifact is produced, and there is no checksum, signature or SBOM step anywhere in the 43-line file. README:55 does direct operators to the releases page. Medium is right — a distribution-integrity gap that becomes exploitable only in combination with a compromised runner or the unpinned action above. The tag-triggered, matrix, sha256sums + cosign + SBOM + attestation fix is standard and workable.

### Startup and version check fetch data from the upstream author's GitHub repo, with errors discarded and no timeout

- **Dimension:** ops-build  
- **Location:** `core/config/init.go:104-106`  
- **Effort:** small

**Evidence**

`core/config/init.go:104-106`: `GetFingerprints("https://raw.githubusercontent.com/41Baloo/balooProxy/main/global/fingerprints/known_fingerprints.json", &firewall.KnownFingerprints)` and the same for `bot_fingerprints.json` and `malicious_fingerprints.json` — return values are discarded at all three call sites. `core/config/generate.go:103` implements it with a bare `resp, err := http.Get(url)` (default client, no timeout). `core/config/init.go:238` `func VersionCheck()` GETs `https://raw.githubusercontent.com/41Baloo/balooProxy/main/global/proxy/version.json`, and `global/proxy/version.json` says `"download": "https://github.com/41Baloo/balooProxy/releases/download/1.5/main"`. `strings -a oryxBuildBinary` confirms all four URLs are baked into the shipped binary.

**Impact**

LancarSec's firewall classification tables — the known/bot/malicious TLS fingerprint maps that decide who gets challenged — would be downloaded at every boot from a third party the fork does not control, with the fetch failing silently (empty maps, so every client looks like an unknown fingerprint) and with no client timeout, so an unreachable or tarpitting host stalls startup indefinitely. The version check additionally advertises an upstream download URL to the operator's console.

**Fix**

Ship the JSON in the repo (`global/fingerprints/*.json` already exist) and load from disk or `//go:embed`; keep updates as an explicit, signed, opt-in refresh against a LancarSec-controlled host using an `http.Client{Timeout: 10*time.Second}`. Check the error at all three call sites and fail loudly. Point `VersionCheck` at a LancarSec endpoint or remove it.

*Verifier:* Verified. core/config/init.go:104, :105 and :106 are three bare `GetFingerprints("https://raw.githubusercontent.com/41Baloo/balooProxy/main/global/fingerprints/{known,bot,malicious}_fingerprints.json", &firewall....)` calls with the returned error discarded at all three sites. core/config/generate.go:102-103 implements it as `resp, err := http.Get(url)` on the default client — no Timeout, confirmed by reading the function. core/config/init.go:237-238 is `func VersionCheck() error { resp, err := http.Get("https://raw.githubusercontent.com/41Baloo/balooProxy/main/global/proxy/version.json")`, and global/proxy/version.json does carry "download": "https://github.com/41Baloo/balooProxy/releases/download/1.5/main". Medium is if anything conservative for a fork: whoever controls that upstream path controls which TLS fingerprints LancarSec classifies as known/bot/malicious, the failure mode is silent (empty maps, so every client reads as an unknown fingerprint and the discarded error hides it), and the default client will not time out. The //go:embed fix is correct and the local JSON already exists in global/fingerprints/.

### The committed binary is built on go1.23.1 and carries 33 reachable stdlib vulnerabilities

- **Dimension:** ops-build  
- **Location:** `oryxBuildBinary`  
- **Effort:** small

**Evidence**

`govulncheck -mode=binary oryxBuildBinary` → "Your code is affected by 33 vulnerabilities from the Go standard library." Symbol-confirmed examples: "GO-2026-6090 Limit handshake messages we are willing to accept post-handshake in crypto/tls ... Found in: crypto/tls@go1.23.1 ... Vulnerable symbols found: tls.Conn.Handshake, tls.Conn.HandshakeContext, tls.Conn.Read, tls.Conn.Write, tls.Dialer.DialContext"; "GO-2026-6089 Apply ReadHeaderTimeout when doing unencrypted HTTP/2 check in net/http"; "GO-2026-6218 Avoid quadratic complexity in resolvePath in net/url".

**Impact**

Anyone who runs the checked-in binary (or a release built the same way) is running a DoS-mitigation proxy that is itself DoS-able through crypto/tls post-handshake message flooding and net/url quadratic path resolution — the exact attack class the product exists to stop.

**Fix**

Delete the artifact, and add a `govulncheck ./...` gate to CI that fails the build on any stdlib or module finding. Rebuild on go1.25.x (currently ≥1.25.13 to clear GO-2026-6090/6089/6218) and re-run `govulncheck -mode=binary` on the release artifact before publishing.

*Verifier:* Verified by re-running the scan: `govulncheck -mode=binary oryxBuildBinary` ends with "Your code is affected by 33 vulnerabilities from the Go standard library" and a targeted grep confirms GO-2026-6090, GO-2026-6089 and GO-2026-6218 are all among them, found in go1.23.1 stdlib packages. Severity lowered one level: the impact sentence 'anyone who runs the checked-in binary' does not follow from anything in the repo — README:55 points operators at the GitHub releases page, not at oryxBuildBinary, which is an Oryx build leftover no documentation references. The real unpatched-runtime exposure lives in the release pipeline (release.yml:20 pins go-version 1.19, which is worse) and is already covered by go-1-19-toolchain-eol. The govulncheck CI gate in the fix is correct and worth doing.

### Three different Go versions across the repo, the declared one (1.19) being EOL

- **Dimension:** ops-build  
- **Location:** `go.mod:3`  
- **Effort:** small

**Evidence**

`go.mod:3` `go 1.19`; `Dockerfile:1` `FROM golang:1.19-alpine`; `.github/workflows/release.yml:20` `go-version: "1.19"`; but the committed artifact reports `go1.23.1` (`go version -m oryxBuildBinary`). No `toolchain` directive anywhere in go.mod (lines 1-30).

**Impact**

Go 1.19 stopped receiving security fixes in Aug 2023, so the documented build path produces a proxy with roughly two years of unpatched net/http, crypto/tls and net/url issues — and the artifact people actually download was built with a fourth, undeclared version, so no one can reason about which stdlib CVEs a given binary carries. The 1.19 floor also blocks the language and runtime features (`min`/`max`, `slices`/`maps`, PGO, improved timers) this refactor wants.

**Fix**

Set `go 1.25` plus `toolchain go1.25.4` in go.mod, bump the Docker base to a digest-pinned `golang:1.25-alpine`, and change CI to `go-version-file: go.mod` so the three places can never diverge again. Then run `go mod tidy` and re-check `go vet ./...`.

*Verifier:* Verified. go.mod:3 is `go 1.19`, Dockerfile:1 is `FROM golang:1.19-alpine`, .github/workflows/release.yml:20 is `go-version: "1.19"`, and the committed artifact reports go1.23.1 — four versions, three declared, none agreeing. I read all 30 lines of go.mod: there is no toolchain directive. Medium is right. The fix works: setting go 1.25 + toolchain go1.25.4 and switching CI to go-version-file: go.mod collapses the three declarations into one. Worth flagging that go1.25.4 is not itself current — `govulncheck ./...` on this tree with the local go1.25.4 still reports 20 called stdlib vulnerabilities including GO-2026-6090/6089/6218 (all fixed in go1.25.13), so the toolchain line should target 1.25.13 or later, not 1.25.4.

### A 21-entry map[string]interface{} plus net.ParseIP plus strings.ToLower is built for every request when any firewall rule exists

- **Dimension:** performance  
- **Location:** `core/server/middleware.go:150-177`  
- **Effort:** medium

**Evidence**

middleware.go:151-175 —
		requestVariables := gofilter.Message{
			"ip.src":                net.ParseIP(ip),
			...
			"http.user_agent": strings.ToLower(reqUa),
			...
		}
		susLv = firewall.EvalFirewallRule(domainSettings, requestVariables, susLv)

gofilter looks fields up lazily by name (`applyRange` does `v, ok := p[n.FieldName()]`, nodes.go:668), so a rule that tests one field still pays for all 21.

**Impact**

Benchmarked at 891 ns/op, 1424 B/op, 9 allocs/op (map header + buckets + the ParseIP 16-byte slice + ToLower's copy of a ~120-byte UA + interface boxing of the int fields). At 50k req/s that is ~4.5% of a core, 450k allocs/s and 71 MB/s of garbage, for data most rulesets never read. `strings.ToLower` and `net.ParseIP` are each paid unconditionally even when no rule references http.user_agent or ip.src.

**Fix**

Compute the union of field names actually referenced by the domain's compiled rules once at config load, and populate only those keys (gofilter's node interface exposes FieldName()). Reuse the map from a sync.Pool and clear it per request instead of allocating a new one. Make ip.src / http.user_agent lazily materialised — parse the IP and lowercase the UA only when a rule in the set names them.

*Verifier:* Code verified: middleware.go:151-175 builds a gofilter.Message literal with exactly 21 keys (I counted them) on every request where `len(domainSettings.CustomRules) != 0` (:150), including unconditional net.ParseIP(ip) at :152 and strings.ToLower(reqUa) at :165. Lazy field lookup confirmed in the module cache at gofilter/nodes.go:664-666 (`v, ok := p[n.FieldName()]`) — the finding's cited line 668 is off by ~3 but the code is there. Severity reduced one level: cost is entirely conditional on a domain having firewall rules configured. One caveat on the fix: gofilter's `node` interface and its FieldName() method (nodes.go:16) are unexported and Filter exposes no node walker, so the referenced-field union must be derived from the raw expression strings (already retained in DomainSettings.RawCustomRules) rather than from the node API; the sync.Pool/lazy-materialisation half of the fix is fine.

### Cache key built by concatenating IP + full TLS fingerprint + User-Agent + hour on every request, three times

- **Dimension:** performance  
- **Location:** `core/server/middleware.go:184-185,204`  
- **Effort:** medium

**Evidence**

middleware.go:184-185 —
	accessKey := ip + tlsFp + reqUa + proxy.CurrHourStr
	encryptedCache, encryptedExists := firewall.CacheIps.Load(accessKey + susLvStr)

and again at :204 `firewall.CacheIps.Store(accessKey+susLvStr, encryptedIP)`. `tlsFp` is the full hex cipher list from fingerprint.go:62-79, typically 400–700 bytes.

**Impact**

Benchmarked at 202.6 ns/op, 848 B/op, 3 allocs/op for the two concatenations alone. At 50k req/s: 150k allocs/s and ~42 MB/s of garbage, plus the sync.Map lookup must then hash a ~700-byte key (another few hundred ns of memory traffic per request). None of this data changes between requests from the same client.

**Fix**

Key the cache on a fixed-size value instead of a giant string: compute `blake3.Sum256` (or maphash) over ip/tlsFp/ua/hour written into a stack `[]byte` via append, and use the resulting [32]byte array (comparable, zero-alloc as a map key) — or better, cache the derived cookie on the *connection* (keyed by RemoteAddr in firewall.Connections) since ip+tlsFp+ua are constant for a keep-alive connection, making this a single pointer load per request.

*Verifier:* Code verified: middleware.go:184 `accessKey := ip + tlsFp + reqUa + proxy.CurrHourStr`, :185 `CacheIps.Load(accessKey + susLvStr)`, :204 `CacheIps.Store(accessKey+susLvStr, ...)`. tlsFp is the raw hex list built in fingerprint.go:62-79 and the sample fingerprints in that file run 200-700 bytes, so the key-size claim holds in origin mode. Severity reduced one level: in Cloudflare mode tlsFp is the literal "Cloudflare" (middleware.go:63) so the key is tiny, and the measured ~200 ns/3 allocs per request is a real but second-order cost next to the global-mutex and transport findings. The hash-key/per-connection-cache fix is sound.

### Cache sweeper holds the global request mutex while ranging both caches, including a full scan whose result is discarded

- **Dimension:** performance  
- **Location:** `core/server/monitor.go:539-570`  
- **Effort:** trivial

**Evidence**

monitor.go:539 `firewall.Mutex.Lock()` … monitor.go:559-563 —
		imgCachelen := 0
		firewall.CacheImgs.Range(func(key, value any) bool {
			imgCachelen++
			return true
		})
… monitor.go:570 `firewall.Mutex.Unlock()`. `imgCachelen` is never read again.

**Impact**

Every 2 minutes the proxy takes the lock that all requests need and holds it for a full O(n) walk of CacheImgs (dead code — the count is discarded) plus, when the condition fires, an O(n) walk-and-delete of CacheIps and CacheImgs. With the unbounded CacheIps of the previous finding holding millions of entries, that is seconds of complete request-path freeze, twice-visible as a latency cliff every 120 s. Neither sync.Map needs this lock at all — they carry their own synchronisation.

**Fix**

Delete the `imgCachelen` loop entirely. Drop `firewall.Mutex` from clearProxyCache — the caches are sync.Maps. If a size bound is wanted, track it with an atomic counter incremented at Store time rather than by scanning.

*Verifier:* Verified: firewall.Mutex.Lock() at monitor.go:539, Unlock at :570, and the CacheImgs counting Range at :559-563 whose `imgCachelen` is written at 559/561 and never read again (grep confirms only those two occurrences) — dead code executed every 2 minutes while holding the request lock. Both sync.Maps carry their own synchronisation so the lock is unnecessary. Severity reduced one level: the walk runs once per 120 s and CacheImgs is keyed on a 6-char captcha prefix so its cardinality is far smaller than CacheIps; the 'seconds of complete freeze' figure is speculative, the lock-held-O(n)-walk itself is not.

### Client IP extracted with strings.Split on every non-Cloudflare request, allocating a slice per request

- **Dimension:** performance  
- **Location:** `core/server/middleware.go:73`  
- **Effort:** trivial

**Evidence**

middleware.go:73 —
		ip = strings.Split(request.RemoteAddr, ":")[0]

**Impact**

Benchmarked at 63.69 ns/op with 2 allocs (the []string header plus its backing array) versus 44.43 ns/op and 1 alloc for net.SplitHostPort, and 0 allocs for a manual LastIndexByte slice. At 50k req/s that is 100k allocs/s of pure waste. It is also wrong for IPv6 peers — `[2001:db8::1]:443` yields `"[2001"`, which then becomes the ratelimit key, so every IPv6 client on the same /16-ish prefix shares one counter and one cache entry, corrupting both the ratelimiter and CacheIps.

**Fix**

`if i := strings.LastIndexByte(request.RemoteAddr, ':'); i > 0 { ip = strings.TrimSuffix(strings.TrimPrefix(request.RemoteAddr[:i], "["), "]") }` — zero allocations, since slicing a string does not copy. Or net.SplitHostPort if the error handling is wanted.

*Verifier:* Verified: middleware.go:73 `ip = strings.Split(request.RemoteAddr, ":")[0]` on the non-Cloudflare path. The IPv6 correctness claim is right and is the substantive part: for a peer of `[2001:db8::1]:443` this yields `[2001`, which then becomes the ratelimit key at :96/:217, the AccessIps lookup key at :79-80, the CacheIps key component at :184, and the x-real-ip value at :358 — so all IPv6 clients collapse onto one counter and one cache entry. The allocation claim is mildly overstated (Split's returned slice header stays on the stack here; it is normally one heap allocation for the backing array, not two). The LastIndexByte fix is correct.

### Counter increments copy the entire DomainData struct out of and back into a map, twice per request

- **Dimension:** performance  
- **Location:** `core/server/middleware.go:97-99,317-319; core/server/serve.go:93-97`  
- **Effort:** small

**Evidence**

middleware.go:97-99 —
		domainData = domains.DomainsData[domainName]
		domainData.TotalRequests++
		domains.DomainsData[domainName] = domainData

and middleware.go:317-319 repeats the pattern for BypassedRequests. DomainData (domains/domain.go:70-92) is ~20 fields including two slice headers — roughly 150-200 bytes.

**Impact**

Four full struct copies per request (read+write × 2 sites), each with a map hash of the host string, all inside the global write lock — so the copies extend the critical section that every other request is queued behind. At 50k req/s that is ~40 MB/s of memcpy and 200k map hashes, to increment two integers. serve.go:93-97 repeats the same pattern on the :80 redirect path.

**Fix**

Store `*DomainData` (or a dedicated counters struct with `atomic.Int64` fields) in the map, so an increment is `ctr.Total.Add(1)` — no lock, no hash, no copy. The Monitor's per-second delta computation reads the same atomics.

*Verifier:* Verified verbatim at middleware.go:97-99 (TotalRequests, inside the Lock at :88) and :317-319 (BypassedRequests, inside the Lock at :306), and the same read-modify-write appears on the :80 redirect path at serve.go:93-97. DomainData (domains/domain.go:70-92) is 17 fields including two slice headers, ~170 bytes by my layout count — matching the finding's 150-200 estimate — so each increment costs two map hashes of the host string plus two full struct copies, all inside the global write lock. The atomic-counters/pointer fix is sound and is the same remediation as the global-mutex finding.

### Firewall rule actions are re-parsed with fmt.Sscan on every request that matches a rule

- **Dimension:** performance  
- **Location:** `core/firewall/eval.go:18,28,38`  
- **Effort:** small

**Evidence**

eval.go:15-22 —
			switch rule.Action[:1] {
			case "+":
				var actionInt int
				_, err := fmt.Sscan(rule.Action[1:], &actionInt)

The action is a config-time constant string stored in domains.Rule{Filter, Action} (domains/domain.go:125-128) and never changes between reloads.

**Impact**

Benchmarked: fmt.Sscan on a one-digit string is 525.5 ns/op with 3 allocs (it builds a scan state and goes through reflection); strconv.Atoi is 7.76 ns/op with 0 allocs — 68× slower for identical output. With three matching rules that is ~1.6 µs and 9 allocs per request; at 50k req/s roughly 8% of a core and 450k allocs/s wasted re-parsing a constant. Note also the latent bug at eval.go:30 — `fmt.Println` with a format string, so that error path prints garbage instead of the message.

**Fix**

Parse once at config load: extend `domains.Rule` with `Delta int` and `Absolute bool` (or an enum), filled in config/init.go:120-123 and monitor.go:461-464 with strconv.Atoi, and reduce EvalFirewallRule to integer arithmetic with no parsing and no fmt.

*Verifier:* Verified: eval.go:18, :28 and :38 call fmt.Sscan on rule.Action, a config-time constant string (domains/domain.go:125-128, filled at config/init.go:120-123 and monitor.go:461-464 and never mutated afterwards). The latent bug at eval.go:30 is real — `fmt.Println("[ ! ] [ Error Evaluating Rule %d : %s ]\n", index, err.Error())` uses a format string with Println. Severity reduced one level: the parse only runs for rules whose filter actually matched (eval.go:13), and EvalFirewallRule itself only runs when the domain has rules (middleware.go:150), so the cost is config-dependent rather than unconditional. The strconv.Atoi/precomputed-enum fix is correct.

### Five header writes per request with non-canonical keys, ~10 allocations

- **Dimension:** performance  
- **Location:** `core/server/middleware.go:102,358-361`  
- **Effort:** trivial

**Evidence**

middleware.go:102 — `writer.Header().Set("baloo-Proxy", "1.5")`
middleware.go:358-361 —
	request.Header.Add("x-real-ip", ip)
	request.Header.Add("proxy-real-ip", ip)
	request.Header.Add("proxy-tls-fp", tlsFp)
	request.Header.Add("proxy-tls-name", browser+botFp)

None of these keys is in canonical form, and none is in net/http's interned common-header table, so textproto must canonicalise (and allocate) each one; `browser+botFp` is a further concatenation.

**Impact**

Benchmarked at 471.1 ns/op, 528 B/op, 10 allocs/op for just the four Add calls. At 50k req/s: 500k allocs/s, ~26 MB/s, ~2.4% of a core. `proxy-tls-fp` also copies the 400–700 byte fingerprint string reference into the upstream request on every proxied call.

**Fix**

Assign directly with pre-canonicalised keys and a preallocated one-element slice: `request.Header["X-Real-Ip"] = []string{ip}` etc., which skips canonicalisation entirely. Precompute `browser+botFp` alongside the fingerprint lookup (it is derived from tlsFp, so it can be cached per connection rather than recomputed per request).

*Verifier:* Verified: middleware.go:102 `writer.Header().Set("baloo-Proxy", "1.5")` and :358-361 four Add calls with lowercase keys plus a `browser+botFp` concatenation. I checked net/textproto's commonHeader table in the local GOROOT: it contains X-Forwarded-For, X-Imforwards and X-Powered-By but not X-Real-Ip, and nothing resembling Proxy-Real-Ip/Proxy-Tls-Fp/Proxy-Tls-Name, so each Add pays a non-interned canonicalisation allocation on top of the map/slice growth. The direct `request.Header["X-Real-Ip"] = []string{ip}` fix works and skips canonicalisation. Minor sloppiness in the write-up: assigning the fingerprint header copies a string header, not the 400-700 bytes (those bytes are written when the upstream request is serialised).

### RoundTrip acquires a pooled buffer for every request and returns a response body backed by that buffer after returning it to the pool

- **Dimension:** performance  
- **Location:** `core/server/serve.go:118-149,189-192`  
- **Effort:** small

**Evidence**

serve.go:120-122 —
	buffer := bufferPool.Get().(*bytes.Buffer)
	buffer.Reset()
	defer bufferPool.Put(buffer)

serve.go:146-149 —
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(buffer.Bytes())),
		}, nil

**Impact**

The deferred Put runs when RoundTrip returns, but ReverseProxy reads the returned Body afterwards — so the bytes being streamed to the client live in a buffer another goroutine has already checked out and Reset/written. Under concurrent backend errors (exactly what happens when the origin is being knocked over) clients receive interleaved or truncated error pages, and the race is a real data race on the buffer's backing array. Separately, the Get/Put pair is executed on the *success* path too, where the buffer is never used — pure overhead on every proxied request, and `resp.Body.Close()` is called twice on the 5xx path (:159 and :187).

**Fix**

Acquire the buffer only inside the two error branches, and copy out before returning: `body := make([]byte, buffer.Len()); copy(body, buffer.Bytes())` (or `bytes.NewReader(append([]byte(nil), buffer.Bytes()...))`), then Put. Remove the duplicate Close at :187. Since these pages are near-constant, prefer precomputed fragments as in the challenge-page finding.

*Verifier:* Verified and it is a genuine correctness bug, not just overhead: serve.go:120-122 gets a pooled buffer with `defer bufferPool.Put(buffer)`, and both error returns (serve.go:146-149 and :189-192) hand back `io.NopCloser(bytes.NewReader(buffer.Bytes()))` — a reader over the pooled backing array that is returned to the pool the instant RoundTrip returns, while ReverseProxy reads that body afterwards. Concurrent 5xx/dial-failure responses can therefore be served interleaved or truncated. The duplicate `resp.Body.Close()` at :159 and :187 is also confirmed (harmless but redundant), and the Get/Put pair does run on the success path at :195 where the buffer is untouched. The copy-out fix is correct.

### Sliding-window buckets have no cardinality cap, so a source-randomised flood grows the maps until OOM

- **Dimension:** performance  
- **Location:** `core/server/middleware.go:96,130,217 (eviction core/server/monitor.go:596-629)`  
- **Effort:** medium

**Evidence**

middleware.go:96 —
	firewall.WindowAccessIps[proxy.Last10SecondTimestamp][ip]++
middleware.go:130 —
			firewall.WindowUnkFps[proxy.Last10SecondTimestamp][tlsFp]++
middleware.go:217 —
		firewall.WindowAccessIpsCookie[proxy.Last10SecondTimestamp][ip]++

The only bound is time: monitor.go:599 evicts a bucket once `utils.TrimTime(windowTime)+proxy.RatelimitWindow < proxy.LastSecondTimestamp`, with RatelimitWindow defaulting to 120 (proxy/proxy.go:45).

**Impact**

There is no key-count limit. A spoofed-source or IPv6-rotating flood at 50k req/s with unique keys inserts 50k entries/s into WindowAccessIps and 50k more into WindowAccessIpsCookie; over the 120 s retention that is ~12M live map entries (roughly 1.5-2 GB with string keys and Go map overhead) before eviction begins, plus repeated map growth — each rehash of a multi-million-entry map happening inside the global write lock. WindowUnkFps is worse: its key is the 400-700 byte fingerprint string. Memory exhaustion is reachable purely by sending traffic, which is the attack this component exists to stop.

**Fix**

Cap the per-bucket key count (e.g. 200k) behind a helper `firewall.Incr(bucket, key)` that drops new keys once the cap is hit while still letting the request run the rest of the stack; and key the fingerprint window on a fixed-size hash of the fingerprint rather than the full string.

*Verifier:* Verified: unbounded key insertion at middleware.go:96 (WindowAccessIps[ts][ip]++), :130 (WindowUnkFps[ts][tlsFp]++, keyed on the full 400-700 byte fingerprint string built in fingerprint.go:62-79) and :217 (WindowAccessIpsCookie[ts][ip]++). The only bound is temporal: monitor.go:599/:610/:621 delete a bucket once `utils.TrimTime(windowTime)+proxy.RatelimitWindow < proxy.LastSecondTimestamp`, with RatelimitWindow defaulting to 120 (proxy/proxy.go:45, floor of 10 enforced at config/init.go:92-95) — no key-count cap anywhere. Map growth/rehash happens inside the global write lock, compounding the first finding. The capped `firewall.Incr` helper plus hashing the fingerprint key is a correct fix.

### TLS fingerprint string is built with `+= fmt.Sprintf` in a loop — O(n²) copying and ~80 allocations per handshake

- **Dimension:** performance  
- **Location:** `core/firewall/fingerprint.go:62-79`  
- **Effort:** small

**Evidence**

fingerprint.go:62-68 —
	fingerprint := ""
	for _, suite := range clientHello.CipherSuites[1:] {
		fingerprint += fmt.Sprintf("0x%x,", suite)
	}
(repeated for SupportedCurves at :71 and SupportedPoints at :76)

**Impact**

Benchmarked with a 30-element list: 8382 ns/op, 3706 B/op, 82 allocs/op. The equivalent `strconv.AppendUint` into a preallocated []byte is 388 ns/op, 224 B/op, 2 allocs — a 21× speedup and 16× less garbage. Real ClientHellos carry 40–70 entries and the cost is quadratic in that count, so 20–30 µs per handshake is realistic. A TLS-handshake flood at 20k handshakes/s therefore burns 0.4–0.6 of a core and 1.6M allocs/s purely on string building, and it does so on the path that then takes the global mutex at :82.

**Fix**

Build into a stack-allocated `buf := make([]byte, 0, 512)` with `buf = append(buf, '0','x'); buf = strconv.AppendUint(buf, uint64(suite), 16); buf = append(buf, ',')`, then one `string(buf)` conversion at the end. Same treatment for curves and points.

*Verifier:* Code verified exactly: fingerprint.go:62 `fingerprint := ""` then `fingerprint += fmt.Sprintf("0x%x,", ...)` at :67 (cipher suites), :72 (curves) and :77 (points) — quadratic string building plus a Sprintf allocation per element, followed by the global Mutex.Lock at :82-84. The strconv.AppendUint fix is correct and preserves the exact output format. Severity reduced one level: this runs once per TLS handshake, not per request, and only in non-Cloudflare mode (serve.go:71-77); tens of microseconds sits far below the asymmetric-crypto cost of the handshake it accompanies, so the '0.4-0.6 of a core at 20k handshakes/s' framing overstates the marginal impact.

### The JS and captcha challenge pages are assembled by concatenating multi-KB string literals, then copied again through the pooled buffer

- **Dimension:** performance  
- **Location:** `core/server/middleware.go:232,296 (via SendResponse at :25-28)`  
- **Effort:** medium

**Evidence**

middleware.go:25-28 —
func SendResponse(str string, buffer *bytes.Buffer, writer http.ResponseWriter) {
	buffer.WriteString(str)
	writer.Write(buffer.Bytes())
}

middleware.go:232 passes a single expression that concatenates ~4 KB of literal HTML with `publicSalt`, `hashedEncryptedIP`, `strconv.Itoa(domainData.Stage2Difficulty)` and more; :296 does the same with ~6 KB of literals plus `captchaData`/`maskData` base64 blobs and `ip`.

**Impact**

This is the hot path *under attack*: once a domain escalates to stage 2 or 3, essentially every request takes it. Benchmarked at a comparable shape, the concatenation alone costs 766.9 ns/op and 4112 B/op, and SendResponse then copies the whole result a second time into the pooled buffer before writing — roughly 8 KB of memory traffic and ~1.5 µs per challenge. At 50k challenges/s that is ~400 MB/s of copying and 7% of a core spent rebuilding a page whose bytes are constant except for three short substitutions.

**Fix**

Split each page into its constant fragments as package-level `[]byte` (or a parsed `text/template` executed straight into the ResponseWriter), and write fragment-variable-fragment directly to the writer — no intermediate string, no second copy. Set Content-Length from the precomputed fragment lengths so the response can be written in one syscall.

*Verifier:* Verified. middleware.go:232 passes one expression concatenating ~4 KB of literal HTML with publicSalt, hashedEncryptedIP and strconv.Itoa(domainData.Stage2Difficulty); :296 does the same with ~6 KB of literals plus captchaData/maskData and ip. SendResponse (middleware.go:25-28) then does buffer.WriteString(str) followed by writer.Write(buffer.Bytes()) — a second full copy through the pooled buffer. Both paths are the hot path once a domain sits at stage 2/3. Severity reduced one level: the pooled buffer is reused so the second copy is memcpy rather than allocation, and each challenge already carries a blake3/HMAC derivation plus (stage 3, on cache miss) PNG encoding, which dominate. Fragment/template fix is sound.

### The terminal UI issues one unbuffered write syscall per line every second and can stall the goroutine that publishes the timestamps the hot path depends on

- **Dimension:** performance  
- **Location:** `core/utils/text.go:53-63,92-97; core/server/monitor.go:66-98,213-218`  
- **Effort:** medium

**Evidence**

utils/text.go:92-97 —
func ClearScreen(length int) {
	fmt.Print("\033[s")
	for j := 1; j < 9+length; j++ {
		fmt.Println("\033[" + fmt.Sprint(j) + ";1H\033[K")
	}
}

utils/text.go:59-61 does one `fmt.Print` per log line, each with `fmt.Sprint(11+i)` string building, and FormatLogs (text.go:30-32) concatenates 9 fragments per line. The Monitor loop calls ClearScreen + printStats + ReadLogs every second (monitor.go:85-97) and takes `firewall.Mutex.Lock()` at :88 to walk all domains.

**Impact**

os.Stdout is unbuffered, so each fmt.Print is a separate write(2). With a 60-row terminal that is ~130 syscalls plus ~600 small string allocations per second, growing with terminal height. The real hazard: if stdout is a pipe (systemd journal, `tee`, a full terminal buffer) a write blocks, the Monitor loop stops, and printStats:213-218 — the only writer of `proxy.Last10SecondTimestamp` and `proxy.LastSecondTimeFormated` — stops publishing. Those are plain non-atomic globals read by every request (middleware.go:96, :184, :308) with no synchronisation, and middleware.go:96 indexes `firewall.WindowAccessIps[proxy.Last10SecondTimestamp]` — the code's own comment at :89-95 admits that a lagging monitor thread makes this 'freeze the entire proxy'.

**Fix**

Wrap stdout in a bufio.Writer and flush once per frame (one syscall per redraw); build the frame into a single []byte with strconv.AppendInt instead of fmt.Sprint per line. Decouple the clock: publish Last10SecondTimestamp / LastSecondTimestamp from a dedicated ticker goroutine into `atomic.Int64`s that never depend on rendering, and read them atomically in middleware.

*Verifier:* Verified. utils/text.go:92-97 ClearScreen emits one fmt.Println per row with an inner fmt.Sprint; text.go:59-61 emits one unbuffered fmt.Print per log line; FormatLogs (text.go:28-33) concatenates 9 fragments per line. The Monitor loop (monitor.go:66-98) runs ClearScreen + the locked domain walk (:88-92) + printStats + ReadLogs every second. The clock-coupling hazard checks out: printStats:213-218 is the only periodic writer of proxy.LastSecondTimestamp / Last10SecondTimestamp / LastSecondTimeFormated / CurrHourStr (Monitor:43-48 sets them once at startup), they are plain non-atomic globals in proxy/proxy.go:52-57, and they are read unsynchronised at middleware.go:96, :184 and :308 — with middleware.go:96 indexing WindowAccessIps by the frozen timestamp, exactly the hazard the in-repo comment at middleware.go:89-95 describes. Both halves of the fix (bufio frame + dedicated ticker publishing atomics) are sound.

### The whole DomainSettings value — including a tls.Certificate — is copied out of a sync.Map on every request

- **Dimension:** performance  
- **Location:** `core/server/middleware.go:145-146; core/domains/util.go:16-23`  
- **Effort:** small

**Evidence**

middleware.go:145-146 —
	settingsQuery, _ := domains.DomainsMap.Load(domainName)
	domainSettings := settingsQuery.(domains.DomainSettings)

domains/domain.go:42-58 shows DomainSettings holds `CustomRules []Rule`, `RawCustomRules []JsonRule`, `DomainProxy *httputil.ReverseProxy`, `DomainCertificates tls.Certificate` and a WebhookSettings of five strings — well over 200 bytes, with tls.Certificate alone carrying six fields including slices. config/init.go:141 and monitor.go:482 store the value, not a pointer.

**Impact**

Every request copies >200 bytes out of the interface on the type assertion, purely to read `CustomRules` and `DomainProxy`. At 50k req/s that is 10 MB/s of pointless memcpy plus the cache pressure of touching certificate fields that are never read on this path. domains.GetCertificate (util.go:18-22) does the same copy per TLS handshake and then returns `&tempDomain.DomainCertificates` — the address of a stack copy, so the certificate is re-heap-allocated on every handshake. The missing `, ok` on the type assertion at :146 is also a panic waiting for a request whose Host is in DomainsData but not DomainsMap.

**Fix**

Store `*domains.DomainSettings` in DomainsMap and assert to the pointer — the copy becomes a single word. Keep the certificate as a `*tls.Certificate` built once at load so GetCertificate returns the shared pointer with no allocation.

*Verifier:* Verified. middleware.go:145-146 does `settingsQuery, _ := domains.DomainsMap.Load(domainName)` then `domainSettings := settingsQuery.(domains.DomainSettings)`, and DomainSettings (domains/domain.go:42-58) is ~320 bytes by my field-by-field count (2 slice headers, a *ReverseProxy, an inline tls.Certificate at ~120 bytes, a 5-string WebhookSettings, 6 ints), copied out of the interface per request just to reach CustomRules and DomainProxy. Both store sites use the value form (config/init.go:141, monitor.go:482). GetCertificate (domains/util.go:16-23) does the same copy and then returns `&tempDomain.DomainCertificates`, the address of that copy, forcing a heap allocation per handshake — verified. The `_` on the type assertion at :146 is real, though a panic is hard to reach in practice since DomainsMap and DomainsData are populated together and neither is ever pruned. Pointer-store fix is correct.

### Discord webhook discards both the response and the error, leaking connections with no client timeout

- **Dimension:** quality-idiom  
- **Location:** `core/utils/discord.go:248-249`  
- **Effort:** trivial

**Evidence**

discord.go:248-249: 'client := &http.Client{}' then 'client.Do(req)' - the *http.Response and the error are both discarded, so resp.Body is never closed. The http.Client is constructed with no Timeout field. SendWebhook is invoked as a goroutine at monitor.go:139, 161, and 197.

**Impact**

Every webhook fires a goroutine that leaks one unclosed response body, so the underlying TCP connection is never returned to the idle pool or closed. With no Timeout, a hung or blackholed Discord endpoint parks that goroutine forever. Under a sustained attack, when webhook notifications fire most often, this accumulates goroutines and sockets in the exact process that must not run out of file descriptors.

**Fix**

resp, err := client.Do(req); if err != nil { return }; defer resp.Body.Close(); io.Copy(io.Discard, resp.Body). Use a package-level http.Client with Timeout set (5-10s) rather than allocating a new one per call.

*Verifier:* Verified. discord.go:248 constructs `client := &http.Client{}` with no Timeout and discord.go:249 calls `client.Do(req)` discarding both the *http.Response and the error, so resp.Body is never closed and the connection is never returned to the idle pool. SendWebhook is launched as a goroutine at monitor.go:139, :161 and :197 exactly as claimed. Since &http.Client{} falls back to http.DefaultTransport, the dial and TLS handshake are bounded but reading the response is not, so a blackholed Discord endpoint can park the goroutine indefinitely. One framing correction: the finding's 'under a sustained attack, when webhook notifications fire most often, this accumulates' overstates the rate — all three call sites are gated on domainData.BufferCooldown == 0, and BufferCooldown is set to 10 and decremented once per second in checkAttack, so webhooks fire at most roughly once per 10 seconds regardless of request volume. It is a slow leak on attack-state transitions, not a per-request leak. Medium still fits given the fd-exhaustion context, and the proposed fix (package-level client with Timeout, drain and close the body) is correct.

### Fourteen unused exported symbols, dead types, and a no-op API action across the tree

- **Dimension:** quality-idiom  
- **Location:** `core/utils/text.go:172`  
- **Effort:** small

**Evidence**

Verified by grep as having zero references outside their own declaration: utils.SafeString (text.go:172, body is 'return string([]byte(str))' - a pure no-op with a name implying sanitization), utils.closestTo10 (text.go:191), utils.JsonEscape (text.go:159), utils.PrintMutex (text.go:17 - a second mutex shadowing the name of server.PrintMutex at monitor.go:30, never locked anywhere), utils.GetOwnIP (ip.go:8), utils.HashToInt (encryption.go:40), utils.LogHeapProfile + utils.LogGoroutineProfile (debug.go:11,25), pnc.LogError (panicHandler.go:34), domains.CacheResponse (domain.go:137), firewall.RequestLog (requests.go:5 - the whole file; all code uses domains.RequestLog), utils.QuickchartResponse (discord.go:276), proxy.JSDifficulty (proxy.go:30), proxy.FailRequestRatelimit (proxy.go:49, assigned at init.go:100 and monitor.go:447, never read). Plus api.go:110-112 'case "RELOAD": firewall.Mutex.Lock(); firewall.Mutex.Unlock()' - locks and immediately unlocks, does nothing, and sends no APIResponse.

**Impact**

utils.SafeString is actively dangerous: a maintainer wrapping user input in it will believe the value is sanitized. proxy.FailRequestRatelimit means the documented 'noRequestsSent' config knob is silently inert. The RELOAD API action returns an empty 200 and never reloads. firewall.RequestLog vs domains.RequestLog is a name collision inviting the wrong import.

**Fix**

Delete all fourteen. Delete core/firewall/requests.go entirely. Either implement the RELOAD action by calling ReloadConfig or remove the case so it hits the ERR_ACTION_NOT_FOUND default. Add a CI step running 'go vet' plus staticcheck U1000 to keep dead code out.

*Verifier:* I grepped every one of the fourteen and all fourteen are confirmed to have zero references outside their own declaration: utils.SafeString (text.go:172, body is literally `return string([]byte(str))`), utils.closestTo10 (text.go:191), utils.JsonEscape (text.go:159), utils.PrintMutex (text.go:17 — every Lock/Unlock in the tree is on server.PrintMutex at monitor.go:30), utils.GetOwnIP (ip.go:8), utils.HashToInt (encryption.go:40), utils.LogHeapProfile/LogGoroutineProfile (debug.go:11,25), pnc.LogError (panicHandler.go:34), domains.CacheResponse (domain.go:137), firewall.RequestLog (requests.go:5 — the entire file; all nine usage sites reference domains.RequestLog), utils.QuickchartResponse (discord.go:276), proxy.JSDifficulty (proxy.go:30), and proxy.FailRequestRatelimit (assigned at init.go:100 and monitor.go:447, never read anywhere — so the documented 'noRequestsSent' knob is genuinely inert). api.go:110-112 `case "RELOAD": firewall.Mutex.Lock(); firewall.Mutex.Unlock()` is confirmed to do nothing and send no APIResponse. One trivial off-by-one: FailRequestRatelimit is declared at proxy.go:50, not :49. Medium holds because two of the items (the inert ratelimit knob and the no-op RELOAD action) are functional gaps, not merely unused code.

### HTTP-to-HTTPS redirect concatenates path and query without '?', corrupting every redirected URL

- **Dimension:** quality-idiom  
- **Location:** `core/server/serve.go:99`  
- **Effort:** trivial

**Evidence**

serve.go:99: http.Redirect(w, r, "https://"+r.Host+r.URL.Path+r.URL.RawQuery, http.StatusMovedPermanently). RawQuery is appended directly to Path with no '?' separator.

**Impact**

A request to http://host/search?q=test is 301-redirected to https://host/searchq=test. Because it is a permanent redirect, browsers cache it, so the broken URL persists for that client after any fix. Every query-bearing plaintext request to a non-Cloudflare deployment is silently mangled.

**Fix**

Use r.URL.RequestURI(), which already renders path plus '?'+query correctly: http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently). middleware.go:226 already uses RequestURI() for exactly this reason.

*Verifier:* Verified verbatim. serve.go:99 is `http.Redirect(w, r, "https://"+r.Host+r.URL.Path+r.URL.RawQuery, http.StatusMovedPermanently)` with no '?' between Path and RawQuery, so http://host/search?q=test redirects to https://host/searchq=test. The 301 status means browsers cache the mangled target, so it persists per-client past a fix. The contrast the finding draws is also real: middleware.go:226 already uses request.URL.RequestURI() for its stage-1 redirect, which renders path plus '?'+query correctly, so the proposed fix is exactly the pattern already used elsewhere in the same package. Scope note that keeps this at medium rather than higher: this handler only exists in the non-Cloudflare origin branch (serve.go:82-100), so a Cloudflare-fronted deployment never reaches it.

### Middleware is a single 335-line function with two multi-kilobyte HTML blobs inlined, while assets/html sits dead

- **Dimension:** quality-idiom  
- **Location:** `core/server/middleware.go:30-364`  
- **Effort:** large

**Evidence**

Middleware spans lines 30-364 (335 lines) and handles domain lookup, rate limiting, fingerprint blocking, rule evaluation, token derivation, three challenge stages, access logging, six reserved paths, and backend forwarding. Line 232 is a single ~4 KB minified HTML/JS string literal; line 296 is a single ~5 KB one. `file core/server/middleware.go` reports 'with very long lines (5390)'. Meanwhile assets/html/ contains captcha.html (7428 B), login.html (3668 B) and error.html (1885 B), and `grep -rn 'assets/' --include=*.go .` returns zero matches - nothing loads them.

**Impact**

The security-critical decision path cannot be unit tested, reviewed line-by-line, or diffed meaningfully; a one-character edit to the challenge markup produces an unreadable diff. The three template files under assets/html are misleading dead weight that a maintainer will edit expecting the change to take effect.

**Fix**

Split into named steps (resolveClient, applyRatelimits, evaluateRules, deriveTokens, serveChallenge, forward). Move the two blobs into assets/html and load them with go:embed + html/template parsed once at init - that also removes the string-concatenation injection surface where ip and publicSalt are spliced into JS at lines 232 and 296. Delete or wire up the existing dead template files.

*Verifier:* Substantively verified. Middleware runs from middleware.go:30 to 364, i.e. 335 lines, and it does handle domain lookup, three rate limits, fingerprint blocking, rule eval, token derivation, three challenge stages, access logging, six reserved paths and backend forwarding. `file` reports 'very long lines (5390)'. assets/html/ holds captcha.html (7428 B), error.html (1885 B) and login.html (3668 B), and `grep -rn 'assets/' --include=*.go .` returns zero matches, so all three files are dead. One measurement is inflated: I measured the actual line lengths and line 232 is 2337 bytes, not '~4 KB' — line 296 at 5390 bytes matches '~5 KB'. Severity is the bigger correction: this is a maintainability/testability finding with no direct exploit of its own, so medium rather than high. Worth noting the fix is better-motivated than the finding argues — line 296 splices `ip` directly into a JS string literal, and in Cloudflare mode ip comes from the attacker-controlled Cf-Connecting-Ip header (middleware.go:61) with no trusted-peer check, so the contextual escaping from html/template would close a live injection hole, not just tidy the diff.

### Panic handler has unreachable code, ignores every write error, and allocates 4 MB per panic

- **Dimension:** quality-idiom  
- **Location:** `core/pnc/panicHandler.go:17-30`  
- **Effort:** small

**Evidence**

panicHandler.go:17-20: 'if err != nil { log.Fatal(err); panic(err) }' - log.Fatal calls os.Exit(1), so the panic on line 19 is unreachable. Line 25-26: 'stackTrace := make([]byte, 4096000); runtime.Stack(stackTrace, false)' discards the returned length n and instead does bytes.TrimRight(stackTrace, "\x00") on line 28. Lines 29 and 36: 'logFile.WriteString(errMsg)' with the error discarded. Line 28 formats time as "15:05:04" - that is hour:minute-of-hour-as-05:second, a typo for "15:04:05". main.go:21-25 separately opens the same crash.log into a second handle that is never written to, since log.SetOutput(io.Discard) on main.go:32 discards it.

**Impact**

log.Fatal writes to the logger that main.go:32 points at io.Discard, so a crash.log open failure exits status 1 with no message anywhere. The timestamp in every crash entry is wrong. Two independent O_APPEND handles on crash.log invite interleaved writes. 4 MB is allocated on each panic when runtime.Stack's actual return value is the correct bound.

**Fix**

Replace log.Fatal+panic with 'return fmt.Errorf("open crash.log: %w", err)' and have main handle it. Use 'n := runtime.Stack(buf, false)' with a 64 KB buffer and slice buf[:n]. Check the WriteString errors. Fix the layout string to "15:04:05". Delete the unused duplicate handle in main.go:21-25.

*Verifier:* Nearly all verified. panicHandler.go:17-20 is `if err != nil { log.Fatal(err); panic(err) }` and log.Fatal calls os.Exit(1), so line 19 is genuinely unreachable. Lines 25-26 allocate `make([]byte, 4096000)` and discard runtime.Stack's returned length, then line 28 does bytes.TrimRight(stackTrace, "\x00"). Lines 29 and 36 discard WriteString errors. Line 28 (and line 35) format time as "15:05:04", which Go's reference layout reads as hour:minute-as-05:second — a typo for "15:04:05", so every crash timestamp is wrong. main.go:21-25 opens a second independent O_APPEND handle on crash.log that is never written to. ONE sub-claim is wrong: the finding says log.Fatal "writes to the logger that main.go:32 points at io.Discard", so failure "exits status 1 with no message anywhere". Ordering refutes that — pnc.InitHndl() runs at main.go:27, BEFORE log.SetOutput(io.Discard) at main.go:32, so the standard logger is still on stderr and the message IS printed. That does not undermine the other four defects, which are all real and correctly located. Medium is right.

### Response writes, http2.ConfigureServer, and APIResponse all discard their errors

- **Dimension:** quality-idiom  
- **Location:** `core/server/middleware.go:25-28`  
- **Effort:** small

**Evidence**

middleware.go:25-28: 'func SendResponse(str string, buffer *bytes.Buffer, writer http.ResponseWriter) { buffer.WriteString(str); writer.Write(buffer.Bytes()) }' - the Write error is dropped, and SendResponse is the sole response path for every block, challenge, and stats reply. serve.go:46, 79, 80 call http2.ConfigureServer(service, &http2.Server{}) discarding its error return. api.go:194 declares APIResponse returning error; all ~15 call sites ignore it. serve.go:89 uses fmt.Fprintf(w, "balooProxy: "+r.Host+" does not exist...") - Fprintf with a non-constant format built from the attacker-controlled Host header.

**Impact**

Write failures on challenge responses are invisible, so a client that never receives its challenge is indistinguishable from one that ignored it, and it then gets counted as a challenge failure at middleware.go:217 and rate-limited. If HTTP/2 configuration fails the server silently runs HTTP/1.1-only. A Host header containing '%s' renders '%!s(MISSING)' into the error page at serve.go:89.

**Fix**

Have SendResponse return the error (or at minimum log it) and check it at the call sites that matter. Check http2.ConfigureServer and fail startup on error. Change serve.go:89 to fmt.Fprint, or better fmt.Fprintf(w, "LancarSec: %s does not exist...", r.Host).

*Verifier:* All four citations verified. middleware.go:25-28 is exactly the quoted SendResponse, discarding writer.Write's error, and it is the sole response path for every block, challenge and stats reply. serve.go:46, :79 and :80 all discard http2.ConfigureServer's error. api.go:194 declares APIResponse returning error and all 19 call sites drop it. serve.go:89 is `fmt.Fprintf(w, "balooProxy: "+r.Host+" does not exist...")` — a non-constant format string built from the attacker-controlled Host header, so a Host containing %s does render %!s(MISSING) into the page, and because the format is non-constant `go vet` does not catch it (my vet run flagged only eval.go:30, confirming this). One causal nit in the impact: the challenge-failure counter at middleware.go:216-218 is incremented BEFORE the challenge is written, so a client is counted whether or not the write succeeded — the silent write error is not what causes the rate-limiting, it merely makes the failure undiagnosable. Medium stands.

### TLS fingerprint builder contradicts its own comment for SupportedPoints and returns nil, nil

- **Dimension:** quality-idiom  
- **Location:** `core/firewall/fingerprint.go:64-79`  
- **Effort:** medium

**Evidence**

fingerprint.go:64 states '//Loop over clientHello parameters and ignore first elements of arrays since they may be randomised by certain browsers'. Line 66 uses CipherSuites[1:] and line 71 uses SupportedCurves[1:], both consistent with that. But line 76 uses 'for _, point := range clientHello.SupportedPoints[:1]' - [:1], which keeps only the first element instead of dropping it, the exact opposite. The function also returns (nil, nil) at both line 57 and line 86, and is wired in as tls.Config.GetConfigForClient at serve.go:72 purely for its Connections side effect.

**Impact**

The [:1] vs [1:] slip means the point-format component of every fingerprint is built by the opposite rule from the rest, so the strings the code generates cannot be reproduced by any external tool and the hardcoded tables at fingerprint.go:12-49 are only correct by accident of having been captured from this same buggy code. Dropping index 0 unconditionally is itself wrong for non-GREASE clients like Firefox, which lose a legitimate cipher suite. Using GetConfigForClient for a side effect and returning nil is a misuse of the TLS API that will surprise any reader.

**Fix**

Decide the rule and apply it uniformly - filter GREASE values by pattern (0x?a?a) rather than by position, which fixes both the [:1]/[1:] inconsistency and the Firefox case - then regenerate the fingerprint tables. Rename the function to reflect that it records rather than configures, and document the nil return.

*Verifier:* The code reads exactly as described. fingerprint.go:64 says 'ignore first elements of arrays since they may be randomised by certain browsers'; line 66 uses CipherSuites[1:] and line 71 uses SupportedCurves[1:], both consistent with that, while line 76 uses SupportedPoints[:1], which keeps the first element instead of dropping it. The function returns (nil, nil) at both line 57 and line 86 and is wired in as tls.Config.GetConfigForClient at serve.go:72 purely for the Connections side effect at fingerprint.go:82-84, which is a real misuse of the TLS API. The GREASE-by-position critique is the substantive part and it is correct: dropping index 0 unconditionally discards a legitimate cipher suite for non-GREASE clients like Firefox, so two clients differing only in their first cipher suite collide. Neither slice can panic — line 55 guarantees len(CipherSuites) >= 1 and lines 70/75 guard the others. Severity down to medium: the shipped tables at fingerprint.go:12-49 were captured from this same code, so every entry ends in the '0x0,' that [:1] preserves and detection works as intended today. The cost is non-portability and a narrow collision class, not a broken control. The proposed fix (filter GREASE by the 0x?a?a pattern, then regenerate the tables) is correct and must include regenerating the tables, as the finding says.

### Two divergent AddDomain implementations, and the one the TUI calls silently drops Stage2Difficulty

- **Dimension:** quality-idiom  
- **Location:** `core/utils/domain.go:11-48`  
- **Effort:** small

**Evidence**

config.AddDomain at generate.go:62-100 and utils.AddDomain at domain.go:11-148 are ~40 lines of near-identical prompt-and-marshal code. They have diverged: generate.go:81 includes 'Stage2Difficulty: utils.AskInt("How difficult should Stage 2 Be? (6 AT MOST recommended)", 5)' in the domains.Domain literal; the utils copy at domain.go:128-134 has no Stage2Difficulty field at all. monitor.go:350 (the interactive 'add' command) calls utils.AddDomain; init.go:230 calls config.AddDomain.

**Impact**

Any domain added through the running proxy's 'add' command is written to config.json with stage2Difficulty absent, i.e. 0. Combined with ReloadConfig skipping the Stage2Difficulty==0 default (init.go:167-169), that domain serves a proof-of-work challenge of difficulty 0 - effectively no challenge - while the operator believes stage 2 is active.

**Fix**

Delete utils.AddDomain (core/utils/domain.go) and have monitor.go:350 call the config package's single implementation. That also removes utils' import of io/ioutil.

*Verifier:* The substance is real but both line citations are fabricated and the severity is inflated. core/utils/domain.go is 48 lines long — 'core/utils/domain.go:11-148' and 'the utils copy at domain.go:128-134' cite lines that do not exist. The actual facts: utils.AddDomain occupies domain.go:11-48; its domains.Domain literal at domain.go:15-35 jumps straight from BypassStage1 (line 29) to BypassStage2 (line 30) with no Stage2Difficulty field, while config.AddDomain at generate.go:62-100 does include `Stage2Difficulty: utils.AskInt(...)` at generate.go:81. monitor.go:350 calls utils.AddDomain and init.go:230 calls config.AddDomain, both as claimed. Severity down to medium because the standalone impact is nil: init.go:167-169 defaults Stage2Difficulty 0 -> 5 on every startup, so a domain added via the TUI serves a correct difficulty-5 challenge after the next restart. The only window in which difficulty actually reaches 0 is via ReloadConfig, which zeroes Stage2Difficulty for EVERY domain regardless — so the claimed high-severity impact is really the reloadconfig-duplicates-load finding, double-counted here. What is left is genuine config-persistence divergence between two copies of the same prompt code.

### getTripperForDomain is a sync.Map that always stores the same shared transport singleton

- **Dimension:** quality-idiom  
- **Location:** `core/server/serve.go:212-219`  
- **Effort:** small

**Evidence**

serve.go:212-219: 'transport, ok := transportMap.Load(domain); if !ok { transport, _ = transportMap.LoadOrStore(domain, defaultTransport) }; return transport.(*http.Transport)'. Nothing anywhere else writes to transportMap - grep for transportMap returns only serve.go:23, 214, and 216. defaultTransport (serve.go:198-210) is one package-level pointer with MaxIdleConns: 10 and MaxConnsPerHost: 10.

**Impact**

The map is pure overhead on every proxied request - a hash lookup plus an interface assertion - to return the same pointer it would have returned unconditionally, while giving readers the false impression that per-domain transport tuning exists. All domains in fact share a pool capped at 10 idle connections and 10 connections per host, which for a reverse proxy fronting a DDoS-targeted origin is a severe and invisible bottleneck.

**Fix**

Either delete getTripperForDomain and transportMap and use defaultTransport directly, or make the abstraction real by building one *http.Transport per domain at config-load time and storing it on DomainSettings. Raise MaxIdleConns/MaxIdleConnsPerHost/MaxConnsPerHost to values appropriate for the expected concurrency.

*Verifier:* Verified in full. serve.go:212-219 is exactly as quoted, and my grep for transportMap returns only three hits — serve.go:23 (declaration), :214 (Load) and :216 (LoadOrStore) — so nothing ever stores anything but the single defaultTransport declared at serve.go:198-210 with MaxIdleConns: 10 and MaxConnsPerHost: 10. Every proxied request therefore pays a sync.Map hash lookup plus an interface type assertion (RoundTrip calls it at serve.go:125) to obtain a pointer that a package-level variable reference would have returned for free, while the naming advertises per-domain tuning that does not exist. MaxConnsPerHost: 10 is a genuine and invisible throughput ceiling to the origin for a reverse proxy. Both proposed fixes are sound. Medium is right — this is performance and misleading abstraction, not a security hole. (The map cannot be grown by attacker-supplied Host values, since middleware 404s unknown hosts before RoundTrip is reached.)

### go vet fails: fmt.Println with Printf directives in the firewall rule engine, breaking go test ./...

- **Dimension:** quality-idiom  
- **Location:** `core/firewall/eval.go:30`  
- **Effort:** trivial

**Evidence**

$ go vet ./... => 'core/firewall/eval.go:30:6: fmt.Println call has possible Printf formatting directive %d'. Line 30: fmt.Println("[ ! ] [ Error Evaluating Rule %d : %s ]\n", index, err.Error()). The sibling '+' branch (line 20) and default branch (line 39) use fmt.Printf with the identical string; only the '-' branch was copy-pasted wrong. $ go test ./... => 'FAIL goProxy/core/firewall [build failed]'.

**Impact**

vet runs as part of go test, so `go test ./...` fails outright today and the firewall package cannot be tested until this is fixed. Operationally, a malformed subtractive rule action (e.g. "-abc") prints the literal '%d'/'%s' text plus '%!(EXTRA int=0...)', so the operator never learns which rule index failed.

**Fix**

Change fmt.Println to fmt.Printf at eval.go:30 to match lines 20 and 39. Then collapse the three branches, which triplicate the same Sscan+report+apply logic, into one helper. Also validate rule.Action at config-load time: rule.Action[:1] at eval.go:15 panics on an empty action string.

*Verifier:* Core claim verified by my own runs. eval.go:30 is exactly `fmt.Println("[ ! ] [ Error Evaluating Rule %d : %s ]\n", index, err.Error())`; siblings at :20 and :40 use fmt.Printf with the identical string. `go vet ./...` emits `core\firewall\eval.go:30:6: fmt.Println call has possible Printf formatting directive %d` and `go test ./...` reports `FAIL goProxy/core/firewall [build failed]`. rule.Action[:1] at eval.go:15 does panic on an empty action string (""[:1] is a slice-bounds panic) and nothing validates Action at config load. BUT the operational impact is overstated twice over: fmt.Println never emits `%!(EXTRA int=0...)` — that is a Printf artifact — and Println prints all three operands space-separated, so the rule index IS printed, just after the literal format text. The operator does learn which rule failed; the output is merely ugly. Real impact reduces to a broken build/vet gate plus cosmetic log noise, which is medium, not high.

### /_bProxy/stats and /_bProxy/fingerprint give an attacker live feedback on whether his flood is bypassing

- **Dimension:** security-authz  
- **Location:** `core/server/middleware.go:324-336`  
- **Effort:** trivial

**Evidence**

	case "/_bProxy/stats":
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("Stage: "+utils.StageToString(domainData.Stage)+"\nTotal Requests: "+strconv.Itoa(domainData.TotalRequests)+"\nBypassed Requests: "+strconv.Itoa(domainData.BypassedRequests)+"\nTotal R/s: "+strconv.Itoa(domainData.RequestsPerSecond)+"\nBypassed R/s: "+strconv.Itoa(domainData.RequestsBypassedPerSecond)+"\nProxy Fingerprint: "+proxy.Fingerprint, buffer, writer)
		return
	case "/_bProxy/fingerprint":
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("IP: "+ip+"\nIP Requests: "+strconv.Itoa(ipCount)+"\nIP Challenge Requests: "+strconv.Itoa(ipCountCookie)+"\nSusLV: "+strconv.Itoa(susLv)+"\nFingerprint: "+tlsFp+...
Neither case checks proxy.AdminSecret or proxy.APISecret — the only gate is having passed the challenge, which stage 1 grants for one extra request (see stage1-is-cookie-echo), or which Host: debug skips entirely (see host-debug-bypasses-challenge).

**Impact**

This is a closed-loop tuning oracle handed to the adversary. Polling /_bProxy/stats once a second tells him the current Stage, the total r/s, and — decisively — the Bypassed r/s, i.e. exactly how many of his requests are reaching the backend. He can automatically search the parameter space (request rate, fingerprint, User-Agent, path) and converge on a bypassing configuration in minutes, with the defender's own telemetry as the fitness function. /_bProxy/fingerprint additionally reports his own ipCount, ipCountCookie, and computed susLv, so he can ride precisely under `requests` and `challengeFailures` without ever tripping them. proxy.Fingerprint also identifies the exact build (main.go:15).

**Fix**

Move both endpoints behind the API secret, or bind them to an admin listener. If a public health endpoint is wanted, return a static 200 with no counters. Under no circumstances should Bypassed R/s or the caller's own ratelimit counters be readable by an unauthenticated client.

*Verifier:* Verified at middleware.go:324-336: /stats emits Stage, TotalRequests, BypassedRequests, RequestsPerSecond, RequestsBypassedPerSecond and proxy.Fingerprint; /fingerprint emits the caller's own ip, ipCount, ipCountCookie, susLv, tlsFp and browser. Neither checks proxy.AdminSecret or proxy.APISecret. proxy.Fingerprint is indeed the build marker at main.go:15. The tuning-oracle argument follows: Bypassed R/s is exactly the attacker's fitness function. One qualification on the title — these are not strictly unauthenticated, since the reserved-path switch is reached only after the :214 challenge gate; 'unauthenticated' holds via the stage-1 echo or the Host: debug path, both of which the finding correctly cross-references. Medium stands.

### Admin secret is embedded in the URL path and compared non-constant-time; the v2 route makes it redundant anyway

- **Dimension:** security-authz  
- **Location:** `core/server/middleware.go:337-355`  
- **Effort:** small

**Evidence**

	case "/_bProxy/" + proxy.AdminSecret + "/api/v1":
		result := api.Process(writer, request, domainData)
		if result {
			return
		}
...
	if strings.HasPrefix(request.URL.Path, "/_bProxy/api/v2") {
		result := api.ProcessV2(writer, request)
and core/api/api.go:155:
	if r.Header.Get("Proxy-Secret") != proxy.APISecret {
		return false
	}

**Impact**

Three problems compound. (1) A secret in the path is logged everywhere a URL is logged: the origin's own access log, Cloudflare's request logs (in the deployment mode this proxy is built for), any CDN or WAF in front, browser history, and the Referer header of anything the admin page loads. (2) The switch-case does a plain non-constant-time string comparison, as does the API secret check at api.go:17 and api.go:155 — no crypto/subtle anywhere in the repo. (3) The v1 path secret buys nothing, because ProcessV2 authenticates on the header alone: an attacker who learns only the API secret reaches every single action through /_bProxy/api/v2/<action> without knowing the admin path secret. In Cloudflare mode the whole exchange is plaintext HTTP on :80 between Cloudflare and the origin (core/server/serve.go:97-112), so the Proxy-Secret header itself is on the wire in the clear. Note also that when api.Process returns false the case does not return — the request with the guessed admin path falls through and is proxied to the backend.

**Fix**

Drop the path secret entirely and authenticate only on the header, compared with `subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1` after a length-independent hash (hmac.Equal over SHA-256 of each side). Serve the admin API on a separate listener bound to localhost or an admin interface, not on the public :80/:443 handler, and require the connection to arrive from an allowlisted source.

*Verifier:* All three sub-claims verified. middleware.go:337 is `case "/_bProxy/" + proxy.AdminSecret + "/api/v1":` — the secret is in the path; `grep -rn 'crypto/subtle\|subtle\.'` over the repo returns nothing, so api.go:17 and api.go:155 are both plain non-constant-time `!=`; and ProcessV2 (api.go:153-157), routed at middleware.go:350-355, authenticates on the header alone, making the v1 path secret redundant. The fall-through observation is also correct: :339-341 returns only when Process returns true, so a correctly-guessed admin path with a wrong API secret is proxied to the backend. Downgraded one level: secret-in-URL log exposure is the real issue; the non-constant-time compare on a 30-char random secret is not remotely exploitable over a network, and the plaintext-on-the-wire point applies to the whole CF-flexible deployment, not to this code.

### Captcha images are cached globally under 6 hex characters of the token, leaking another user's token material on collision

- **Dimension:** security-authz  
- **Location:** `core/server/middleware.go:235-292 (CacheImgs declared at core/firewall/general.go:33, not :402)`  
- **Effort:** small

**Evidence**

			secretPart := encryptedIP[:6]
			publicPart := encryptedIP[6:]
...
			captchaCache, captchaExists := firewall.CacheImgs.Load(secretPart)
...
				firewall.CacheImgs.Store(secretPart, [2]string{captchaData, maskData})
The cached image embeds the *other* user's public half — middleware.go:246-247 draw `publicPart[6:]` and `publicPart[:6]` into it. CacheImgs is a single process-global sync.Map (core/firewall/general.go:402) shared by every domain and every client.

**Impact**

The cache key is 24 bits of entropy. By the birthday bound, with roughly 4,000 concurrent stage-3 clients a collision is likely, and under an actual attack — the only time stage 3 is active — far more than 4,000 distinct clients hit stage 3. On a collision, client B is served the PNG generated for client A, which has A's publicPart rendered into it. A and B share the first 6 hex characters by construction, so B learns 58 of the 64 hex characters of A's live stage-3 token alongside the 6 he already knows — that is A's complete token, and B can impersonate A's challenge state for the rest of the hour. Eviction does not help: clearProxyCache only trims CacheImgs under specific CPU/memory conditions (core/server/monitor.go:552-560), which a proxy under load will not satisfy.

**Fix**

Key the image cache on the full token (or a hash of it), not a 6-character prefix, and never render one client's token material into an artifact that another client's cache key can reach. Add a real TTL-based eviction instead of the CPU/memory-gated bulk clear.

*Verifier:* Verified and the mechanism is worse than a generic cache-key collision. middleware.go:235-236 splits on 6 hex chars (24 bits), :240/:287 key CacheImgs on secretPart alone, and :246-247 render the OWNER's publicPart[6:] and publicPart[:6] into that cached image. On collision B is served A's PNG; because A and B share secretPart by construction, B still solves his own captcha correctly while reading A's publicPart off the image — giving B A's complete 64-char token. Eviction is gated on monitor.go:564 `(cpu < 15 && mem > 25) || mem > 95`, unlikely under the load that produces stage 3. One citation error: CacheImgs is declared at core/firewall/general.go:33, not :402 (that file is 50 lines). Medium stands.

### FILL_IP_CACHE holds the global firewall mutex while generating 19,980 random strings, stalling the entire request path

- **Dimension:** security-authz  
- **Location:** `core/api/api.go:101-109`  
- **Effort:** trivial

**Evidence**

	// Useful to fill up your ipCache and see how your proxy performs with high memory usage
	case "FILL_IP_CACHE":
		firewall.Mutex.Lock()
		for i := 0; i < 19980; i++ {
			firewall.CacheIps.Store(utils.RandomString(24), utils.RandomString(64))
		}
		firewall.Mutex.Unlock()
firewall.Mutex is the single global RWMutex the request hot path depends on — core/server/middleware.go:40 (RLock for domain lookup), :88 (Lock for the sliding window), :129 (Lock for the fingerprint window), :216 (Lock for the challenge-failure window), :306 (Lock for logging).

**Impact**

One authenticated request generates 19,980 × 88 = ~1.76 million calls into math/rand while holding the write lock that every single inbound request must acquire. For the duration, the proxy serves nothing — every goroutine blocks at middleware.go:88. Repeat the call in a loop and the proxy is down, with the DDoS mitigation layer itself as the amplifier. The cache entries are also never bounded: clearProxyCache only evicts when `(proxyCpuUsage < 15 && proxyMemUsage > 25) || proxyMemUsage > 95` (core/server/monitor.go:552), a condition that a busy proxy will not meet, so the memory is retained. This is a debug helper — its own comment says so — shipped enabled in production with no build tag.

**Fix**

Delete FILL_IP_CACHE from the production build, or put it behind a build tag. If it must stay, drop the mutex (CacheIps is a sync.Map and needs no external lock — note the neighbouring `case "RELOAD"` at api.go:110-112 locks and immediately unlocks, doing nothing at all), cap the iteration count, and rate-limit the action.

*Verifier:* Code verified verbatim at api.go:101-109, including the debug-only comment, and firewall.Mutex is confirmed as the global lock the hot path takes at middleware.go:40, 88, 129, 216 and 306. The neighbouring RELOAD case at api.go:110-112 does indeed lock and immediately unlock, doing nothing. The eviction gate at monitor.go:564 `(cpu < 15 && mem > 25) || mem > 95` is real, so entries are retained. Downgraded one level on measurement: I benchmarked the exact loop (19,980 iterations of RandomString(24)+RandomString(64) into a sync.Map) at 35-42 ms, not a proxy-wide outage per call, and it requires the API secret plus a passed challenge. Unbounded memory growth under a loop is the more durable half of this.

### Open redirect in the stage-1 challenge response

- **Dimension:** security-authz  
- **Location:** `core/server/middleware.go:226`  
- **Effort:** trivial

**Evidence**

			http.Redirect(writer, request, request.URL.RequestURI(), http.StatusFound)
I confirmed the behavior with a Go program that feeds a raw request line through http.ReadRequest and then http.Redirect exactly as the middleware does:
  target="//evil.com/"  URL.Path="//evil.com/" RequestURI()="//evil.com/"  -> Location: "//evil.com/"
  target="/normal"      URL.Path="/normal"     RequestURI()="/normal"      -> Location: "/normal"
http.Redirect skips its path-cleaning branch when the parsed target has a non-empty Host, and url.Parse("//evil.com/") yields Host="evil.com".

**Impact**

Any first-time visitor request (no cookie, stage 1 — the default stage for every domain) to `https://target.com//evil.com/` is answered with `Location: //evil.com/`, a protocol-relative redirect the browser resolves to `https://evil.com/`. The attacker gets a redirect that originates from the protected domain, over its valid certificate, before any challenge is solved — ideal for phishing, and it also lets him launder the target's reputation past link filters. No authentication and no cookie are needed; the redirect is emitted by the challenge issuance itself.

**Fix**

Redirect to a sanitized, origin-relative target: reject or rewrite any RequestURI starting with `//` or containing a scheme, e.g. build the location as "/" + strings.TrimLeft(request.URL.EscapedPath(), "/") plus the raw query, and verify the parsed result has empty Scheme and Host before writing it.

*Verifier:* Verified at middleware.go:226 and reproduced independently: I fed raw request lines through http.ReadRequest and called http.Redirect exactly as the middleware does. target "//evil.com/" -> Location "//evil.com/"; "//evil.com/x?a=b" -> Location "//evil.com/x?a=b"; "/normal" -> "/normal"; "/%2Fevil.com" -> "/%2Fevil.com" (not exploitable). http.Redirect skips path cleaning when url.Parse yields a non-empty Host, which "//evil.com/" does. Reachable on any first-visit request to a configured Host at the default stage 1, with no cookie and no authentication. Medium is right for an open redirect.

### Ratelimits run before firewall rules, so an `action: 0` whitelist cannot whitelist, and whitelisted clients still accrue challenge failures until blocked

- **Dimension:** security-authz  
- **Location:** `core/server/middleware.go:107-140 (rule eval at :177)`  
- **Effort:** small

**Evidence**

	//Ratelimit faster if client repeatedly fails the verification challenge
	if ipCountCookie > proxy.FailChallengeRatelimit {
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("Blocked by BalooProxy.\nYou have been ratelimited. (R1)", buffer, writer)
		return
	}
...
	if ipCount > proxy.IPRatelimit {
...(R2)... }
EvalFirewallRule only runs afterwards, at middleware.go:177:
		susLv = firewall.EvalFirewallRule(domainSettings, requestVariables, susLv)
And the challenge-failure counter is incremented even when the rules set susLv to 0, because the increment sits above the switch (middleware.go:214-218):
	if !strings.Contains(request.Header.Get("Cookie"), "__bProxy_v="+encryptedIP) {

		firewall.Mutex.Lock()
		firewall.WindowAccessIpsCookie[proxy.Last10SecondTimestamp][ip]++

**Impact**

An operator writes `{"expression": "(ip.src in {203.0.113.7})", "action": "0"}` to whitelist a payment webhook, a health checker, or an office range. It does not work. R1/R2/R3 have already returned before the rule is ever evaluated, so the "whitelisted" source is still hard-blocked at `requests` and `challengeFailures`. Worse, because susLv 0 makes encryptedIP the empty string (middleware.go:190 `case 0: //whitelisted` leaves it ""), the cookie predicate degrades to `Contains(cookie, "__bProxy_v=")`, which a cookieless client such as a webhook poster never satisfies — so every one of its requests increments WindowAccessIpsCookie and, after 40 requests in the 2-minute window, R1 blocks the very source the operator explicitly whitelisted. The failure is silent and looks like a backend outage.

**Fix**

Evaluate the firewall rules first, then apply the ratelimits only when susLv > 0, so an action of 0 is a true bypass. Skip the WindowAccessIpsCookie increment entirely when susLv == 0, and give susLv 0 an explicit early pass rather than routing it through the cookie-comparison branch with an empty expected value.

*Verifier:* Verified end to end. R1 at middleware.go:108 and R2 at :115 both return before EvalFirewallRule is called at :177, and core/firewall/eval.go:35-44 confirms a bare "0" action sets result = 0 and returns, so an operator's whitelist rule cannot bypass either limit. The second-order bug is also real: susLv 0 leaves encryptedIP as "" (:189-190), the predicate at :214 degrades to Contains(cookie, "__bProxy_v="), a cookieless webhook poster never satisfies it, and the WindowAccessIpsCookie increment at :216-218 sits above the switch and fires on every such request — so a whitelisted source is hard-blocked by R1 after challengeFailures requests in the window. Medium is right.

### The TLS fingerprint allowlist is derived only from client-chosen ClientHello fields, so a scripted client claims "Chromium" and disables the unknown-fingerprint ratelimit

- **Dimension:** security-authz  
- **Location:** `core/firewall/fingerprint.go:62-79 (Chromium entry at :14) — cited :344-361 and :296 do not exist in an 87-line file`  
- **Effort:** large

**Evidence**

	fingerprint := ""

	for _, suite := range clientHello.CipherSuites[1:] {
		fingerprint += fmt.Sprintf("0x%x,", suite)
	}

	if len(clientHello.SupportedCurves) > 0 {
		for _, curve := range clientHello.SupportedCurves[1:] {
			fingerprint += fmt.Sprintf("0x%x,", curve)
		}
	}
	if len(clientHello.SupportedPoints) > 0 {
		for _, point := range clientHello.SupportedPoints[:1] {
The consequence in the hot path (core/server/middleware.go:84 and :121-132):
	browser = firewall.KnownFingerprints[tlsFp]
...
	//Ratelimit fingerprints that don't belong to major browsers
	if browser == "" {
		if fpCount > proxy.FPRatelimit {
...(R3)... }

**Impact**

The fingerprint is nothing but the cipher-suite list, the curve list, and one EC point format — every byte of which the client picks. An attacker using utls (or any BoringSSL/NSS wrapper) sets the ClientHello to Chrome's published ordering, matches the `"0x1301,0x1302,0x1303,0xc02b,..."` entry in KnownFingerprints (core/firewall/fingerprint.go:296), and gets browser="Chromium". That does two things: it skips the R3 unknown-fingerprint ratelimit branch entirely, which is the only control specifically aimed at scripted clients, and it satisfies the shipped rule `ip.engine eq ""` → `+1` (examples/config.json), so the attacker's suspicion level never gets bumped. Nothing in the fingerprint covers extension order, signature algorithms, ALPN, or the HTTP/2 SETTINGS frame — the signals that actually separate a real Chrome from a mimic. Dropping index 0 unconditionally (`CipherSuites[1:]`, `SupportedCurves[1:]`) also means two clients differing only in their first cipher or first curve are indistinguishable, and a non-GREASE client such as Firefox loses a legitimate value.

**Fix**

Compute a spec-accurate JA4/JA3 from the raw ClientHello (extension list, signature algorithms, ALPN), not from the handful of fields tls.ClientHelloInfo exposes, and filter GREASE by value pattern (0x?a?a) instead of blindly dropping index 0. Treat a known-browser fingerprint as one weak signal that must agree with the User-Agent and the HTTP/2 fingerprint, never as a ratelimit exemption on its own.

*Verifier:* Substance verified but the primary location is fabricated: core/firewall/fingerprint.go is 87 lines long, so :344-361 does not exist. The quoted code is real and sits at fingerprint.go:62-79, and the Chromium KnownFingerprints entry the finding cites as :296 is actually fingerprint.go:14. With that corrected the analysis holds: the fingerprint is only CipherSuites[1:], SupportedCurves[1:] and SupportedPoints[:1] — all client-chosen — and browser != "" skips the R3 branch at middleware.go:121-132 entirely while satisfying the shipped `ip.engine eq ""` +1 rule. The unconditional index-0 drop losing a legitimate value for non-GREASE clients is correct. Medium is right; note this whole path is dead in Cloudflare mode, where tlsFp/browser are hardcoded to "Cloudflare" (:63-64).

### Unseparated concatenation in accessKey lets an attacker shift hour digits into the User-Agent and pre-mint tokens for a future hour

- **Dimension:** security-authz  
- **Location:** `core/server/middleware.go:184`  
- **Effort:** trivial

**Evidence**

	accessKey := ip + tlsFp + reqUa + proxy.CurrHourStr
The hour component is the bare hour-of-day integer with no padding (core/server/monitor.go:217-218):
	proxy.CurrHour, _, _ = proxy.LastSecondTime.Clock()
	proxy.CurrHourStr = strconv.Itoa(proxy.CurrHour)
reqUa is `request.UserAgent()` (middleware.go:148), fully attacker-controlled, and in Cloudflare mode tlsFp is the constant "Cloudflare" (middleware.go:63) and ip comes from an attacker-controlled header (middleware.go:61).

**Impact**

Because the fields are concatenated with no delimiter, `ua="Mozilla/5.0" + hour="15"` and `ua="Mozilla/5.01" + hour="5"` produce the byte-identical accessKey, hence the identical token. Concrete attack: at 05:30 the attacker requests the target with `User-Agent: Mozilla/5.01`, solves the stage-2 or stage-3 challenge once, and stores the returned token T. At 15:00, when the honest token for `User-Agent: Mozilla/5.0` from that IP rolls over, the required value is exactly T — he replays it without solving anything. Every single-digit hour h yields free tokens for hours "1h" and "2h", so a few solves during the quiet morning cover most of the afternoon and evening. The hourly rotation, which is the only replay bound in the design, buys nothing against a prepared attacker. The same ambiguity means two distinct clients can collide onto one CacheIps entry (middleware.go:185/204) and be served each other's token.

**Fix**

Join the fields with a delimiter that cannot occur in any of them, or better, feed them as separate length-prefixed writes into a keyed BLAKE3/HMAC instead of concatenating into one string. Use a zero-padded absolute time bucket (`time.Now().UTC().Format("2006-01-02-15")`) rather than a bare hour-of-day integer that repeats daily.

*Verifier:* The ambiguity is real and I checked the arithmetic: middleware.go:184 concatenates with no delimiter, and monitor.go:217-218 sets CurrHourStr via strconv.Itoa of a bare Clock() hour with no zero padding, so "Mozilla/5.01"+"5" and "Mozilla/5.0"+"15" both produce "...Mozilla/5.015" and therefore the identical Encrypt() input. The cross-client CacheIps collision at :185/:204 follows directly. Downgraded one level: the pre-minting payoff depends on the attacker being served the stage-2/3 challenge during the quiet hour, which is the same precondition as token-not-bound-to-domain-or-path rather than an independent break, and it only maps single-digit hours h onto "1h"/"2h". Ambiguous key construction in a security boundary is a genuine defect; the exploitation story is incremental.

### `Host: debug` reaches a hardcoded stage-0 domain that skips the entire challenge chain and hits the reserved _bProxy paths

- **Dimension:** security-authz  
- **Location:** `core/config/init.go:195-203`  
- **Effort:** small

**Evidence**

	domains.DomainsMap.Store("debug", domains.DomainSettings{
		Name: "debug",
	})

	firewall.Mutex.Lock()
	domains.DomainsData["debug"] = domains.DomainData{
		Name:             "debug",
		Stage:            0,
Middleware keys off the raw Host header (core/server/middleware.go:38-41): `domainName := request.Host` / `domainData, domainFound := domains.DomainsData[domainName]`. susLv starts at the stage (middleware.go:105 `susLv := domainData.Stage`), and stage 0 takes the no-op branch in both switches (middleware.go:190 `case 0:  //whitelisted` and middleware.go:223 `case 0:  //This request is not to be challenged (whitelist)`). The DomainSettings stored for "debug" has a nil DomainProxy, which is dereferenced unconditionally at middleware.go:363 `domainSettings.DomainProxy.ServeHTTP(writer, request)`.

**Impact**

`curl -H 'Host: debug' http://target/_bProxy/fingerprint` — susLv is 0, no cookie is required, no challenge is issued, and execution falls straight through to the reserved-path switch at middleware.go:324. The attacker gets unauthenticated access to /_bProxy/stats, /_bProxy/fingerprint, /_bProxy/verified, and both API entry points without ever touching a challenge. This is also a free panic generator: any Host: debug request that is not one of the reserved paths reaches the nil DomainProxy and panics. Middleware deliberately has no recover (middleware.go:32 `// defer pnc.PanicHndl() we wont do this during prod, to avoid overhead`), so it unwinds into net/http's per-connection recover, and since logging is discarded (main.go:32 `log.SetOutput(io.Discard)`) the operator sees nothing at all — no crash.log entry, no TUI line.

**Fix**

Never expose the internal `debug` pseudo-domain through Host routing: key it under a name that cannot appear in a Host header (e.g. a sentinel with a NUL or a separate map), or gate it behind a config flag that defaults to off. Independently, nil-check DomainProxy before ServeHTTP and return 500, and treat susLv 0 as "skip challenge" only for domains that actually configured a whitelist rule.

*Verifier:* Verified. core/config/init.go:195-203 stores the "debug" pseudo-domain with Stage: 0 and a DomainSettings whose DomainProxy (*httputil.ReverseProxy, core/domains/domain.go:48) is nil. Middleware keys on raw request.Host (:38-41), susLv := domainData.Stage (:105), and susLv 0 no-ops both switches (:189, :222) — I traced the control flow: with no Cookie header, `!strings.Contains("", "__bProxy_v=")` is true, the block is entered, case 0 does nothing, and execution falls out of the switch to :306 and on to the reserved-path switch at :324. So /_bProxy/stats, /fingerprint, /verified and /credits are reachable with `Host: debug` and no challenge. Any other path nil-derefs at :363. Downgraded one level: the panic is recovered per-connection by net/http, so it resets one connection rather than crashing the process (the 'no crash.log, no TUI line' point is correct — main.go:32 discards log output), and both API entry points still require their secrets. Real impact is unauthenticated telemetry plus connection-level panics.

### An RSA private key is committed to the repository

- **Dimension:** security-crypto  
- **Location:** `assets/server/server.key:1 (wired in at examples/config.json:34-35, :72-73, :110-111; loaded at core/config/init.go:132-135)`  
- **Effort:** small

**Evidence**

`git ls-files | grep -i -E "key|pem|crt|cert"` returns `assets/server/server.crt` and `assets/server/server.key` — both are tracked.
`head -3 assets/server/server.key` -> `-----BEGIN RSA PRIVATE KEY-----` / `MIIEow<key-body-withheld>…`
`openssl x509 -in assets/server/server.crt -noout -subject -dates` -> `subject=CN=baloo.dog`, `notBefore=Dec 17 00:00:00 2022 GMT`, `notAfter=Mar 17 23:59:59 2023 GMT`.
README.md:128-132 points operators at these filenames as the certificate/key example.

**Impact**

A usable private key sits in every clone and in the published container image. Because README.md names `server.crt`/`server.key` as the example paths and config.json takes bare filenames (core/domains/domain.go:29-30), an operator can easily point a live domain at this bundled pair, serving traffic under a key that every reader of the repository holds — and under an expired certificate for someone else's domain (baloo.dog), which the rebrand would carry over unchanged. It also trains users to keep key material next to the binary in the deploy directory.

**Fix**

Delete both files from the working tree and purge them from history, add `*.key`/`*.pem` to .gitignore, and have the proxy generate a throwaway self-signed pair at first run (or fail loudly) instead of shipping one. Update README to show absolute paths outside the repo and to state that the key must never be committed.

*Verifier:* Verified. git ls-files tracks assets/server/server.crt and assets/server/server.key; the key parses as a real 2048-bit PKCS#1 RSA private key, and the certificate parses as subject CN=baloo.dog, SANs [baloo.dog www.baloo.dog], notBefore 2022-12-17, notAfter 2023-03-17 — matching the finding exactly. Worse than stated: examples/config.json does not merely name them as an example, it wires them into all three domains (:34-35, :72-73, :110-111), and core/config/init.go:132-135 loads exactly those paths whenever Cloudflare mode is off. README.md:128-132 documents the same filenames. Medium is right for an expired third-party key.

### Challenge OTPs rotate only once per calendar day, on a one-hour sleep loop, and a reloaded secret is not re-derived

- **Dimension:** security-crypto  
- **Location:** `core/server/monitor.go:639-658 and :414-416`  
- **Effort:** small

**Evidence**

core/server/monitor.go:650-657 `currTime := time.Now()` / `currDate := currTime.Format("2006-01-02")` / `proxy.CookieOTP = utils.EncryptSha(proxy.CookieSecret, currDate)` … / `time.Sleep(1 * time.Hour)` — the key material changes only when the date string changes, while the loop wakes on an unaligned hourly schedule.
The comment at core/server/monitor.go:646 claims otherwise: `//This has now been changed to an hour, for better performance`.
core/server/monitor.go:414-416 (ReloadConfig) `proxy.CookieSecret = domains.Config.Proxy.Secrets["cookie"]` … — the base secrets are replaced but the OTPs derived from them are not recomputed; the goroutine will only pick them up at its next wake, up to an hour later.

**Impact**

Three defects. The OTP has a 24-hour lifetime, so a single leaked OTP mints challenge tokens for a full day. The rotation is applied at an arbitrary offset within the hour after midnight (the goroutine's phase depends on process start), so a multi-node deployment rotates at different wall-clock moments and clients bounce between nodes re-solving challenges. And an operator who rotates a compromised secret and runs `reload` gets no protection for up to an hour — the compromised key keeps issuing valid tokens, exactly when the operator believes it is dead.

**Fix**

Derive the OTP from an aligned time bucket (`time.Now().UTC().Format("2006-01-02-15")`) so all nodes agree, and recompute on a short aligned ticker rather than an hourly Sleep. Call the derivation function directly at the end of ReloadConfig so a secret rotation takes effect immediately. Keep the previous bucket's OTP valid for a short grace window so in-flight clients are not re-challenged at the boundary.

*Verifier:* Verified. monitor.go:650-651 formats currDate as "2006-01-02" (date only), :653-655 derive all three OTPs from it, :657 sleeps a flat 1 hour — so key material changes once per calendar day, on an unaligned hourly phase set by process start, and the comment at :646 claiming hourly rotation is wrong. ReloadConfig at monitor.go:414-416 replaces CookieSecret/JSSecret/CaptchaSecret but never recomputes the OTPs, so a rotated secret takes up to an hour to take effect. All three sub-claims hold; the aligned-bucket fix is correct.

### OTP and hour-bucket globals are written by background goroutines and read on the request hot path with no synchronization

- **Dimension:** security-crypto  
- **Location:** `core/proxy/proxy.go:24-33 and :52-53; writers core/server/monitor.go:217-218, :653-655, :414-416; readers core/server/middleware.go:184-198`  
- **Effort:** small

**Evidence**

core/proxy/proxy.go:24-33 declares them as plain package vars: `CookieSecret string` / `CookieOTP string` / `JSSecret string` / `JSOTP string` / `CaptchaSecret string` / `CaptchaOTP string`, and :52-53 `CurrHour int` / `CurrHourStr string`.
Writers: core/server/monitor.go:653-655 (`generateOTPSecrets` goroutine, started at monitor.go:57 `go generateOTPSecrets()`), core/server/monitor.go:217-218 (`proxy.CurrHour, _, _ = proxy.LastSecondTime.Clock()` / `proxy.CurrHourStr = strconv.Itoa(proxy.CurrHour)`), and core/server/monitor.go:414-416 (ReloadConfig, driven by terminal input).
Readers: core/server/middleware.go:184 `accessKey := ip + tlsFp + reqUa + proxy.CurrHourStr` and :192/194/198 `utils.Encrypt(accessKey, proxy.CookieOTP)` / `proxy.JSOTP` / `proxy.CaptchaOTP` — no lock, no atomic, on every request.

**Impact**

A string header is two words (data pointer + length); concurrent write and read is a genuine data race, which Go does not guarantee to be tear-free. The benign outcome is a request deriving its token from a half-updated OTP at the rotation instant, producing a token that never validates — a burst of spurious challenge failures which the code counts against the client (middleware.go:217) and can escalate into a self-inflicted ratelimit. The malign outcome is a torn pointer/length pair producing an out-of-range slice or garbage key material. `go test -race`/`go build -race` will flag this immediately.

**Fix**

Publish the OTP triple through a single `atomic.Pointer[otpSet]` (or a small RWMutex-guarded struct) that the generator swaps wholesale and the middleware loads once per request; do the same for CurrHourStr. That also gives the request a consistent view of all three OTPs, which the current code does not have.

*Verifier:* Verified. core/proxy/proxy.go:24-33 declares CookieSecret/CookieOTP/JSSecret/JSOTP/CaptchaSecret/CaptchaOTP as plain package vars and :52-53 CurrHour/CurrHourStr likewise. Writers: monitor.go:653-655 in the generateOTPSecrets goroutine, monitor.go:217-218 in printStats (every second), monitor.go:414-416 from terminal input. Readers: middleware.go:184 and :192/:194/:198 on every request with no lock — firewall.Mutex is taken around the counter maps at :88-100 and :216-218 but never around these. CurrHourStr is the worse case, rewritten once per second against unsynchronised per-request reads. This is a genuine data race the Go memory model does not make tear-free. The torn-slice outcome is speculative but the race and the token-mismatch burst are not; medium is right.

### Proxy-to-backend TLS runs with InsecureSkipVerify:true — the origin hop is unauthenticated

- **Dimension:** security-crypto  
- **Location:** `core/server/serve.go:206 (transport built at :198-210, used at :125 via :212-219)`  
- **Effort:** small

**Evidence**

core/server/serve.go:206 `TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},` inside `var defaultTransport = &http.Transport{ … }`, which is the transport handed to every domain: core/server/serve.go:212-219 `func getTripperForDomain(domain string) *http.Transport { transport, ok := transportMap.Load(domain); if !ok { transport, _ = transportMap.LoadOrStore(domain, defaultTransport) } … }` and used by core/server/serve.go:125 `transport := getTripperForDomain(req.Host)`.
Backends are configured per domain with a scheme that may be https: core/domains/domain.go:28 `Scheme string \`json:"scheme"\``, wired at core/config/init.go:126-129 `httputil.NewSingleHostReverseProxy(&url.URL{ Scheme: domain.Scheme, Host: domain.Backend })`.

**Impact**

For any domain configured with `"scheme": "https"`, certificate chain and hostname verification are both off. Anyone in a position to redirect or intercept the proxy-to-origin path (a hostile network between the DDoS scrubber and the customer's server, a hijacked BGP route, a compromised host in the same datacenter, or a DNS answer for the backend name) terminates that TLS with a self-signed certificate and reads or rewrites every request and response — including the session cookies and credentials of all users the proxy is protecting. It also silently negates the reason the operator chose https for the backend hop.

**Fix**

Drop InsecureSkipVerify and set `ServerName` to the configured backend hostname. Where the origin uses a private CA or a self-signed cert, add a per-domain `backendCA` config option loaded into `RootCAs`, or a pinned certificate fingerprint — and make the insecure mode an explicit, per-domain, documented opt-in rather than the global default.

*Verifier:* Verified. core/server/serve.go:206 is `TLSClientConfig: &tls.Config{InsecureSkipVerify: true},` inside defaultTransport (declared at :198), and getTripperForDomain at :212-219 is the only writer of transportMap (grep: serve.go:23 declare, :214 Load, :216 LoadOrStore) — nothing ever stores a different transport, so every domain gets the insecure one via serve.go:125. domain.Scheme (core/domains/domain.go:28) is wired into the reverse proxy at core/config/init.go:126-129, so an https backend really is unverified. Severity trimmed one level: every shipped example uses "scheme": "http" (examples/config.json:33, :71, :109), so exploitation requires both an https backend and a network position on the proxy-to-origin hop. Fix is correct.

### ReloadConfig re-reads secrets without the CHANGE_ME/placeholder validation that startup enforces

- **Dimension:** security-crypto  
- **Location:** `core/server/monitor.go:401-416 vs core/config/init.go:40-63`  
- **Effort:** small

**Evidence**

core/config/init.go:40-63 validates on startup: `proxy.CookieSecret = domains.Config.Proxy.Secrets["cookie"]` / `if strings.Contains(proxy.CookieSecret, "CHANGE_ME") { panic("[ … ] [ Cookie Secret Contains 'CHANGE_ME', Refusing To Load ]") }` — repeated for JS, captcha, admin, and API secrets.
core/server/monitor.go:414-416 has no equivalent guard: `proxy.CookieSecret = domains.Config.Proxy.Secrets["cookie"]` / `proxy.JSSecret = domains.Config.Proxy.Secrets["javascript"]` / `proxy.CaptchaSecret = domains.Config.Proxy.Secrets["captcha"]`.
ReloadConfig also never re-reads AdminSecret or APISecret at all, so those two cannot be rotated without a restart.

**Impact**

The startup refusal to run with placeholder secrets is bypassable at runtime: an operator who edits config.json down to the example values (examples/config.json:6-11 ships `"CHANGE_ME"` / `"CHANGE_ME1"` …) and types `reload` gets a running proxy whose challenge secrets are the publicly documented placeholders, with no error shown. Conversely, rotating adminsecret/apisecret in config.json and reloading silently keeps the old credentials live, so an operator responding to a leak believes they have rotated when they have not.

**Fix**

Extract the secret-loading-and-validation block into one function called by both config.Load and ReloadConfig, extend it to reject empty and too-short values, and have ReloadConfig abort the reload (keeping the previous config) rather than panicking a live proxy. Include AdminSecret and APISecret in the reload path.

*Verifier:* Verified. core/config/init.go:40-63 has five CHANGE_ME panics; core/server/monitor.go:414-416 assigns the same three secrets with no guard at all, and grepping the whole ReloadConfig body (monitor.go:401 onward) confirms AdminSecret and APISecret are never re-read, so they cannot be rotated without a restart. examples/config.json:5-11 really does ship "CHANGE_ME"/"CHANGE_ME1"/"CHANGE_ME2"/"CHANGE_ME3", so the described runtime bypass of the startup refusal is reachable. Note this partly overlaps otp-rotation-daily-with-lag on the same three lines; the shared-function fix resolves both.

### Security policy data (the fingerprint block/allow lists) is fetched from a third-party repository at startup with no integrity verification

- **Dimension:** security-crypto  
- **Location:** `core/config/init.go:104-106 and :224-227, core/config/generate.go:102-118`  
- **Effort:** small

**Evidence**

core/config/init.go:104-106 `GetFingerprints("https://raw.githubusercontent.com/41Baloo/balooProxy/main/global/fingerprints/known_fingerprints.json", &firewall.KnownFingerprints)` / `…/bot_fingerprints.json", &firewall.BotFingerprints)` / `…/malicious_fingerprints.json", &firewall.ForbiddenFingerprints)`.
core/config/generate.go:102-118 `func GetFingerprints(url string, target *map[string]string) error { resp, err := http.Get(url); … body, err := ioutil.ReadAll(resp.Body); … err = json.Unmarshal(body, &target); … }` — no signature check, no checksum, no size limit, no timeout, and the return value is discarded at the three call sites.
core/config/init.go:224-227 makes a second startup dependency hard-fail: `vcErr := VersionCheck(); if vcErr != nil { panic(…) }`, where VersionCheck (init.go:237-238) is another `http.Get` to the same repository.

**Impact**

The tables that decide which TLS fingerprints are known browsers, which are bots and which are outright forbidden (consumed at core/server/middleware.go:84-85 and :135) are downloaded from an account the operator does not control, with only transport trust and no signature. Whoever controls that repository — or anyone who compromises it — can flip a legitimate browser fingerprint into ForbiddenFingerprints (instant self-inflicted outage for real users) or empty BotFingerprints (attack traffic reclassified as benign). The three errors are ignored, so a failed or truncated fetch leaves stale/partial policy silently in place, and the unrelated VersionCheck panics the proxy outright if GitHub is unreachable.

**Fix**

Bundle the fingerprint JSON in the repository under global/fingerprints and load it from disk (the LancarSec fork already plans this) so startup has no network dependency. If remote refresh is kept, sign the payload and verify with an embedded public key, enforce a timeout and a size limit, and never replace a good in-memory table with the result of a failed fetch. Make VersionCheck advisory rather than fatal.

*Verifier:* Verified. core/config/init.go:104-106 makes three unauthenticated GETs to raw.githubusercontent.com/41Baloo/balooProxy and discards all three return values; core/config/generate.go:102-118 is plain http.Get with no timeout, no size limit, no signature or checksum, unmarshalling straight over the live policy maps. Those maps are the block/allow decision at middleware.go:84-85 and :135. Separately confirmed: core/config/init.go:224-227 panics the whole proxy when VersionCheck (init.go:237-238, another GET to the same repo) fails, so GitHub being unreachable is a hard startup failure. All claims hold. Medium is appropriate for a fork inheriting policy from an account it does not control; bundling under global/fingerprints is the right fix.

### Server TLS config sets no MinVersion or cipher policy, and enables client-style renegotiation that is meaningless on a server

- **Dimension:** security-crypto  
- **Location:** `core/server/serve.go:71-75`  
- **Effort:** trivial

**Evidence**

core/server/serve.go:71-75 `TLSConfig: &tls.Config{ GetConfigForClient: firewall.Fingerprint, GetCertificate: domains.GetCertificate, Renegotiation: tls.RenegotiateOnceAsClient, },` — no MinVersion, no MaxVersion, no CipherSuites, no CurvePreferences.
go.mod:3 `go 1.19`; Dockerfile:1 `FROM golang:1.19-alpine`; .github/workflows/release.yml:20 `go-version: "1.19"`.
core/firewall/fingerprint.go:52-58 also closes the connection but returns a nil error on a malformed hello: `if !(len(clientHello.CipherSuites) > 0) { defer clientHello.Conn.Close(); return nil, nil }`.

**Impact**

Built with the pinned Go 1.19 toolchain, a crypto/tls server with no MinVersion accepts TLS 1.0 and 1.1 and their CBC/SHA-1 cipher suites, so the origin-mode listener (:443) negotiates downgraded, BEAST/Lucky13-class connections with any client that offers them — on the box whose entire purpose is to be the hardened edge. Because Go's GODEBUG defaults are keyed to the go.mod directive, simply building with go1.25 does not reliably fix this; only an explicit MinVersion does. `Renegotiation: tls.RenegotiateOnceAsClient` is a client-side field and does nothing here, which suggests the setting was intended as hardening and silently is not.

**Fix**

Set `MinVersion: tls.VersionTLS12` (TLS 1.3 preferred where the client base allows), give an explicit CipherSuites list for the 1.2 path with AEAD suites only, and delete the Renegotiation field. Bump the go.mod directive to the current toolchain so future crypto/tls defaults are inherited rather than frozen at 1.19 semantics.

*Verifier:* Verified and empirically confirmed. serve.go:71-75 is exactly the TLSConfig block with GetConfigForClient/GetCertificate/Renegotiation and no MinVersion, MaxVersion, CipherSuites or CurvePreferences; firewall.Fingerprint (core/firewall/fingerprint.go:52-87) returns (nil, nil) on every path, so it never supplies a hardened config either. I built a minimal server with this exact config in a module with `go 1.19` on the local go1.25.4 toolchain: TLS1.0 ACCEPTED (0x301), TLS1.1 ACCEPTED (0x302). Changing only the go.mod directive to `go 1.22` flipped both to REJECTED. That proves the finding's central claim — the tls10server GODEBUG default IS keyed to the go.mod directive, so bumping the toolchain alone does not fix it. Renegotiation: tls.RenegotiateOnceAsClient is indeed a client-only field and a no-op on a server. Only correction: the malformed-hello note points at fingerprint.go:52-58 when the check is at :55-58.

### /_bProxy/stats and /_bProxy/fingerprint disclose mitigation state to any client

- **Dimension:** security-http  
- **Location:** `core/server/middleware.go:325-333`  
- **Effort:** trivial

**Evidence**

case "/_bProxy/stats":
	writer.Header().Set("Content-Type", "text/plain")
	SendResponse("Stage: "+utils.StageToString(domainData.Stage)+"\nTotal Requests: "+strconv.Itoa(domainData.TotalRequests)+"\nBypassed Requests: "+...+"\nProxy Fingerprint: "+proxy.Fingerprint, buffer, writer)
	return
case "/_bProxy/fingerprint":
	...SendResponse("IP: "+ip+"\nIP Requests: "+strconv.Itoa(ipCount)+"\nIP Challenge Requests: "+strconv.Itoa(ipCountCookie)+"\nSusLV: "+strconv.Itoa(susLv)+...

**Impact**

Neither endpoint checks any secret — passing the (bypassable) challenge is the only gate. An attacker running a flood gets a free real-time oracle: current challenge stage, total vs. bypassed r/s, and their own remaining ratelimit budget and computed suspicion level. That is exactly the feedback loop needed to tune a flood to stay just under every threshold, and to detect the instant the operator raises the stage. `proxy.Fingerprint` additionally identifies the deployment.

**Fix**

Require the `Proxy-Secret` header (as api.ProcessV2 does, core/api/api.go:155) on both endpoints, or bind them to an operator-configured source CIDR. Keep only `/_bProxy/credits` and `/_bProxy/verified` unauthenticated.

*Verifier:* Verified. core/server/middleware.go:325 (/_bProxy/stats) and :329 (/_bProxy/fingerprint) are plain switch cases with no secret check, unlike /_bProxy/api/v1 at :337 and api.ProcessV2's Proxy-Secret gate at core/api/api.go:155. The disclosed fields match the finding: stage, total/bypassed requests, RPS, proxy.Fingerprint, and the caller's own ipCount/ipCountCookie/susLv. Only the challenge gates them, and that gate is itself forgeable under finding 1. Medium is right for a real-time tuning oracle on a mitigation appliance.

### Admin API secret embedded in the URL path and compared non-constant-time

- **Dimension:** security-http  
- **Location:** `core/server/middleware.go:337`  
- **Effort:** small

**Evidence**

case "/_bProxy/" + proxy.AdminSecret + "/api/v1":
	result := api.Process(writer, request, domainData)

and core/api/api.go:17
	if request.Header.Get("proxy-secret") != proxy.APISecret {
		return false
	}

**Impact**

A secret in the request line is logged by every intermediary — Cloudflare's request logs, the origin's access log, any browser history or Referer if the URL is ever loaded in a page — and is cached as a cache key by CDNs. Rotating it means rotating a URL. Separately, `!=` on the API secret is a byte-wise comparison that short-circuits, giving a (small but real, and amplifiable over many requests) timing side channel. When the header secret is wrong, api.Process returns false and the switch case falls through, so the admin URL — secret and all — is proxied to the customer's backend and lands in their logs too.

**Fix**

Move the admin secret to an `Admin-Secret` request header, keep only a fixed `/_bProxy/api/v1` path, compare both secrets with crypto/subtle.ConstantTimeCompare, and return 404 (not a fallthrough to the backend) when authentication fails.

*Verifier:* Verified. core/server/middleware.go:337 is case "/_bProxy/" + proxy.AdminSecret + "/api/v1", and core/api/api.go:17 compares with a short-circuiting != against proxy.APISecret. The proxied-on-failure claim is behaviourally correct even though Go switches do not fall through: the case body is 'result := api.Process(...); if result { return }', so a false result exits the switch and execution continues to DomainProxy.ServeHTTP at line 363, sending the secret-bearing URL to the customer backend. Medium is right.

### Challenge page loads its proof-of-work code from a mutable CDN ref with no SRI

- **Dimension:** security-http  
- **Location:** `core/server/middleware.go:232`  
- **Effort:** small

**Evidence**

<script src="https://cdn.jsdelivr.net/gh/41Baloo/balooPow@main/balooPow.min.js"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.0.0/crypto-js.min.js"></script>

**Impact**

The stage-2 interstitial — served on the protected domain's own origin, to every visitor of every customer, exactly when the site is under attack — executes JavaScript pulled from a third party at `@main`, an unpinned mutable Git ref, with no `integrity` attribute and no CSP restricting script-src. Whoever controls that GitHub branch (or a jsDelivr cache-poisoning bug) executes arbitrary code in the origin of every site the proxy protects, reading challenge cookies and any session cookie not marked HttpOnly. It is also an availability dependency: if jsDelivr is unreachable, no visitor can solve the challenge and the site is fully down while under attack.

**Fix**

Self-host the PoW bundle and crypto-js from the proxy binary (embed with go:embed and serve under `/_bProxy/`), or at minimum pin an immutable version tag plus a `integrity="sha384-..."` attribute and `crossorigin="anonymous"`, and add a CSP script-src that names only the allowed origin.

*Verifier:* Verified. core/server/middleware.go:232 embeds <script src="https://cdn.jsdelivr.net/gh/41Baloo/balooPow@main/balooPow.min.js"> and a crypto-js script from cdnjs, both without integrity or crossorigin attributes, and there is no CSP on the response (only Content-Type and Cache-Control at lines 230-231). @main is a mutable ref, so this is both a supply-chain execution path into every protected origin and an availability dependency during exactly the attack window the page exists for. Medium is right.

### IPv6 client addresses are parsed with strings.Split on ':' and collapse into shared buckets

- **Dimension:** security-http  
- **Location:** `core/server/middleware.go:73`  
- **Effort:** trivial

**Evidence**

ip = strings.Split(request.RemoteAddr, ":")[0]

Verified with go1.25.4: strings.Split("[2001:db8::1]:51234", ":")[0] == "[2001".

**Impact**

In origin (non-Cloudflare) mode every IPv6 client is reduced to the text before the first colon of the bracketed address — `"[2001"` for the whole 2001::/16 space, `"[2a00"` for another. All of those clients then share one ratelimit counter (`firewall.AccessIps[ip]`, line 79) and one challenge-cookie counter, so a single IPv6 attacker trips `ipCount > proxy.IPRatelimit` for every unrelated IPv6 visitor in the same nibble — a trivially triggered collateral ban of a large slice of the internet. Conversely the same string is baked into the challenge token key (line 184), so a token minted by one IPv6 client is valid for every other client sharing the prefix and the same UA and TLS fingerprint: a challenge bypass. `net.ParseIP("[2001")` in the firewall DSL (line 153) also returns nil, so all `ip.src` rules silently never match IPv6.

**Fix**

Use `host, _, err := net.SplitHostPort(request.RemoteAddr)` and `net.ParseIP(host)`, then normalise to a canonical form (and to a /64 prefix for ratelimit keying) before using it as a counter key or token input.

*Verifier:* Verified in code at core/server/middleware.go:73 and empirically with go1.25.4: strings.Split("[2001:db8::1]:51234", ":")[0] == "[2001". That value keys firewall.AccessIps/AccessIpsCookie (lines 79-80), the WindowAccessIps bucket (line 96), the challenge accessKey (line 184), and is passed to net.ParseIP for ip.src (line 152) where it yields nil. Both consequences follow: collateral ratelimiting across a whole IPv6 nibble, and token reuse across any client sharing the prefix plus UA plus TLS fingerprint. Origin-mode only, which is why medium rather than high.

### Open redirect in the stage-1 challenge via a scheme-relative request target

- **Dimension:** security-http  
- **Location:** `core/server/middleware.go:226`  
- **Effort:** trivial

**Evidence**

writer.Header().Set("Set-Cookie", "_1__bProxy_v="+encryptedIP+"; SameSite=Lax; path=/; Secure")
http.Redirect(writer, request, request.URL.RequestURI(), http.StatusFound)

Verified with go1.25.4 against net/http: for the request line `GET //evil.com/x?a=b HTTP/1.1`, `r.URL.Path == "//evil.com/x"`, `r.URL.Host == ""`, `r.URL.RequestURI() == "//evil.com/x?a=b"`, and `http.Redirect` emits `Location: //evil.com/x?a=b`.

**Impact**

`url.ParseRequestURI` (server side) refuses to parse the authority for a scheme-relative target, but `url.Parse` inside http.Redirect does parse it, so u.Host != "" and the value is emitted verbatim. Every protected domain therefore serves a 302 to an arbitrary third-party host from a URL of the form `https://victim.com//attacker.com/`, inheriting the victim domain's reputation for phishing, OAuth `redirect_uri` abuse and token leakage via Referer. Stage 1 is the default stage for every domain (core/config/init.go:174 `Stage: 1`), so this is reachable on a normal first visit.

**Fix**

Reject or normalise request targets beginning with `//` before redirecting, and build the Location explicitly from a validated path: `u := *request.URL; u.Scheme=""; u.Host=""; if strings.HasPrefix(u.Path, "//") { u.Path = "/" + strings.TrimLeft(u.Path, "/") }; http.Redirect(w, r, u.RequestURI(), http.StatusFound)`.

*Verifier:* Code verified at core/server/middleware.go:226 (http.Redirect with request.URL.RequestURI()), and behaviour verified empirically with go1.25.4: for request line 'GET //evil.com/x?a=b HTTP/1.1' the server-side parse yields URL.Path="//evil.com/x", URL.Host="", RequestURI()="//evil.com/x?a=b", and http.Redirect emits Location: //evil.com/x?a=b verbatim (url.Parse inside Redirect does resolve the authority, so the relative-path fixup branch is skipped). Reachable on first visit since core/config/init.go:173 sets Stage: 1. Downgraded one level: an unauthenticated open redirect is conventionally medium, not high.

### Proxy challenge cookies are not HttpOnly and are forwarded verbatim to the backend

- **Dimension:** security-http  
- **Location:** `core/server/middleware.go:225`  
- **Effort:** small

**Evidence**

if !strings.Contains(request.Header.Get("Cookie"), "__bProxy_v="+encryptedIP) {
...
	writer.Header().Set("Set-Cookie", "_1__bProxy_v="+encryptedIP+"; SameSite=Lax; path=/; Secure")
...
(line 363) domainSettings.DomainProxy.ServeHTTP(writer, request)

`grep -rn "HttpOnly" --include=*.go core/` returns nothing, and no code removes `*__bProxy_v` from request.Header before ServeHTTP.

**Impact**

The bypass token is readable by any JavaScript running on the protected origin and is also sent upstream on every proxied request. A single reflected-XSS bug on the customer's backend, a compromised third-party script, or a shared/multi-tenant backend that logs request headers yields a token that grants full challenge bypass for that IP+fingerprint+UA for the rest of the hour — the attacker can then hand it to a botnet sharing the spoofed Cf-Connecting-Ip. The backend has no legitimate use for the proxy's internal cookie.

**Fix**

Set `HttpOnly` on `_1__bProxy_v` (stage 1 is server-set, so nothing breaks), and strip every cookie whose name ends in `__bProxy_v` from request.Header before calling DomainProxy.ServeHTTP — rebuild the Cookie header from request.Cookies() minus the proxy's own entries.

*Verifier:* Verified. core/server/middleware.go:225 sets _1__bProxy_v with only SameSite=Lax; path=/; Secure, and a repo-wide grep for HttpOnly returns zero hits. No code removes *__bProxy_v from request.Header before core/server/middleware.go:363 calls domainSettings.DomainProxy.ServeHTTP. Token scope confirmed: accessKey = ip+tlsFp+reqUa+proxy.CurrHourStr (line 184), and CurrHourStr is the clock hour (core/server/monitor.go:47-48), so a stolen token is valid for the remainder of that hour. Downgraded to medium: exploitation requires a separate XSS or header-logging bug on the customer backend.

### Proxy-to-backend TLS runs with InsecureSkipVerify for every domain

- **Dimension:** security-http  
- **Location:** `core/server/serve.go:206`  
- **Effort:** medium

**Evidence**

var defaultTransport = &http.Transport{
...
	TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
...
}

func getTripperForDomain(domain string) *http.Transport {
	transport, ok := transportMap.Load(domain)
	if !ok {
		transport, _ = transportMap.LoadOrStore(domain, defaultTransport)
	}
	return transport.(*http.Transport)
}

**Impact**

Any domain configured with `"scheme": "https"` (core/config/init.go:126-129) connects to its backend with certificate validation entirely disabled and no way to re-enable it — the map only ever stores the one shared defaultTransport. An attacker positioned between the proxy and the origin (a hostile hop in a hosting provider, a poisoned DNS answer for the backend hostname, an ARP-spoofing neighbour in the same datacenter VLAN) silently MITMs all traffic for every protected site, including the challenge cookies the proxy forwards. `MaxConnsPerHost: 10` is also shared across all domains, so one slow backend starves the others.

**Fix**

Build a per-domain *http.Transport in config.buildDomain with `TLSClientConfig: &tls.Config{ServerName: <backend host>, MinVersion: tls.VersionTLS12}` and verification on by default, exposing an explicit per-domain `backend_tls_verify: false` escape hatch for self-signed origins. Size MaxIdleConns/MaxConnsPerHost per domain rather than globally.

*Verifier:* Verified exactly as cited. core/server/serve.go:206 is TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, and getTripperForDomain (serve.go:212-219) only ever LoadOrStores the single shared defaultTransport, so there is genuinely no per-domain override path. core/config/init.go:126-128 does build the reverse proxy from domain.Scheme, so an https backend is configurable and would run unverified. MaxIdleConns/MaxConnsPerHost 10 are global as claimed (serve.go:208-209). Medium is right.

### Ratelimit and block responses return HTTP 200 with no Cache-Control

- **Dimension:** security-http  
- **Location:** `core/server/middleware.go:25-28`  
- **Effort:** trivial

**Evidence**

if ipCountCookie > proxy.FailChallengeRatelimit {
	writer.Header().Set("Content-Type", "text/plain")
	SendResponse("Blocked by BalooProxy.\nYou have been ratelimited. (R1)", buffer, writer)
	return
}

func SendResponse(str string, buffer *bytes.Buffer, writer http.ResponseWriter) {
	buffer.WriteString(str)
	writer.Write(buffer.Bytes())
}  // middleware.go:25-28 — WriteHeader is never called, so Go emits 200

**Impact**

Every block path (R1/R2/R3 at lines 110/117/125, the forbidden-fingerprint block at 138, and the suspicious-level blocks at 201 and 300) answers 200 OK with a cacheable body. With Cloudflare in front — the documented primary deployment — an attacker who trips their own ratelimit on `/`, `/main.css` or any cacheable asset can get "Blocked by BalooProxy" stored in the shared CDN cache under a 200 and served to every legitimate visitor: a cache-poisoning denial of service driven by the mitigation itself. It also makes blocks invisible to any monitoring that counts non-2xx responses.

**Fix**

Call `writer.WriteHeader(http.StatusTooManyRequests)` (or 403 for the fingerprint/suslevel blocks) before writing the body, and set `Cache-Control: no-store` plus `Retry-After` on every block and challenge response.

*Verifier:* Verified. core/server/middleware.go:25-28 SendResponse writes the body without ever calling WriteHeader, so Go emits 200. Block paths confirmed at lines 110, 117, 125, 138, 201 and 300 — all exactly as cited — and none of the text/plain block paths sets Cache-Control (only the two HTML challenge pages at 231 and 295 do). With Cloudflare in front and extension-based default caching, a 200 text/plain block body on a cacheable asset path is a genuine shared-cache poisoning vector. Medium is right.

### TLS MinVersion never set — the HTTPS listener accepts TLS 1.0 and 1.1

- **Dimension:** security-http  
- **Location:** `core/server/serve.go:71-75`  
- **Effort:** trivial

**Evidence**

TLSConfig: &tls.Config{
	GetConfigForClient: firewall.Fingerprint,
	GetCertificate:     domains.GetCertificate,
	Renegotiation:      tls.RenegotiateOnceAsClient,
},

`grep -rn "MinVersion" --include=*.go core/` returns nothing, and firewall.Fingerprint returns `nil, nil` (core/firewall/fingerprint.go:86) so no per-client config overrides the base one.

**Impact**

Go's crypto/tls defaults to VersionTLS10 as the server minimum (only the client default was raised to 1.2). The origin-mode :443 listener therefore negotiates TLS 1.0/1.1 with CBC-only ciphersuites, exposing clients to BEAST/Lucky13-class attacks and failing PCI-DSS 3.2.1 and every modern baseline — on a product sold as a security appliance. `Renegotiation: tls.RenegotiateOnceAsClient` on a server config is also inert (server-side renegotiation is unsupported in Go) and gives a false sense of hardening.

**Fix**

Set `MinVersion: tls.VersionTLS12` (ideally 1.3 where the client base allows), pin an explicit CipherSuites list for the 1.2 path, set `NextProtos: []string{"h2", "http/1.1"}` deliberately, and delete the meaningless Renegotiation field.

*Verifier:* Verified. core/server/serve.go:71-75 sets only GetConfigForClient, GetCertificate and Renegotiation; a repo-wide grep for MinVersion returns nothing, and firewall.Fingerprint returns nil,nil so no per-client override applies. The TLS 1.0 claim holds specifically because go.mod:3 declares 'go 1.19', which pins the tls10server GODEBUG to its pre-1.22 default; the finding states the Go default flatly without that nuance, and the issue self-heals once the go directive moves to >=1.22. The Renegotiation-is-inert-on-a-server observation is correct. Downgraded to medium: accepting TLS 1.0/1.1 is a compliance/hardening defect, not an exploitable break.


## LOW

### Credits endpoint: what the GPL actually requires you to keep when rebranding

- **Dimension:** branding  
- **Location:** `core/server/middleware.go:343-346`  
- **Effort:** small

**Evidence**

core/server/middleware.go:343-346:
	//Do not remove or modify this. It is required by the license
	case "/_bProxy/credits":
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("BalooProxy; Lightweight http reverse-proxy https://github.com/41Baloo/balooProxy. Protected by GNU GENERAL PUBLIC LICENSE Version 2, June 1991", buffer, writer)

**Impact**

Category (e) legal. This is the one `baloo` hit in the inventory you may NOT simply sed away. The GPL (both v2 §2(a)/§1 and v3 §5(a)) requires that modified files carry prominent notices stating that you changed them and the date, that the whole work stay licensed under the same GPL, and that all existing copyright notices and license notices be preserved. GPL v3 §7(b) additionally permits the original author to require preservation of specified reasonable legal notices or author attributions — the `//Do not remove or modify this` comment is upstream asserting exactly that. Deleting this endpoint, or stripping the upstream project name and repo URL from it, is a plausible license violation that terminates your rights under §8/§4 and is the kind of thing that gets a commercial fork of a security product publicly called out.

**Fix**

Keep the route (renamed to `/_lancarsec/credits` along with the rest of the prefix — the PATH is a wire token you may change; the CONTENT is the legal artifact). Rewrite the body to ADD your identity while PRESERVING upstream's, e.g.: `LancarSec; Lightweight http reverse-proxy. Derived from balooProxy (https://github.com/41Baloo/balooProxy), Copyright (C) 41Baloo. Modified by <LancarSec entity>, <year>. Licensed under the GNU GENERAL PUBLIC LICENSE Version <N as per LICENSE>.` What must stay: the upstream project name, the upstream copyright holder, the link, and the license statement. What may be added: your name, your modification notice, your product name. What must NOT happen: removing the upstream attribution, or relicensing. Separately, add per-file 'modified by' notices and keep the LICENSE file byte-identical. If the fork is distributed as a binary, GPL v3 §6 also obliges you to offer the corresponding source of YOUR modified version to recipients.

*Verifier:* The cited code exists exactly as quoted: middleware.go:343 is the `//Do not remove or modify this. It is required by the license` comment, :344 the `/_bProxy/credits` case, :346 the credits string naming BalooProxy and the upstream repo URL. The legal reasoning (preserve upstream name/copyright/link, add rather than replace, keep LICENSE byte-identical) is sound and the warning against blanket-sed'ing this line is the operationally useful part. However this contains no verifiable code defect — it is advisory, and it duplicates the location already covered by credits-license-version-mismatch. 'high' overstates it for a finding whose only ask is 'do not delete this string'.

### Operator TUI 'help' command links to github.com/41Baloo/balooProxy

- **Dimension:** branding  
- **Location:** `core/server/monitor.go:262`  
- **Effort:** trivial

**Evidence**

core/server/monitor.go:262:
	fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("help") + " ]: " + utils.PrimaryColor("Displays all available commands. More detailed information can be found at ") + "https://github.com/41Baloo/balooProxy#commands")

**Impact**

Category (c) user-visible string. Operator-facing only (the terminal UI), so no external exposure, but it is the documentation entry point your own admins hit when they type `help` — it sends them to upstream's README, which will drift from LancarSec's behaviour as the fork diverges. Every command documented there (`stage`, `domain`, `add`, `clrlogs`, `reload`, listed at monitor.go:263-267) is a place where upstream docs and fork behaviour can silently disagree.

**Fix**

Point at LancarSec's own documentation URL. If no docs site exists yet, drop the URL from the string rather than shipping a link to a competitor's/upstream's README — a `help` command that lists the commands inline (which monitor.go:263-267 already does) is complete without it.

*Verifier:* Verified verbatim at core/server/monitor.go:262 — the help output appends `https://github.com/41Baloo/balooProxy#commands`. Operator-terminal only, no external exposure. Severity low is correct.

### README.md: 27 'baloo' lines including docker image name, download link, and upstream SwaggerHub API docs

- **Dimension:** branding  
- **Location:** `README.md:11, :45, :49, :55, :57, :60, :63, :64, :68, :77, :82, :86, :120, :162, :166, :174, :178, :182, :186, :191, :216, :442, :447, :475, :487, :489, :502`  
- **Effort:** medium

**Evidence**

README.md:55:
	To start, download the [latest version of balooProxy](https://github.com/41Baloo/balooProxy/releases) balooProxy or compile it from source.
README.md:63:
	... build the Docker image by running `docker build -t baloo-proxy .` ... run the Docker image using `docker run -d -p 80:80 -p 443:443 -t baloo-proxy`.
README.md:68:
	... searching for a "`baloo-proxy`" header in "Response Headers" of your request. If that exist, you successfully setup balooProxy
README.md:502:
	A full documentation of BalooProxies 2.0 API can be found at https://app.swaggerhub.com/apis-docs/BalooProxy/BalooProxy/2.0.0#/

(`grep -ciE baloo README.md` → 27)

**Impact**

Category (c) user-visible string, plus two dependency links. Three hits are more than cosmetic: README.md:55 sends operators to 41Baloo's GitHub releases to DOWNLOAD THE BINARY — your users would install upstream's build, not yours, and any release-asset compromise there lands on your users' origins; README.md:63-64 names the docker image `baloo-proxy`, which is what operators will actually tag and run; README.md:68's verification step depends on the `baloo-Proxy` response header and breaks the moment you rename it. README.md:502 points at upstream's SwaggerHub for the v2 API contract — a doc you neither control nor can keep in sync, describing the `/_bProxy/api/v2` paths you are about to rename.

**Fix**

Full rewrite, not a sed pass — the download and Docker instructions must point at LancarSec's own release channel and image name (`lancarsec`), and README.md:68 must be updated in lockstep with the response-header rename. Replace the SwaggerHub link at :502 with a LancarSec-owned API doc, or inline the v2 contract in the README; do not leave readers pointed at a spec that will diverge from your renamed `/_lancarsec/api/v2` routes. Keep an explicit 'derived from balooProxy' attribution paragraph — that supports the GPL notice obligation rather than conflicting with it.

*Verifier:* Verified exhaustively: `grep -niE baloo README.md | cut -d: -f1` returns exactly 11,45,49,55,57,60,63,64,68,77,82,86,120,162,166,174,178,182,186,191,216,442,447,475,487,489,502 — an exact match for the 27 cited line numbers, with no additions or omissions. The three load-bearing hits are confirmed: :55 links to 41Baloo's releases page for the binary download, :63-64 name the docker image baloo-proxy, :502 points at app.swaggerhub.com/apis-docs/BalooProxy/BalooProxy/2.0.0. The :68 coupling to the `baloo-proxy` response header is real. Severity is generous for documentation with no runtime path.

### Stage-2 challenge tells your visitors to contact upstream's Discord handle '@ddosmitigation'

- **Dimension:** branding  
- **Location:** `core/server/middleware.go:232`  
- **Effort:** trivial

**Evidence**

core/server/middleware.go:232, in the inlined stage-2 challenge JS:
	.Solve().then(e=>{if(e.match == ""){solved(e)}else alert("Navigator Missmatch ("+e.match+"). Please contact @ddosmitigation")});

**Impact**

Category (c) user-visible string, with a support-routing consequence. When the PoW library detects a navigator mismatch, a JS `alert()` fires in the visitor's browser instructing them to contact `@ddosmitigation` — the upstream author's handle, not yours. Your customers' end users get directed to a third party you do not control, who has no relationship with them and no ability to help. It also confirms to anyone probing the challenge exactly which upstream product is deployed. `grep -rno "ddosmitigation"` finds exactly one occurrence, so this is a single-site fix.

**Fix**

Replace `@ddosmitigation` with your own support contact, or better, remove the `alert()` entirely — a blocking modal is poor UX on a challenge page and the mismatch reason is only useful to you. Render a neutral inline message and report the mismatch value back to the proxy for logging instead.

*Verifier:* Verified. `grep -rno "ddosmitigation" .` excluding the committed binary returns exactly one hit: core/server/middleware.go:232, inside the inlined stage-2 JS, `alert("Navigator Missmatch ("+e.match+"). Please contact @ddosmitigation")`. Single-site fix as claimed. Severity is generous for a string that only fires on a navigator-mismatch branch of a third-party library; it is a branding/UX blemish, not medium-impact.

### Unknown-Host response identifies the proxy as 'balooProxy' to unconfigured-domain probes

- **Dimension:** branding  
- **Location:** `core/server/serve.go:89 (reachable only in non-Cloudflare mode, :80 redirect handler assigned at serve.go:82)`  
- **Effort:** trivial

**Evidence**

core/server/serve.go:87-90:
	if !domainFound {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "balooProxy: "+r.Host+" does not exist. If you are the owner please check your config.json if you believe this is a mistake")
		return
	}

**Impact**

Category (c) user-visible string. This fires on the UNAUTHENTICATED, pre-challenge path — anyone who connects to the origin IP with an arbitrary `Host:` header gets it. That makes it the easiest possible product fingerprint: no challenge to solve, no cookie needed, just `curl -H 'Host: x' <origin>`. It additionally reflects the attacker-supplied `r.Host` back into the response body and names `config.json`, disclosing the config filename. Note this is also a `fmt.Fprintf` with a non-constant format string built by concatenation — attacker-controlled `%` verbs in the Host header land in the format argument.

**Fix**

Rename to `LancarSec` and stop echoing `r.Host`: return a fixed generic message with HTTP 404 and no product identifier at all. Change `fmt.Fprintf(w, "..."+r.Host+"...")` to `io.WriteString(w, "...")` — the current form is a `go vet` printf finding waiting to happen as well as an echo primitive.

*Verifier:* The line is verified verbatim at core/server/serve.go:89, and the go-vet non-constant-format-string point is correct (fmt.Fprintf with a concatenated format and no args; a Host containing %s renders %!s(MISSING)). But the reachability claim is materially wider than the code supports. This handler is assigned only inside the `else` branch at serve.go:53 — i.e. NON-Cloudflare mode only — and only to the plain :80 redirect server (serve.go:82-100). In Cloudflare mode (serve.go:35-52) the :80 handler is Middleware and this string is unreachable entirely, and it is never reachable on :443 in either mode. So 'anyone who connects to the origin IP with an arbitrary Host: header gets it' holds only for cleartext :80 in origin mode. Downgraded accordingly.

### assets/html/login.html ships a 'balooProxy Dashboard' page that no Go code references

- **Dimension:** branding  
- **Location:** `assets/html/login.html:140, :151`  
- **Effort:** trivial

**Evidence**

assets/html/login.html:140:
	<h1>balooProxy Dashboard</h1>
assets/html/login.html:151:
	<p> If you forgot your username or password, you can delete/modify the data found in proxyData.db </p>

No Go source references either file — `grep -rn "login.html\|captcha.html\|assets/html" --include="*.go" .` returns zero hits; the live challenge markup is inlined in core/server/middleware.go:232 and :296 instead.

**Impact**

Category (c) user-visible string, on a dead code path. Both HTML assets under assets/html/ are orphaned — the middleware serves its own inlined copies, so these files are never read at runtime. They still ship in the repo and in any Docker image built from it (Dockerfile:9 `COPY . .`), so the branding leaks to anyone reading the source or the image layers. login.html:151 also references `proxyData.db`, a BoltDB store from a `core/db` package that no longer exists in this tree (it is still visible in the stale binary artifact), and tells the reader that deleting a file resets admin credentials. captcha.html:199 is a stale duplicate of the inlined stage-3 markup, which means a future edit to the real challenge in middleware.go will leave this copy silently divergent.

**Fix**

Delete assets/html/login.html and assets/html/captcha.html — they are dead. If you instead want to move the inlined challenge markup OUT of middleware.go (which is worthwhile; the two inlined blobs at :232 and :296 are ~4KB single-line string literals), then make these the real templates, `//go:embed` them, rebrand the `<h1>`, and delete the inlined copies so there is exactly one source of truth.

*Verifier:* Every sub-claim verified. assets/html/login.html:140 is `<h1>balooProxy Dashboard</h1>`; :151 is the `proxyData.db` sentence. `grep -rn "login.html\|captcha.html\|assets/html" --include="*.go" .` returns zero hits, so both assets are genuinely dead — the live markup is inlined at middleware.go:232 and :296. Dockerfile:9 is `COPY . .`, so they do ship in the image. The core/db claim is corroborated independently: `strings oryxBuildBinary` contains /workspaces/balooProxy/core/db/db.go and core/db/init.go, neither of which exists in the tree. Severity low is correct.

### examples/config.json ships baloo.one / baloo.dog domains and upstream's GitHub avatar as the webhook identity

- **Dimension:** branding  
- **Location:** `examples/config.json:31, :38, :39, :69, :76, :107, :114`  
- **Effort:** trivial

**Evidence**

examples/config.json:31,38-39:
	"name": "baloo.one",
	"webhook": {
		"name": "balooProxy",
		"avatar": "https://avatars.githubusercontent.com/u/73783549",
examples/config.json:69:
	"name": "9090.baloo.dog",
examples/config.json:107:
	"name": "baloo.dog",

(The `name`/`avatar` pair is consumed at core/utils/discord.go:43-44 as `Username:`/`Avatar:` on the outgoing webhook payload.)

**Impact**

Categories (c) user-visible string and (d) external dependency. Three example domains and three webhook blocks carry upstream branding. The `avatar` field is not inert documentation: core/utils/discord.go:43-44 puts it directly into the Discord webhook JSON as `avatar_url`, so any operator who copies this example verbatim — the normal path, since examples/config.json is the starter config — posts their DDoS attack alerts into their own Discord under the username `balooProxy` with 41Baloo's GitHub avatar (`u/73783549`) rendered from githubusercontent.com. That is upstream branding appearing inside your customers' incident channels, plus a hotlink to a third-party image on every alert.

**Fix**

Rewrite all three domain names to LancarSec-appropriate examples, set `"name": "LancarSec"`, and either self-host the avatar or drop the `avatar` key (discord.go tolerates an empty `avatar_url`). Also scrub the placeholder webhook URL `https://discord.com/api/webhooks/<upstream-webhook-id-withheld>/XXXX...` — the numeric webhook ID is real-shaped and should be fully redacted in an example file.

*Verifier:* All seven cited lines verified: examples/config.json:31 baloo.one, :38 "name": "balooProxy", :39 avatar https://avatars.githubusercontent.com/u/73783549, :69 9090.baloo.dog, :76, :107 baloo.dog, :114. The consumption chain is real: core/utils/discord.go:43-44 sets Username/Avatar from the domain webhook config (again at :212-213), and the struct tag at discord.go:256 is `Avatar string \`json:"avatar_url"\`` with no omitempty, so an empty avatar serializes as "" rather than being dropped — Discord tolerates that, so the fix's parenthetical holds. Placeholder webhook URL with a real-shaped snowflake ID confirmed at :37. Severity slightly generous for a starter file nobody is obliged to copy verbatim.

### Admin API endpoints abuse the global lock: a 20k-iteration critical section and a no-op lock/unlock

- **Dimension:** concurrency  
- **Location:** `core/api/api.go:102-112`  
- **Effort:** small

**Evidence**

// Useful to fill up your ipCache and see how your proxy performs with high memory usage
case "FILL_IP_CACHE":
	firewall.Mutex.Lock()
	for i := 0; i < 19980; i++ {
		firewall.CacheIps.Store(utils.RandomString(24), utils.RandomString(64))
	}
	firewall.Mutex.Unlock()

	APIResponse(writer, true, map[string]interface{}{})
case "RELOAD":
	firewall.Mutex.Lock()
	firewall.Mutex.Unlock()

and api.go:73-76 / 84-86 hand out the live maps: `ipsAll := firewall.AccessIps` … `firewall.Mutex.RUnlock()` … then serialise them after the lock is released.

**Impact**

`FILL_IP_CACHE` holds the single global write lock across ~40,000 `RandomString` calls and 19,980 sync.Map stores — the whole proxy is frozen for the duration, from one authenticated HTTP request. `RELOAD` is a lock immediately followed by an unlock: it does nothing except add contention, so the documented reload action silently no-ops. `GET_IP_REQUESTS`/`GET_FINGERPRINT_REQUESTS` copy only the map *header* under RLock and then let `encoding/json` iterate the live map after unlocking — a concurrent write from Middleware while `APIResponse` marshals it is a "concurrent map iteration and map write" fatal error that no `recover` can catch, killing the process.

**Fix**

Delete `FILL_IP_CACHE` from production builds (or move it behind a build tag); make `RELOAD` actually call the reload routine; and snapshot maps into a fresh copy while the lock is held before marshalling them.

*Verifier:* The primary claims at the cited lines are verified verbatim. api.go:102-107: FILL_IP_CACHE holds firewall.Mutex.Lock across 19,980 iterations doing two utils.RandomString calls plus a sync.Map.Store each — the whole proxy frozen for the duration from one authenticated request (auth is a `proxy-secret` header check, api.go:17). api.go:110-112: RELOAD is `Mutex.Lock()` immediately followed by `Mutex.Unlock()` and nothing else, so the documented reload silently no-ops. One sub-claim is refuted: the 'concurrent map iteration and map write fatal error' for GET_IP_REQUESTS / GET_FINGERPRINT_REQUESTS (api.go:73-76, 84-86) cannot occur. evaluateRatelimit does not mutate the published maps — it replaces them wholesale (`firewall.AccessIps = map[string]int{}` at monitor.go:597, :608, :619) under the write lock and then fills only the fresh map, all before Unlock at :630. The map object the API captured under RLock is therefore never written again and is safe to marshal after the unlock. Low stands.

### No shutdown path, no context cancellation, and every background loop is an uninterruptible sleep-poll

- **Dimension:** concurrency  
- **Location:** `main.go:47-50`  
- **Effort:** medium

**Evidence**

main.go:47-50:
	go server.Serve()
	//Keep server running
	select {}

Background loops, all `for { ... time.Sleep(...) }` with no stop condition and no context:
monitor.go:97  `time.Sleep(1 * time.Second)`   (Monitor)
monitor.go:571 `time.Sleep(2 * time.Minute)`  (clearProxyCache)
monitor.go:634 `time.Sleep(5 * time.Second)`  (evaluateRatelimit)
monitor.go:657 `time.Sleep(1 * time.Hour)`    (generateOTPSecrets)

A repo-wide grep for `context.` returns exactly one hit — `DialContext` at serve.go:199. There is no `Server.Shutdown`, no signal handling, and `ListenAndServe` errors `panic` (serve.go:51, 108, 113).

**Impact**

There is no way to stop the proxy other than killing it: in-flight requests are severed, the crash log and any buffered state are lost, and a restart drops every challenge cookie because the OTPs re-derive from a fresh clock. The `time.Sleep` polling design also means a config reload cannot re-tune the sweep intervals, and a 1-hour sleep in `generateOTPSecrets` cannot be interrupted at all — after a reload changes `proxy.CookieSecret`, the new secret is not used until up to an hour later. `select{}` as the parking primitive additionally means a panic escaping any background goroutine (PanicHndl re-panics at panicHandler.go:30) takes the process down with no cleanup.

**Fix**

Thread a root `context.Context` from main through every background loop (`for { select { case <-ctx.Done(): return; case <-ticker.C: ... } }`), handle SIGINT/SIGTERM, and call `srv.Shutdown(ctx)` with a deadline instead of `select{}` + `panic`.

*Verifier:* Verified. main.go:47-50 is `go server.Serve()` followed by `select {}` with no signal handling. All four background loops are unconditional `for { ... time.Sleep(...) }` with no stop path: monitor.go:97 (1s), :571 (2m), :634 (5s), :657 (1h). ListenAndServe errors panic at serve.go:51, :108 and :113. My own repo-wide grep for `context.` returns exactly one hit, the DialContext closure at serve.go:199, confirming there is no cancellation plumbing anywhere. pnc.PanicHndl re-panicking after writing crash.log is confirmed at core/pnc/panicHandler.go:30, so a panic in any background goroutine takes the process down. The 1-hour uninterruptible sleep meaning a reloaded CookieSecret (monitor.go:414) is not applied until the next generateOTPSecrets tick (:657) is also correct. Low is the right level for a design gap with no attacker-reachable trigger.

### Ratelimit thresholds and secrets are rewritten by the reload path with no synchronisation against readers

- **Dimension:** concurrency  
- **Location:** `core/server/monitor.go:444-447`  
- **Effort:** small

**Evidence**

monitor.go:444-447 (runs on the `commands` goroutine via the `reload` / `add` commands):
	proxy.IPRatelimit = domains.Config.Proxy.Ratelimits["requests"]
	proxy.FPRatelimit = domains.Config.Proxy.Ratelimits["unknownFingerprint"]
	proxy.FailChallengeRatelimit = domains.Config.Proxy.Ratelimits["challengeFailures"]
	proxy.FailRequestRatelimit = domains.Config.Proxy.Ratelimits["noRequestsSent"]

read with no lock on the hot path:
middleware.go:108 `if ipCountCookie > proxy.FailChallengeRatelimit {`
middleware.go:115 `if ipCount > proxy.IPRatelimit {`
middleware.go:123 `if fpCount > proxy.FPRatelimit {`

Similarly monitor.go:414-416 writes `proxy.CookieSecret`/`JSSecret`/`CaptchaSecret`, which the `generateOTPSecrets` goroutine reads at monitor.go:653-655 — the same variables already proven racy by the detector for their OTP outputs.

**Impact**

Unsynchronised int and string globals shared between the reload goroutine and every handler goroutine. Reads of an `int` that is being written are not guaranteed to observe either the old or new value on all architectures, and there is no happens-before edge at all, so a handler can keep reading a cached stale threshold indefinitely or observe the zero value written by a `map` miss — with `proxy.IPRatelimit == 0` every request is blocked as ratelimited. The secret rewrite racing the OTP rotator can produce an OTP derived from a half-updated secret string, invalidating every outstanding challenge cookie.

**Fix**

Fold all of these into the atomically-published config snapshot (see the config finding) and read one snapshot per request, or at minimum make each an `atomic.Int64` / `atomic.Pointer[string]`.

*Verifier:* Cited lines verified exactly: monitor.go:444-447 assigns proxy.IPRatelimit/FPRatelimit/FailChallengeRatelimit/FailRequestRatelimit from the reload path, read with no lock at middleware.go:108, 115, 123; monitor.go:414-416 writes proxy.CookieSecret/JSSecret/CaptchaSecret, read by generateOTPSecrets at :653-655. Real unsynchronised sharing between the commands goroutine and every handler. Downgraded one level because the concrete impact is refuted: `proxy.IPRatelimit = domains.Config.Proxy.Ratelimits["requests"]` is a single assignment with no zero-write beforehand, so there is no transient window in which a handler observes 0 and blocks all traffic — a 0 there would mean the config genuinely lacks the key, a configuration bug rather than a race. Likewise the OTP consequence is bounded by the fact that the OTP input is a daily date string (monitor.go:651) and EncryptSha output is fixed-length hex, per my verdict on the OTP finding. What remains is a -race-detectable race on plain int/string globals; worth folding into an atomic snapshot, at low severity.

### Webhook goroutines are spawned unbounded with a timeout-less HTTP client and an unclosed response body

- **Dimension:** concurrency  
- **Location:** `core/utils/discord.go:243-249`  
- **Effort:** small

**Evidence**

core/utils/discord.go:
	req, err := http.NewRequest("POST", domainSettings.DomainWebhooks.URL, bytes.NewBuffer(webhookPayload))
	if err != nil { return }
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	client.Do(req)

Spawned as bare goroutines from the Monitor loop while it holds the global lock:
monitor.go:139 `go utils.SendWebhook(domainData, domainSettings, int(1))`
monitor.go:161 `go utils.SendWebhook(domainData, domainSettings, int(0))`
monitor.go:197 `go utils.SendWebhook(domainData, domainSettings, int(0))`

The same function also does a blocking `qc.GetShortUrl()` network call to quickchart.io at discord.go:207.

**Impact**

`&http.Client{}` has no `Timeout`, so a hung or blackholed webhook endpoint (or quickchart.io) parks the goroutine forever — no cancellation, no context. Each fires a fresh `http.Client` with its own transport, so connections are never pooled and, since the response body is never read or closed, the underlying TCP connection and its reader goroutine leak on every call. Under a flapping attack (`BufferCooldown` toggling once per second per domain) these accumulate one per second per domain with nothing bounding them. Note `RequestLogger` is also read by the goroutine (`domainData.RequestLogger[0]`, discord.go:18) from a struct copied under the lock — and `pnc.PanicHndl` re-panics (panicHandler.go:30), so an empty `RequestLogger` there kills the whole process.

**Fix**

One package-level `http.Client{Timeout: 5 * time.Second}`, always `defer resp.Body.Close()` after draining, and replace the bare `go` with a small bounded worker pool (e.g. 4 workers behind a 256-deep channel) that drops rather than queues when saturated.

*Verifier:* Cited code verified: discord.go:243-249 builds the POST, then `client := &http.Client{}` with no Timeout and `client.Do(req)` with the returned response neither drained nor closed; the blocking qc.GetShortUrl() to quickchart.io is at :207; the three bare `go utils.SendWebhook(...)` spawns are at monitor.go:139, 161, 197, inside checkAttack which Monitor calls while holding firewall.Mutex (:88-92). Downgraded one level because two sub-claims are wrong. (a) `&http.Client{}` has a nil Transport, so it uses the shared http.DefaultTransport — connections ARE pooled and there is no per-call transport; the leak is the undrained body preventing connection reuse, not a fresh transport per call. (b) The 'empty RequestLogger kills the whole process via discord.go:18' claim is not reachable: all three call sites append to RequestLogger immediately beforehand (monitor.go:121-129, 155-160, 191-196), so index 0 always exists. Also the accumulation rate is bounded by BufferCooldown = 10 (monitor.go:164, 201), i.e. at most one flap per ~10s per domain, not one per second. The missing Timeout and unclosed body are genuine and worth the proposed shared-client + worker-pool fix.

### Errors are stringified with concatenation instead of wrapped, discarding the chain for errors.Is/As

- **Dimension:** deps-toolchain  
- **Location:** `core/config/init.go:240`  
- **Effort:** small

**Evidence**

core/config/init.go:238-253 (VersionCheck), three times:
```go
resp, err := http.Get("https://raw.githubusercontent.com/41Baloo/balooProxy/main/global/proxy/version.json")
if err != nil {
	return errors.New("Failed to check for proxy version: " + err.Error())
}
```
plus init.go:246 and init.go:252 with the identical pattern.
core/config/generate.go:105, :111, :116 in GetFingerprints:
```go
return errors.New("failed to fetch fingerprints: " + err.Error())
```
core/domains/util.go:11:
```go
return DomainSettings{}, errors.New("domain not found")
```
These all flow into init.go:226 `panic("[ " + utils.PrimaryColor("!") + " ] [ " + vcErr.Error() + " ]")`.

**Impact**

`err.Error()` concatenation flattens the error into a string, so `errors.Is(err, context.DeadlineExceeded)` or `errors.As(err, &netErr)` can never work upstream. In config/init.go this matters concretely: a transient network failure reaching GitHub and a malformed JSON body produce indistinguishable errors, and both take the same `panic` at init.go:226 — the proxy refuses to start because a version-check HTTP call failed. `errors.Join` (Go 1.20) is likewise unavailable at the 1.19 directive for aggregating the per-domain rule-compile failures in monitor.go:76.

**Fix**

Use `fmt.Errorf("check proxy version: %w", err)` at init.go:240/246/252 and `fmt.Errorf("fetch fingerprints: %w", err)` at generate.go:105/111/116; define `var ErrDomainNotFound = errors.New("domain not found")` in core/domains and return it as a sentinel from util.go:11. Then make init.go:226 distinguish a network error (log and continue) from a real config error (panic) via `errors.As`.

*Verifier:* The primary evidence is correct: config/init.go:240, :246 and :252 are all `return errors.New("Failed to check for proxy version: " + err.Error())` inside VersionCheck; generate.go:105, :111 and :116 are the identical pattern in GetFingerprints; domains/util.go:11 is `return DomainSettings{}, errors.New("domain not found")`; and init.go:226 really does `panic(...)` on any VersionCheck error, so a transient network failure to GitHub is indistinguishable from malformed JSON and both refuse startup — that part of the impact is real and well-argued. One citation is fabricated: 'aggregating the per-domain rule-compile failures in monitor.go:76' — monitor.go:76 is `} else {` inside the terminal-height clamp; the rule-compile loop calling gofilter.NewFilter is at monitor.go:456 (and config/init.go:115). The %w and sentinel-error fixes are correct. Correctly self-rated low.

### Four C-style counted loops that Go 1.22's range-over-int replaces

- **Dimension:** deps-toolchain  
- **Location:** `core/api/api.go:104`  
- **Effort:** trivial

**Evidence**

core/api/api.go:102-107 (the FILL_IP_CACHE debug action):
```go
case "FILL_IP_CACHE":
	firewall.Mutex.Lock()
	for i := 0; i < 19980; i++ {
		firewall.CacheIps.Store(utils.RandomString(24), utils.RandomString(64))
	}
```
core/utils/image.go:45-46:
```go
for i := 0; i < size; i++ {
	for j := 0; j < size-i; j++ {
```
core/server/middleware.go:267:
```go
for i := 0; i < numTriangles; i++ {
```
`for range n` requires `go >= 1.22`; go.mod:3 is `go 1.19`.

**Impact**

In api.go:104 the index `i` is never read, so the loop variable is pure noise; in image.go and middleware.go the counted form obscures that these are simple bounded repeats inside the captcha renderer that runs on every stage-3 challenge. Low functional risk, but `gopls modernize` cannot fix any of them while the go directive sits at 1.19.

**Fix**

After the go.mod bump: `for range 19980 {` (api.go:104), `for range numTriangles {` (middleware.go:267), `for i := range size { for j := range size - i {` (image.go:45-46). `modernize -fix ./...` does all four automatically.

*Verifier:* All four sites verified. api.go:102-107 is the FILL_IP_CACHE case with `for i := 0; i < 19980; i++` at :104 and `i` genuinely unread in the body. utils/image.go:45-46 is `for i := 0; i < size; i++ { for j := 0; j < size-i; j++ {` inside DrawTriangle, and both i and j are used, so the suggested `for i := range size { for j := range size - i {` is a correct rewrite. middleware.go:267 is `for i := 0; i < numTriangles; i++` with i unused in the body, so `for range numTriangles` is right. range-over-int does require go >= 1.22. Correctly self-rated low.

### Hand-rolled min/max comparisons that the Go 1.21 builtins replace

- **Dimension:** deps-toolchain  
- **Location:** `core/server/monitor.go:118-123`  
- **Effort:** trivial

**Evidence**

core/server/monitor.go:118-123:
```go
if domainData.RequestsPerSecond > domainData.PeakRequestsPerSecond {
	domainData.PeakRequestsPerSecond = domainData.RequestsPerSecond
}
if domainData.RequestsBypassedPerSecond > domainData.PeakRequestsBypassedPerSecond {
	domainData.PeakRequestsBypassedPerSecond = domainData.RequestsBypassedPerSecond
}
```
Also monitor.go:73-78, the max-with-floor idiom:
```go
pHeight := tempHeight - 15
if pHeight < 0 {
	proxy.MaxLogLength = 0
} else {
	proxy.MaxLogLength = pHeight
}
```
The `min`/`max` builtins require `go >= 1.21`; go.mod:3 says `go 1.19`, so they are currently rejected by the compiler.

**Impact**

Six lines of branch noise in the per-second attack-detection loop where two expressions suffice, and the monitor.go:73-78 form is the classic clamp that reviewers must read carefully to confirm it has no off-by-one. Purely a readability/maintenance cost, but it is exactly the kind of hand-rolling the toolchain bump is supposed to retire.

**Fix**

After bumping go.mod to 1.21+: `domainData.PeakRequestsPerSecond = max(domainData.PeakRequestsPerSecond, domainData.RequestsPerSecond)` (and the bypassed twin), and `proxy.MaxLogLength = max(tempHeight-15, 0)`.

*Verifier:* Both snippets are quoted exactly. monitor.go:118-123 is the two peak-comparison if-blocks inside checkAttack's BufferCooldown branch, and monitor.go:73-78 is the `pHeight := tempHeight - 15` clamp writing proxy.MaxLogLength. The min/max builtins do require go >= 1.21 and go.mod:3 is go 1.19, so they are genuinely rejected today. The proposed rewrites are semantically identical (max(tempHeight-15, 0) matches the if/else exactly). Correctly self-rated low.

### github.com/inancgumus/screen is a 2019 pseudo-version, ~150 lines, of which this project uses two six-line functions

- **Dimension:** deps-toolchain  
- **Location:** `go.mod:22`  
- **Effort:** small

**Evidence**

go.mod:22 `github.com/inancgumus/screen v0.0.0-20190314163918-06e984b86ed3`
`go list -m -json github.com/inancgumus/screen@latest` -> `"Time": "2019-03-14T16:39:18Z"` (tip = the pinned commit); `go list -m -versions` returns no tags at all.
The entire non-Windows implementation (clear_others.go):
```go
func Clear()       { fmt.Print("\033[2J") }
func MoveTopLeft() { fmt.Print("\033[H") }
```
Used at monitor.go:39-40, 80-81, 342-343, 348-349, 351-352, 358-359, 376-377, 384-385, 390-391 — always as the `Clear()`+`MoveTopLeft()` pair, never `Size()`.
The Windows implementation is a kernel32 LazyDLL wrapper doing `*(*uintptr)(unsafe.Pointer(&cursor))` reinterpret casts on struct values.

**Impact**

An untagged 6-year-old personal repo is a build-blocking dependency for a production security proxy, and (per the x/crypto finding) it is the sole reason golang.org/x/crypto is linked. The Windows path additionally passes struct values through `unsafe.Pointer`-to-`uintptr` casts that today's `go vet -unsafeptr` conventions discourage.

**Fix**

Vendor the two functions into `core/screen/`. The proxy only ever runs its TUI on the deployment host, so the portable `fmt.Print("\033[2J")` / `fmt.Print("\033[H")` pair is sufficient; keep a `//go:build windows` file with the kernel32 calls only if Windows console operation is a supported target. Then delete the require. Verified: after substitution, `go mod tidy && go build ./...` succeeds and both `github.com/inancgumus/screen` and `golang.org/x/crypto` leave `go list -m all`.

*Verifier:* Verified precisely. go.mod:22 carries the 2019 pseudo-version; `go list -m -versions github.com/inancgumus/screen` returns the module name with no tags; clear_others.go is exactly the two quoted one-line functions; clear_windows.go is a kernel32 syscall.NewLazyDLL wrapper containing three `*(*uintptr)(unsafe.Pointer(&cursor))` reinterpret casts, as claimed; the module totals 129 lines across three .go files ('~150' is fair); and I confirmed by grep that all ten call sites (monitor.go 39-40, 80-81, 342-343, 348-349, 351-352, 358-359, 376-377, 384-385, 390-391) are the Clear()+MoveTopLeft() pair and Size() is never called. I reproduced the vendoring fix and it builds clean. Severity dropped one level to low: this is dependency hygiene on a TUI cosmetic, and its only real weight — pulling in x/crypto — is already counted in the separate x/crypto finding, so rating both above low double-counts the same cost.

### sync.Map wiped by Range+Delete instead of the Go 1.23 Map.Clear method

- **Dimension:** deps-toolchain  
- **Location:** `core/server/monitor.go:552-557`  
- **Effort:** trivial

**Evidence**

core/server/monitor.go:552-557:
```go
if (proxyCpuUsage < 15 && proxyMemUsage > 25) || proxyMemUsage > 95 {
	firewall.CacheIps.Range(func(key, value any) bool {
		firewall.CacheIps.Delete(key)
		return true
	})
}
```
and monitor.go:564-569, the identical shape for `firewall.CacheImgs`.
The targets are declared at core/firewall/general.go:29 `CacheIps = sync.Map{}` and general.go:33 `CacheImgs = sync.Map{}`.
`go doc sync.Map.Clear` on the local toolchain:
```
func (m *Map) Clear()
    Clear deletes all the entries, resulting in an empty Map.
```

**Impact**

Range+Delete walks and individually deletes every entry while holding the global `firewall.Mutex` (taken at monitor.go:539, released at 570) — the same mutex the request hot path takes at middleware.go:68 and :89. Under a large IP cache this is an O(n) stall of all request processing; `Map.Clear()` swaps the underlying map in one step. The neighbouring `imgCachelen` counting Range at monitor.go:559-562 walks the image cache under the same lock for a value that is then never used.

**Fix**

After bumping to go 1.23+: `firewall.CacheIps.Clear()` and `firewall.CacheImgs.Clear()`, and delete the unused `imgCachelen` counting loop at monitor.go:559-562 entirely.

*Verifier:* Verified. monitor.go:552-557 is the CacheIps Range+Delete under the quoted CPU/mem condition, monitor.go:564-569 is the identical shape for CacheImgs, and monitor.go:559-562 is the imgCachelen counting Range whose result is genuinely never read. firewall.Mutex is taken at monitor.go:539 and released at :570, spanning all of it. Targets confirmed at firewall/general.go:29 `CacheIps = sync.Map{}` and general.go:33 `CacheImgs = sync.Map{}`, and sync.Map.Clear exists on the local toolchain. The contention claim holds directionally — Clear() on Go's HashTrieMap resets a fixed-width root rather than walking n entries — though the hot-path lock the finding points at is `firewall.Mutex.Lock()` on middleware.go:88, not :89 (:89 is the comment above it); the RLock is correctly at :68. Correctly self-rated low.

### zeebo/blake3 is one patch behind; quickchart-go is a stale 137-line HTTP wrapper worth inlining

- **Dimension:** deps-toolchain  
- **Location:** `go.mod:8`  
- **Effort:** small

**Evidence**

`go list -m -u all`: `github.com/zeebo/blake3 v0.2.3 [v0.2.4]`. Used at core/utils/encryption.go:20 `hash := blake3.Sum256([]byte(input + key))`. `go list -m -json github.com/zeebo/blake3@latest` -> v0.2.4, `"Time": "2024-08-14T14:47:02Z"`. It is also the sole reason for the `github.com/klauspost/cpuid/v2` indirect (go.mod:14) per `go mod why -m`.
`github.com/henomis/quickchart-go v1.0.0` (go.mod:21) — `go list -m -versions` shows only `v0.1.0-alpha1 v0.1.0-alpha2 v1.0.0`; latest release is `"Time": "2022-03-02T12:47:32Z"`. The whole module is one 3.5KB file (quickchart-go.go) with `go 1.17` and zero dependencies. Used only at core/utils/discord.go:13 and discord.go:201-207:
```go
qc := quickchartgo.New()
qc.Config = chartConfig
qc.Width = 500
qc.Height = 300
qc.BackgroundColor = "#2B2D31"
qc.Version = "2.9.4"
chartUrl, chartErr := qc.GetShortUrl()
```
To its credit it does set a sane default: quickchart-go.go:47 `Timeout: 10 * time.Second`, applied to a per-call `&http.Client{Timeout: qc.Timeout}` at line 136.

**Impact**

Neither is dangerous today. blake3 v0.2.4 is a free patch already picked up by the `go get -u ./...` verified above. quickchart-go is a supply-chain hop (a single-maintainer repo, unreleased since 2022) that exists to POST a JSON config to quickchart.io and read back a short URL — and it does that from the attack-alert path in `SendWebhook`, meaning a compromised or squatted future version would sit inside the code that fires during an active DDoS.

**Fix**

blake3: covered by `go get -u ./...`. quickchart-go: replace the 7 lines at discord.go:201-207 with a direct `http.Post` to `https://quickchart.io/chart/create` using a package-level `*http.Client` that has an explicit Timeout, and drop the require — it removes a third-party module for roughly 20 lines of in-tree code you can actually audit. If the dependency is kept, at minimum note that discord.go should not block the attack-detection loop on a 10s external call.

*Verifier:* Verified. `go list -m -u all` shows `github.com/zeebo/blake3 v0.2.3 [v0.2.4]`, encryption.go:20 is `hash := blake3.Sum256([]byte(input + key))`, and `go mod why -m github.com/klauspost/cpuid/v2` traces solely through blake3/internal/consts as claimed. quickchart-go v1.0.0 offers only v0.1.0-alpha1, v0.1.0-alpha2 and v1.0.0; the module is a single 3583-byte (3.5 KB) file with `go 1.17` and no requires; discord.go:201-207 is the quoted seven-line block. The 10 s default Timeout is real (quickchart-go.go:47), applied to a per-call client at line 137 (the finding says 136 — off by one). The observation that this blocks inside the attack-alert path during an active DDoS is a fair operational note. Correctly self-rated low.

### A security product with no SECURITY.md, CONTRIBUTING.md, Makefile, or reproducible build documentation

- **Dimension:** ops-build  
- **Location:** `README.md:55-63`  
- **Effort:** small

**Evidence**

`ls -la SECURITY.md CONTRIBUTING.md Makefile .dockerignore` → all four "No such file or directory". The only build documentation is prose: README:55 "download the latest version of balooProxy ... or compile it from source" and README:63 "build the Docker image by running `docker build -t baloo-proxy .`" — neither states a Go version, build flags, or how to verify an artifact.

**Impact**

There is no coordinated-disclosure channel, so a researcher who finds a bypass in the challenge stack has nowhere to report it except a public issue. There is also no single source of truth for how to build, so the Dockerfile, the release workflow and any developer each produce a differently-flagged binary — which is precisely how the 1.19/1.23.1 divergence happened.

**Fix**

Add `SECURITY.md` (supported versions, a security contact, disclosure window), `CONTRIBUTING.md`, and a `Makefile` with `build`, `docker`, `lint`, `vet`, `test`, `vuln` targets that the Dockerfile and CI both invoke, so there is exactly one build command.

*Verifier:* Verified. `ls SECURITY.md CONTRIBUTING.md Makefile .dockerignore` reports all four missing. The only build documentation is prose at README:55 ("To start, download the latest version of balooProxy ... or compile it from source") and README:63 ("build the Docker image by running `docker build -t baloo-proxy .`"), neither stating a Go version, build flags or a verification step. Low is right — process/documentation debt with no direct exploit. The causal link in the impact is genuine: with three independently declared Go versions (go.mod:3, Dockerfile:1, release.yml:20) and no shared build command, the 1.19-vs-1.23.1 divergence is exactly what one expects. The Makefile-as-single-source-of-truth fix is sound.

### Archived boltdb/bolt is a direct dependency but is never imported

- **Dimension:** ops-build  
- **Location:** `go.mod:6`  
- **Effort:** trivial

**Evidence**

`go.mod:6` `github.com/boltdb/bolt v1.3.1` in the first `require` block (direct, no `// indirect`). `grep -rn "boltdb\|bolt\." --include=*.go .` over the whole tree returns no matches. Its strings are nonetheless linked into the committed artifact — `go version -m oryxBuildBinary` lists `dep github.com/boltdb/bolt v1.3.1`, and `strings` shows bolt error text ("bucket already exists", "page %d already freed").

**Impact**

An abandoned, read-only-since-2017 key-value store sits in the dependency graph and every SBOM/audit report for a security product, inflating the attack surface reviewers must clear and adding weight to the binary, for zero functionality. Downstream users doing supply-chain review will flag it.

**Fix**

Delete the line and run `go mod tidy`; if persistence is planned for LancarSec, add `go.etcd.io/bbolt` (the maintained fork) at the point it is actually imported.

*Verifier:* Verified and independently corroborated. go.mod:6 is `github.com/boltdb/bolt v1.3.1` in the first require block with no // indirect marker; `grep -rn "boltdb|bolt\." --include=*.go .` returns nothing across the tree; `go list -deps .` contains no bolt package; and `go mod why github.com/boltdb/bolt` reports "(main module does not need package github.com/boltdb/bolt)". The linked-into-the-artifact claim also holds: `go version -m oryxBuildBinary` lists dep github.com/boltdb/bolt v1.3.1 and `strings -a` finds the bolt error text "bucket already exists". Low is right. Deleting the line and running go mod tidy is safe — nothing imports it, so nothing breaks.

### GPL v2 LICENSE present but no source file carries a copyright or license header

- **Dimension:** ops-build  
- **Location:** `main.go:1`  
- **Effort:** small

**Evidence**

`LICENSE` is 35,823 bytes of GPL v2 text, but every Go file starts straight at the package clause: `main.go:1` `package main`, `core/server/middleware.go:1` `package server`, `core/firewall/eval.go:1` `package firewall`, `core/api/api.go:1` `package api` — checked with `head -3` on each, no comment block precedes any of them. README's only attribution is a swagger link at the file's end ("A full documentation of BalooProxies 2.0 API...").

**Impact**

GPL v2 §1 and its "How to Apply These Terms" appendix expect each file to carry a copyright notice and a reference to the license. Once files are rebranded to LancarSec and mixed into other trees, there is nothing in the source itself recording that this code is GPL v2 and derived from 41Baloo/balooProxy — a real relicensing/compliance exposure for a commercial fork, and it strips the upstream author's attribution.

**Fix**

Prepend a short header to every `.go` file: `// Copyright (c) 2022-2024 41Baloo (balooProxy contributors)` / `// Copyright (c) 2026 LancarSec` / `// SPDX-License-Identifier: GPL-2.0-only`. Add a `NOTICE` file naming github.com/41Baloo/balooProxy as the upstream, and keep the `/_lancarsec/credits` endpoint. Enforce with an `addlicense -check` step in CI.

*Verifier:* Verified. LICENSE is 35,823 bytes of GPL v2 text, and `head -3` on main.go, core/server/middleware.go, core/firewall/eval.go and core/api/api.go shows each starting directly at its package clause with no preceding comment block. Low is right. One correction to the reasoning: GPL v2 §1 requires that existing copyright notices be kept intact on distribution — it does not mandate a per-file header; per-file headers are the recommendation in the 'How to Apply These Terms' appendix. The compliance exposure the finding describes is still real for a commercial rebrand (nothing in the source itself records GPL v2 or the 41Baloo/balooProxy origin once files are renamed), and the SPDX header + NOTICE + addlicense fix is the standard remedy.

### No .gitattributes: Windows checkouts get CRLF and gofmt flags every Go file

- **Dimension:** ops-build  
- **Location:** `.gitattributes (absent); working-tree CRLF via core.autocrlf=true`  
- **Effort:** trivial

**Evidence**

`ls .gitattributes` → "No such file or directory"; `git config core.autocrlf` → `true`; `file core/api/api.go` → "ASCII text, with CRLF line terminators". Consequently `gofmt -l .` lists all 25 tracked Go files (core/api/api.go, core/api/structs.go, core/config/generate.go, ...), and `gofmt -d core/proxy/proxy.go | cat -A` shows the entire diff is line endings only: `-package proxy^M$`, `-^M$`, `-const (^M$`.

**Impact**

Any `gofmt -w`/`goimports` run on a Windows clone rewrites all 3,098 lines of the codebase, producing whole-file diffs that bury real changes and make review of a security-critical hot path impossible. It also means a `gofmt -l` CI gate (recommended above) would be red on Windows and green on Linux for identical content.

**Fix**

Add `.gitattributes` with `* text=auto eol=lf` and `*.go text eol=lf`, plus `*.crt`/`*.pem`/`*.json` as needed, then renormalise once with `git add --renormalize .`. Verify afterwards that `gofmt -l .` prints nothing.

*Verifier:* Verified. `ls .gitattributes` → no such file; `git config core.autocrlf` → true; `file core/api/api.go` → "ASCII text, with CRLF line terminators"; and `gofmt -l .` does list all 25 tracked Go files. I checked one detail the finding did not: the tracked blobs are clean — `git show HEAD:core/api/api.go | od -c` shows bare \n with no \r, so the CRLF exists only in the Windows working copy via autocrlf. That confirms rather than weakens the impact (identical content, red gofmt gate on Windows and green on Linux) but means `git add --renormalize .` in the fix is a no-op here; adding .gitattributes with `* text=auto eol=lf` is the part that matters, and it is the correct fix. Low is right.

### The anti-tamper release fingerprint is committed in a source comment next to the variable it protects

- **Dimension:** ops-build  
- **Location:** `main.go:15`  
- **Effort:** trivial

**Evidence**

`main.go:15` `var Fingerprint string = "S3LF_BU1LD_0R_M0D1F13D" // 455b9300-0a6f-48f1-82ee-bb1f6cf43500`. That variable is what `.github/workflows/release.yml:25-30` injects (`echo "uuid=$(uuidgen)"` then `go build -ldflags "-X 'main.Fingerprint=${{ env.uuid }}'"`), it is assigned at `main.go:19` `proxy.Fingerprint = Fingerprint`, and it is served to admins at `core/server/middleware.go:327` `... +"\nProxy Fingerprint: "+proxy.Fingerprint`. `strings -a oryxBuildBinary | grep S3LF_BU1LD` confirms the committed artifact is a self/modified build.

**Impact**

The whole point of the injected UUID is to let an operator distinguish an official build from a modified one via the admin endpoint. Publishing a real release UUID in a comment means anyone can rebuild a backdoored proxy with `-X main.Fingerprint=455b9300-...` and have it report as genuine — the integrity check is defeated by reading line 15 of main.go.

**Fix**

Remove the comment. Replace the ldflags UUID with a value that cannot be forged offline: stamp `main.Version`/`main.Commit` for display, and prove authenticity with cosign signatures plus published checksums rather than a shared string echoed by the admin API.

*Verifier:* Verified. main.go:15 is exactly `var Fingerprint string = "S3LF_BU1LD_0R_M0D1F13D" // 455b9300-0a6f-48f1-82ee-bb1f6cf43500`; it is assigned at main.go:19 `proxy.Fingerprint = Fingerprint`, injected by .github/workflows/release.yml:25-30, and served at core/server/middleware.go:327 in the /_bProxy/stats response as "\nProxy Fingerprint: "+proxy.Fingerprint. `strings -a oryxBuildBinary | grep S3LF_BU1LD` matches, confirming the committed artifact is a self/modified build. Severity lowered one level because the causal claim is overstated: the scheme is already broken independently of line 15 — release.yml:38 publishes the same UUID in the release title (`title: "Prerelease ${{ env.uuid }}"`), and any downloader can `strings` an official binary to recover it. A shared plaintext token echoed by an endpoint can never prove authenticity, so removing the comment does not fix anything; only the signature/checksum half of the proposed fix is real.

### A switch case expression concatenates the admin secret into a path on every request

- **Dimension:** performance  
- **Location:** `core/server/middleware.go:337`  
- **Effort:** trivial

**Evidence**

middleware.go:337 —
	case "/_bProxy/" + proxy.AdminSecret + "/api/v1":

The case expression is not a constant (proxy.AdminSecret is a var set at config load, config/init.go:55), so Go evaluates it at runtime each time control reaches that case — i.e. for every request whose path is not one of the three literals above it, which is essentially all real traffic.

**Impact**

Measured with the same five-case switch shape: 36.28 ns/op and 1 alloc/op attributable to the concatenation. At 50k req/s that is 50k needless allocations per second and ~0.2% of a core to rebuild a string that never changes between config reloads.

**Fix**

Precompute `proxy.AdminAPIPath = "/_lancarsec/" + proxy.AdminSecret + "/api/v1"` once in config.Load and ReloadConfig, and compare against that variable in an `if` before the switch (or as the switch case), so no allocation happens per request.

*Verifier:* Verified: middleware.go:337 is `case "/_bProxy/" + proxy.AdminSecret + "/api/v1":`, and proxy.AdminSecret is a package var assigned at config/init.go:55 (and never const), so the case expression is a runtime concatenation evaluated in order for every request that does not match the three literal cases at :325/:329/:333. Severity reduced one level: the concatenation result never escapes, so the compiler uses a stack temp buffer and only spills to the heap when the joined string exceeds 32 bytes (fixed 16 bytes of literal + secret length) — the '1 alloc/op' figure holds only for secrets longer than 16 characters, and ~36 ns/request is a fraction of a percent of the request path. Precomputing the path at config load is correct and trivially safe.

### Per-connection fingerprint map is a plain map guarded by the same mutex the request path needs

- **Dimension:** performance  
- **Location:** `core/firewall/general.go:35,38-49; core/firewall/fingerprint.go:81-84; read at core/server/middleware.go:76-77`  
- **Effort:** small

**Evidence**

firewall/general.go:35 — `Connections = map[string]string{}`
fingerprint.go:82-84 —
	Mutex.Lock()
	Connections[remoteAddr] = fingerprint
	Mutex.Unlock()
firewall/general.go:46-48 —
		Mutex.Lock()
		delete(Connections, remoteAddr)
		Mutex.Unlock()

**Impact**

Connection setup and teardown contend with the request hot path on the same global lock, so a connection-churn flood (open TLS, send nothing, close) can starve request processing without sending a single HTTP request. The read at middleware.go:77 also holds the lock while hashing the RemoteAddr string on every request. The map is written exactly once per connection and read once per request — the textbook sync.Map case that the code already uses correctly for CacheIps.

**Fix**

Move `Connections` to a `sync.Map` (or better, attach the fingerprint to the connection via a context value set in ConnContext, eliminating the map and the RemoteAddr string key entirely).

*Verifier:* Verified: general.go:35 `Connections = map[string]string{}`, written under Mutex.Lock at fingerprint.go:82-84 on every TLS handshake, deleted under Mutex.Lock at general.go:46-48 on StateHijacked/StateClosed (wired via ConnState at serve.go:60 and :69), and read under RLock at middleware.go:76-77. Connection churn therefore contends with the request path on the same global lock, and the map is genuinely write-once/read-per-request — the sync.Map pattern the code already uses for CacheIps/CacheImgs. Severity low is appropriate. Note the ConnContext variant of the fix needs care: the fingerprint is produced in tls.Config.GetConfigForClient, after ConnContext has run, so it would have to be stashed via a mutable per-conn holder rather than a plain context value.

### API body-read failure writes an error response then falls through and processes a nil body

- **Dimension:** quality-idiom  
- **Location:** `core/api/api.go:21-26`  
- **Effort:** trivial

**Evidence**

api.go:21-26: 'reqBody, err := io.ReadAll(request.Body); if err != nil { APIResponse(writer, false, map[string]interface{}{"ERROR": ERR_BODY_READ_FAILED}) }' - no 'return true'. Execution continues to line 31, json.Unmarshal(reqBody, &apiRequest), with reqBody nil. The immediately following error branch at lines 32-37 does correctly 'return true', which shows the omission is accidental.

**Impact**

A truncated request body produces two JSON documents written to the same response: the ERR_BODY_READ_FAILED object followed by an ERR_JSON_READ_FAILED object. Any client parsing the response strictly fails on trailing data; a lenient one silently reads only the first.

**Fix**

Add 'return true' after the APIResponse call at api.go:25. Also check APIResponse's returned error - it is declared 'func APIResponse(...) error' at api.go:194 but every one of its ~15 call sites discards the result.

*Verifier:* Verified exactly. api.go:21-26 reads the body and, on error, calls APIResponse with ERR_BODY_READ_FAILED but has no `return true`; execution falls through to api.go:31 json.Unmarshal(reqBody, &apiRequest) with reqBody nil, which errors and writes a second JSON document before returning true at api.go:36. The neighbouring branch's correct `return true` does show the omission is accidental. APIResponse is indeed declared `error` at api.go:194 and I counted 19 call sites, all discarding it (the finding's '~15' is approximate). Severity is inflated, though: api.go:17 gates the whole handler on `request.Header.Get("proxy-secret") != proxy.APISecret`, so this is reachable only by a caller who already holds the API secret, and the worst outcome is a malformed double-document response to that authenticated caller. Low, not medium.

### Errors rebuilt by string concatenation instead of %w, losing the wrapped cause

- **Dimension:** quality-idiom  
- **Location:** `core/config/init.go:240`  
- **Effort:** small

**Evidence**

init.go:240,246,252 all do 'return errors.New("Failed to check for proxy version: " + err.Error())' - the same prefix three times, capitalized, no %w. generate.go:105,111,116 repeat the pattern with 'failed to fetch fingerprints: ' + err.Error(). serve.go:132-138 goes further and shreds the transport error apart with strings.Split on spaces, dropping any token containing '.', '/', or brackets, then renders the remnants into an HTML page.

**Impact**

errors.Is and errors.As cannot see through these - a caller cannot test for context.DeadlineExceeded or a *net.OpError behind a version-check failure. The capitalized 'Failed'/'Error' prefixes violate Go's error-string convention and read wrongly when wrapped by a caller.

**Fix**

Use fmt.Errorf("check proxy version: %w", err) and lowercase, non-punctuated error strings. Collapse the three identical returns in VersionCheck into one wrap at the call site.

*Verifier:* All citations verified verbatim. init.go:240, :246 and :252 each return `errors.New("Failed to check for proxy version: " + err.Error())` — same capitalized prefix three times, no %w. generate.go:105, :111 and :116 repeat the pattern with 'failed to fetch fingerprints: '. serve.go:132-138 does split the transport error on spaces and drop every token containing '.', '/' or brackets, and serve.go:140-144 then writes the remnants into an HTML page as both title and body. The errors.Is/errors.As point is technically correct and the capitalized error strings do violate Go convention. Severity down to low, though: VersionCheck's only caller is init.go:224-227, which immediately panics with the string, so nothing in the tree ever calls errors.Is on these values — the lost cause is a future-maintainability cost, not a present defect.

### SCREAMING_SNAKE_CASE type and constant names, plus non-idiomatic initialisms

- **Dimension:** quality-idiom  
- **Location:** `core/api/structs.go:3-18`  
- **Effort:** small

**Evidence**

structs.go declares 'type API_REQUEST struct', 'type API_RESPONSE struct', and constants ERR_DOMAIN_NOT_FOUND, ERR_ACTION_NOT_FOUND, ERR_BODY_READ_FAILED, ERR_JSON_READ_FAILED. config/structs.go:120 declares 'type GLOBAL_PROXY_VERSIONS struct'. discord.go:272-274 declares 'type WebhookImage struct { Url string }' - Url rather than the Go initialism URL, while WebhookSettings.URL at domain.go:113 spells it correctly. Local naming is also inconsistent: api.go:176 uses 'uncastedDomainSettingsdomain'.

**Impact**

Reads as transliterated C/PHP rather than Go and will be flagged by every linter a new contributor runs. The Url/URL split inside the same feature makes field references easy to get wrong.

**Fix**

Rename to APIRequest, APIResponse (the func APIResponse at api.go:194 must be renamed too, e.g. writeJSON), errDomainNotFound/errActionNotFound/... as unexported consts or a typed error enum, proxyVersions, and WebhookImage.URL. Rename uncastedDomainSettingsdomain to raw or settingsVal.

*Verifier:* Every content claim is true but the primary line citation is fabricated. core/api/structs.go is 18 lines long, so 'core/api/structs.go:213-228' cannot exist; likewise core/config/structs.go is 7 lines, so 'config/structs.go:120' is invented. The real locations: ERR_DOMAIN_NOT_FOUND / ERR_ACTION_NOT_FOUND / ERR_BODY_READ_FAILED / ERR_JSON_READ_FAILED at api/structs.go:4-7, API_REQUEST at api/structs.go:10, API_RESPONSE at api/structs.go:15, GLOBAL_PROXY_VERSIONS at config/structs.go:3. The two secondary citations are correct: discord.go:272-274 does declare `type WebhookImage struct { Url string }` while WebhookSettings.URL at domains/domain.go:113 spells the initialism properly, and api.go:176 does use `uncastedDomainSettingsdomain`. Severity low is right. Note the proposed rename to APIResponse collides with the existing `func APIResponse` at api.go:194, which the finding correctly flags and proposes renaming to writeJSON.

### Zero conforming doc comments on 75 exported symbols and zero package docs

- **Dimension:** quality-idiom  
- **Location:** `core/proxy/proxy.go:9-60`  
- **Effort:** medium

**Evidence**

75 exported funcs, types, and methods across the tree. Only four have any preceding comment at all (monitor.go ReloadConfig, and utils/text.go AddLogs, ReadLogs, ClearLogs), and none of the four begins with the symbol name as godoc requires - they read '// Only run in locked thread' and '// This would ideally be in package config...'. No .go file in the repo begins with a package doc comment. The whole core/proxy package (proxy.go:9-60) is 30 undocumented exported globals with no explanation of ownership or synchronization.

**Impact**

godoc output is empty for every package. For core/proxy specifically - where CurrHourStr, Last10SecondTimestamp, and the OTP secrets are read on the request hot path but written by the monitor goroutine - the absence of any documented ownership rule is why callers cannot tell which globals need which lock.

**Fix**

Add package doc comments and godoc-form comments ('// Middleware handles ...') on exported symbols, prioritizing core/proxy and core/firewall where the concurrency contract is implicit. Enforce with revive's exported rule in CI.

*Verifier:* Independently verified and the numbers are exact. My count of `^func [A-Z]` / `^func (recv) [A-Z]` / `^type [A-Z]` across core/ and main.go returns precisely 75. Scanning for exported declarations preceded by a comment line returns precisely four, and they are exactly the four named: monitor.go:401 ReloadConfig, text.go:22 AddLogs, text.go:36 ReadLogs, text.go:68 ClearLogs. None begins with the symbol name ('// This would ideally be in package config...', '// Only run in locked thread'), so none is godoc-conforming. No .go file in the tree starts with a package doc comment. core/proxy/proxy.go:9-60 is indeed a bare var block of undocumented exported globals — the finding says 30, I count 37 plus the ProxyVersion const, so it understates. The ownership point is fair: CurrHourStr and Last10SecondTimestamp are written by printStats() on the monitor goroutine and read unsynchronized on the request hot path at middleware.go:96/184 with nothing documenting that. Severity down to low — this is a lint/documentation gap with no runtime consequence of its own.

### gofmt -l flags all 25 Go files; the drift is 100% CRLF line endings with no .gitattributes

- **Dimension:** quality-idiom  
- **Location:** `core/firewall/requests.go:1`  
- **Effort:** trivial

**Evidence**

$ gofmt -l . lists all 25 .go files. $ gofmt -d core/firewall/requests.go shows every line replaced with an identical line. $ file core/firewall/requests.go => 'ASCII text, with CRLF line terminators'. Normalizing to LF in a scratch copy and re-running gofmt -l produces empty output, confirming there is no semantic formatting drift - only line endings. There is no .gitattributes in the repo root.

**Impact**

gofmt -l, and therefore any CI formatting gate, fails on every file, so the check is useless and will be disabled or ignored - masking real formatting drift later. Contributors on Linux and Windows will produce whole-file diffs against each other.

**Fix**

Add a .gitattributes with '*.go text eol=lf', run 'gofmt -w .' after normalizing, and commit the renormalization as one isolated commit so it does not pollute later diffs. Add 'test -z "$(gofmt -l .)"' to CI once clean.

*Verifier:* Reproduced end to end. `gofmt -l .` lists all 25 .go files. `file core/firewall/requests.go` reports 'ASCII text, with CRLF line terminators'. I copied the tree to a scratch directory, stripped CR with sed, and re-ran gofmt -l: output was empty, proving the drift is 100% line endings with zero semantic formatting difference, exactly as claimed. There is no .gitattributes in the repo root. The consequence is correct — a CI gate of `test -z "$(gofmt -l .)"` fails on every file today, so it would be disabled and stop catching real drift. Low is the right severity and the proposed remediation sequence (.gitattributes with '*.go text eol=lf', one isolated renormalization commit, then enable the gate) is sound.

### API secret verification has no rate limit, no lockout, and no logging of failures

- **Dimension:** security-authz  
- **Location:** `core/api/api.go:15-19`  
- **Effort:** small

**Evidence**

func Process(writer http.ResponseWriter, request *http.Request, domainData domains.DomainData) bool {

	if request.Header.Get("proxy-secret") != proxy.APISecret {
		return false
	}
And core/api/api.go:153-157 for v2. On failure both return false silently — no counter is incremented, nothing is written to domainData.LastLogs, and main.go:32 sends log output to io.Discard. The only ratelimits in the product are the generic per-IP ones at core/server/middleware.go:108-127, which are keyed on an IP the attacker controls in Cloudflare mode (see cf-connecting-ip-unverified).

**Impact**

An attacker can grind the API secret at whatever rate the box accepts connections, from as many spoofed identities as he likes, and neither the operator's TUI nor crash.log nor any webhook will show a single failed attempt. There is no exponential backoff, no per-secret attempt counter, no alert. Given that a successful guess yields GET_IP_CACHE (every client's challenge token) and FILL_IP_CACHE (a proxy-wide stall), silent unlimited guessing is the wrong default for the one credential that owns the whole mitigation layer. A 30-character alphanumeric secret is not brute-forceable, but a shorter operator-chosen one — nothing enforces length, see empty-secrets-accepted — is.

**Fix**

Add a dedicated counter for API auth failures keyed on the socket peer (not the spoofable header IP), block that peer after a small threshold, and emit each failure to the TUI log and the Discord webhook. Add a fixed ~200 ms delay on failure so grinding is rate-bound even before the threshold.

*Verifier:* Facts verified: api.go:15-19 and :153-157 both return false silently, no counter, no LastLogs write, and main.go:32 sets log output to io.Discard. But the impact is materially overstated and I am dropping it two levels. api.Process/ProcessV2 are reached only from the reserved-path switch at middleware.go:324/350, which sits AFTER the R1/R2 ratelimits (:107-127) and after the :214 challenge gate — so in origin mode a grinder is capped by the `requests` limit (500 per 2-minute window per IP) and must also carry a valid challenge cookie. Unmetered grinding therefore requires the CF header spoof from cf-connecting-ip-unverified, and the finding itself concedes a 30-char alphanumeric secret is not brute-forceable. What survives is a genuine but low-severity observability gap: no logging or alerting on admin auth failure.

### OTP secrets rotate on a date string checked by a fixed 1-hour sleep, so rotation lags up to 59 minutes and secrets never change faster than daily

- **Dimension:** security-authz  
- **Location:** `core/server/monitor.go:639-658`  
- **Effort:** small

**Evidence**

func generateOTPSecrets() {
...
	//This has now been changed to an hour, for better performance

	for {

		currTime := time.Now()
		currDate := currTime.Format("2006-01-02")

		proxy.CookieOTP = utils.EncryptSha(proxy.CookieSecret, currDate)
		proxy.JSOTP = utils.EncryptSha(proxy.JSSecret, currDate)
		proxy.CaptchaOTP = utils.EncryptSha(proxy.CaptchaSecret, currDate)

		time.Sleep(1 * time.Hour)
	}
}
The comment claims hourly rotation but the key material is the date. The only sub-daily variation is proxy.CurrHourStr inside accessKey (core/server/middleware.go:184), which is the bare hour-of-day (core/server/monitor.go:217-218) and repeats every 24 hours.

**Impact**

Three consequences. (1) The loop sleeps a fixed hour from process start rather than aligning to the boundary, so the date rollover is picked up as much as 59 minutes late; a multi-server deployment whose processes started at different minutes will disagree on the OTP for up to an hour, and every client that lands on the wrong server is forced to re-solve — a self-inflicted availability problem the attacker can trigger by causing a restart. (2) These three values are the entire keying material for token forgery; they derive deterministically from the config secrets and the calendar date, so anyone who ever reads config.json can forge any client's token for any past or future date, forever, with no way to revoke short of editing the file. (3) Because the only intra-day variation is a repeating hour-of-day integer, the scheme has no monotonic time component, which is what makes the pre-minting attack in accesskey-concat-hour-shift work.

**Fix**

Derive the OTP from a monotonic aligned bucket (`time.Now().UTC().Truncate(time.Hour).Format(time.RFC3339)`) and recompute it on demand in the request path (or on a ticker aligned to the boundary via time.Until of the next bucket), not on a drifting fixed sleep. Accept the previous bucket's token for a short grace period so rotation does not force every client to re-solve simultaneously.

*Verifier:* Verified: monitor.go:639-658, the key material is `currTime.Format("2006-01-02")` (date only) despite the comment claiming hourly, and the loop ends in a fixed `time.Sleep(1 * time.Hour)` rather than aligning to the boundary, so date rollover is picked up up to 59 minutes late and processes started at different minutes disagree. The only sub-daily variation is CurrHourStr (monitor.go:217-218), a bare repeating hour-of-day. Downgraded one level: consequence (1) is a re-solve annoyance on a single server and a multi-server skew that the source comment already acknowledges as a known tradeoff; consequence (2) is inherent to any keyed-MAC scheme, not a defect; consequence (3) is a restatement of accesskey-concat-hour-shift. Real correctness bug, modest security consequence.

### Stage 1 is a pure echo of a server-issued Set-Cookie and grants an hour of unlimited access across every domain and path

- **Dimension:** security-authz  
- **Location:** `core/server/middleware.go:224-227`  
- **Effort:** small

**Evidence**

		case 1:
			writer.Header().Set("Set-Cookie", "_1__bProxy_v="+encryptedIP+"; SameSite=Lax; path=/; Secure")
			http.Redirect(writer, request, request.URL.RequestURI(), http.StatusFound)
			return
Stage 1 is the default for every domain: core/config/init.go:173 `Stage: 1,` and core/server/monitor.go:509 `Stage: 1,`. The token is not marked HttpOnly and is the same value the check at middleware.go:214 demands.

**Impact**

The server hands the client the exact secret the check requires, with no proof of anything. A three-line script — GET, read Set-Cookie, replay — passes stage 1 forever. Because the token is keyed on (ip, fp, ua, hour) and not on the domain, the path, or a request counter, one round trip per bot IP per hour buys unlimited requests for that hour, on every path and every domain the proxy serves. The baseline posture of the product is therefore "can you make two HTTP requests", and an attacker's amortized cost is one extra request per IP per hour, not per request. The cookie also lacks HttpOnly, so any XSS on the protected backend exfiltrates a working bypass token.

**Fix**

At minimum add HttpOnly to the stage-1 cookie and bind the token to the domain (see token-not-bound-to-domain-or-path). Treat stage 1 as a cookie-support probe only — never as a trust grant — and cap how many requests one stage-1 token may carry before it must be reissued.

*Verifier:* Verified: middleware.go:224-227 sets `_1__bProxy_v=`+encryptedIP with SameSite=Lax, path=/, Secure and no HttpOnly, and that is precisely the value the :214 check demands; stage 1 is the default at config/init.go:173 and monitor.go:509. Downgraded one level because this describes the intended semantics of the weakest tier — stage 1 is documented as the cheap cookie-support probe, and the domain-binding complaint is a duplicate of token-not-bound-to-domain-or-path. The independently actionable defect here is the missing HttpOnly flag, which makes any XSS on a protected backend an exfiltration of a working bypass token.

### The challenge cookie is validated by an unanchored substring search over the raw Cookie header rather than a real cookie parse

- **Dimension:** security-authz  
- **Location:** `core/server/middleware.go:214`  
- **Effort:** small

**Evidence**

	if !strings.Contains(request.Header.Get("Cookie"), "__bProxy_v="+encryptedIP) {
The code never calls request.Cookie(...) or request.Cookies(). The stage prefixes the proxy itself issues (`_1__bProxy_v=` at middleware.go:225, `_2__bProxy_v=` at :232, and `"+ip+"_3__bProxy_v=` at :296) all merely happen to end with the matched substring; the check is blind to which one it is.

**Impact**

Three consequences. (1) The token is accepted in any cookie, under any name, at any position — `Cookie: junk=__bProxy_v=<token>` passes — so any edge rule that strips or inspects cookies named `_1__bProxy_v`/`_2__bProxy_v`/`_3__bProxy_v` is not actually a control, and the token can be smuggled past a WAF that watches for those names. (2) The stage prefix is not verified, so the check cannot distinguish which challenge tier produced the cookie; only the differing OTP keys separate the stages, and any future change that unifies those keys silently collapses all three tiers into one. (3) When susLv is 0 the expected value is the empty string, degrading the predicate to `Contains(cookie, "__bProxy_v=")` — satisfiable by any client that sends the literal text, with no token at all. The token is also forwarded untouched to the backend (nothing strips it before middleware.go:363 `domainSettings.DomainProxy.ServeHTTP`), so a compromised or nosy backend collects working bypass tokens for every visitor.

**Fix**

Parse cookies properly with request.Cookie(name) for the specific stage's name, compare the value with subtle.ConstantTimeCompare, and require the name to match the stage being enforced. Delete the proxy's own cookies from the request before forwarding upstream.

*Verifier:* Verified at middleware.go:214. `request.Cookie`/`request.Cookies` appear nowhere in the repo — the check is a raw substring search over the Cookie header, so the token is accepted under any cookie name at any position, the `_1_`/`_2_`/`_3_` stage prefixes issued at :225, :232 and :296 are never verified (only the differing OTP keys separate the tiers), and with susLv 0 the predicate degrades to Contains(cookie, "__bProxy_v="). The forwarding claim also checks out: nothing strips proxy cookies before `domainSettings.DomainProxy.ServeHTTP` at :363. Low is right — no direct bypass, but a fragile control and a WAF-evasion surface.

### GET_IP_CACHE returns every live challenge token in plaintext, and the cache is only evicted under CPU/RAM pressure

- **Dimension:** security-crypto  
- **Location:** `core/server/monitor.go:551-569 (eviction gate) and core/api/api.go:91-100 (post-auth dump)`  
- **Effort:** small

**Evidence**

core/api/api.go:91-100 `case "GET_IP_CACHE": cacheIps := make(map[string]interface{}); firewall.CacheIps.Range(func(key, value any) bool { cacheIps[fmt.Sprint(key)] = value; return true }); APIResponse(writer, true, map[string]interface{}{ "IP_CACHE": cacheIps })`.
What is in there: core/server/middleware.go:204 `firewall.CacheIps.Store(accessKey+susLvStr, encryptedIP)` and :196 `firewall.CacheIps.Store(encryptedIP, hashedEncryptedIP)` — keys are `ip+tlsFp+userAgent+hour+stage`, values are the valid tokens.
Eviction is conditional: core/server/monitor.go:551-557 `// Only clear if proxy isnt under attack / memory is running out` / `if (proxyCpuUsage < 15 && proxyMemUsage > 25) || proxyMemUsage > 95 { firewall.CacheIps.Range(func(key, value any) bool { firewall.CacheIps.Delete(key); return true }) }` — contradicting the comment at core/firewall/general.go:27-28 that claims a 2-minute cache.

**Impact**

One API call returns a ready-to-replay credential for every currently challenged visitor, plus their IP, TLS fingerprint and User-Agent — a complete session-hijack list and a privacy dump. Because eviction only fires in a narrow CPU/RAM window, tokens from previous hours accumulate for the process lifetime, widening the exposure and giving an attacker who controls the User-Agent an unbounded-growth primitive on a map that holds secrets. The FILL_IP_CACHE action (api.go:102-107) deliberately inserts 19980 entries, showing the map is expected to grow without bound.

**Fix**

Remove GET_IP_CACHE, or return only counts and redacted keys. Give CacheIps a real TTL (store an expiry with each entry and sweep unconditionally on a ticker) and cap its size. Store a MAC of the token rather than the token itself where only equality is needed, so a cache dump is not directly replayable.

*Verifier:* Code verified exactly: api.go:91-100 ranges CacheIps into the response; middleware.go:196 and :204 store hashedEncryptedIP and the live token keyed by ip+tlsFp+UA+hour+stage; monitor.go:551-557 gates CacheIps eviction on (cpu<15 && mem>25) || mem>95, contradicting the 2-minute claim in core/firewall/general.go:27-28; FILL_IP_CACHE at api.go:102-107 inserts 19980 entries. Severity trimmed one level because the dump is post-authentication and only reachable by a caller who already holds the API secret and therefore already controls the proxy — it is not an unauthenticated disclosure. The genuinely independent defect is the eviction gate: tokens and captcha images accumulate for the process lifetime under any normal load, giving an attacker who rotates User-Agent an unbounded memory-growth primitive on a DDoS-mitigation box. The TTL/cap fix is right; removing GET_IP_CACHE is optional.

### The stage-1 challenge cookie is set without HttpOnly, exposing the bypass token to any script on the protected site

- **Dimension:** security-crypto  
- **Location:** `core/server/middleware.go:225`  
- **Effort:** trivial

**Evidence**

core/server/middleware.go:225 `writer.Header().Set("Set-Cookie", "_1__bProxy_v="+encryptedIP+"; SameSite=Lax; path=/; Secure")` — Secure and SameSite are set, HttpOnly is not. This is the one cookie the server itself issues; stages 2 and 3 are written by client JS (middleware.go:232 and :296) and cannot be HttpOnly by construction.
The value is the full bypass credential checked at core/server/middleware.go:214.

**Impact**

Any XSS or malicious third-party script on a protected origin can read `document.cookie`, exfiltrate the token, and hand attack traffic a credential that skips the proxy's challenge for the rest of the hour — for every visitor the script touches. Since the token is derived from ip+fingerprint+UA (middleware.go:184), a stolen token is directly usable by anyone who replicates those three attacker-controllable values in Cloudflare mode.

**Fix**

Append `; HttpOnly` to the stage-1 Set-Cookie. Redesign stages 2 and 3 so the client posts its solution to an endpoint that sets an HttpOnly cookie server-side, instead of having JavaScript write the credential into document.cookie.

*Verifier:* Verified verbatim at core/server/middleware.go:225: `"_1__bProxy_v="+encryptedIP+"; SameSite=Lax; path=/; Secure"` — Secure and SameSite present, HttpOnly absent. The value is the exact string checked at :214, and stages 2 and 3 are written by client JS (:232, :296) so they genuinely cannot be HttpOnly as designed. Impact is correctly scoped and correctly rated low: it requires a pre-existing XSS or hostile third-party script on the protected origin. The suggested redesign (post the solution to an endpoint that sets the cookie server-side) is sound and would also close the stage-2/3 gap.

### :80→:443 redirect drops the '?' before the query and runs before any mitigation

- **Dimension:** security-http  
- **Location:** `core/server/serve.go:99`  
- **Effort:** trivial

**Evidence**

http.Redirect(w, r, "https://"+r.Host+r.URL.Path+r.URL.RawQuery, http.StatusMovedPermanently)

preceded by
	firewall.Mutex.Lock()
	domainData = domains.DomainsData[r.Host]
	domainData.TotalRequests++
	domains.DomainsData[r.Host] = domainData
	firewall.Mutex.Unlock()

**Impact**

`r.URL.Path + r.URL.RawQuery` concatenates without `?`, so `http://site/search?q=x` redirects to `https://site/searchq=x` — the query silently becomes part of the path, breaking every link that arrives over HTTP and, on backends that route on path prefixes, sending user-supplied query text into path-matching logic. `r.URL.Path` is also the decoded path re-emitted unencoded, so percent-encoded segments are mangled. Separately this handler is reachable with no challenge, no ratelimit and no fingerprint check, yet takes the global write mutex on every request — an unauthenticated lock-contention amplifier on port 80.

**Fix**

Redirect with `r.URL.RequestURI()` after normalising a leading `//` (see the stage-1 open-redirect finding), i.e. `http.Redirect(w, r, "https://"+r.Host+safeRequestURI(r), http.StatusMovedPermanently)`, and increment the counter with an atomic rather than the global mutex.

*Verifier:* Verified. core/server/serve.go:99 is http.Redirect(w, r, "https://"+r.Host+r.URL.Path+r.URL.RawQuery, http.StatusMovedPermanently) — the '?' separator is genuinely absent, and r.URL.Path is the decoded path re-emitted unencoded. The lock-contention point is also accurate: serve.go:93-97 takes firewall.Mutex.Lock() on every unauthenticated :80 request just to increment TotalRequests, ahead of any challenge or ratelimit. Low is right; the exact defect is line 99, not the whole 82-100 range.

### CONNECT and arbitrary methods are forwarded to the backend with no allowlist

- **Dimension:** security-http  
- **Location:** `core/server/middleware.go:363`  
- **Effort:** trivial

**Evidence**

func Middleware(writer http.ResponseWriter, request *http.Request) {
...
	domainName := request.Host

	firewall.Mutex.RLock()
	domainData, domainFound := domains.DomainsData[domainName]

No method inspection occurs before `domainSettings.DomainProxy.ServeHTTP(writer, request)` (line 363); `request.Method` is only ever read as a firewall-DSL variable (line 161).

**Impact**

Go's http.Server accepts CONNECT and hands it to the handler; for a CONNECT whose authority matches a configured domain name the request is passed straight to httputil.ReverseProxy and relayed to the backend, letting the proxy be used to reach the backend with a method the operator never intended. More broadly, any method — TRACE, PROPFIND, arbitrary verbs — reaches the backend unless the operator remembers to write a firewall rule, and the example config's method rule only raises the suspicion level rather than blocking (examples/config.json, `"expression": "(http.method ne \"GET\" and http.method ne \"POST\")", "action": "+2"`).

**Fix**

Reject `http.MethodConnect` with 405 at the top of Middleware before any other work, and add a configurable per-domain method allowlist that defaults to the standard safe/idempotent set plus POST/PUT/PATCH/DELETE.

*Verifier:* Reachability verified empirically with go1.25.4: 'CONNECT victim.com HTTP/1.1' parses with Method=CONNECT, Host="victim.com" (portless authority is accepted), URL.Path="", so the domain lookup at core/server/middleware.go:39 succeeds, the reserved-path switch misses, and the request reaches DomainProxy.ServeHTTP at line 363. No method inspection exists; request.Method is only read as a DSL variable at line 161. The impact is narrower than an open tunnel — Request.write re-emits it as a CONNECT to the backend, which will normally reject it — so low is the right level.

### Challenge and block pages ship no security response headers

- **Dimension:** security-http  
- **Location:** `core/server/middleware.go:230-231,294-295`  
- **Effort:** small

**Evidence**

writer.Header().Set("Content-Type", "text/html")
writer.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0") // Prevent special(ed) browsers from caching the challenge

The same two lines are the complete header set for the stage-3 captcha at lines 294-295. No X-Frame-Options, Content-Security-Policy, X-Content-Type-Options or Referrer-Policy is set anywhere in the file.

**Impact**

The captcha page can be framed by any site, so an attacker overlays it and farms real humans' captcha solutions (classic clickjacking captcha-relay) to mint valid `_3__bProxy_v` cookies. Absent nosniff, the text/plain block responses (lines 109, 116, 124, 137) can be content-sniffed in older engines. Absent a CSP, the XSS at line 296 has no second line of defence. Absent Referrer-Policy, the full challenge URL — which for the admin path contains the admin secret (line 337) — leaks to any third-party resource the page loads.

**Fix**

Add a small helper that sets `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'; default-src 'none'; script-src 'self' <cdn>; style-src 'unsafe-inline'`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer` on every proxy-generated response, challenge and block alike.

*Verifier:* The factual claim is verified: core/server/middleware.go:230-231 and 294-295 set only Content-Type and Cache-Control, and no X-Frame-Options, CSP, nosniff or Referrer-Policy appears anywhere in the file. But the headline impact does not follow: the described clickjacking captcha-relay does not work here, because a framed challenge page sets the _3__bProxy_v cookie in the victim's browser and the attacker can read neither the cross-origin captcha image nor the solution, so no token is minted for the attacker. What survives is the defence-in-depth argument (no CSP behind the line-296 XSS, no nosniff on the text/plain blocks, full challenge URL including the admin secret leaking via Referer). Downgraded to low.

### Challenge cookie validated by unanchored substring match on the raw Cookie header

- **Dimension:** security-http  
- **Location:** `core/server/middleware.go:214`  
- **Effort:** small

**Evidence**

if !strings.Contains(request.Header.Get("Cookie"), "__bProxy_v="+encryptedIP) {

**Impact**

The token is never parsed as a cookie: any cookie name ending in `__bProxy_v`, and any cookie whose *value* happens to contain the substring, satisfies the check — so a backend that reflects user input into a Set-Cookie value, or a sibling subdomain that can set cookies on the parent domain, can plant a matching substring. The comparison is also byte-wise and short-circuiting rather than constant-time, and at suspicion level 0 `encryptedIP` is the empty string so the predicate degenerates to matching the bare prefix. Parsing would additionally let the code reject the multi-cookie confusion the stage-3 page creates by prefixing the cookie name with the client IP (line 296).

**Fix**

Read the specific cookie with `request.Cookie("_1__bProxy_v")` / `_2_` / `_3_` per stage and compare with `subtle.ConstantTimeCompare([]byte(c.Value), []byte(expected)) == 1`.

*Verifier:* The code claim is verified at core/server/middleware.go:214: strings.Contains(request.Header.Get("Cookie"), "__bProxy_v="+encryptedIP), an unanchored, non-constant-time substring test on the raw header. Two of the stated impacts do not follow, though. Planting a matching substring via a reflected Set-Cookie or a sibling subdomain gains nothing, because the substring must contain encryptedIP itself — the secret the attacker is trying to obtain. And the susLv-0 degeneration is inconsequential: when susLv is 0 the switch case 0 is an explicit no-op, so a failed match there still falls through to the backend. What is real is that any cookie name ending in __bProxy_v satisfies the check, so the per-stage cookies (_1_, _2_, <ip>_3_) are accepted interchangeably. Low is already correct.

### HTTP/2 configured with an all-defaults server: no stream, frame or idle limits

- **Dimension:** security-http  
- **Location:** `core/server/serve.go:46,79-80`  
- **Effort:** trivial

**Evidence**

http2.ConfigureServer(service, &http2.Server{})
...
http2.ConfigureServer(service, &http2.Server{})
http2.ConfigureServer(serviceH, &http2.Server{})

**Impact**

A zero-value http2.Server leaves MaxConcurrentStreams at the 250 default, MaxReadFrameSize at 1 MiB, MaxUploadBufferPerConnection/PerStream at their defaults and IdleTimeout unset. Against an appliance whose whole purpose is absorbing L7 floods that is far too permissive: 250 concurrent streams per connection multiplied by the connection count sets the real request concurrency, 1 MiB read frames let a client force large per-connection buffers cheaply, and the http.Server ReadTimeout/WriteTimeout (serve.go:56-59) do not bound individual h2 streams the way they bound HTTP/1 requests. `ConfigureServer` is also called on the plain-HTTP :80 servers (lines 46, 79) where it does nothing, which hides the fact that Cloudflare-flexible mode serves HTTP/1.1 only.

**Fix**

Pass a tuned &http2.Server{MaxConcurrentStreams: 100, MaxReadFrameSize: 16384, IdleTimeout: proxy.IdleTimeoutDuration, MaxUploadBufferPerConnection: 1<<20} and make the values configurable; drop the no-op ConfigureServer calls on the plain :80 listeners.

*Verifier:* Verified: core/server/serve.go:46, 79 and 80 all pass a zero-value &http2.Server{}, leaving MaxConcurrentStreams at 250 and MaxReadFrameSize at 1 MiB. The observation that ConfigureServer on the plain :80 servers (lines 46, 79) is a no-op is also correct, since those are started with ListenAndServe and TLSNextProto is never consulted. Downgraded to low: this is a tuning/hardening gap with no concrete exploit demonstrated, and it sits well below the unbounded-map and spoofable-IP issues in the same package.

### No request body size limit anywhere in the request path

- **Dimension:** security-http  
- **Location:** `core/api/api.go:21`  
- **Effort:** small

**Evidence**

func Middleware(writer http.ResponseWriter, request *http.Request) {
...
	domainName := request.Host

`grep -rn "MaxBytesReader" --include=*.go core/` returns nothing. The admin API reads the body unbounded: core/api/api.go:21 `reqBody, err := io.ReadAll(request.Body)`. Only `MaxHeaderBytes: 1 << 20` is set (core/server/serve.go:43, 62, 76).

**Impact**

Every request body is streamed to the backend with no ceiling, so the proxy happily relays unbounded uploads and provides zero protection against body-based volumetric abuse of a backend that has its own limit but pays the bandwidth. On the admin API path the body is fully buffered in memory before the JSON parse (api.go:21), so a client that knows or brute-forces the `proxy-secret` — compared with `!=`, non-constant-time, api.go:17 — can allocate arbitrary heap with one chunked request. For an appliance whose job is absorbing abuse, an explicit cap belongs at the edge.

**Fix**

Wrap the body once at the top of Middleware — `request.Body = http.MaxBytesReader(writer, request.Body, maxBodyBytes)` with a configurable default (10 MiB) — and additionally use io.LimitReader in api.Process. Make the cap per-domain configurable for endpoints that legitimately accept large uploads.

*Verifier:* The absence is real: repo-wide grep for MaxBytesReader returns nothing, core/api/api.go:21 is an unbounded io.ReadAll(request.Body), core/api/api.go:17 compares the secret with a short-circuiting !=, and only MaxHeaderBytes: 1<<20 is set (core/server/serve.go:43,62,76). But the severity is inflated: relaying request bodies to the backend without a proxy-side ceiling is default reverse-proxy behaviour, not a vulnerability, and the unbounded admin-API ReadAll sits behind a secret the attacker must already possess. The cited location core/server/middleware.go:30-38 is the function preamble, not the defect. Corrected to low.

### TLS fingerprint tables fetched over the network at startup with the error discarded

- **Dimension:** security-http  
- **Location:** `core/config/init.go:104-106`  
- **Effort:** small

**Evidence**

fmt.Println("Loading Fingerprints ...")

GetFingerprints("https://raw.githubusercontent.com/41Baloo/balooProxy/main/global/fingerprints/known_fingerprints.json", &firewall.KnownFingerprints)
GetFingerprints("https://raw.githubusercontent.com/41Baloo/balooProxy/main/global/fingerprints/bot_fingerprints.json", &firewall.BotFingerprints)
GetFingerprints("https://raw.githubusercontent.com/41Baloo/balooProxy/main/global/fingerprints/malicious_fingerprints.json", &firewall.ForbiddenFingerprints)

GetFingerprints returns an error (core/config/generate.go:109) that is discarded at all three call sites.

**Impact**

The classification tables that drive `browser`, `botFp` and the forbidden-fingerprint block (middleware.go:84-85, 135-140) are sourced from a third-party HTTP endpoint at every startup, and a fetch failure is silent — the operator gets 'Loading Fingerprints ...' and a proxy running on whatever was last compiled in, with no signal that the update did not apply. Anyone who controls that repository (or the resolver/TLS path in a restricted network) can push a table that labels an attack tool as 'Chromium', disabling the unknown-fingerprint ratelimit at line 122-127 for that tool across every deployment. A startup network dependency is also a hard availability coupling for a DDoS appliance.

**Fix**

Bundle the fingerprint JSON in the binary with go:embed as the authoritative source, make any remote refresh opt-in, signed, and applied to an atomically swapped copy, and at minimum check and surface the returned error at all three call sites.

*Verifier:* Verified. core/config/init.go:104, 105 and 106 call GetFingerprints against raw.githubusercontent.com and discard the returned error at all three sites, immediately after the reassuring fmt.Println at line 102. The tables feed browser/botFp classification (middleware.go:84-85) and the forbidden-fingerprint block (middleware.go:135-139), and a failed fetch leaves the target maps empty with no signal. One citation is off: GetFingerprints is declared at core/config/generate.go:102, not :109 (line 109 is the ioutil.ReadAll inside it). Low is right.


## INFO

### .vscode/launch.json is tracked but — contrary to expectation — leaks no local paths

- **Dimension:** ops-build  
- **Location:** `.vscode/launch.json:1-12`  
- **Effort:** trivial

**Evidence**

Full file, 12 lines: `{ "version": "0.2.0", "configurations": [ { "name": "Debug main.go", "type": "go", "request": "launch", "mode": "auto", "program": "${workspaceFolder}/main.go" } ] }`. It is tracked deliberately: `.gitignore:33` `.vscode/*` followed by `.gitignore:36` `!.vscode/launch.json`.

**Impact**

No leak — `${workspaceFolder}` is a portable VS Code variable, and there are no absolute paths, usernames, hostnames, ports or env vars in the file. Reported only to close the question and prevent a needless removal; the only cost is a personal editor preference imposed on every contributor.

**Fix**

No action required for security. Optionally drop the `!.vscode/launch.json` negation at `.gitignore:36` and move the config to `.vscode/launch.json.example` so contributors' debugger settings stay personal.

*Verifier:* Verified, and the finding's own negative conclusion is correct. .vscode/launch.json is exactly the 12 lines quoted, with program set to the portable ${workspaceFolder}/main.go and no absolute paths, usernames, hostnames, ports or env vars. It is tracked deliberately: .gitignore:33 is `.vscode/*` and .gitignore:36 is `!.vscode/launch.json`. Correctly filed as info with no action required — this is a self-refuting entry that closes the question rather than a defect, and the optional cleanup would not break anything.


---

## Completeness critic — what the 9 dimensions missed

An independent agent re-read the repo asking "what did this audit not look at?".
These are additional verified findings, mostly plain correctness bugs that no security or
performance dimension was assigned to hunt.

### [high] 5 firewall DSL fields are registered but never supplied — geo/ASN/body rules silently fail open, and negated ones match every request

- **Location:** `core/firewall/filter.go:7-8,12,24-25 (vs core/server/middleware.go:151-175)`

**Evidence**

filter.go registers 26 fields including `ip.country`, `ip.asn`, `ip.requests`, `http.headers`, `http.body`. The gofilter.Message built at middleware.go:151-175 supplies only 21 — those five are never set. core/firewall/filter.go is the only .go file in the repo that NO audit dimension cites even once. I ran the pinned gofilter against a Message missing those keys:
  expr="ip.country eq \"CN\""      Apply=false
  expr="ip.country ne \"CN\""      Apply=true
  expr="ip.asn eq 13335"            Apply=false
  expr="ip.requests > 100"          Apply=false
  expr="http.body contains \"select\"" Apply=false
All five compile without error at core/config/init.go:115, so nothing warns the operator.

**Impact**

An operator writes `{"expression":"(ip.country eq \"CN\")","action":"5"}` to geo-block a flood source; the rule compiles, appears in GET_FIREWALL_RULES, and never fires — the block silently does nothing. The inverse is worse: `(ip.country ne \"ID\")` with action `"0"` (the natural way to express "only allow Indonesia") matches EVERY request in the world and whitelists the entire internet past stages 1-3. `http.body contains "..."` — the only WAF-style body-inspection primitive the DSL advertises — never matches any request, so a payload-filtering rule is inert.

**Fix**

Either populate the five fields in middleware.go (http.body requires buffering the body — gate it behind a per-domain flag with a size cap; ip.country/ip.asn need a GeoIP source or should be dropped from filter.go entirely), or make config.Load reject any rule whose expression references a field not present in the request-variable set. Add a single source of truth: one `var dslFields = map[string]gofilter.FieldType{...}` used both by filter.go's RegisterField loop and by an assertion that middleware's Message covers every key.

### [high] Three README firewall-rule examples reference non-existent fields; copying any of them panics the proxy at startup or kills it on `reload`

- **Location:** `README.md:411,493,363 (compiled at core/config/init.go:115-118, core/server/monitor.go:456-459)`

**Evidence**

I fed the README's own examples to the pinned gofilter:
  `(http.header matches "(?=.*\d)")`  -> Field with name "http.header" does not exists.   (registry has http.headers)
  `(http.engine eq "")`               -> Field with name "http.engine" does not exists.    (registry has ip.engine)
  `(proxy.rps_bypassed le 50)`        -> Field with name "proxy.rps_bypassed" does not exists. (registry has proxy.rps_allowed)
The README's `matches` example also uses a lookahead: gofilter returned `error parsing regexp: invalid or unsupported Perl syntax: (?=` — Go's RE2 cannot compile it at all. Separately, `ip.src in {203.0.113.7}` (the set syntax two audit findings assume works, and which "Wireshark display filter" implies) is a hard `syntax error` in this 2017 gofilter build; only `ip.src eq 203.0.113.7` and `ip.src == 203.0.113.0/24` parse.

**Impact**

An operator copies a documented example into config.json. On a cold start, config/init.go:117 panics and the proxy never comes up. Far worse: typing `reload` in the TUI on a live box hits monitor.go:458, which panics, and pnc.PanicHndl re-panics at core/pnc/panicHandler.go:30 — the DDoS-mitigation process dies mid-attack because of a documentation copy-paste. No dimension checked README examples against the field registry or the regex engine.

**Fix**

Fix README.md:411 to `http.headers` (and to an RE2-compatible regex — RE2 has no lookahead), :493 to `ip.engine`, :363 to `proxy.rps_allowed`; delete or correct any `in {}` set-syntax references. Then make rule compilation non-fatal: collect per-rule errors, report them to the TUI, and have ReloadConfig abort and keep the previous config rather than panicking a running proxy.

### [high] Stage-3 captcha erases answer pixels that are never written into the mask — ~79% of generated captchas are unsolvable by a human

- **Location:** `core/utils/image.go:48-49 (parameters from core/server/middleware.go:243,262,268-271)`

**Evidence**

DrawTriangle does `dst.Set(x+i+shift, y+j, src.At(x+i,y+j))` then unconditionally `src.Set(x+i,y+j, transparent)`. image.RGBA.Set silently no-ops outside bounds, so when `x+i+shift` falls off the 100px canvas the pixel is destroyed in the captcha and never recorded in the mask. I ran the real code with the real parameter distributions (shift=rand.Intn(50)-25, size=rand.Intn(5)+10, x=rand.Intn(100-size), 10-29 triangles):
  triangle at x=85 size=14 shift=+24 -> pixels erased from captcha but MISSING from mask: 105 ; correctly carried: 0 ; max written x = 122 vs bounds (0,0)-(100,37)
  Monte Carlo, 200k captchas: at least one triangle loses pixels in 79.3% (158561/200000).
Negative shifts overflow the LEFT edge, which is exactly where the green answer is drawn (middleware.go:248: x=rand.Intn(25)).

**Impact**

Stage 3 is the last-resort tier the proxy escalates to when stage 2 is being bypassed. A large fraction of the time the six green answer characters have chunks permanently deleted with no slider position that restores them — legitimate humans cannot pass, and because the image is cached under a 6-char key (middleware.go:240,287) the same broken captcha is re-served. The audit analysed how easily a *bot* solves this captcha (security-authz) and how it is cached (performance) but nobody checked whether a person can solve it.

**Fix**

Clamp the triangle origin so the whole shifted footprint stays in bounds: pick `x` from `[max(0,-shift), 100-size-max(0,shift))`. Better, only erase a source pixel after confirming the destination write landed: check `dst.Bounds().At/In` before `src.Set`. Add a regression test asserting that for every (shift,size,x) the union of mask and captcha reconstructs the original image.

### [high] ReloadConfig only adds domains — a domain deleted from config.json keeps serving traffic to its old backend until the process is restarted

- **Location:** `core/server/monitor.go:403-528 (writes at :482 and :507; no delete anywhere)`

**Evidence**

ReloadConfig resets the display slice at :403 (`domains.Domains = []string{}`) but `domains.DomainsMap` (a sync.Map, written at :482) and `domains.DomainsData` (a map, written at :507) are only ever *stored into*. There is no `Delete`/`delete` call in the function. Middleware resolves a request purely by `domains.DomainsData[request.Host]` (middleware.go:41) and `domains.DomainsMap.Load(domainName)` (middleware.go:145), both of which still hold the removed entry with its still-live `DomainProxy` pointing at the old backend.

**Impact**

An operator removes a compromised or decommissioned domain from config.json and runs `reload` — the documented zero-downtime way to apply config changes. The proxy reports success, the domain disappears from the TUI domain list, and it keeps proxying every request for that Host to the backend that was supposed to be cut off. Same for renaming a domain: the old name stays live forever. There is no way to revoke a domain without a full restart, and nothing tells the operator that.

**Fix**

Build the new DomainsMap/DomainsData into fresh containers and swap them in (an `atomic.Pointer` to an immutable snapshot, per the concurrency findings), so removal is implicit. If mutating in place, explicitly diff the old key set against the new and `delete`/`Delete` the difference — remembering to preserve the `debug` entry only if it is intentionally kept.

### [high] The `stage` command's lock is silently ignored whenever an attack cooldown is active — exactly when an operator uses it

- **Location:** `core/server/monitor.go:114 (set at :328-329, advertised at :272 and as `proxy.stage_locked` in core/firewall/filter.go:29)`

**Evidence**

checkAttack gates the whole auto-escalation block on `if !domainData.StageManuallySet || (domainData.BufferCooldown > 0)`. The `stage N` command sets `StageManuallySet = true` (monitor.go:329) but does not touch BufferCooldown. BufferCooldown is set to 10 on attack detection (:164, :201) and only decrements while `!BypassAttack && !RawAttack` (:135-136). So during an attack the second disjunct is true and the switch at :146-182 runs regardless of the lock: a manually pinned Stage 3 is dropped back to 2 by :179-180 on the next one-second tick, and a pinned Stage 1 is escalated by :149-151.

**Impact**

An operator watching a flood types `stage 3` to force captcha on everything. The TUI shows `Stage Locked > true` (:272) and the DSL field `proxy.stage_locked` reads true, yet within one second the auto state machine has moved the stage back. The lock appears to work in calm conditions (BufferCooldown == 0) and fails only under attack, so it is unlikely to be noticed in testing.

**Fix**

Make the manual lock authoritative for the stage while still allowing telemetry/logging to run: keep the RequestLogger append and the webhook cooldown outside the gate, and wrap only the `switch domainData.Stage` block (:146-182) plus the raw-attack stage effects in `if !domainData.StageManuallySet`. Add a test asserting the stage is invariant across a simulated attack once StageManuallySet is set.

### [medium] json.Decode error discarded on both the load and reload paths: an empty or truncated config.json nil-derefs at startup and half-applies on reload

- **Location:** `core/config/init.go:36-38 (and core/server/monitor.go:410-412)`

**Evidence**

`json.NewDecoder(file).Decode(&domains.Config)` at init.go:36 discards its error, and init.go:38 immediately dereferences `domains.Config.Proxy.Cloudflare`. `domains.Config` is a nil `*Configuration` at startup (core/domains/domain.go:17). I reproduced the decode behaviour exactly:
  content=""                            decode err=EOF             Config==nil? true  -> `Config.Proxy.Cloudflare` PANICS: nil pointer dereference
  content="{\"proxy\":{\"cloudflare\":true}," decode err=unexpected EOF  Config==nil? true  -> PANICS
  content="     "                       decode err=EOF             Config==nil? true  -> PANICS
This is reachable because config.json is written non-atomically (truncate-then-write) by ioutil.WriteFile at core/config/generate.go:53, :96 and core/utils/domain.go:44 — a kill or disk-full during the `add` command leaves a 0-byte or partial file. On the reload path (monitor.go:410) Config is already non-nil, so a partial parse instead mutates the live config in place and continues silently.

**Impact**

An interrupted `add` permanently bricks startup with an opaque nil-pointer panic and no message naming config.json (log output is discarded at main.go:32). On reload, a malformed edit is half-applied to a running proxy — ratelimit thresholds and secrets partially updated — with no error shown, and monitor.go:530 then panics with index-out-of-range if the partial parse produced zero domains.

**Fix**

Check the Decode error at both sites and fail with a message naming the file and the JSON offset. Decode into a fresh `Configuration` value, validate it, and only then publish it. Write config.json atomically (write to config.json.tmp, fsync, os.Rename) at generate.go:53/:96 and utils/domain.go:44, and at 0600 rather than 0644.

### [medium] proxy.RamUsage is Alloc/Sys — a heap-liveness ratio, not memory pressure — so the only cache-eviction safety valve can never fire under a leak

- **Location:** `core/server/monitor.go:238 (consumed at :552 and :564)`

**Evidence**

`proxy.RamUsage = fmt.Sprintf("%.2f", float64(ramStats.Alloc)/float64(ramStats.Sys)*100)`. `MemStats.Alloc` is live heap bytes; `MemStats.Sys` is total bytes obtained from the OS by the runtime. The ratio is bounded by construction and describes GC state, not host memory. The eviction gate at :552/:564 is `(proxyCpuUsage < 15 && proxyMemUsage > 25) || proxyMemUsage > 95`. As the CacheIps/CacheImgs leak grows, `Sys` grows alongside `Alloc`, so the ratio plateaus rather than climbing toward 95.

**Impact**

The audit repeatedly states (performance/high, concurrency/high, security-crypto/low) that the caches are dumped "until RAM hits 95%" and treats that as a real, if late, safety valve. It is not: the `> 95` emergency branch is effectively unreachable, and the `> 25` threshold is meaningless. The proxy therefore has no memory-pressure backstop at all — it OOM-kills without ever attempting the emergency eviction the code appears to implement. The same value is exported to operators via the API as `RAM_USAGE` (core/api/api.go:62,70) and to Discord as `{{proxy.ram}}` (core/utils/discord.go:21), so dashboards built on it are reporting a number that has nothing to do with memory headroom.

**Fix**

Replace the eviction gate with a real bound: track cache entry counts with an atomic incremented at Store time and evict on count plus a per-entry TTL, independent of any CPU/RAM heuristic. If a memory figure is still wanted for display, use `ramStats.HeapAlloc` against a configured budget, or read host memory (gopsutil's mem package is already in the dependency graph) — and rename the field so nobody reads Alloc/Sys as "RAM usage" again.

### [medium] github.com/shirou/gopsutil v3.21.11+incompatible — the largest dependency subtree in the module — is absent from the entire deps-toolchain review

- **Location:** `go.mod:24 (sole use: core/server/monitor.go:19,220)`

**Evidence**

go.mod:24 pins `github.com/shirou/gopsutil v3.21.11+incompatible`. The `+incompatible` suffix means this v3 tag has no go.mod — it is the pre-modules import path, superseded by `github.com/shirou/gopsutil/v3` and now `/v4`. It drags in four transitive deps that exist for nothing else: go-ole v1.3.0, yusufpapurcu/wmi v1.2.4, tklauser/go-sysconf v0.3.14, tklauser/numcpus v0.8.0 (go.mod:20-25). The single call site is `cpu.Percent(0, false)` at monitor.go:220, feeding a TUI line and the (broken, see above) eviction gate. The deps-toolchain dimension enumerated gofilter, inancgumus/screen, boltdb, blake3, quickchart-go and every golang.org/x/* module, and produced a per-dependency finding for each — gopsutil and its four children appear in none of them.

**Impact**

A 2021 `+incompatible` pin on a package that does OS-specific syscalls, WMI queries on Windows and /proc parsing on Linux is the largest unreviewed attack surface in the dependency graph of a security appliance, and it will show up on every customer SBOM. It is also the reason `go mod tidy` cannot cleanly modernise the module. Note `github.com/stretchr/testify v1.8.1` also sits in go.mod:16 as an indirect dep of a repo with zero test files — further evidence tidy has not been run.

**Fix**

Either bump to `github.com/shirou/gopsutil/v4` (a one-line import change for `cpu.Percent`) or drop the dependency entirely: with the RamUsage gate fixed the CPU figure is decorative TUI output, and `runtime.NumCPU()` plus process CPU time from `syscall.Getrusage`/`GetProcessTimes` covers it without four transitive modules. Verify with `go list -m all` before and after.

### [medium] ReloadConfig indexes domains.Domains[0] unguarded and resets every domain to Stage 1 with zeroed counters

- **Location:** `core/server/monitor.go:530 (state reset at :507-526)`

**Evidence**

`proxy.WatchedDomain = domains.Domains[0]` at :530 with no length check. `domains.Domains` is emptied at :403 and only repopulated from `domains.Config.Domains` (:450). Any config.json with an empty `domains` array — or the partially-decoded config from the discarded-error path above — makes this an index-out-of-range panic, which pnc.PanicHndl re-raises at core/pnc/panicHandler.go:30, killing the process. Note config.Load guards the identical situation at init.go:229-234; ReloadConfig does not. Separately, :507-526 assigns a fresh DomainData with `Stage: 1`, `TotalRequests: 0`, `BypassedRequests: 0` and `RequestLogger: []` for every domain.

**Impact**

Two distinct operator-triggered outages. (1) A `reload` with an emptied or malformed domains list panics a live proxy rather than reporting an error. (2) A `reload` during an active flood instantly drops every domain from Stage 3 back to Stage 1 and zeroes the counters checkAttack uses to re-escalate — mitigation is off, and it takes at least one full second plus a fresh BypassStage1 breach to come back. The audit caught that Stage2Difficulty is dropped here; it did not note that the stage itself, the attack flags and the counters are all reset too.

**Fix**

Guard :530 (`if len(domains.Domains) > 0`) and, better, carry forward the surviving DomainData for domains that still exist: copy the existing struct and overwrite only the config-derived fields, so Stage, StageManuallySet, counters and RequestLogger persist across a reload. Reserve the fresh-zero-value path for domains that are genuinely new.

### [low] The terminal-resize condition is always false in its width half — the assignment on the preceding line makes it unsatisfiable

- **Location:** `core/server/monitor.go:69-70`

**Evidence**

Line 69: `proxy.TWidth = tempWidth + 18`. Line 70: `if tempHeight != proxy.THeight || tempWidth+18 != proxy.TWidth {`. The second disjunct compares `tempWidth+18` against the value just assigned from `tempWidth+18`, so it is unconditionally false. The redraw at :80-83 therefore only ever fires on a *height* change.

**Impact**

Narrowing the terminal horizontally leaves the previous frame's wider lines on screen without a clear, so the TUI renders corrupted/overlapping output until the height also changes. Minor on its own, but it is a dead branch in the one loop that also publishes `proxy.Last10SecondTimestamp` and `proxy.CurrHourStr` to the request hot path (:213-218), and no dimension flagged it — the quality-idiom dimension reviewed monitor.go extensively for panics, dead code and copy-paste but not for unsatisfiable conditions.

**Fix**

Capture the old width before assigning: `oldW := proxy.TWidth; proxy.TWidth = tempWidth + 18; if tempHeight != proxy.THeight || proxy.TWidth != oldW { ... }`. While there, the `+18` fudge exists only to compensate for ANSI escape bytes counted by `len()` in utils.ReadLogs:58 — compute a real display width instead so the truncation at text.go:59 stops slicing mid-escape and mid-rune on attacker-supplied User-Agents.

### [low] CpuUsage is a string emitted as a bare JSON number; on cpu.Percent error the chart config is malformed and the proxy then POSTs an empty webhook

- **Location:** `core/utils/discord.go:76 (fallthrough at :211-240)`

**Evidence**

`domains.RequestLog.CpuUsage` is typed `string` (core/domains/domain.go:134) and is set to the literals "ERR" (monitor.go:222) or "ERR_S0" (monitor.go:228) whenever `cpu.Percent` fails or returns an empty slice. discord.go:76 writes it unquoted: `CpuLoadData += '{"x": "'+currTime+'", "y": ' + fmt.Sprint(request.CpuUsage) + ' },'` — producing `"y": ERR }`, invalid JSON. quickchart then fails, `chartErr != nil`, and the `if chartErr == nil` block at :211 is skipped — so `webhookContent` remains the zero `Webhook{}` initialised at :33 and is still marshalled and POSTed at :240-249.

**Impact**

On any host where gopsutil's CPU probe fails (containers with restricted /proc, unusual Windows configs — and gopsutil is itself the unreviewed dependency above), every attack-stop notification degrades to a Discord POST of `{"content":"","embeds":null,"username":"","avatar_url":""}`, which Discord rejects with 400. The operator receives no attack-ended alert and no error, since the response and error from client.Do are both discarded at :249. The audit covered the goroutine/timeout/body-leak issues in this function but not the empty-payload fallthrough or the type bug feeding it.

**Fix**

Type RequestLog.CpuUsage as float64 (or quote it in the chart JSON and store a numeric field alongside), and build the chart config with encoding/json rather than string concatenation. Add `if webhookContent.Username == "" && len(webhookContent.Embeds) == 0 { return }` before :240, or restructure so the `chartErr != nil` path still sends a chartless embed rather than nothing.

### [low] Four files are cited by no audit dimension, including the DSL field registry and an undocumented outbound HTTP call

- **Location:** `core/firewall/filter.go:1, core/utils/ip.go:9, core/utils/debug.go:11, assets/html/error.html:1`

**Evidence**

Cross-referencing every file:line the audit cites against `git ls-files`: core/firewall/filter.go (34 lines, the RegisterField schema for the entire firewall DSL) is cited zero times — which is how the field-mismatch finding above survived. core/utils/ip.go is cited zero times and contains `http.Get("http://checkip.amazonaws.com")` at :9 — an outbound call over plaintext HTTP to a third party; `grep -rn GetOwnIP --include=*.go .` returns only its own declaration, so it is dead, but both the branding dimension's and ops-build's enumerations of "external endpoints contacted at runtime" list only githubusercontent, jsdelivr, cdnjs, quickchart and Discord — amazonaws is absent from both. core/utils/debug.go (36 lines, LogHeapProfile/LogGoroutineProfile, both unreferenced) is cited zero times; the quality dimension's "fourteen unused exported symbols" finding names SafeString, FailRequestRatelimit, RELOAD and firewall.RequestLog but neither of these. assets/html/error.html is cited zero times, while the same dimension's dead-asset finding names only login.html and captcha.html — error.html:3 literally contains the Go source fragment `` ` + resp.Status + ` `` in its <title>, confirming it is a stale paste of the serve.go:171-176 blob.

**Impact**

filter.go is the schema for the security-critical rule engine and going unread hid a fail-open. ip.go leaves an undocumented cleartext third-party endpoint in the binary that would be linked the moment anyone calls it, and makes the audit's "no remaining external dependencies" inventories incomplete. debug.go would write unbounded heap/goroutine profiles into the working directory if ever wired up. error.html misleads a maintainer into editing a file the proxy never reads.

**Fix**

Delete core/utils/ip.go, core/utils/debug.go and assets/html/error.html (add profiling back behind net/http/pprof on a localhost-bound admin listener if it is wanted). Keep filter.go but reconcile it with middleware's Message per the first finding. Re-run the external-endpoint inventory with `grep -rn 'http.Get\|http.Post\|http.NewRequest\|https\?://' --include=*.go .` rather than from memory.

### [low] evaluateRatelimit is the only background goroutine without pnc.PanicHndl — and it is the one whose death freezes the ratelimit clock

- **Location:** `core/server/monitor.go:576-578`

**Evidence**

Every other long-lived goroutine opens with `defer pnc.PanicHndl()`: Monitor (:36), commands (:288), clearProxyCache (:535), generateOTPSecrets (:641), Serve (core/server/serve.go:33) and its TLS child (:106), SendWebhook (core/utils/discord.go:28). `func evaluateRatelimit()` at :576 has no such defer — the function body starts directly with `for {`.

**Impact**

evaluateRatelimit is the goroutine that prefills the sliding-window buckets (:581-594) whose absence causes the nil-map write the audit's top concurrency finding describes, and it is the sole writer of firewall.AccessIps / AccessIpsCookie / UnkFps. If it panics — e.g. on the concurrent map access the audit documents elsewhere — nothing is written to crash.log, so the operator investigating a dead proxy finds an empty crash.log and concludes there was no crash. It is a small inconsistency in exactly the wrong place.

**Fix**

Add `defer pnc.PanicHndl()` as the first line of evaluateRatelimit for parity. More durably, fix the re-panic at core/pnc/panicHandler.go:30 so background-goroutine panics are logged and the goroutine restarted rather than taking the process down, and stop discarding the standard logger at main.go:32.

### [info] Attack classes I tested that the audit did not consider — terminal-escape injection into the operator TUI is blocked by Go, not by this code

- **Location:** `core/utils/text.go:30-32 (reached from core/server/middleware.go:307-315)`

**Evidence**

FormatLogs interpolates `log.Useragent` and `log.Path` — both fully attacker-supplied — raw into an ANSI-escape-laden string that is fmt.Print'ed to the operator's TTY (utils.ReadLogs:59,61). No dimension considered log-injection-to-terminal as an attack class, and utils.SafeString (text.go:172, `string([]byte(str))`) looks like an abandoned attempt at exactly this defence. I tested whether a payload can reach it: `http.ReadRequest` on `User-Agent: A\x1b[2J\x1b[1;1HPWNED\x07` returns `malformed MIME header line` — Go's header-value validator rejects bytes below 0x20 other than tab, so ESC cannot traverse the header. The path is likewise safe: net/url rejects control bytes in the request target. Bytes 0x80-0xFF (including the 8-bit CSI 0x9B) do pass Go's validator, but modern UTF-8 terminals do not interpret bare 0x9B.

**Impact**

No action needed today — reported so the LancarSec fork does not lose the protection by accident. The safety here comes entirely from Go's stdlib header parser, not from anything in this codebase. Any future change that logs a value obtained from a source Go does not validate (a JSON API field, a database row, a Cf-* header re-derived from a trusted proxy chain, or a switch to a hand-rolled parser) reintroduces it immediately.

**Fix**

Sanitise at the log-formatting boundary rather than relying on the transport: in FormatLogs, strip or escape any byte < 0x20 and 0x7F-0x9F from Useragent and Path (`strconv.Quote` on the untrusted fields is the one-line version), and delete the misleading no-op utils.SafeString. Also note the truncation at text.go:59 slices a string containing both ANSI escapes and multi-byte UTF-8 by byte offset, which can emit a partial escape sequence or an invalid rune to the terminal.


---

# Re-audit — 2026-08-31 (ultracode pipeline)

The original audit above is preserved untouched. This re-audit re-ran the full pipeline against
HEAD `0f734e8` (wave-9 W1 landed at `d1d62e9`): 9 dimension finders, 9 hostile refute-first
verifiers ("default to refuted unless you can verify it yourself"), a completeness critic hunting
for uncovered areas, and this synthesis. Raw findings with per-finding evidence (file:line,
commands run) live in `audit-rerun-2026-08-31/*.json` in the HarnessAgents workspace, outside
the repo.

## Scorecard

| Dimension | Raised | Verified | Refuted | Already fixed by W1 | Unchecked |
|---|---|---|---|---|---|
| crypto | 11 | 11 | 0 | 1 (CRYPTO-01) | 0 |
| deps | 5 | 5 | 0 | 0 | 0 |
| authz | 7 | 7 | 0 | 2 (AUTHZ-03/04) | 0 |
| perf | 15 | 15 | 0 | 0 | 0 |
| quality | 10 | 10 | 0 | 0 | 0 |
| concurrency | 13 | 12 | 1 (CONC-12) | 0 | 0 |
| brand | 21 | 20 | 0 | 1 (BRAND-06) | 0 |
| ops | 2 | 2 | 0 | 0 | 0 |
| http | 6 | 6 | 0 | 2 (HTTP-01/04) | 0 |
| critic | 0 new | — | all proposals self-refuted | — | — |
| **total** | **90** | **88** | **1** | **6** | **0** |

## Convergence map (multi-dimension dedup)

- `AUTHZ-01 = CRYPTO-02` — empty/short challenge secrets accepted (high)
- `AUTHZ-03 = HTTP-01` — stage-1 open redirect — **fixed in `d1d62e9`**
- `AUTHZ-04 = HTTP-04` — cacheable block 200s — **fixed in `d1d62e9`**
- `AUTHZ-05 = CONC-02 = CRYPTO-04` — reload publishes secrets/flags/thresholds as unsynchronized globals (high)
- `AUTHZ-06 = QUAL-01 = HTTP-02` — body-size config is dead code (medium)
- `HTTP-05 = QUAL-02` — omitted `ratelimits` section publishes threshold 0, block-everyone (medium)
- `HTTP-06 = CRYPTO-06` — admin secret persisted verbatim in LastLogs (low; capped by challenge gate)
- `CONC-01 = PERF-10` — nil sliding-window bucket: panic under `firewall.Mutex` without defer (critical; PERF-10 additionally notes wave 7's "lazy creation" claim was never implemented)
- `CONC-09 = PERF-01` — single coarse `firewall.Mutex` serialises the request path (high)
- `CONC-04 = PERF-02` — sliding-window maps: unbounded cardinality vs O(n) rebuild under lock (two symptoms, one family)
- `QUAL-08 = HTTP-03` — discarded log output makes handler panics invisible

## Significant live findings (dedup'd, ordered by severity)

1. **[critical] Nil-window panic freezes the whole proxy** (CONC-01, PERF-10;
   `core/server/monitor.go` sliding-window prefill + firewall request path). A request hitting a
   missing window bucket panics while holding `firewall.Mutex` with a non-defer unlock — the
   mutex stays wedged and every subsequent request blocks forever.
2. **[high] Empty/short challenge secrets accepted** (AUTHZ-01, CRYPTO-02;
   `core/config/pipeline.go:252-266`). Validation passes on empty secrets; the hourly OTP and
   every clearance token become publicly derivable — full challenge bypass. Fix: reject
   empty/short secrets at load.
3. **[high] Unsynchronized config publish on reload** (AUTHZ-05, CONC-02, CRYPTO-04): bare
   assignments to ~15 package globals while the request path reads them concurrently — torn
   reads across the set mid-reload.
4. **[high] Unbounded sliding-window cardinality** (CONC-04): attacker-controlled key
   population grows the window maps without a cap — memory exhaustion under high-cardinality
   sources (botnets, spoofed /64s).
5. **[high, perf] Coarse `firewall.Mutex` taken 2-3x per request for writing** (PERF-01,
   CONC-09); `evaluateRatelimit` rebuilds ALL client totals from scratch under the exclusive
   lock every 5s (PERF-02); `utils.AddLogs` appends unboundedly under the global write lock on
   every verified request (PERF-03).
6. **[medium] Body-size limits are dead code** (AUTHZ-06, QUAL-01, HTTP-02;
   `core/server/middleware.go:706` is the sole reader): `max_body_size` and per-domain
   `maxBodySize` are normalised, validated and published but never enforced — a 1024-byte domain
   cap silently enforces 10 MiB, and the `-1` unlimited sentinel is ignored.
7. **[medium] Omitted `ratelimits` section publishes zero thresholds** (HTTP-05, QUAL-02;
   `core/config/pipeline.go:547-551`): nil map publishes 0 for every threshold; enforcement has
   no `limit > 0` guard, so after one monitor tick every non-whitelisted client gets 429. No
   warning is logged.
8. **[medium] `debug` pseudo-domain panics** (HTTP-03, NEW this re-audit,
   `core/config/pipeline.go:675-686`): `Host: debug` reaches a `DomainSettings` with nil
   `DomainProxy`; `ServeHTTP` on the nil proxy panics per connection (process survives,
   connection dropped), and `main.go:40` `io.Discard` swallows the trace. Verified with a
   runtime probe.
9. **[medium] Reload never republishes the OTP set** (AUTHZ-02): rotated challenge secrets stay
   inert until the next UTC hour.
10. **[medium, perf]** eviction sweep under the coarse lock (PERF-05, CONC-08), window
    granularity gaps (PERF-04), per-request gofilter map + `fmt.Sscan` of rule actions
    (PERF-06/07), challenge-page string re-materialisation and full captcha regeneration per
    request (PERF-08/09).
11. **[low]** unsupervised webhook goroutines (CONC-05), `proxy.Initialised` unsynchronised
    (CONC-06), `ReadLogs` unlocked iteration (CONC-07), domains slice publish mismatch
    (CONC-11), stdin-EOF busy-spin (CONC-10), constant-time compare on fresh conversions +
    admin-path concat per request (PERF-11/12), TUI stop-the-world stats per second (PERF-13),
    `readCookies` before custom parse (PERF-15), non-constant-time secret compares (CRYPTO-05/09),
    0644 crash.log beside 0600 secrets (CRYPTO-07), hasher-pool saturation from stale OTP keys
    (CRYPTO-08), captcha colour bias (CRYPTO-10), dead `HashToInt` (CRYPTO-11), unchecked
    type-assertion in `checkAttack` (QUAL-06), dead `domains.Get` (QUAL-09), copy-paste clusters
    (QUAL-10), `APIResponse` error discarded at ~18 sites (QUAL-07).
12. **[deps, medium] Go 1.25 has left upstream security support** (DEPS-01): toolchain bump
    belongs in wave 11.
13. **[ops] quickchart-go still a direct dependency** (ops-2; owner decision pending).

## Already fixed by wave-9 W1 (confirmed at `d1d62e9`)

- Open redirect (HTTP-01, AUTHZ-03): guard rejects `URL.Host != ""` / `Path` starting `//` with
  400 before the redirect; probe-verified (no Location, no cookie).
- Cacheable block 200s (HTTP-04, AUTHZ-04): `SendResponseWithStatus` sends real statuses +
  `Cache-Control: no-store` on every block/ratelimit/404 path; test-asserted.
- CDN PoW assets (CRYPTO-01): stage 2 now loads first-party immutable embeds
  (`/_bProxy/balooPow.min.js`, `/_bProxy/crypto-js.min.js`); CDN hosts absent from served bodies.

## Completeness critic

Probed areas the 9 finders had not covered: API handlers beyond GET_LOGS, serve.go listener
lifecycle/timeouts, transport internals, config parse edges, utils, TUI, test hygiene, deploy
scripts, docs-vs-code claims. Zero findings survived the critic's own refutation — finder
coverage was complete at this HEAD. (Terminal-escape log injection into the operator TUI was
re-checked and remains blocked by Go's header validator, consistent with the original audit;
the protection is the stdlib's, not this codebase's.)

## Wave folding (2026-08-31)

- **Wave 9 W2** (existing: middleware decomposition + html/template): add the `debug` nil-proxy
  guard (HTTP-03, ~3 lines) and treat QUAL-03 as the slice's own motivation.
- **Wave 9 W3** (new — config correctness): reject empty/short secrets (AUTHZ-01/CRYPTO-02),
  ratelimits defaults + load warning (HTTP-05/QUAL-02), wire body limits (AUTHZ-06/QUAL-01/
  HTTP-02), republish OTP on reload (AUTHZ-02), redact admin secret from logs (HTTP-06/
  CRYPTO-06).
- **Wave 9 W4** (new — concurrency hardening): nil-window fix + defer unlock (CONC-01/PERF-10),
  defer unlocks in supervised workers (CONC-03), window-map cardinality caps (CONC-04),
  synchronized/atomic config publish (CONC-02/AUTHZ-05/CRYPTO-04), unsupervised goroutines
  (CONC-05), Initialised atomic (CONC-06), ReadLogs lock (CONC-07), eviction/lock decomposition
  (CONC-08/09/PERF-01/02/05), stdin EOF (CONC-10), domains publish (CONC-11), plus the perf
  mediums/lows above.
- **Wave 10** (rebrand): brand inventory complete (20/21 verified + BRAND-06 already fixed by
  W1; second-pass verification 2026-09-01 found only line/count drift, 0 refuted); **BRAND-01 is
  the critical note** — the BLAKE3 KDF context embeds the module path, so rebranding rotates
  every derived token: a deploy-time break of the same class as the W1 stage-3 cookie change.
  Concrete rename targets and the dual-accept grace window are already prescribed in the
  original audit's rebrand section (AUDIT.md :220-253); the test suite pins every rebranded
  surface (19 baloo lines in middleware_test.go + monitor/bench azferius imports), so the
  rename and its test-pin flips must land in one atomic commit.
- **Wave 11**: add the Go toolchain bump (DEPS-01); CRYPTO-03 feeds the stage-3 captcha
  redesign; Cf-Ja3-Hash passthrough per the owner's 2026-08-31 decision.
