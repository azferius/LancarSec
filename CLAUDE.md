# LancarSec — Context for Claude

## What this is

LancarSec is a fork of **balooProxy** (`github.com/41Baloo/balooProxy`, GPL v2) — a single-binary
Go HTTP reverse proxy with L7 DDoS mitigation, a 3-stage browser challenge (cookie → JS
proof-of-work → captcha), TLS fingerprinting, and a Wireshark-style firewall rule DSL.

The tree is currently **unmodified upstream** at commit `4d4f128` (Oct 2024): 25 `.go` files,
3098 lines, module `goProxy`, `go 1.19`. Nothing has been rebranded or fixed yet. A previous
fork attempt was reset away on 2026-08-30 to restart cleanly from upstream.

**Goal of this fork, in the owner's words:** improve performance, improve security, improve code
quality, move to the latest Go and latest dependencies, and rebrand every marker to LancarSec.

## Read these first

| File | What it is |
| --- | --- |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | How the code works today — per-package map, request dataflow with line anchors, and 40+ non-obvious gotchas. Read before touching anything. |
| [`docs/AUDIT.md`](docs/AUDIT.md) | 185 verified findings + an 11-wave roadmap + the breaking-change list. This is the work queue. |

Both were produced 2026-08-30 by a 24-agent audit: 4 agents mapped the architecture, 9 audited
in parallel across separate dimensions, and each dimension's findings were re-checked by an
independent agent instructed to refute them. 21 findings were refuted and dropped. Locations in
those documents were verified twice — trust them, but re-read the line before editing it, since
line numbers shift as waves land.

## Audit result in one table

| Severity | Count |
| --- | --- |
| critical | 8 |
| high | 40 |
| medium | 80 |
| low | 42 |
| info | 1 |

The eight critical ones, since they shape every decision below:

1. **Every secret is identical on every install.** `utils.RandomString` (`core/utils/encryption.go:30-38`)
   uses top-level `math/rand`, which under Go 1.19 is seeded with `1` unless `rand.Seed` is called —
   and it never is. Every operator who ran the first-launch wizard, and every Docker/release build,
   got the same `AdminSecret`, `APISecret`, cookie/JS/captcha secrets.
2. **`Cf-Connecting-Ip` is trusted from any peer** (`core/server/middleware.go:59-71`). One header
   defeats ratelimits, bans, and token binding entirely.
3. **One global `RWMutex` is taken 3–4× per request** (`core/firewall/general.go:10`), twice for
   writing. The proxy gets *slower* with more cores — measured 43.7 ns/op at GOMAXPROCS=1 degrading
   to 90.9 ns/op at 16. That is the opposite of what a mitigation front end needs.
4. **The hot path has bare `Lock()`/`Unlock()` with no `defer`**, and `middleware.go:96` can panic on
   a nil map. `net/http` recovers the handler panic, the lock is never released, and the whole proxy
   deadlocks permanently.
5. **Ratelimits read a snapshot refreshed every 5 s** (`core/server/monitor.go:576-636`), so there is
   a 5-second unmetered burst window on every threshold.
6. **`reload` disables the JS proof-of-work.** `ReloadConfig` rebuilds `DomainData` without
   `Stage2Difficulty` (`core/server/monitor.go:507-526`), so it becomes 0 and the stage-2 page prints
   the exact token it is asking for.
7. **20 stdlib vulnerabilities are symbol-reachable** on the request path (govulncheck), from the
   Go 1.19 pin.
8. **A real ZeroSSL private key is committed** at `assets/server/server.key` — a genuine RSA key for
   `CN=baloo.dog`, not a dev placeholder. The certificate expired 2023-03-17, so live exposure is
   nil, but it must still leave the tree and the history. Alongside it, an 11 MB unstripped ELF at
   `oryxBuildBinary` built from `/workspaces/balooProxy`.

## Roadmap — 11 waves

Full detail with per-item file:line and exit criteria is in `docs/AUDIT.md`. The order is by
dependency and risk, not by severity. Do not reorder waves 1–3.

| Wave | Name | Why it sits here |
| --- | --- | --- |
| 1 | Repo hygiene, secret purge, history rewrite | Rewrites git history and renormalises CRLF→LF in all 25 files. Must be the literal first commit or every later branch needs rebasing onto rewritten history. |
| 2 | Toolchain, dependency graph, module path | `go 1.19` blocks `min`/`max`, `clear`, range-over-int, `errors.Join`, and the Go 1.22 loopvar semantics. Nothing downstream can use modern Go until this lands. |
| 3 | Test harness, benchmark baseline, CI gates | **Nothing after this may start until it lands.** Zero tests exist across 3098 lines, and wave 7 rewrites a 335-line function that decides whether traffic is blocked. |
| 4 | Config load unification | `ReloadConfig` is a 131-line divergent copy-paste of `config.Load`. Until they are one function, every fix must be written twice or it silently regresses on `reload`. |
| 5 | Secrets, token derivation, admin auth | Lands after wave 4 so each fix lands in exactly one place. |
| 6 | Client identity: trusted-proxy + IPv6 | Changes what the ratelimit map *keys* are. Wave 7's sharding is only meaningful once the key space is bounded. |
| 7 | Hot-path concurrency rewrite | Largest and riskiest. Needs the toolchain (2), the tests and benchmark baseline (3), and the corrected keys (6). |
| 8 | Upstream transport and response path | Independent of 7; sequenced after so throughput measurements aren't confounded. |
| 9 | Challenge rendering, XSS, middleware decomposition | Splits the 335-line `Middleware` once, after the hot path is stable. |
| 10 | Wire-visible rebrand + legal notices | **One commit, one deploy, atomic.** Every token here is protocol-visible and two break live sessions. |
| 11 | Deferred hard problems | Spec-accurate JA4 from raw ClientHello; stage-3 captcha redesign. Both change detection behaviour rather than fix a defect. |

### Quick wins — safe to land immediately, before wave 1

- `fmt.Println` → `fmt.Printf` at `core/firewall/eval.go:30`. The whole module fails `go vet` on this
  one line, so no CI gate can be added until it's fixed.
- Add `Stage2Difficulty: domain.Stage2Difficulty` + the `== 0 { = 5 }` default to
  `core/server/monitor.go:507-526`. One line; until it lands, any `reload` disables stage 2.
- `r.URL.Path + r.URL.RawQuery` → `r.URL.RequestURI()` at `core/server/serve.go:99`. Today every
  query-bearing request is 301-redirected (and browser-cached) to a mangled URL — `/search?q=x`
  becomes `/searchq=x`.
- `Header.Add` → `Header.Set` for the four backend identity headers at `core/server/middleware.go:358-361`,
  with a `Del` of inbound `X-Real-Ip`/`X-Forwarded-For` first.
- Give every `httputil.ReverseProxy` a shared `BufferPool` (`core/config/init.go:126-130`,
  `core/server/monitor.go:467-471`). Five lines, removes a 32 KiB alloc per proxied response.
- Delete `case "FILL_IP_CACHE"` (`core/api/api.go:101-109`). One authenticated request freezes the
  entire proxy for ~1.76M `math/rand` calls under the global write lock.
- `term.IsTerminal` guard on `commands()` (`core/server/monitor.go:290-296`). Under systemd/docker/nohup
  that loop spins a full core at 100% forever.
- `MinVersion: tls.VersionTLS12` at `core/server/serve.go:71-75`. The `:443` listener currently
  negotiates TLS 1.0/1.1.

## Rebrand map

Wave 10, atomic. Everything below is protocol-visible; the module-path rename in wave 2 is not.

| Upstream | LancarSec | Breaks |
| --- | --- | --- |
| module `goProxy` | `lancarsec` | build only (37 import lines, must be one commit) |
| header `baloo-Proxy: 1.5` | `LancarSec-Proxy`, hidden by default behind `hide_version_header` | monitoring that greps for it |
| cookie `__bProxy_v` | `__lSec_v` | **invalidates every issued clearance cookie** — expect a challenge storm at cutover |
| path `/_bProxy/` | `/_lancarsec/` | any API automation, CDN/WAF path rules |
| admin secret in URL path | `Admin-Secret` header on a fixed route | every admin bookmark and script |
| `BalooProxy` in 8 block/error pages | `LancarSec` | cosmetic |

Four sites reach Baloo infrastructure at runtime and must be cut — they are an availability and
supply-chain problem, not just branding:

- `core/config/init.go:104-106` fetches the fingerprint tables from `raw.githubusercontent.com/41Baloo`
  every startup, **discarding the error**. `global/fingerprints/*.json` already exist in the tree —
  `//go:embed` them.
- `core/config/init.go:224-226` version-checks against the same host and **panics on failure**. The
  proxy refuses to boot without outbound internet.
- `core/server/middleware.go:232` loads the balooPow JS from `cdn.jsdelivr.net/gh/41Baloo` — a mutable
  ref, and it leaks every challenged client's IP to a third party. Vendor and `//go:embed` it.
- `oryxBuildBinary` embeds `/workspaces/balooProxy` paths and the full pre-rebrand token set.

### GPL v2 — what must stay

`LICENSE` is the stock GPL v2 text; leave it byte-identical. The `/_bProxy/credits` endpoint
(`core/server/middleware.go:343-346`) exists to satisfy attribution — keep the route, and rewrite the
body to **add** LancarSec's identity while **preserving** upstream's. Add a `NOTICE` file naming
`github.com/41Baloo/balooProxy` as upstream. Do not remove upstream's copyright from anything.

## Conventions for this fork

- **`docs/AUDIT.md` is the work queue.** Before starting anything, check whether it is already a
  numbered finding there. Do not re-derive.
- **No new runtime dependency on GitHub or any Baloo-owned host.** Bundle data in `global/` and
  `//go:embed` it.
- **Hot path first, always.** This is a DDoS mitigation proxy: the metric that matters is per-request
  cost while under attack. Anything added to `core/server/middleware.go` needs a benchmark diff.
- **`realClientIP` will be the single source of truth for the subject IP** once wave 6 lands. Every
  ratelimit key, cache key, and log row uses its return value — never `RemoteAddr` directly, and never
  a raw header.
- **No `panic()` for ordinary errors.** 22 sites do this today, including the live reload path where a
  config typo kills a running proxy.
- **Cookie/header/path tokens are `lSec` / `LancarSec` / `_lancarsec`.** Never mix with `bProxy`.
- Don't reintroduce `io/ioutil`.

## Known traps

Not bugs to fix — things that will waste your time if you don't know them. The full list is in
`docs/ARCHITECTURE.md`.

- **`ReloadConfig` only adds domains.** A domain deleted from `config.json` keeps serving traffic to
  its old backend until the process restarts. It also resets every domain to Stage 1 with zeroed
  counters and indexes `domains.Domains[0]` unguarded (`core/server/monitor.go:530`).
- **`Serve()` reads `Proxy.Cloudflare` exactly once** at `core/server/serve.go:35`. The listener
  topology is frozen at that moment; `reload` updates the global but cannot rebind.
- **`config.Load()` is recursive.** With zero domains configured it calls `AddDomain()` then `Load()`
  again (`core/config/init.go:229-231`), re-running the GitHub fetch and the version check's
  10-second sleep from scratch.
- **`config.Load()` decodes from a nil `*os.File`** when `config.json` was missing
  (`core/config/init.go:27-36`). It only works because `(*os.File).Read` on a nil receiver returns
  `ErrInvalid` rather than panicking — and the decode error is discarded.
- **`crash.log` is opened twice**, and `log.SetOutput(io.Discard)` at `main.go:32` means recovered
  handler panics are invisible.
- **Five firewall DSL fields are registered but never supplied** (`core/firewall/filter.go`). Geo/ASN/body
  rules silently fail open, and negated ones match every request. Three README rule examples reference
  fields that don't exist — copying any of them panics the proxy at startup.
- **~79% of generated captchas are unsolvable by a human.** `core/utils/image.go:48-49` erases answer
  pixels that were never written into the mask.
- **There is no graceful shutdown.** No `signal.Notify`, no `Shutdown`, no context; `main()` blocks on
  a bare `select{}` and every listener error path panics.

## Toolchain

Local Go is `1.25.4`. Target `go 1.25` + an explicit `toolchain` directive in `go.mod`.

Dependency verdicts from the audit:

| Module | Verdict |
| --- | --- |
| `github.com/boltdb/bolt` | Archived 2017 and **never imported** — delete the require. |
| `github.com/inancgumus/screen` | 2019 pseudo-version, ~30 lines. Replace with a 6-line local `core/screen`. |
| `github.com/kor44/gofilter` | Untagged 2017 pseudo-version, personal repo, no `go.mod`. This is the firewall rule engine — **vendor it into `core/gofilter/` preserving its LICENSE.** |
| `github.com/shirou/gopsutil` | `v3.21.11+incompatible`, non-module. v4 has a proper module path. |
| `golang.org/x/*` | ~2 years stale; 45 module-level advisories including an `x/net` http2 infinite-loop DoS reachable from the transport. |
| `github.com/henomis/quickchart-go` | Replaceable with a direct `http.Post`. |

Build for deploy:

```bash
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o lancarsec .
```

## Re-running the audit

The workflow that produced `docs/AUDIT.md` and `docs/ARCHITECTURE.md` is worth re-running after
waves 7 and 10. Ask for it with the `ultracode` keyword; the script is saved at
`.claude/projects/G--LancarSec/<session>/workflows/scripts/lancarsec-audit-*.js`.
