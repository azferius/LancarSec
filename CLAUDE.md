# LancarSec — Context for Claude

LancarSec is a fork/rebrand of the open-source **balooProxy** (`github.com/41Baloo/balooProxy`). It is a Go-based HTTP reverse-proxy with DDoS mitigation, TLS fingerprinting, and a Wireshark-style firewall DSL. The upstream project is GPL v2; LancarSec inherits that license.

This file exists so future sessions can pick up the work without re-deriving project history.

## Identity

- Product name: **LancarSec**
- Target deployment domain: **`sec.splay.id`** (and siblings like `9090.sec.splay.id`)
- Go module path: `lancarsec`
- Origin upstream: `41Baloo/balooProxy` (GPL v2). All visible branding was renamed; the `LICENSE` file itself is the standard GNU GPL v2 text and stays untouched.

## Layout

```
main.go                     entry point
core/
  api/                      JSON API (v1 legacy + v2 path-based)
  config/                   config.json loader (init.go) + interactive generator (generate.go) + structs
  domains/                  per-domain state, settings, TLS cert resolver
  firewall/                 gofilter rule eval, fingerprint maps, sliding-window counters
  pnc/                      panic handler + crash.log writer
  proxy/                    global runtime state (timeouts, OTP secrets, version const)
  server/                   HTTP entry (serve.go), request middleware (middleware.go), terminal UI (monitor.go)
  trusted/                  trusted-proxy CIDR loader + IsTrusted(ip)  ← LancarSec addition
  utils/                    color output, encryption, captcha image, Discord webhook, etc.
assets/
  html/                     login/captcha/error templates (mostly inlined in Go strings)
  server/                   dev self-signed cert+key
global/
  fingerprints/             TLS fingerprint JSON (known/bot/malicious) — read locally, never fetched
  proxy/version.json        placeholder for the future sec.splay.id version endpoint
  trusted/                  trusted-proxy CIDR text files (Cloudflare v4/v6 + extra)
examples/config.json        starter config (uses sec.splay.id-style domain names)
```

## Rebrand rules (what was changed from upstream)

| Upstream | LancarSec |
| --- | --- |
| Go module `goProxy` | `lancarsec` |
| Response header `baloo-Proxy: 1.5` | `LancarSec-Proxy: 1.0` |
| Cookie prefix `__bProxy_v` | `__lSec_v` |
| Path prefix `/_bProxy/` | `/_lancarsec/` |
| String literals `BalooProxy`, `balooProxy` | `LancarSec` |
| Fingerprints fetched from GitHub (`raw.githubusercontent.com/41Baloo/balooProxy/…`) | Read locally from `global/fingerprints/*.json` |
| Version check hitting GitHub | No-op stub with `// TODO` noting the future `sec.splay.id` endpoint |
| Credits endpoint mentioning BalooProxy | `"LancarSec; Lightweight http reverse-proxy. Protected by GNU GENERAL PUBLIC LICENSE Version 2, June 1991"` |

The one intentional remaining `Baloo` reference is the `BalooPow` proof-of-work JS library, loaded from `cdn.jsdelivr.net/gh/41Baloo/balooPow@main`. User directive: **do not self-host external JS libraries**. A `// TODO` comment in `core/server/middleware.go` flags this — remove once LancarSec publishes its own PoW bundle on `sec.splay.id`.

## SSL / TLS deployment modes

Three modes, selected by two booleans in `config.proxy`:

| `cloudflare` | `cloudflare_full_ssl` | Mode | Listeners | User cert required | Real IP source | TLS fingerprint |
| --- | --- | --- | --- | --- | --- | --- |
| `false` | — | Origin | `:80` (redirect) + `:443` HTTPS | yes | `RemoteAddr` | enabled |
| `true` | `false` | Flexible | `:80` HTTP | no | `Cf-Connecting-Ip` via trusted proxy | disabled (`"Cloudflare"` sentinel) |
| `true` | `true` | Full SSL | `:80` (redirect) + `:443` HTTPS | yes | `Cf-Connecting-Ip` via trusted proxy | disabled (CF terminates client TLS) |

`cloudflare_full_ssl: true` without `cloudflare: true` panics at startup — the combination is invalid.

Implementation is split into `server.serveOrigin`, `server.serveCloudflareFlexible`, and `server.serveCloudflareFullSSL` in `core/server/serve.go`. The common HTTPS + :80-redirect plumbing lives in `buildTLSServers`/`runPlusRedirect`. Cert loading in both `config/init.go` and `server/monitor.go#ReloadConfig` is gated on `!proxy.Cloudflare || proxy.CloudflareFullSSL`.

## Trusted-proxy real-IP resolution

`core/trusted` loads CIDRs from:

- `global/trusted/cloudflare_ipv4.txt` (from `https://www.cloudflare.com/ips-v4/`)
- `global/trusted/cloudflare_ipv6.txt` (from `https://www.cloudflare.com/ips-v6/`)
- `global/trusted/extra.txt` (currently `217.217.27.0/24`)

`server.Middleware` calls `realClientIP(r)` which only honors `Cf-Connecting-Ip` / `X-Real-Ip` / `X-Forwarded-For` when the socket peer matches a trusted CIDR. Otherwise it falls back to `RemoteAddr`. This is **only** used to identify the subject IP — it does not bypass firewall, ratelimit, or challenge logic. Every IP (real or peer) still runs the full stack.

To refresh the Cloudflare lists, re-run:

```
curl -sL https://www.cloudflare.com/ips-v4/ -o global/trusted/cloudflare_ipv4.txt
curl -sL https://www.cloudflare.com/ips-v6/ -o global/trusted/cloudflare_ipv6.txt
```

## Toolchain

- Go 1.26 (`go.mod` directive, Dockerfile base image, `.github/workflows/release.yml`).
- `io/ioutil` removed; replaced with `os.ReadFile` / `os.WriteFile`.
- `go vet ./...` and `go build ./...` both clean after the rebrand.
- Dependencies were refreshed with `go get -u ./... && go mod tidy`. Notable bumps: `golang.org/x/net v0.53.0`, `golang.org/x/crypto v0.50.0`, `golang.org/x/image v0.39.0`, `github.com/zeebo/blake3 v0.2.4`.

## External endpoints still contacted at runtime

- `quickchart.io` — generated attack graphs for Discord webhooks (via `github.com/henomis/quickchart-go`).
- Discord webhook URLs per domain — user-configured.
- `cdn.jsdelivr.net` + `cdnjs.cloudflare.com` — served to the **client's browser** as `<script src>` for the JS PoW challenge, not fetched by the proxy itself.

No GitHub runtime dependency remains — everything Baloo-specific is either bundled locally (fingerprints) or stubbed (version check).

## Security hardening layers (v2)

Hardening wave applied 2026-04-24. Every item below is intentional — don't revert without reviewing the attack it mitigates.

### Critical fixes
- **Ratelimit hot-path reads `Window*` directly** via `firewall.SumWindow(…)`. Old code read `AccessIps`/`AccessIpsCookie`/`UnkFps` which only refreshed every 5 s; an attacker could push unbounded traffic from a single IP in that gap. Now ratelimit decisions are instantaneous.
- **Window bucket cap** at `firewall.MaxBucketKeys = 200_000` (via `firewall.Incr`). High-cardinality attacks (IPv6 rotation, unique-per-request) can't OOM the proxy. Overflow keys are dropped from counting but still go through the rest of the stack.
- **Atomic `domains.CountersFor(name)`** replaces the per-request copy-modify-write of `DomainsData` under DataMu. Middleware now does `ctr.Total.Add(1)` — no lock, no struct copy. `checkAttack` reads back via `ctr.Total.Load()`.
- **`atomic.Pointer[Configuration]`** (`domains.LoadConfig`/`StoreConfig`) eliminates the nil-deref race where a reload blanked `domains.Config` mid-request.
- **`atomic.Pointer` for fingerprint tables** (`firewall.LookupKnown`/`LookupBot`/`LookupForbidden`). Reload swaps the published map instead of mutating it, so no data race on read.
- **TLS 1.2 minimum** (`MinVersion` in `tls.Config`) so attackers can't force a downgrade to 1.0/1.1.
- **10 MiB request body cap** via `http.MaxBytesReader` in middleware.
- **`CONNECT` rejected** at top of middleware so `httputil.ReverseProxy` can't be abused as an open tunnel.
- **Admin API secret moved from URL path to `Admin-Secret` header**. Old `/path/<secret>/api/v1` form could leak via access logs, `Referer`, CDN cache.
- **HTTP/2 limits** explicit: `MaxConcurrentStreams: 100`, `MaxReadFrameSize: 16 KiB` (rapid-reset hardening).

### Crypto hygiene
- `utils.Encrypt` now uses **keyed BLAKE3**, not `blake3(input+key)` concat. Eliminates the `Encrypt("ab","cdef") == Encrypt("abc","def")` ambiguity.
- `utils.EncryptSha` uses **HMAC-SHA256** instead of raw `sha256(input+key)`.
- `utils.RandomString` / `utils.RandomIntN` pull from **crypto/rand**. Captcha offsets, triangle placement, etc. are no longer precomputable from a deterministic math/rand seed.
- **OTP rotation is hourly, aligned** (`YYYY-MM-DD-HH`). The previous daily bucket forced a cliff at midnight; hourly rotation is smoother and keeps replay window shorter.

### Cookie / TLS fingerprint
- **Stage 1 cookie is `HttpOnly`** (`_1__lSec_v`). Stages 2/3 are set by client JS and can't be HttpOnly from JS by design.
- **`stripProxyCookies`** removes every `*__lSec_v` cookie from the request before forwarding upstream. Backend never sees the challenge token — XSS on the backend can't bleed it out.
- **Spec-compliant JA4** via `core/tlsparse` + a `peekListener` in origin mode that captures raw ClientHello bytes before the TLS stack consumes them. Extension list, signature algorithms, ALPN all parsed from the wire. `firewall.ComputeJA4Spec` byte-matches the FoxIO spec; `ComputeJA4Fallback` is the best-effort path for Full-SSL mode where we only see Cloudflare's handshake.
- **Legacy hex-list fingerprint GREASE-filtered by pattern**, not by dropping index 0. Firefox and other non-GREASE clients now get a correct fingerprint instead of losing a legit cipher.

### Cloudflare layered mode (primary deployment)
- `proxy.cloudflare_enforce_origin: true` — middleware rejects any request whose socket peer is not in the trusted-proxy CIDR list with 403. Attackers who discover the origin IP can't bypass Cloudflare. `realClientIP` already ignored headers from non-trusted peers; this adds a hard block.
- `Cf-Ja3-Hash` passthrough: when Cloudflare forwards a JA3 hash header (Enterprise TLS fingerprinting add-on), LancarSec exposes it as `ip.ja4 = "cf:<hash>"` in firewall rules.
- WebSocket upgrades are forced to at least Stage 2 (JS PoW) so a long-lived socket isn't granted by a cookie-level check.

### Challenge UI/UX (v2)
- Stage 2 HTML now rendered by `server.renderJSChallenge(…)`, Stage 3 by `renderCaptchaChallenge(…)`. Inline CSS, modern dark card, indeterminate progress bar, watermark `Security by LancarSec` in the footer. Security headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`) set on both.

### Robustness
- Bounded webhook worker pool (`utils.EnqueueWebhook`, 4 workers, 256-deep queue, 5 s HTTP timeout). `SendWebhook` still works as a compat shim.
- Captcha cache has real TTL (`firewall.CaptchaCacheTTL = 2 min`, `sweepCaptchaCache` in the periodic job). Replaced the old CPU/mem-gated bulk eviction which could leak under slow-drip attacks.
- `RequestLogger` capped at 600 entries (10 min @ 1 s), dropping the oldest half in one shot to avoid realloc churn.

### Operational polish
- `hide_version_header: true` in `config.json` suppresses the `LancarSec-Proxy: 1.0` response header.
- Double SIGTERM during shutdown forces an immediate `os.Exit(1)` instead of hanging on a stuck connection.

## Concurrency model

`firewall` used to guard every shared map with one `Mutex`. That's been split:

- `firewall.DataMu` (RWMutex) — guards `domains.DomainsData` (hot on every request).
- `firewall.CountersMu` (RWMutex) — guards the sliding-window ratelimit maps (`AccessIps`, `AccessIpsCookie`, `UnkFps`, `Window*`).
- `firewall.Connections` / `firewall.JA4s` — `sync.Map` (write on TLS handshake, read every request, no external lock).
- `firewall.CacheIps` / `firewall.CacheImgs` — `sync.Map` (challenge caches).

Middleware hot path takes CountersMu and DataMu separately (not one big lock). `firewall.Mutex` no longer exists; any new code should pick the right lock by what it touches.

## Fingerprints

Two identifiers are recorded per TLS connection:

- Legacy ballistic string (`firewall.Connections`) — used to look up `KnownFingerprints`, `BotFingerprints`, `ForbiddenFingerprints` in `global/fingerprints/*.json`.
- **JA4 TLS** (`firewall.JA4s`, computed in `core/firewall/ja4.go`) — best-effort, since Go's `tls.ClientHelloInfo` doesn't expose the raw extension list. The cipher-suite hash is spec-accurate; the extension/sig-alg hash synthesizes extensions from the parsed fields we do have (`0`, `10`, `11`, `13`, `16`, `43`). Good enough to tell Chrome from Firefox from Python-requests from curl, but will not byte-match an external JA4 calculator. Exposed to firewall rules as `ip.ja4` and to backends as the `proxy-tls-ja4` header.

Full spec-accurate JA4 needs raw ClientHello parsing (see Foxio's reference). That's deferred.

## Graceful shutdown

`main.go` listens for SIGINT/SIGTERM and calls `server.Shutdown(ctx)` with a 15 s deadline. `server.Serve` stashes the `*http.Server` instances in package-level vars; `ListenAndServe*` treats `http.ErrServerClosed` as a clean exit instead of panicking.

## Transport package

`core/transport` owns the `RoundTripper` and a per-domain `*http.Transport` registry. `transport.Register(domain, Config{...})` is called from `config.buildDomain` for every domain, so `BackendTLSVerify`, `MaxIdleConns`, `MaxConnsPerHost` are honored per-domain. The old single shared `defaultTransport` in `core/server` is gone.

## Conventions to preserve in future edits

- Don't reintroduce `ioutil`.
- Don't add runtime `http.Get` calls to GitHub — bundle data in `global/` instead.
- Cookie/header/path tokens use `lSec` / `LancarSec` / `_lancarsec` consistently. Don't mix with `bProxy`.
- When touching middleware, remember `realClientIP` is the single source of truth for the subject IP. All ratelimits, cache keys, and log rows use its return value.
- The `/_lancarsec/credits` endpoint still exists because GPL v2 wants a visible attribution. Keep it rebranded but present.
