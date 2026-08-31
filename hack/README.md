# hack/ — external load & memory-DoS harness

Go benchmarks measure functions. This directory measures the *process*: real
throughput through the real `:80` listener, p99 latency end-to-end, and — the
reason this harness exists — resident memory growth under an attack that keeps
minting new sliding-window map keys.

Everything here is a measurement tool. Nothing here is imported by the proxy,
and nothing here changes proxy behaviour. It is the tripwire waves 4–9 lean on:
run it before a wave and after, and the numbers move (or don't) exactly where
the wave claims.

## Contents

| File | What it is |
| --- | --- |
| `stuborigin/main.go` | A trivial HTTP origin that answers instantly from a fixed byte slice. Makes the measurement about LancarSec, not a backend. |
| `loadtest.sh` | Drives throughput/latency load and records req/s, p99 and peak RSS. Uses vegeta or hey. |
| `memgrowth.sh` | **The important one.** Sends a unique `Cf-Connecting-Ip` per request and records the RSS slope — the direct measure of the unbounded-map memory DoS. |
| `config.test.json` | A minimal LancarSec config that points at the stub origin and passes the loader's validation. |

## Prerequisites

- **Go** (to build the proxy and the stub origin).
- A load generator for the throughput script — **[vegeta]** (preferred) or
  **[hey]**:
  ```sh
  go install github.com/tsenart/vegeta/v12@latest   # preferred
  go install github.com/rakyll/hey@latest           # alternative
  ```
  On Windows, make sure `%USERPROFILE%\go\bin` is on `PATH` so Git Bash sees the
  binary. `memgrowth.sh` prefers vegeta but falls back to a built-in `curl` loop
  if neither is installed (lower request rate, still unique-per-request).
- The shell scripts are POSIX `sh` and run from **Git Bash on Windows** and from
  **Linux** unchanged. They detect the OS to read RSS the right way
  (`tasklist`/PowerShell on Windows, `/proc/<pid>/status` on Linux).

[vegeta]: https://github.com/tsenart/vegeta
[hey]: https://github.com/rakyll/hey

## config.test.json

A single domain `bench.local` proxying to the stub origin at `127.0.0.1:8080`,
in **Cloudflare / flexible** mode (listener is `:80` only, real client IP read
from `Cf-Connecting-Ip`). That mode is deliberate: it is production's mode, and
it is the mode where the memory DoS lives, because the map key comes straight
from an attacker-controlled header.

Three things are tuned for measurement, not for realism:

- **`trusted_proxies` contains loopback** (`127.0.0.1/32`, `::1/128`). From wave
  6 on, `Cf-Connecting-Ip` is only believed when the socket peer is inside the
  trusted set — that is the whole point of the wave. Both harnesses connect from
  loopback, so without those two entries every request would resolve to the same
  subject IP, `loadtest.sh -i` would become inert and `memgrowth.sh` would
  measure a flat line for the wrong reason. **Do not copy this into a real
  config**: trusting loopback is safe only because nothing remote can be a
  loopback peer. A production file lists Cloudflare's ranges (which
  `core/trusted` bundles) plus the operator's own balancers, and nothing else.
  `cloudflare_enforce_origin` stays `false` here for the same reason — with it
  on, the harness would still work from loopback, but any preflight from another
  host would collect 403s instead of measurements.

- **All four ratelimits are set to 1e9.** The harness must measure the proxy's
  work, not its refusal to work. With real limits, `loadtest.sh` (one fixed IP)
  would get `(R2)`-blocked in seconds. Do not copy these limits into a real
  config.
- **One firewall rule, `(http.path eq "/bench") -> action "0"`.** Action `0`
  means "whitelist / stage 0", so `/bench` is proxied straight through with no
  challenge. Without it, a fresh client hitting `/` gets a **302** stage-1
  cookie redirect and you'd be benchmarking the challenge path, not the proxy
  path. Both scripts preflight for this and abort with an explanation if they
  see a 302.

Every key the loader dereferences is present. Verified against
`core/config/init.go` and `core/domains/domain.go`:

- `proxy.secrets.cookie` / `.javascript` / `.captcha`, `proxy.adminsecret`,
  `proxy.apisecret` — all set and **none contain the substring `CHANGE_ME`**,
  which the loader panics on.
- `proxy.ratelimits.requests` / `.unknownFingerprint` / `.challengeFailures` /
  `.noRequestsSent`, `proxy.timeout.*`, `proxy.ratelimit_time`.
- Per domain: `name`, `backend`, `scheme`, and — because this is Cloudflare
  mode — empty `certificate`/`key` (cert loading is skipped when
  `proxy.cloudflare` is true, so no cert files need to exist).

**Booted for real?** Yes. The proxy was built and started with this config on
Windows; `GET /bench` with `Host: bench.local` returned **200** and the stub
origin's body, and the TUI showed the `bench.local` domain at stage 1. This is
not a config that only looks plausible — it runs.

> The proxy still makes two outbound `http.Get` calls at startup that this
> harness does not stub: three fingerprint-list fetches and one version check,
> all to `raw.githubusercontent.com` (see `core/config/init.go`). They need
> network egress the first time you boot. They are unrelated to what the harness
> measures, but if you run fully offline the loader will block/slow on them —
> that is upstream behaviour, not a harness bug, and is on the waves-4–9 list to
> bundle locally.

## Running it — the full sequence

From the repo root, in Git Bash (Windows) or a Linux shell.

### 1. Build

```sh
go build -o /tmp/stuborigin      ./hack/stuborigin      # .exe on Windows
go build -o /tmp/lancarsec       .                      # .exe on Windows
cp hack/config.test.json /tmp/config.json
```

LancarSec reads `config.json` from its **working directory**, so run it from
wherever you put that copy.

### 2. Start the stub origin

```sh
/tmp/stuborigin -listen 127.0.0.1:8080 -size 1024 &
```

`-size` is the response body in bytes. Sweep it (64, 1024, 65536) to find where
the proxy's copy path, rather than its decision path, dominates.

### 3. Start LancarSec against it

```sh
cd /tmp && ./lancarsec &      # reads /tmp/config.json
```

Give it a couple of seconds, then sanity-check the path the scripts will hit:

```sh
curl -s -o /dev/null -w '%{http_code}\n' \
  -H 'Host: bench.local' -H 'Cf-Connecting-Ip: 10.0.0.1' \
  http://127.0.0.1/bench            # expect: 200
```

### 4. Throughput / latency

```sh
hack/loadtest.sh -d 30 -c 50
```

Auto-detects vegeta or hey, auto-detects the LancarSec pid, samples its RSS
during the run, and appends a row to `./hack-results/loadtest.csv`. Force a
generator with `-g vegeta` / `-g hey`; pass the pid explicitly with `-p` if
auto-detect picks the wrong process.

### 5. Memory growth — the money shot

```sh
hack/memgrowth.sh -d 60 -r 5000 -c 50
```

Sends a distinct `Cf-Connecting-Ip` on every request for 60s and prints the RSS
slope in KiB/s, appending to `./hack-results/memgrowth.csv`. Raw per-second
samples land in `hack-results/memgrowth-<stamp>/rss.txt` — plot them if you want
the curve.

## What a good result looks like TODAY (the baseline)

Measured on this repo at wave 3, Windows, stub `-size 1024`, from a cold proxy
start. Absolute numbers are hardware-specific; the **shapes** are the contract.

### loadtest.sh — flat memory, that's correct

```
 throughput       ~3.8k req/s
 p99 latency      ~32 ms
 success          100.00%
 RSS start        ~26 MiB
 RSS peak         ~30 MiB     <- essentially flat
 RSS end          ~30 MiB
```

`loadtest.sh` hammers from **one** IP, so it creates one map entry and RSS
barely moves. Flat RSS here is the *expected, healthy* result — this script is
the throughput/latency baseline, not the memory test.

### memgrowth.sh — RSS climbs without bound, and that is the bug

30s at 5000 req/s, unique IP per request, one measured run:

```
 RSS start        ~16 MiB
 RSS peak         ~120 MiB
 RSS end          ~119 MiB
 net growth       ~103 MiB
 slope            ~2970 KiB/s      <- POSITIVE, roughly linear the whole run
```

Raw samples climb monotonically (`16572 → 30520 → 42200 → … → 122932 KiB`).
That climb **is** the vulnerability. In `core/server/middleware.go`, Cloudflare
mode does `ip = request.Header.Get("Cf-Connecting-Ip")` and then, on the hot
path, `firewall.WindowAccessIps[ts][ip]++`. Nothing caps the number of distinct
`ip` keys. Every new header value is a new map entry, and each 10-second window
bucket holds its keys until `evaluateRatelimit` sweeps buckets older than
`ratelimit_time` (120s by default). Point a botnet — or one attacker rotating a
header field that costs nothing to change — at it, and memory grows for as long
as the attack runs. There is no code path today that makes this slope flatten.

## What each wave should change about the numbers

| Wave | Expected effect on the harness |
| --- | --- |
| **4–5** | Behaviour-preserving refactors and the crypto/`StageToString` fixes. `memgrowth.sh` slope stays **positive** — none of these touch map cardinality. `loadtest.sh` throughput should not regress meaningfully. If wave 5's `Encrypt`/`EncryptSha` change adds work to the cache-miss path, a small p99 bump is acceptable; a large one is a finding. |
| **6** | First real cardinality control on the sliding-window maps (`MaxBucketKeys` / bucket cap). `memgrowth.sh` slope should **drop sharply** and RSS peak should stop tracking attack duration. This is the first wave where re-running `memgrowth.sh` unchanged produces a visibly different, flatter curve. |
| **7** | The `Middleware` rewrite. Re-run **both**: `loadtest.sh` throughput/p99 should be at least as good as the wave-3 baseline (the rewrite is meant to be faster, not slower), and `memgrowth.sh` slope should be **~0** — allocator noise only, indistinguishable from `loadtest.sh`'s flat line. A near-zero slope here is the proof the memory DoS is closed. |
| **8–9** | Whatever else changes behaviour. Treat any `memgrowth.sh` slope that creeps back above ~0, or any `loadtest.sh` throughput regression versus the last recorded CSV row, as a regression to explain before merging. |

The CSV files (`hack-results/loadtest.csv`, `hack-results/memgrowth.csv`) are
append-only run logs. Keep them across waves so a regression shows up as a row
that breaks the trend, not as a number nobody can compare against.

## Flags worth knowing

`loadtest.sh -h` and `memgrowth.sh -h` list everything. The ones you'll reach
for:

- `-d SECONDS` — attack duration.
- `-c N` — concurrent workers/connections.
- `-r RATE` — target req/s (`loadtest.sh`: vegeta only; `memgrowth.sh`: vegeta).
- `-p PID` — sample this exact process. On Windows this is the **Windows** pid
  from `tasklist`, not the MSYS job number Git Bash prints for `&`.
- `-g GENERATOR` — force `vegeta`/`hey` (loadtest) or `vegeta`/`curl` (memgrowth).
- `-u URL` / `-H HOST` — retarget if you change the domain in the config.
- `stuborigin -delay 5ms` — model a slow backend (leave at 0 for any real
  measurement); `-size N` — response body size; `-status N` — response code.
