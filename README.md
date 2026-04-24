# LancarSec

LancarSec is a lightweight HTTP reverse-proxy with built-in DDoS mitigation, TLS fingerprinting, and a rule-based firewall engine. It is designed to sit in front of web backends and absorb bot/DDoS traffic before it reaches the origin.

## Features

### TLS Fingerprinting

LancarSec inspects the TLS ClientHello of every incoming connection and extracts a fingerprint. That fingerprint can be used to:

- Whitelist well-known clients (SEO crawlers, internal tools)
- Blacklist known-bad fingerprints (exploit scanners, headless browsers)
- Ratelimit unknown fingerprints that abuse proxy rotation
- Enrich logs with browser/tool identification

### Staged DDoS Mitigation

LancarSec ships with three stacked challenges. Under normal load the weakest (and most invisible) challenge is in effect; if attackers bypass it, LancarSec automatically escalates.

- **Cookie Challenge** — invisible, passed automatically by every standards-compliant HTTP client. Cheap first line of defense.
- **PoW JS Challenge** — a browser-solved proof of work based on the underlying PoW library. Typical solve times: difficulty 1 ≈ 0.21s, difficulty 5 ≈ 3.1s.
- **Custom Captcha** — image captcha used as a last resort or to protect especially sensitive paths.

### DDoS Alerts

Per-domain Discord webhook alerts fire when a bypassing attack starts and when it ends. Supports placeholders: `{{domain.name}}`, `{{attack.start}}`, `{{attack.end}}`, `{{proxy.cpu}}`, `{{proxy.ram}}`.

### Cloudflare Mode

LancarSec can run behind Cloudflare. In this mode `Cf-Connecting-Ip` is used for the real client IP (validated against the trusted proxy list) but features that require direct-to-client TLS — such as TLS fingerprinting — are disabled.

### Trusted Proxy Real-IP Resolution

When the peer socket matches one of the trusted CIDRs in `global/trusted/`, LancarSec honors `Cf-Connecting-Ip`, `X-Real-Ip`, or `X-Forwarded-For` to derive the real client IP. Requests that do not come from a trusted proxy use the socket address directly. This only affects **which IP rules are evaluated against** — it does not bypass any firewall, ratelimit, or challenge logic.

The shipped trusted list includes:

- `global/trusted/cloudflare_ipv4.txt` — Cloudflare IPv4 ranges
- `global/trusted/cloudflare_ipv6.txt` — Cloudflare IPv6 ranges
- `global/trusted/extra.txt` — additional CIDRs (e.g. `217.217.27.0/24`)

## Installation

### Server Setup

Grab the latest build or compile from source with Go 1.19+.

```
git clone <this repo>
cd lancarsec
go build -o main .
```

If you already have a `config.json`, place it next to the `main` binary. If not, start `./main` once and answer the prompts — it will write a starter `config.json` and then exit (Ctrl-C).

### Running as a Service

Either install it as a systemd unit or run it inside a `screen` session:

```
apt install screen
screen -S lancarsec
./main
# detach: Ctrl-a d
# reattach: screen -d -r
```

### Docker

```
docker build -t lancarsec .
docker run -d -p 80:80 -p 443:443 -t lancarsec
docker attach <container-id>    # detach with Ctrl-p Ctrl-q
```

### DNS Setup

Point an `A`/`AAAA` record for the protected domain at the LancarSec host.

- **With Cloudflare**: set Proxy status to `Proxied`, and set `cloudflare: true` in `config.json`.
- **Without Cloudflare**: set Proxy status to `DNS only` (if managed by Cloudflare at all), and leave `cloudflare: false`.

Make sure no DNS record points to the backend directly — otherwise attackers can bypass LancarSec.

A successful request will carry a `LancarSec-Proxy` response header.

## Configuration

`config.json` has three top-level fields: `proxy`, `domains`, and (per-domain) `firewallRules`.

### Proxy

| Field | Type | Notes |
| --- | --- | --- |
| `cloudflare` | bool | Run behind Cloudflare. TLS fingerprinting will be disabled; set Cloudflare's SSL mode to "Flexible". |
| `maxLogLength` | int | How many log entries to render in the terminal. |
| `secrets` | map | Must contain `cookie`, `javascript`, `captcha`. Generate strong random strings. |
| `ratelimits` | map | `requests`, `unknownFingerprint`, `challengeFailures`, `noRequestsSent` — all per-IP within the rolling window. |

### Domains

| Field | Type | Notes |
| --- | --- | --- |
| `name` | string | The hostname being proxied (e.g. `example.com`). |
| `scheme` | string | `http` or `https`. HTTP is faster and cheaper if the backend is co-located. |
| `backend` | string | Backend host, optionally `host:port`. |
| `certificate` / `key` | string | Paths to the TLS cert and key. Ignored in Cloudflare mode. |
| `webhook` | map | Discord webhook + per-state messages. |

Webhooks only fire when the stage is not manually locked, only when the first stage is bypassed, and when the attack ends.

## Terminal

### Main HUD

- `cpu` — CPU usage %
- `stage` — current mitigation stage
- `stage locked` — whether `stage` was pinned via command
- `total` / `bypassed` — incoming and forwarded r/s
- `connections` — open L4 connections
- `latest logs` — recent forwarded requests

### Commands

- `help` — list all commands
- `stage N` — pin stage to N; `stage 0` re-enables auto-stage
- `domain <name>` — switch terminal view to another domain (omit to list)
- `add` — interactively add a new domain
- `reload` — re-read `config.json` (also runs automatically every 5 hours)

## Custom Firewall Rules

LancarSec uses [gofilter](https://github.com/kor44/gofilter) to evaluate Wireshark-style filter expressions against each request.

### Fields

| Name | Type | Meaning |
| --- | --- | --- |
| `ip.src` | IP | Client IP |
| `ip.engine` | string | Detected browser (empty if unknown) |
| `ip.bot` | string | Known bot name (empty if not applicable) |
| `ip.fingerprint` | string | Raw TLS fingerprint |
| `ip.http_requests` | int | Forwarded HTTP requests in the current window |
| `ip.challenge_requests` | int | Challenge attempts in the current window |
| `http.host` | string | Request Host |
| `http.version` | string | `HTTP/1.1` or `HTTP/2` |
| `http.method` | string | Uppercase method |
| `http.query` | string | Raw query string |
| `http.path` | string | Request path |
| `http.user_agent` | string | **Lowercased** User-Agent |
| `http.cookie` | string | Raw Cookie header |
| `proxy.stage` | int | Current stage |
| `proxy.cloudflare` | bool | Whether Cloudflare mode is on |
| `proxy.stage_locked` | bool | Whether the stage is pinned |
| `proxy.attack` | bool | Under raw attack |
| `proxy.bypass_attack` | bool | Under bypassing attack |
| `proxy.rps` | int | Incoming r/s |
| `proxy.rps_allowed` | int | Forwarded r/s |

### Operators

- Comparison: `eq`/`==`, `ne`/`!=`, `gt`/`>`, `lt`/`<`, `ge`/`>=`, `le`/`<=`
- Logical: `and`/`&&`, `or`/`||`, `not`/`!`
- Matching: `contains`, `matches` (regex)

### Structure

```json
"firewallRules": [
    { "expression": "(http.path eq \"/captcha\")", "action": "3" },
    { "expression": "(http.path eq \"/curl\" and ip.bot eq \"Curl\")", "action": "0" }
]
```

Rules are evaluated top to bottom. Rules with a numeric `action` short-circuit; rules with a `+N` action just mutate `susLv` and let evaluation continue.

### Actions

`susLv` starts at the current stage and can be mutated by rules. Final value drives the response:

| `susLv` | Behavior |
| --- | --- |
| `0` | Allow — no challenge. |
| `1` | Cookie challenge. |
| `2` | JS PoW challenge. |
| `3` | Captcha. |
| `4+` | Block. |

Static actions (`"action": "3"`) pin `susLv` and stop evaluation. Additive actions (`"action": "+1"`) bump `susLv` and continue. Order rules with higher static actions first.

## API

TODO — the LancarSec API is being rebuilt. The documentation endpoint will live under `sec.splay.id` once available.

## License

LancarSec is distributed under the GNU General Public License, version 2. See `LICENSE`.
