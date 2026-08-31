# global/trusted — bundled trusted-proxy ranges

Three text files plus the `trustedips` Go package that embeds them with `//go:embed`.
`core/trusted` parses them at process init and answers `IsTrusted(netip.Addr)` from the result.

| File | Entries | Source |
| --- | --- | --- |
| `cloudflare_ipv4.txt` | 15 | <https://www.cloudflare.com/ips-v4/> |
| `cloudflare_ipv6.txt` | 7 | <https://www.cloudflare.com/ips-v6/> |
| `extra.txt` | 0 | site-local, empty by default |

**Fetched 2026-08-31.** Both Cloudflare files are verbatim copies of the response body, one CIDR
per line, with a trailing newline added. Nothing else has been edited into them — keep it that
way, so a refresh is a plain overwrite and a `diff` against a fresh fetch is meaningful.

## What a line in here grants

A peer whose address falls in one of these ranges is believed when it says who the real client
is: `Cf-Connecting-Ip`, `X-Real-Ip`, `X-Forwarded-For`. That is the whole grant, and it is
enough to matter — a peer that can name the client can name a different one on every request,
which dodges every per-IP ratelimit and ban in the proxy, and can bind a challenge token to an
address that is not its own.

It grants nothing else. Every request, from a trusted peer or not, still runs the full firewall,
ratelimit, challenge and ban stack against whichever address it ends up with.

## Why embedded and not fetched at runtime

Cloudflare publishes these over HTTP and it is tempting to refresh them at startup. Wave 4
removed the last startup network call from this proxy, and the reasons apply here with more
force, because this particular list decides who is believed about identity:

1. **A fetch can fail, and the failure has a direction.** Failing open — an empty list, trusting
   nobody — turns every visitor into their proxy's IP and collapses the ratelimit buckets.
   Failing closed onto a stale copy is correct but needs a cache, which is an embed with extra
   failure modes. Neither is better than not fetching.
2. **A fetch hands an outside party a switch.** Whoever controls that endpoint would decide who
   this proxy trusts, with no review here, at a moment nobody here chose.
3. **A fetch makes two runs of the same binary enforce different policy**, which makes an
   incident unreproducible.

Embedding removes all three: the ranges a binary ships with are the ranges it enforces, and
refreshing them is a rebuild — the same review, rollout and rollback path as any other change.
The lists move roughly once a year, so this costs close to nothing.

`core/trusted` **panics at init** if a bundled file is unparseable, if either Cloudflare list is
empty, or if one holds the wrong address family (the two `curl` commands below, swapped). All
three are build defects that would otherwise produce a running proxy with a plausible-looking
but wrong allowlist.

## The empty set means trust nobody

`core/trusted.IsTrusted` returns false for every address until `Load` has run, and the bundled
ranges are deliberately **not** installed as a default. A security decision must not depend on
nobody having forgotten to wire the call.

The failure mode of that choice is loud rather than silent: behind Cloudflare, an unloaded set
makes every visitor read as one of ~20 Cloudflare addresses, so the shared ratelimit bucket
saturates within seconds and the operator finds out. The alternative — defaulting to open —
would accept forged identity from the internet while every dashboard looked healthy.

Loopback gets no special treatment either. If a local nginx, Caddy or HAProxy terminates TLS in
front of LancarSec, list `127.0.0.1/32` explicitly; see `extra.txt`.

## Refreshing the Cloudflare lists

```bash
curl -sSL https://www.cloudflare.com/ips-v4/ -o global/trusted/cloudflare_ipv4.txt
printf '\n' >> global/trusted/cloudflare_ipv4.txt
curl -sSL https://www.cloudflare.com/ips-v6/ -o global/trusted/cloudflare_ipv6.txt
printf '\n' >> global/trusted/cloudflare_ipv6.txt

go test ./core/trusted/...   # must stay green
```

(The `printf` is because Cloudflare serves the body without a trailing newline.)

Then update the fetch date at the top of this file, and rebuild. `TestLoadDefaultsToTheBundledRanges`
fails if a refresh returns fewer prefixes than the lists have ever published, which is what a
truncated download looks like.

The two `Test...CloudflareIPv{4,6}IsTrusted` tests name specific addresses inside specific
ranges. If a refresh legitimately drops one of those ranges they will fail — update the fixture,
and note that a range leaving the list means real edge servers stop being trusted, which is worth
knowing about deliberately rather than by surprise.

## Format

Applies to all three files, and to the entries in `config.json` that reach `Load` as `extra`:

- One entry per line; blank lines ignored.
- `#` starts a comment, on its own line or after an entry. **File syntax only** — a config entry
  is one value, not a line of a file, so `#` there is a parse error.
- An entry is a CIDR prefix (`203.0.113.0/24`, `2001:db8::/32`) or a bare address taken as a
  single host (`203.0.113.7` means `203.0.113.7/32`).
- Unmasked prefixes are masked on load: `203.0.113.7/24` is read as `203.0.113.0/24`.
- IPv4-mapped prefixes (`::ffff:198.51.100.0/120`) are rewritten to their IPv4 form, because
  lookups unmap first and the entry would otherwise be silently dead.

Rejected, loudly:

- `0.0.0.0/0` and `::/0`. A default route is not an allowlist; it is the absence of one, and it
  reinstates exactly the hole this directory exists to close.
- IPv6 zones (`fe80::1%eth0`). A zone names a local interface, not a peer.
- IPv4-mapped prefixes shorter than `/96`, which straddle real IPv6 space and the mapped IPv4
  range and have no unambiguous meaning.

## Lookup cost

`IsTrusted` is called once per request. It is allocation-free, and the prefixes are stored as
pre-masked integers rather than `netip.Prefix` so a lookup is an AND and a compare. Mean of 5
runs, AMD Ryzen 7 5700X, go1.25.14 windows/amd64, ns/op:

| | `netip.Prefix.Contains` | masked ints |
| --- | --- | --- |
| IPv4 hit, 2nd of 15 | 19.6 | 7.7 |
| IPv4 hit, 12th of 15 | 85.6 | 15.5 |
| IPv4 miss, all 15 tested | 114.6 | 18.7 |
| IPv6 hit, 2nd of 7 | 32.3 | 10.6 |
| IPv6 miss, all 7 tested | 72.5 | 14.4 |

The miss is what a direct-to-origin client costs, so it is the number to watch: 18.7 ns against
the 429 ns/op whole-middleware baseline is about 4% of a request. A linear scan is the right
shape here and the numbers say it stays so well past 22 prefixes — reproduce them with

```bash
go test -run=XXX -bench=. -benchmem -count=5 ./core/trusted/
```
