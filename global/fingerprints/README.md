# global/fingerprints — bundled TLS-fingerprint tables

Three JSON documents plus the `fingerprints` Go package that embeds them with `//go:embed`.
`core/firewall` seeds `KnownFingerprints`, `BotFingerprints` and `ForbiddenFingerprints` from
here at process init.

| File | Entries | What a hit means |
| --- | --- | --- |
| `known_fingerprints.json` | 9 | Recognised human browser. Skips the unknown-fingerprint ratelimit. |
| `bot_fingerprints.json` | 16 | Recognised tool or crawler. Label only — does **not** block. |
| `malicious_fingerprints.json` | 8 | **Hard block.** The only table that denies a request outright. |

## Provenance

The data originates in `github.com/41Baloo/balooProxy` (GPL v2), at the fork point
`4d4f128`. It is third-party data, not original LancarSec work, and it is unsigned: treat any
refresh as a code change requiring review, because a wrong entry in
`malicious_fingerprints.json` blocks real traffic and a wrong entry in
`known_fingerprints.json` waves an attacker past a ratelimit.

## Why embedded and not fetched

Before wave 4 the tables were fetched at every startup with three `http.Get` calls against
`raw.githubusercontent.com/41Baloo/...`, and **all three call sites discarded the returned
error**. That gave the fork four problems at once:

1. **Remote control of the block list.** Whoever could write to that upstream repository could
   change what every LancarSec deployment blocks and allows, with no review here.
2. **Silent degradation.** A failed or truncated fetch left the small hardcoded fallback tables
   in `core/firewall/fingerprint.go` in place, with no log line. That is a fail-open in
   `ForbiddenFingerprints` (which had exactly one entry) and simultaneously a fail-closed in
   `KnownFingerprints` (every real browser reads as unknown and gets the stricter ratelimit).
3. **No offline boot.** An air-gapped or egress-filtered origin quietly ran with degraded
   classification.
4. **Non-determinism.** Two runs of the same binary could classify the same client differently.

Embedding removes all four. There is no fetch, so there is no fallback and nothing to fail open
to; the tables are a property of the binary. `fingerprints.go` validates each bundle at init and
**panics** if one is unparseable, empty, or contains an entry that could never match — loudly, at
startup, before any listener opens.

## Refreshing

Edit the JSON in place and rebuild. Keep these invariants, which `parse` enforces:

- Top-level value is a JSON object of string → string.
- No empty keys (an empty key is exactly what an all-GREASE ClientHello derives — the only
  fingerprint left empty since the wave 11 prep GREASE fix — so it would match one).
- No empty labels (firewall rules compare against the label).
- Every key ends in `,` — `firewall.Fingerprint` comma-terminates every element it emits, so a
  key without one is unreachable.

Keys must also match the string `firewall.Fingerprint` actually derives, which is *not* a
standard JA3/JA4: it skips RFC 8701 GREASE values (0x?a?a for ciphers and curves, 0x?a for point
formats) wherever they sit, emits every non-GREASE element of each list, and renders curves via
`tls.CurveID`'s `String()` hex (so X25519 is `0x583235353139`). Since the wave 11 prep GREASE fix
it no longer drops index 0 blindly, so a non-GREASE client keeps its first cipher and curve —
entries generated before that fix from non-GREASE clients (Firefox-family keys were regenerated;
Dalvik and the bot table were not) are missing those leading elements until a live-traffic
refresh. See the comments in `core/firewall/fingerprint_test.go` before hand-writing an entry.
