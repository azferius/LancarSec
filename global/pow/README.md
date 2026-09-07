# Stage-2 proof-of-work bundle

Compiled-in (`//go:embed`, see `pow.go`), served first-party from `/_lancarsec/`.
This removes the last runtime dependency on third-party CDNs: the stage-2 page
previously loaded `cdn.jsdelivr.net/gh/41Baloo/balooPow@main` (mutable ref, no
SRI) and `cdnjs.cloudflare.com/.../crypto-js/4.0.0` on every challenge.

## Files

| File | Source | SHA-256 (as vendored) |
| --- | --- | --- |
| `pow.min.js` | `cdn.jsdelivr.net/gh/41Baloo/balooPow@main/balooPow.min.js`, fetched 2026-08-31 | `f89b9368804bda853f5f40c0b7bcd774cd6c4fdb389a865e23b4966d1fa53f1a` |
| `crypto-js.min.js` | `cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js`, fetched 2026-08-31 | `769a555de553babc35a3338f344dd7aa16260c93cea2c7db290707c90484e7cc` |

## The one-line patch

Upstream `balooPow.min.js` builds a Web Worker whose script imports crypto-js
from cdnjs — pinned to 4.0.0 (predates CVE-2023-46233, fixed in 4.2.0) and
still a third-party call at challenge time. Inside the vendored copy, exactly
one substring was rewritten (quotes are escaped in the source because the
worker script is a JS string literal):

- before: `importScripts('https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.0.0/crypto-js.min.js');`
- after:  `importScripts(self.location.origin+'/_lancarsec/crypto-js.min.js');`

`self.location.origin` inside a blob worker is the origin of the creating
page, so the worker resolves the first-party path on whichever domain is being
challenged. SHA-256 before the patch:
`71273963e8355d9187de0d91f237e543b3bdb2cf9353d241f38e2ac9368e7073`.

The stage-2 page's own crypto-js `<script>` tag is kept (upstream order
preserved) but now also points at `/_lancarsec/crypto-js.min.js`.

**2026-09-07:** the wave-10 rebrand renamed the served route to `/_lancarsec/`
but missed this string, which lives inside a minified JS string literal and so
matched no `.go` grep. The worker therefore imported a path nothing served:
`importScripts` threw, every worker resolved with no solution, and stage 2 was
unsolvable for every challenged visitor from the wave-10 cutover until this
fix. `TestPowAssetsReferenceOnlyServedPaths` now fails if any embedded asset
names a path the middleware does not route.

## Licenses

- `crypto-js.LICENSE` — MIT (brix/crypto-js 4.2.0), shipped alongside.
- `balooPow` has no LICENSE file upstream (404 at `@main/LICENSE`). It is
  distributed as part of the balooProxy GPL v2 work this fork derives from;
  the wave-10 `NOTICE` pass names `41Baloo/balooProxy` as upstream. Do not
  strip this attribution.

## Refreshing

Re-fetch both files from the pinned sources, re-apply the one-line patch, and
update the hashes in this table. Refreshing is a rebuild — the same review and
rollback path as any other change to the proxy.
