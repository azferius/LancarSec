# Stage-2 proof-of-work bundle

Compiled-in (`//go:embed`, see `pow.go`), served first-party from `/_bProxy/`.
This removes the last runtime dependency on third-party CDNs: the stage-2 page
previously loaded `cdn.jsdelivr.net/gh/41Baloo/balooPow@main` (mutable ref, no
SRI) and `cdnjs.cloudflare.com/.../crypto-js/4.0.0` on every challenge.

## Files

| File | Source | SHA-256 (as vendored) |
| --- | --- | --- |
| `balooPow.min.js` | `cdn.jsdelivr.net/gh/41Baloo/balooPow@main/balooPow.min.js`, fetched 2026-08-31 | `80137512f0c1b9c7de9443f070a25e17207812e3a4694deea30b563ec3a216aa` |
| `crypto-js.min.js` | `cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js`, fetched 2026-08-31 | `769a555de553babc35a3338f344dd7aa16260c93cea2c7db290707c90484e7cc` |

## The one-line patch

Upstream `balooPow.min.js` builds a Web Worker whose script imports crypto-js
from cdnjs — pinned to 4.0.0 (predates CVE-2023-46233, fixed in 4.2.0) and
still a third-party call at challenge time. Inside the vendored copy, exactly
one substring was rewritten (quotes are escaped in the source because the
worker script is a JS string literal):

- before: `importScripts('https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.0.0/crypto-js.min.js');`
- after:  `importScripts(self.location.origin+'/_bProxy/crypto-js.min.js');`

`self.location.origin` inside a blob worker is the origin of the creating
page, so the worker resolves the first-party path on whichever domain is being
challenged. SHA-256 before the patch:
`71273963e8355d9187de0d91f237e543b3bdb2cf9353d241f38e2ac9368e7073`.

The stage-2 page's own crypto-js `<script>` tag is kept (upstream order
preserved) but now also points at `/_bProxy/crypto-js.min.js`.

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
