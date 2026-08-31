// Package pow ships the stage-2 proof-of-work scripts as compiled-in data.
//
// The stage-2 page used to load balooPow from jsDelivr and crypto-js 4.0.0
// from cdnjs — a mutable ref with no SRI, so the repo owner, jsDelivr or
// cdnjs could neuter or mutate the challenge for every challenged visitor
// mid-attack, and the client's IP leaked to two third parties on every
// challenge. They are now embedded and served first-party from /_bProxy/
// (see core/server/middleware.go).
//
// The worker inside balooPow imported crypto-js 4.0.0 from cdnjs itself;
// that import was rewritten to the first-party path, which is also the
// crypto-js 4.2.0 upgrade (CVE-2023-46233, fixed in 4.2.0). The exact
// one-line diff and both SHA-256 sums are recorded in README.md.
package pow

import _ "embed"

//go:embed balooPow.min.js
var BalooPow []byte

//go:embed crypto-js.min.js
var CryptoJS []byte
