// Package trustedips ships the trusted-proxy address lists as compiled-in data.
//
// It holds bytes and nothing else. All parsing, validation and lookup live in
// core/trusted, which imports this package; the split exists only because
// //go:embed cannot reach outside its own directory, so the data files and the
// directive that embeds them have to sit together.
//
// The package name deliberately differs from its directory. The directory is
// global/trusted to match global/fingerprints, but the identifier `trusted`
// belongs to core/trusted, the package operators and reviewers actually reason
// about.
//
// # Why embedded and never fetched
//
// Cloudflare publishes these ranges over HTTP, and it is tempting to refresh
// them at startup. Wave 4 removed the last startup network call for reasons
// that apply here with more force, because this list decides who is believed
// about client identity:
//
//   - A fetch can fail, and the failure has a direction. Fail-open (keep an
//     empty list and trust nobody) turns every visitor into their proxy's IP
//     and collapses the ratelimits; fail-closed on a stale list is fine but
//     needs a cache, which is just an embed with extra failure modes.
//   - A fetch makes an outside party able to change who this proxy trusts,
//     with no review in this repository, at a moment nobody here chose.
//   - A fetch makes two runs of the same binary enforce different policy.
//
// Embedding removes all three. The ranges a binary ships with are the ranges it
// enforces; refreshing them is a rebuild, which is the same review, rollout and
// rollback path as any other change to the proxy. The lists move roughly once a
// year, so this costs almost nothing.
//
// Refreshing is documented in README.md in this directory.
package trustedips

import _ "embed"

// The three lists are held as strings rather than []byte on purpose: strings
// are immutable, so these can be handed straight to a caller without the
// defensive copy that global/fingerprints has to make for its maps.

//go:embed cloudflare_ipv4.txt
var cloudflareIPv4 string

//go:embed cloudflare_ipv6.txt
var cloudflareIPv6 string

//go:embed extra.txt
var extra string

// CloudflareIPv4 returns the verbatim contents of cloudflare_ipv4.txt, one CIDR
// prefix per line, as published at https://www.cloudflare.com/ips-v4/.
func CloudflareIPv4() string { return cloudflareIPv4 }

// CloudflareIPv6 returns the verbatim contents of cloudflare_ipv6.txt, one CIDR
// prefix per line, as published at https://www.cloudflare.com/ips-v6/.
func CloudflareIPv6() string { return cloudflareIPv6 }

// Extra returns the contents of extra.txt, the site-local list. It is empty of
// entries by default and consists only of comments explaining the format; see
// the file itself.
func Extra() string { return extra }
