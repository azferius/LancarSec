package config

// The trusted-proxy set: where the pipeline hands off to core/trusted.
//
// ---------------------------------------------------------------------------
// INTEGRATION POINT - READ THIS BEFORE MERGING WAVE 6
// ---------------------------------------------------------------------------
//
// core/trusted is built by a different agent in the same wave and does not
// exist in this worktree. `go build ./...` here is green because loadTrusted
// is a variable holding a placeholder rather than a direct call to a package
// that is not on disk yet.
//
// Wiring it up when the two branches meet is exactly two lines:
//
//	import "github.com/azferius/lancarsec/core/trusted"
//
//	var loadTrusted = trusted.Load
//
// and deleting trustedLoadUnwired below. The signature is the shared contract
// for this wave and matches it exactly:
//
//	func Load(extra []string) (int, error)
//
// If that has not happened, the proxy honours NO forwarded client-IP headers
// from anyone, because the trusted set is empty. That is fail-closed for
// header trust - a spoofed Cf-Connecting-Ip is ignored rather than believed -
// but it is also a live misconfiguration in Cloudflare mode: every client
// behind Cloudflare is attributed to Cloudflare's own address, so they share a
// ratelimit bucket and a challenge token. And with cloudflare_enforce_origin
// on, an empty trusted set rejects every request. Do not ship the placeholder.
//
// ---------------------------------------------------------------------------

// loadTrusted installs the trusted-proxy set. It is called from publish, once,
// with the operator-supplied CIDR list; core/trusted merges the bundled
// Cloudflare ranges itself and returns the total prefix count.
//
// It is a variable for two reasons: the placeholder above, and so the pipeline
// tests can count calls and prove that a configuration refused by validate
// never reaches the install. Production never reassigns it.
var loadTrusted = trustedLoadUnwired

// trustedLoadUnwired is the placeholder. It installs nothing and reports zero
// prefixes; it deliberately does not re-parse the list, because validate has
// already done that and a second parser here would be the second code path
// this pipeline exists to prevent.
func trustedLoadUnwired(extra []string) (int, error) {
	_ = extra
	return 0, nil
}
