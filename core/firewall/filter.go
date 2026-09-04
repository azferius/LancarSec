package firewall

import "github.com/azferius/lancarsec/core/gofilter"

// Fields is the firewall DSL's vocabulary: every name an operator may write in
// a rule expression, and its type. It is the SINGLE SOURCE OF TRUTH - init
// registers exactly these with gofilter, and TestRuleFieldsAreAllSupplied
// drives a real request through Middleware for each one to prove the request
// path actually populates it.
//
// WAVE 13: five names were removed from this list - ip.country, ip.asn,
// ip.requests, http.headers and http.body. They were registered but never
// written into the gofilter.Message the middleware builds, and gofilter
// returns false for a missing key, so a rule naming one of them compiled
// cleanly, appeared in GET_FIREWALL_RULES, and silently never matched. The
// negated form was worse: `ip.country ne "ID"` with action 0 - the natural way
// to write "only allow Indonesia" - matched every request on earth and
// whitelisted the entire internet past stages 1-3.
//
// An unregistered name is refused by the parser at config load, naming the
// field, so those rules now fail loudly at the only moment an operator can act
// on them instead of quietly doing nothing in production.
//
// What it would take to bring each one back, since removal is not the same as
// "impossible":
//
//   - ip.country / ip.asn need a GeoIP or ASN source. That is a data
//     dependency and a licence question, not a code change.
//   - http.body requires buffering the request body before it is proxied.
//     Gate it behind a per-domain flag with a size cap, or it is a memory
//     amplifier on exactly the traffic it is meant to inspect.
//   - http.headers is cheap but has no obvious rendering: gofilter has no map
//     type, so it would have to be one flattened string, and the flattening
//     format becomes part of the operator's rule syntax forever. Pick it
//     deliberately, with tests, rather than inherit upstream's stub.
//
// ponytail: removed rather than stubbed. A field that parses and never matches
// is worse than one that does not exist, because the operator believes it.
var Fields = map[string]gofilter.FieldType{
	"ip.src":                gofilter.FT_IP,
	"ip.engine":             gofilter.FT_STRING,
	"ip.bot":                gofilter.FT_STRING,
	"ip.fingerprint":        gofilter.FT_STRING,
	"ip.http_requests":      gofilter.FT_INT,
	"ip.challenge_requests": gofilter.FT_INT,

	"http.host":       gofilter.FT_STRING,
	"http.version":    gofilter.FT_STRING,
	"http.method":     gofilter.FT_STRING,
	"http.url":        gofilter.FT_STRING,
	"http.query":      gofilter.FT_STRING,
	"http.path":       gofilter.FT_STRING,
	"http.user_agent": gofilter.FT_STRING,
	"http.cookie":     gofilter.FT_STRING,

	"proxy.stage":         gofilter.FT_INT,
	"proxy.cloudflare":    gofilter.FT_BOOL,
	"proxy.stage_locked":  gofilter.FT_BOOL,
	"proxy.attack":        gofilter.FT_BOOL,
	"proxy.bypass_attack": gofilter.FT_BOOL,
	"proxy.rps":           gofilter.FT_INT,
	"proxy.rps_allowed":   gofilter.FT_INT,
}

func init() {
	for name, kind := range Fields {
		gofilter.RegisterField(name, kind)
	}
}
