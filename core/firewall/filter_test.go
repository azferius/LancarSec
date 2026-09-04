package firewall

import (
	"slices"
	"testing"

	"github.com/azferius/lancarsec/core/gofilter"
)

// TestFieldsIsTheDocumentedVocabulary pins the firewall DSL's vocabulary as a
// literal list, in BOTH directions.
//
// The other guards on this map iterate over it, so they can only catch a name
// that is registered and should not be. Removing a name they cannot see at all:
// the iteration simply gets shorter and every assertion still passes, while an
// operator's working rule stops compiling and the proxy refuses to start on a
// config that was valid yesterday.
//
// So the list below is written out. Changing the DSL means editing it, which is
// the point — the field names are a published interface (README documents each
// one) and a config.json in production is written against them.
func TestFieldsIsTheDocumentedVocabulary(t *testing.T) {
	want := []string{
		"http.cookie",
		"http.host",
		"http.method",
		"http.path",
		"http.query",
		"http.url",
		"http.user_agent",
		"http.version",
		"ip.bot",
		"ip.challenge_requests",
		"ip.engine",
		"ip.fingerprint",
		"ip.http_requests",
		"ip.src",
		"proxy.attack",
		"proxy.bypass_attack",
		"proxy.cloudflare",
		"proxy.rps",
		"proxy.rps_allowed",
		"proxy.stage",
		"proxy.stage_locked",
	}

	got := make([]string, 0, len(Fields))
	for name := range Fields {
		got = append(got, name)
	}
	slices.Sort(got)

	if !slices.Equal(got, want) {
		t.Errorf("the DSL vocabulary changed.\ngot:  %v\nwant: %v\n\nAdding a field: supply it in the middleware's gofilter.Message, document it in README.md, add a probe to TestMiddlewareEveryRegisteredRuleFieldIsSupplied, and add it here.\nRemoving one: every config.json using it stops loading, so say so in PROGRESS.md as a breaking change.", got, want)
	}
}

// Every field's registered TYPE matters as much as its name: it decides how the
// parser reads the operand, so changing one silently changes what an operator's
// existing rule means.
func TestFieldTypesAreStable(t *testing.T) {
	for name, kind := range Fields {
		var want gofilter.FieldType
		switch name {
		case "ip.src":
			want = gofilter.FT_IP
		case "ip.http_requests", "ip.challenge_requests", "proxy.stage", "proxy.rps", "proxy.rps_allowed":
			want = gofilter.FT_INT
		case "proxy.cloudflare", "proxy.stage_locked", "proxy.attack", "proxy.bypass_attack":
			want = gofilter.FT_BOOL
		default:
			want = gofilter.FT_STRING
		}
		if kind != want {
			t.Errorf("field %q is registered %v, want %v", name, kind, want)
		}
	}
}
