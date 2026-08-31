package config

// Wave 6 configuration surface: trusted proxies, cloudflare_enforce_origin and
// the request body ceiling.
//
// New surface, not a pinned bug — nothing here flips a wave-6 assertion,
// because the defects wave 6 fixes live in core/server. What this file pins is
// the pipeline's half of the contract, and the three options it added:
//
//   - proxy.trusted_proxies decides whose Cf-Connecting-Ip / X-Real-Ip /
//     X-Forwarded-For is believed. Before wave 6 the answer was "everybody's",
//     which is the R1/R2 ratelimit bypass, the mirror-DoS that blocks a victim
//     by sending traffic tagged with their address, and the botnet-portable
//     challenge token.
//   - proxy.cloudflare_enforce_origin rejects a peer outside that set, so an
//     attacker who has found the origin address cannot talk to it at all.
//   - proxy.max_body_size / domains[].maxBodySize cap a relayed request body.
//
// The pipeline's job for all three is identical and is what these tests are
// really about: a bad value is refused BEFORE anything is published, so a
// reload with a typo leaves the running proxy exactly as it was.

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/azferius/lancarsec/core/domains"
	"github.com/azferius/lancarsec/core/proxy"
)

// ---------------------------------------------------------------------------
// normalise
// ---------------------------------------------------------------------------

func TestNormaliseTrustedProxies(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil stays nil", nil, nil},
		{"whitespace is trimmed", []string{"  10.0.0.0/8\t"}, []string{"10.0.0.0/8"}},
		{"empty entries are dropped", []string{"", "   ", "10.0.0.0/8"}, []string{"10.0.0.0/8"}},
		// An operator naming their own jump host writes an address, not a /32.
		{"a bare v4 address becomes its /32", []string{"217.217.27.27"}, []string{"217.217.27.27/32"}},
		{"a bare v6 address becomes its /128", []string{"2001:db8::1"}, []string{"2001:db8::1/128"}},
		// Masking is what makes the dedupe below collapse anything at all:
		// 10.1.2.3/8 and 10.0.0.0/8 select exactly the same set of peers.
		{"prefixes are masked", []string{"10.1.2.3/8"}, []string{"10.0.0.0/8"}},
		{"duplicates collapse", []string{"10.1.2.3/8", "10.0.0.0/8", "10.255.0.0/8"}, []string{"10.0.0.0/8"}},
		// An unparseable entry survives verbatim so validate can name back
		// exactly what the operator wrote.
		{"garbage is preserved for the error message", []string{" not-a-cidr "}, []string{"not-a-cidr"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &domains.Configuration{Proxy: domains.Proxy{TrustedProxies: tc.in}}

			normalise(cfg)
			if !reflect.DeepEqual(cfg.Proxy.TrustedProxies, tc.want) {
				t.Fatalf("TrustedProxies = %#v, want %#v", cfg.Proxy.TrustedProxies, tc.want)
			}

			// normalise's contract: running it twice changes nothing.
			normalise(cfg)
			if !reflect.DeepEqual(cfg.Proxy.TrustedProxies, tc.want) {
				t.Fatalf("normalise is not idempotent: %#v, want %#v", cfg.Proxy.TrustedProxies, tc.want)
			}
		})
	}
}

func TestNormaliseWave6Defaults(t *testing.T) {
	cfg := &domains.Configuration{
		Domains: []domains.Domain{
			{Name: "inherits", Backend: "127.0.0.1:9"},
			{Name: "overrides", Backend: "127.0.0.1:9", MaxBodySize: 1024},
			{Name: "unlimited", Backend: "127.0.0.1:9", MaxBodySize: unlimitedBodySize},
		},
	}

	normalise(cfg)

	// The flag that locks an operator out of their own origin if it is ever
	// defaulted on. If a later wave flips this assertion, read the field
	// comment in core/domains first — false is not an oversight.
	if cfg.Proxy.CloudflareEnforceOrigin {
		t.Error("cloudflare_enforce_origin defaulted to true; it must default to false")
	}

	if cfg.Proxy.MaxBodySize != defaultMaxBodySize {
		t.Errorf("proxy MaxBodySize = %d, want the %d default", cfg.Proxy.MaxBodySize, defaultMaxBodySize)
	}

	// An absent per-domain key inherits, a configured one survives, and the
	// unlimited sentinel is not mistaken for "unset".
	if cfg.Domains[0].MaxBodySize != defaultMaxBodySize {
		t.Errorf("inherits: MaxBodySize = %d, want %d", cfg.Domains[0].MaxBodySize, defaultMaxBodySize)
	}
	if cfg.Domains[1].MaxBodySize != 1024 {
		t.Errorf("overrides: MaxBodySize = %d, want the configured 1024", cfg.Domains[1].MaxBodySize)
	}
	if cfg.Domains[2].MaxBodySize != unlimitedBodySize {
		t.Errorf("unlimited: MaxBodySize = %d, want the %d sentinel", cfg.Domains[2].MaxBodySize, unlimitedBodySize)
	}

	// A proxy-wide override is what a domain with no key of its own inherits.
	other := &domains.Configuration{
		Proxy:   domains.Proxy{MaxBodySize: 4096},
		Domains: []domains.Domain{{Name: "inherits", Backend: "127.0.0.1:9"}},
	}
	normalise(other)
	if other.Domains[0].MaxBodySize != 4096 {
		t.Errorf("MaxBodySize = %d, want the proxy-wide 4096", other.Domains[0].MaxBodySize)
	}

	before := cfg.Domains[0].MaxBodySize
	normalise(cfg)
	if cfg.Domains[0].MaxBodySize != before {
		t.Error("normalise is not idempotent for MaxBodySize")
	}
}

// ---------------------------------------------------------------------------
// validate
// ---------------------------------------------------------------------------

func TestValidateAcceptsATrustedProxyList(t *testing.T) {
	cfg := cfgFixture("example.com")
	cfg.Proxy.CloudflareEnforceOrigin = true
	cfg.Proxy.TrustedProxies = []string{
		"173.245.48.0/20",
		"2400:cb00::/32",
		"127.0.0.1",
		"  10.1.2.3/8  ",
	}

	normalise(cfg)
	if err := validate(cfg); err != nil {
		t.Fatalf("validate rejected a good trusted-proxy list: %v", err)
	}

	want := []string{"173.245.48.0/20", "2400:cb00::/32", "127.0.0.1/32", "10.0.0.0/8"}
	if !reflect.DeepEqual(cfg.Proxy.TrustedProxies, want) {
		t.Errorf("TrustedProxies = %#v, want %#v", cfg.Proxy.TrustedProxies, want)
	}
}

func TestValidateRejectsABadTrustedProxyEntry(t *testing.T) {
	cases := []struct {
		name  string
		entry string
	}{
		{"not an address at all", "not-a-cidr"},
		{"prefix length out of range", "10.0.0.0/33"},
		{"v6 prefix length out of range", "2001:db8::/129"},
		{"a hostname", "proxy.example.com/24"},
		{"a range, which netip does not parse", "10.0.0.1-10.0.0.9"},
		{"a negative prefix length", "2001:db8::/-1"},
		// A zone-scoped address is meaningless for a peer check and netip
		// refuses it in a prefix, so it must not slip through as a bare addr.
		{"a zoned v6 address", "fe80::1%eth0"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cfgFixture("example.com")
			cfg.Proxy.TrustedProxies = []string{"10.0.0.0/8", tc.entry}

			normalise(cfg)
			err := validate(cfg)
			if err == nil {
				t.Fatalf("validate accepted trusted_proxies entry %q", tc.entry)
			}
			// Naming the offending string is the whole point: an operator with
			// forty CIDRs has to be told which one of them is wrong.
			if !strings.Contains(err.Error(), tc.entry) {
				t.Errorf("error %q does not name the offending entry %q", err, tc.entry)
			}
		})
	}
}

func TestValidateRejectsABadBodySize(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(cfg *domains.Configuration)
		want   string
	}{
		{"proxy-wide", func(c *domains.Configuration) { c.Proxy.MaxBodySize = -2 }, "max_body_size"},
		{"per-domain", func(c *domains.Configuration) { c.Domains[0].MaxBodySize = -1000 }, "maxBodySize"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cfgFixture("example.com")
			tc.mutate(cfg)
			normalise(cfg)

			err := validate(cfg)
			if err == nil {
				t.Fatal("validate accepted a body size below the unlimited sentinel")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name the %s key", err, tc.want)
			}
		})
	}

	// -1 is a legitimate opt-out, not a typo: an upload endpoint needs it.
	cfg := cfgFixture("example.com")
	cfg.Proxy.MaxBodySize = unlimitedBodySize
	cfg.Domains[0].MaxBodySize = unlimitedBodySize
	normalise(cfg)
	if err := validate(cfg); err != nil {
		t.Fatalf("validate rejected the unlimited sentinel: %v", err)
	}
}

// ---------------------------------------------------------------------------
// build and publish
// ---------------------------------------------------------------------------

func TestBuildCarriesTheResolvedBodySize(t *testing.T) {
	cfgIsolate(t)
	cfgSpyTrusted(t)

	cfg := cfgFixture("inherits.example", "unlimited.example")
	cfg.Proxy.MaxBodySize = 2048
	cfg.Domains[1].MaxBodySize = unlimitedBodySize

	cfgPublish(t, cfg, modeStartup)

	// The request path reads DomainSettings, so the number has to arrive there
	// already resolved: a zero would read as "no limit" in http.MaxBytesReader.
	if got := cfgSettings(t, "inherits.example").MaxBodySize; got != 2048 {
		t.Errorf("inherits.example MaxBodySize = %d, want the proxy-wide 2048", got)
	}
	if got := cfgSettings(t, "unlimited.example").MaxBodySize; got != unlimitedBodySize {
		t.Errorf("unlimited.example MaxBodySize = %d, want %d", got, unlimitedBodySize)
	}
}

func TestPublishInstallsTheTrustedSetAndTheFlags(t *testing.T) {
	cfgIsolate(t)
	calls := cfgSpyTrusted(t)

	cfg := cfgFixture("example.com")
	cfg.Proxy.CloudflareEnforceOrigin = true
	cfg.Proxy.MaxBodySize = 4096
	cfg.Proxy.TrustedProxies = []string{"173.245.48.0/20", "127.0.0.1"}

	cfgPublish(t, cfg, modeStartup)

	if len(*calls) != 1 {
		t.Fatalf("loadTrusted was called %d times, want exactly one install per publish", len(*calls))
	}
	// publish must hand over the NORMALISED list, not the raw one, so
	// core/trusted parses exactly the strings validate approved.
	want := []string{"173.245.48.0/20", "127.0.0.1/32"}
	if !reflect.DeepEqual((*calls)[0], want) {
		t.Errorf("loadTrusted got %#v, want %#v", (*calls)[0], want)
	}

	if !proxy.CloudflareEnforceOrigin {
		t.Error("proxy.CloudflareEnforceOrigin was not published")
	}
	if proxy.MaxBodySize != 4096 {
		t.Errorf("proxy.MaxBodySize = %d, want 4096", proxy.MaxBodySize)
	}
}

// The invariant that decides where trusted.Load runs.
//
// A reload whose CIDR list is broken must be refused by validate, so the
// previously published configuration AND the previously installed trusted set
// both keep running. If the install happened in build — or anywhere before
// validate — one typo would swap the trusted set out from under a
// configuration that was then rejected, and every per-IP decision the proxy
// makes would be made against a set no configuration ever asked for. In
// Cloudflare mode with enforcement on, that is a total outage; with
// enforcement off, it is silently believing or disbelieving the wrong peers.
func TestReloadWithABrokenTrustedListKeepsTheRunningConfiguration(t *testing.T) {
	cfgIsolate(t)
	calls := cfgSpyTrusted(t)

	good := cfgFixture("a.example", "b.example")
	good.Proxy.TrustedProxies = []string{"173.245.48.0/20"}
	good.Proxy.MaxBodySize = 4096
	cfgWrite(t, good)
	if err := Reload(); err != nil {
		t.Fatalf("first Reload: %v", err)
	}

	if len(*calls) != 1 {
		t.Fatalf("loadTrusted was called %d times after the first reload, want 1", len(*calls))
	}
	published := domains.Config
	wantDomains := append([]string(nil), domains.Domains...)
	wantData := domains.DomainsData["a.example"]
	wantSettings := cfgSettings(t, "a.example")

	broken := cfgFixture("a.example", "b.example")
	broken.Proxy.TrustedProxies = []string{"173.245.48.0/20", "10.0.0.0/33"}
	broken.Proxy.MaxBodySize = 65536
	broken.Domains[0].Backend = "127.0.0.1:19"
	cfgWrite(t, broken)

	err := Reload()
	if err == nil {
		t.Fatal("Reload accepted a config.json with an unparseable trusted_proxies entry")
	}
	if !strings.Contains(err.Error(), "10.0.0.0/33") {
		t.Errorf("error %q does not name the offending entry", err)
	}

	// Nothing was installed, and nothing else was republished either.
	if len(*calls) != 1 {
		t.Errorf("loadTrusted was called %d times, want 1 — the refused reload installed a trusted set", len(*calls))
	}
	if domains.Config != published {
		t.Error("domains.Config was replaced by a refused reload")
	}
	if proxy.MaxBodySize != 4096 {
		t.Errorf("proxy.MaxBodySize = %d, want the previous 4096", proxy.MaxBodySize)
	}
	if !reflect.DeepEqual(domains.Domains, wantDomains) {
		t.Errorf("domains.Domains = %v, want %v", domains.Domains, wantDomains)
	}
	if !reflect.DeepEqual(domains.DomainsData["a.example"], wantData) {
		t.Error("a refused reload rewrote DomainsData")
	}
	if got := cfgSettings(t, "a.example"); got.DomainProxy != wantSettings.DomainProxy {
		t.Error("a refused reload republished DomainSettings, so the backend moved")
	}

	// And the proxy is still reloadable: the refusal left no wedged state.
	cfgWrite(t, good)
	if err := Reload(); err != nil {
		t.Fatalf("Reload after a refusal: %v", err)
	}
	if len(*calls) != 2 {
		t.Errorf("loadTrusted was called %d times, want 2 after a successful reload", len(*calls))
	}
}

// ---------------------------------------------------------------------------
// the shipped templates
// ---------------------------------------------------------------------------
//
// A template that no longer decodes into the real structs is worse than no
// template: it is a config an operator copies, edits, and cannot start. Both
// files are decoded HERE, into domains.Configuration, by the same parse stage
// the proxy itself runs.

// cfgParseTemplate runs the real parse stage over a repo-relative path.
func cfgParseTemplate(t *testing.T, path string) *domains.Configuration {
	t.Helper()
	cfg, err := parse(path)
	if err != nil {
		t.Fatalf("%s does not parse into domains.Configuration: %v", path, err)
	}
	return cfg
}

func TestExampleConfigTemplate(t *testing.T) {
	cfg := cfgParseTemplate(t, "../../examples/config.json")

	// The new keys are present and safe before normalise touches anything.
	if cfg.Proxy.CloudflareEnforceOrigin {
		t.Error("the example ships cloudflare_enforce_origin: true — a copy-paste deployment would 403 its own operator")
	}
	if cfg.Proxy.MaxBodySize != defaultMaxBodySize {
		t.Errorf("example max_body_size = %d, want the %d default so the file documents it", cfg.Proxy.MaxBodySize, defaultMaxBodySize)
	}
	if len(cfg.Proxy.TrustedProxies) == 0 {
		t.Error("the example shows no trusted_proxies entries, so it does not document the format")
	}

	// Documentation prefixes only (RFC 5737 / RFC 3849). A template must never
	// ship a routable range: whoever copies it would be trusting a network
	// they do not control, and trusting a peer means believing whatever
	// Cf-Connecting-Ip it sends.
	for _, entry := range cfg.Proxy.TrustedProxies {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			t.Fatalf("example trusted_proxies entry %q is not a CIDR: %v", entry, err)
		}
		documentation := false
		for _, reserved := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
			if netip.MustParsePrefix(reserved).Overlaps(prefix) {
				documentation = true
			}
		}
		if !documentation {
			t.Errorf("example trusted_proxies entry %q is not an RFC 5737 / RFC 3849 documentation range", entry)
		}
	}

	var sawOverride, sawInherit bool
	for _, domain := range cfg.Domains {
		if domain.MaxBodySize == 0 {
			sawInherit = true
		}
		if domain.MaxBodySize > 0 {
			sawOverride = true
		}
	}
	if !sawInherit || !sawOverride {
		t.Error("the example should show both an inherited (0) and an overridden per-domain maxBodySize")
	}

	// The example still has to be a VALID config apart from its placeholders.
	// The only thing validate may object to is the CHANGE_ME secrets, which
	// are the deliberate prompt to the operator; anything else means the
	// template has rotted away from the structs.
	normalise(cfg)
	err := validate(cfg)
	if err == nil {
		t.Fatal("the example config no longer carries CHANGE_ME placeholders")
	}
	if !strings.Contains(err.Error(), "CHANGE_ME") {
		t.Fatalf("the example config is broken for a reason other than its placeholders: %v", err)
	}

	// With the placeholders replaced it must pass end to end.
	for key := range cfg.Proxy.Secrets {
		cfg.Proxy.Secrets[key] = "replaced-" + key
	}
	cfg.Proxy.AdminSecret = "replaced-admin"
	cfg.Proxy.APISecret = "replaced-api"
	normalise(cfg)
	if err := validate(cfg); err != nil {
		t.Fatalf("the example config fails validate once its placeholders are replaced: %v", err)
	}
}

func TestHackTemplateStillLoads(t *testing.T) {
	cfg := cfgParseTemplate(t, "../../hack/config.test.json")

	if cfg.Proxy.CloudflareEnforceOrigin {
		t.Error("the harness config enables cloudflare_enforce_origin; the load harnesses would collect 403s, not measurements")
	}
	if cfg.Proxy.MaxBodySize != defaultMaxBodySize {
		t.Errorf("harness max_body_size = %d, want the %d default", cfg.Proxy.MaxBodySize, defaultMaxBodySize)
	}

	// The harnesses drive Cf-Connecting-Ip from loopback. Without loopback in
	// the trusted set every request collapses onto one subject IP and
	// memgrowth.sh measures nothing.
	loopback := map[string]bool{"127.0.0.1/32": false, "::1/128": false}
	for _, entry := range cfg.Proxy.TrustedProxies {
		if _, known := loopback[entry]; known {
			loopback[entry] = true
		}
	}
	for entry, present := range loopback {
		if !present {
			t.Errorf("harness trusted_proxies is missing %q", entry)
		}
	}

	// Unlike the example this one carries real values, so it must pass
	// outright — that is what "passes the loader's validation" in
	// hack/README.md means, and the harnesses are useless if it stops.
	normalise(cfg)
	if err := validate(cfg); err != nil {
		t.Fatalf("hack/config.test.json no longer passes validate: %v", err)
	}
	if _, err := build(cfg); err != nil {
		t.Fatalf("hack/config.test.json no longer builds: %v", err)
	}
}
