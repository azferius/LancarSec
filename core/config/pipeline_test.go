package config

// Wave 4 tests for the unified configuration pipeline.
//
// Everything here runs against the REAL stages (parse, normalise, validate,
// build, publish) and the real Reload entry point. Nothing in this file makes a
// network call: Load is deliberately not exercised, because it fetches the
// fingerprint tables and the version manifest from GitHub. The stages Load adds
// on top of Reload are only those two fetches plus the interactive prompts.
//
// The four defects these pin, all of which shipped:
//
//   - a reloaded domain got Stage2Difficulty 0, which made the stage-2 page
//     print the exact token it demanded;
//   - a domain deleted from config.json kept serving to its old backend;
//   - a reload during an attack reset every counter and dropped the stage back
//     to 1, throwing the mitigation away;
//   - an invalid config was half-published before the first check ran.

import (
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/azferius/lancarsec/core/domains"
	"github.com/azferius/lancarsec/core/firewall"
	"github.com/azferius/lancarsec/core/gofilter"
	"github.com/azferius/lancarsec/core/proxy"
	"github.com/azferius/lancarsec/core/transport"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// cfgDomain returns a domain that passes validate as-is.
func cfgDomain(name string) domains.Domain {
	return domains.Domain{
		Name:             name,
		Backend:          "127.0.0.1:9",
		Scheme:           "http",
		Stage2Difficulty: 4,
		BypassStage1:     75,
		BypassStage2:     250,
		FirewallRules: []domains.JsonRule{
			{Expression: `http.path eq "/captcha"`, Action: "3"},
		},
	}
}

// cfgFixture returns a configuration that passes validate as-is. Cloudflare is
// on so build does not need a real keypair on disk.
func cfgFixture(names ...string) *domains.Configuration {
	cfg := &domains.Configuration{
		Proxy: domains.Proxy{
			Cloudflare:      true,
			AdminSecret:     "admin-secret-0123456789",
			APISecret:       "api-secret-0123456789",
			RatelimitWindow: 120,
			Secrets: map[string]string{
				"cookie":     "cookie-secret-0123456789",
				"javascript": "js-secret-0123456789",
				"captcha":    "captcha-secret-0123456789",
			},
			Ratelimits: map[string]int{
				"requests":           500,
				"unknownFingerprint": 150,
				"challengeFailures":  40,
				"noRequestsSent":     10,
			},
			Timeout: domains.TimeoutSettings{Idle: 3, Read: 5, Write: 7, ReadHeader: 5},
		},
	}
	for _, name := range names {
		cfg.Domains = append(cfg.Domains, cfgDomain(name))
	}
	return cfg
}

// cfgIsolate points the pipeline at a scratch directory and restores every
// global it publishes into.
func cfgIsolate(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir())

	oldConfig := domains.Current()
	oldDomains := domains.Domains
	oldData := domains.DomainsData
	oldWatched := proxy.WatchedDomain
	oldCloudflare := proxy.Cloudflare
	oldWindow := proxy.RatelimitWindow
	oldAdmin, oldAPI := proxy.AdminSecret, proxy.APISecret
	oldCookie, oldJS, oldCaptcha := proxy.CookieSecret, proxy.JSSecret, proxy.CaptchaSecret
	oldIPRatelimit := proxy.IPRatelimit
	oldEnforceOrigin := proxy.CloudflareEnforceOrigin
	oldMaxBody := proxy.MaxBodySize
	oldLoadTrusted := loadTrusted

	domains.Publish(nil)
	domains.Domains = []string{}
	domains.DomainsData = map[string]domains.DomainData{}
	domains.DomainsMap = sync.Map{}

	t.Cleanup(func() {
		domains.Publish(oldConfig)
		domains.Domains = oldDomains
		domains.DomainsData = oldData
		domains.DomainsMap = sync.Map{}
		proxy.WatchedDomain = oldWatched
		proxy.Cloudflare = oldCloudflare
		proxy.RatelimitWindow = oldWindow
		proxy.AdminSecret, proxy.APISecret = oldAdmin, oldAPI
		proxy.CookieSecret, proxy.JSSecret, proxy.CaptchaSecret = oldCookie, oldJS, oldCaptcha
		proxy.IPRatelimit = oldIPRatelimit
		proxy.CloudflareEnforceOrigin = oldEnforceOrigin
		proxy.MaxBodySize = oldMaxBody
		loadTrusted = oldLoadTrusted
	})
}

// cfgSpyTrusted replaces the trusted.Load seam with a recorder and returns it.
// Every call publish makes lands in the slice, so a test can assert not only
// what was installed but that a refused configuration installed nothing at all.
func cfgSpyTrusted(t *testing.T) *[][]string {
	t.Helper()

	calls := &[][]string{}
	previous := loadTrusted
	loadTrusted = func(extra []string) (int, error) {
		*calls = append(*calls, append([]string(nil), extra...))
		return len(extra), nil
	}
	t.Cleanup(func() { loadTrusted = previous })
	return calls
}

func cfgWrite(t *testing.T, cfg *domains.Configuration) {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(ConfigPath, raw, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// cfgPublish runs the whole pipeline over cfg the way Reload does.
func cfgPublish(t *testing.T, cfg *domains.Configuration, m mode) {
	t.Helper()
	normalise(cfg)
	if err := validate(cfg); err != nil {
		t.Fatalf("validate: %v", err)
	}
	built, err := build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	publish(built, m)
}

func cfgSettings(t *testing.T, name string) domains.DomainSettings {
	t.Helper()
	value, ok := domains.DomainsMap.Load(name)
	if !ok {
		t.Fatalf("DomainsMap has no entry for %q", name)
	}
	settings, ok := value.(domains.DomainSettings)
	if !ok {
		t.Fatalf("DomainsMap entry for %q is %T, want domains.DomainSettings", name, value)
	}
	return settings
}

// ---------------------------------------------------------------------------
// normalise
// ---------------------------------------------------------------------------

func TestNormaliseFillsDefaults(t *testing.T) {
	cfg := &domains.Configuration{
		Proxy: domains.Proxy{RatelimitWindow: 3},
		Domains: []domains.Domain{
			{Name: " example.com ", Backend: " 127.0.0.1:80 ", Scheme: "HTTPS"},
			{Name: "other.example", Backend: "127.0.0.1:81", Stage2Difficulty: 7},
		},
	}

	normalise(cfg)

	if cfg.Proxy.RatelimitWindow != minRatelimitWindow {
		t.Errorf("RatelimitWindow = %d, want the %d floor", cfg.Proxy.RatelimitWindow, minRatelimitWindow)
	}
	if cfg.Domains[0].Name != "example.com" || cfg.Domains[0].Backend != "127.0.0.1:80" {
		t.Errorf("name/backend were not trimmed: %q / %q", cfg.Domains[0].Name, cfg.Domains[0].Backend)
	}
	if cfg.Domains[0].Scheme != "https" {
		t.Errorf("Scheme = %q, want it lowercased", cfg.Domains[0].Scheme)
	}
	// The whole point of wave 4: this default now happens on BOTH entry points,
	// because there is only one normalise.
	if cfg.Domains[0].Stage2Difficulty != defaultStage2Difficulty {
		t.Errorf("Stage2Difficulty = %d, want the %d default", cfg.Domains[0].Stage2Difficulty, defaultStage2Difficulty)
	}
	if cfg.Domains[1].Stage2Difficulty != 7 {
		t.Errorf("Stage2Difficulty = %d, want the configured 7 to survive", cfg.Domains[1].Stage2Difficulty)
	}

	before := *cfg
	normalise(cfg)
	if cfg.Domains[0].Stage2Difficulty != before.Domains[0].Stage2Difficulty {
		t.Error("normalise is not idempotent")
	}
}

func TestNormaliseDefaultsEmptySchemeToHTTP(t *testing.T) {
	cfg := &domains.Configuration{Domains: []domains.Domain{{Name: "a", Backend: "b"}}}
	normalise(cfg)
	if cfg.Domains[0].Scheme != "http" {
		t.Errorf("Scheme = %q, want http", cfg.Domains[0].Scheme)
	}
}

// ---------------------------------------------------------------------------
// validate
// ---------------------------------------------------------------------------

func TestValidateAcceptsAGoodConfig(t *testing.T) {
	cfg := cfgFixture("example.com", "other.example")
	normalise(cfg)
	if err := validate(cfg); err != nil {
		t.Fatalf("validate rejected a good config: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(cfg *domains.Configuration)
	}{
		// ReloadConfig carried none of these five checks, so a `reload` could
		// install a CHANGE_ME secret that Load had refused to start with.
		{"cookie secret", func(c *domains.Configuration) { c.Proxy.Secrets["cookie"] = "CHANGE_ME1" }},
		{"javascript secret", func(c *domains.Configuration) { c.Proxy.Secrets["javascript"] = "CHANGE_ME2" }},
		{"captcha secret", func(c *domains.Configuration) { c.Proxy.Secrets["captcha"] = "CHANGE_ME3" }},
		{"admin secret", func(c *domains.Configuration) { c.Proxy.AdminSecret = "CHANGE_ME" }},
		{"api secret", func(c *domains.Configuration) { c.Proxy.APISecret = "CHANGE_ME" }},

		// A missing secrets map indexes to "" in validate, so empty and
		// missing used to pass the CHANGE_ME-only check silently.
		{"empty cookie secret", func(c *domains.Configuration) { c.Proxy.Secrets["cookie"] = "" }},
		{"short admin secret", func(c *domains.Configuration) { c.Proxy.AdminSecret = "short" }},
		{"missing secrets map", func(c *domains.Configuration) { c.Proxy.Secrets = nil }},

		{"no domains", func(c *domains.Configuration) { c.Domains = nil }},
		{"empty name", func(c *domains.Configuration) { c.Domains[0].Name = "" }},
		{"duplicate name", func(c *domains.Configuration) { c.Domains[1].Name = c.Domains[0].Name }},
		{"reserved name", func(c *domains.Configuration) { c.Domains[0].Name = DebugDomain }},
		{"no backend", func(c *domains.Configuration) { c.Domains[0].Backend = "" }},
		{"unsupported scheme", func(c *domains.Configuration) { c.Domains[0].Scheme = "ftp" }},
		{"negative difficulty", func(c *domains.Configuration) { c.Domains[0].Stage2Difficulty = -1 }},
		{"difficulty at token length", func(c *domains.Configuration) { c.Domains[0].Stage2Difficulty = stage2TokenLength }},
		{"empty rule action", func(c *domains.Configuration) { c.Domains[0].FirewallRules[0].Action = "" }},
		{"non numeric rule action", func(c *domains.Configuration) { c.Domains[0].FirewallRules[0].Action = "block" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cfgFixture("example.com", "other.example")
			tc.mutate(cfg)
			normalise(cfg)
			if err := validate(cfg); err == nil {
				t.Fatalf("validate accepted %s", tc.name)
			}
		})
	}
}

func TestValidateAction(t *testing.T) {
	cases := []struct {
		action string
		ok     bool
	}{
		{"0", true},
		{"3", true},
		{"+2", true},
		{"-2", true},
		{"", false},
		{"+", false},
		{"-", false},
		{"+abc", false},
		{"block", false},
		// " 7" reaches EvalFirewallRule's default branch, where fmt.Sscan skips
		// the leading space and treats it as an ABSOLUTE set -- an invisible
		// character that changes what the rule means. Rejected at load now.
		{" 7", false},
		{"+-3", false},
		{"3.5", false},
	}

	for _, tc := range cases {
		err := validateAction(tc.action)
		if tc.ok && err != nil {
			t.Errorf("validateAction(%q) = %v, want nil", tc.action, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("validateAction(%q) = nil, want an error", tc.action)
		}
	}
}

// ---------------------------------------------------------------------------
// build
// ---------------------------------------------------------------------------

func TestBuildRejectsAnUncompilableRule(t *testing.T) {
	cfg := cfgFixture("example.com")
	cfg.Domains[0].FirewallRules = []domains.JsonRule{{Expression: "http.path eq", Action: "1"}}
	normalise(cfg)

	if _, err := build(cfg); err == nil {
		t.Fatal("build accepted an uncompilable firewall rule")
	}
}

// The vendored gofilter parser panics on `matches` with an unquoted operand
// (regexp.Compile(val.(string)) on a non-string, no recover in NewFilter). That
// used to take the whole process down - on startup, and on a live reload of a
// serving proxy.
func TestBuildContainsTheGofilterPanic(t *testing.T) {
	cfg := cfgFixture("example.com")
	cfg.Domains[0].FirewallRules = []domains.JsonRule{{Expression: "ip.src matches 1.2.3.4", Action: "1"}}
	normalise(cfg)

	built, err := build(cfg)
	if err == nil {
		t.Fatalf("build accepted a rule that panics the parser (built %+v)", built)
	}
}

// Wave 4 fixed the vendored parser: an unquoted `matches` operand used to
// panic through an unchecked val.(string) assertion, and NewFilter had no
// recover, so one config typo killed the proxy at startup or on reload.
// It now returns an error naming the field and the type it actually got.
//
// The recover in compileFilter is kept as defence in depth: core/gofilter is
// vendored third-party code and this was not the only assertion in it.
func TestGofilterReturnsAnErrorForAnUnquotedMatchesOperand(t *testing.T) {
	for _, expr := range []string{
		"ip.src matches 1.2.3.4",
		"ip.asn matches 1234",
		"http.user_agent matches ff:ee",
		"proxy.attack matches true",
	} {
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("gofilter.NewFilter(%q) panicked: %v", expr, recovered)
				}
			}()
			if _, err := gofilter.NewFilter(expr); err == nil {
				t.Errorf("gofilter.NewFilter(%q) returned no error", expr)
			}
		}()
	}
}

func TestBuildRejectsAMissingCertificate(t *testing.T) {
	cfg := cfgFixture("example.com")
	cfg.Proxy.Cloudflare = false
	cfg.Domains[0].Certificate = "does-not-exist.crt"
	cfg.Domains[0].Key = "does-not-exist.key"
	normalise(cfg)

	if _, err := build(cfg); err == nil {
		t.Fatal("build accepted a domain whose keypair cannot be loaded")
	}
}

func TestBuildInstallsTheSharedRoundTripper(t *testing.T) {
	cfgIsolate(t)

	cfg := cfgFixture("example.com")
	normalise(cfg)
	built, err := build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	// Every domain's reverse proxy must carry the transport.RoundTripper
	// rather than http.DefaultTransport: it is what applies the per-domain
	// read timeout and renders the backend-error page. A nil here means a
	// backend failure reaches the client as a bare 502 with no page.
	got := built.domains[0].settings.DomainProxy.Transport
	if _, ok := got.(*transport.RoundTripper); !ok {
		t.Errorf("Transport = %#v, want *transport.RoundTripper", got)
	}
	// Wave 8: the proxy must also draw its 32 KiB response buffers from the
	// shared pool instead of allocating one per proxied response.
	if built.domains[0].settings.DomainProxy.BufferPool == nil {
		t.Error("DomainProxy.BufferPool is nil; every proxied response allocates a fresh 32 KiB buffer")
	}
}

func TestBuildWiresPassBackendErrorsAndTransportConfig(t *testing.T) {
	cfgIsolate(t)

	// WAVE 8 (assertion flipped): the transport REGISTRY used to be configured
	// here in build. It is global state, and build is the last stage that can
	// fail, so a refused config could leak its backend_tls_skip_verify onto
	// the still-running domains. The registry is now configured in publish;
	// this test's seam records what build itself does, and it must be
	// nothing. The per-domain transport's skip-verify semantics are pinned in
	// core/transport's own tests.
	configures := 0
	previousConfigure := configureTransports
	configureTransports = func(string, transport.Options) { configures++ }
	t.Cleanup(func() { configureTransports = previousConfigure })

	cfg := cfgFixture("opted.example")
	cfg.Domains[0].PassBackendErrors = true
	cfg.Proxy.BackendTLSSkipVerify = true
	normalise(cfg)
	built, err := build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	got, ok := built.domains[0].settings.DomainProxy.Transport.(*transport.RoundTripper)
	if !ok {
		t.Fatalf("Transport = %#v, want *transport.RoundTripper", got)
	}
	if !got.PassBackendErrors {
		t.Error("PassBackendErrors did not reach the domain's RoundTripper")
	}
	if configures != 0 {
		t.Errorf("build configured %d transports; the registry swap belongs to publish", configures)
	}
}

// The registry swap publish performs must carry the config's
// backend_tls_skip_verify for every configured domain.
func TestPublishConfiguresTransportsWithTLSSetting(t *testing.T) {
	cfgIsolate(t)

	calls := map[string]transport.Options{}
	previousConfigure := configureTransports
	configureTransports = func(name string, opts transport.Options) { calls[name] = opts }
	t.Cleanup(func() { configureTransports = previousConfigure })

	opted := cfgFixture("a.example", "b.example")
	opted.Proxy.BackendTLSSkipVerify = true
	cfgPublish(t, opted, modeStartup)

	if len(calls) != 2 {
		t.Fatalf("publish configured %d transports, want one per domain (2)", len(calls))
	}
	for _, name := range []string{"a.example", "b.example"} {
		if !calls[name].SkipVerify {
			t.Errorf("transport for %q was configured with SkipVerify=false; the opt-out did not reach it", name)
		}
	}

	for name := range calls {
		delete(calls, name)
	}
	defaults := cfgFixture("a.example", "b.example")
	cfgPublish(t, defaults, modeReload)
	if len(calls) != 2 {
		t.Fatalf("publish configured %d transports on reload, want 2", len(calls))
	}
	for _, name := range []string{"a.example", "b.example"} {
		if calls[name].SkipVerify {
			t.Errorf("transport for %q kept SkipVerify after the flag was removed", name)
		}
	}
}

type stubTripper struct{}

func (*stubTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, nil }

// ---------------------------------------------------------------------------
// publish
// ---------------------------------------------------------------------------

func TestPublishStartupBuildsFreshDomains(t *testing.T) {
	cfgIsolate(t)

	cfgPublish(t, cfgFixture("a.example", "b.example"), modeStartup)

	if got, want := domains.Domains, []string{"a.example", "b.example"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("domains.Domains = %v, want %v", got, want)
	}
	if proxy.WatchedDomain != "a.example" {
		t.Errorf("WatchedDomain = %q, want the first configured domain", proxy.WatchedDomain)
	}
	data := domains.DomainsData["a.example"]
	if data.Stage != 1 || data.StageManuallySet {
		t.Errorf("fresh domain = stage %d (locked %v), want stage 1 unlocked", data.Stage, data.StageManuallySet)
	}
	if data.Stage2Difficulty != 4 {
		t.Errorf("Stage2Difficulty = %d, want 4", data.Stage2Difficulty)
	}
	if _, ok := domains.DomainsData[DebugDomain]; !ok {
		t.Error("the debug domain was not registered")
	}
	if _, ok := domains.DomainsMap.Load(DebugDomain); !ok {
		t.Error("the debug domain has no DomainsMap entry")
	}
	// Proxy-wide settings ReloadConfig used to skip entirely.
	if proxy.AdminSecret != "admin-secret-0123456789" || proxy.APISecret != "api-secret-0123456789" {
		t.Errorf("admin/api secrets were not published: %q / %q", proxy.AdminSecret, proxy.APISecret)
	}
	if proxy.RatelimitWindow != 120 {
		t.Errorf("RatelimitWindow = %d, want 120", proxy.RatelimitWindow)
	}
}

// The headline wave 4 fix: a reload must not throw away the mitigation the
// proxy has already escalated to, and must not leave Stage2Difficulty at 0.
func TestPublishReloadPreservesLiveState(t *testing.T) {
	cfgIsolate(t)

	cfgPublish(t, cfgFixture("a.example", "b.example"), modeStartup)

	// Simulate an ongoing attack on a.example.
	firewall.Mutex.Lock()
	live := domains.DomainsData["a.example"]
	live.Stage = 3
	live.StageManuallySet = true
	live.RawAttack = true
	live.BypassAttack = true
	live.BufferCooldown = 7
	live.TotalRequests = 91000
	live.BypassedRequests = 4100
	live.PrevRequests = 90000
	live.PrevBypassed = 4000
	live.RequestsPerSecond = 1000
	live.PeakRequestsPerSecond = 2500
	live.LastLogs = []domains.DomainLog{{IP: "1.2.3.4"}}
	live.RequestLogger = []domains.RequestLog{{Total: 1000}}
	domains.DomainsData["a.example"] = live
	firewall.Mutex.Unlock()

	next := cfgFixture("a.example")
	next.Domains[0].Stage2Difficulty = 6
	cfgPublish(t, next, modeReload)

	got := domains.DomainsData["a.example"]
	if got.Stage != 3 || !got.StageManuallySet {
		t.Errorf("stage = %d (locked %v), want the live 3 (locked) to survive the reload", got.Stage, got.StageManuallySet)
	}
	if !got.RawAttack || !got.BypassAttack || got.BufferCooldown != 7 {
		t.Errorf("attack state was reset: raw=%v bypass=%v cooldown=%d", got.RawAttack, got.BypassAttack, got.BufferCooldown)
	}
	if got.TotalRequests != 91000 || got.BypassedRequests != 4100 {
		t.Errorf("counters were zeroed: total=%d bypassed=%d", got.TotalRequests, got.BypassedRequests)
	}
	if got.PrevRequests != 90000 || got.PrevBypassed != 4000 || got.RequestsPerSecond != 1000 || got.PeakRequestsPerSecond != 2500 {
		t.Errorf("rate state was zeroed: %+v", got)
	}
	if len(got.LastLogs) != 1 || len(got.RequestLogger) != 1 {
		t.Errorf("logs were dropped: %d logs, %d request-log entries", len(got.LastLogs), len(got.RequestLogger))
	}
	// The one field the configuration owns.
	if got.Stage2Difficulty != 6 {
		t.Errorf("Stage2Difficulty = %d, want the reloaded 6 (it used to become 0)", got.Stage2Difficulty)
	}
}

func TestPublishReloadRemovesDeletedDomains(t *testing.T) {
	cfgIsolate(t)

	resets := 0
	resetTransports = func(map[string]struct{}) { resets++ }

	cfgPublish(t, cfgFixture("a.example", "b.example"), modeStartup)
	cfgPublish(t, cfgFixture("a.example"), modeReload)

	if _, ok := domains.DomainsData["b.example"]; ok {
		t.Error("a domain removed from config.json still has DomainsData; it would keep serving to its old backend")
	}
	if _, ok := domains.DomainsMap.Load("b.example"); ok {
		t.Error("a domain removed from config.json still has DomainsMap settings")
	}
	if len(domains.Domains) != 1 || domains.Domains[0] != "a.example" {
		t.Errorf("domains.Domains = %v, want [a.example]", domains.Domains)
	}
	if _, ok := domains.DomainsData["a.example"]; !ok {
		t.Error("the surviving domain was dropped")
	}
	if _, ok := domains.DomainsData[DebugDomain]; !ok {
		t.Error("converging on config.json deleted the debug domain")
	}
	if resets == 0 {
		t.Error("resetTransports was not called, so the removed domain's pooled backend connections survive it")
	}
}

func TestPublishResetsTransportsWhenABackendMoves(t *testing.T) {
	cfgIsolate(t)

	cfgPublish(t, cfgFixture("a.example"), modeStartup)

	resets := 0
	resetTransports = func(map[string]struct{}) { resets++ }

	unchanged := cfgFixture("a.example")
	cfgPublish(t, unchanged, modeReload)
	if resets != 0 {
		t.Errorf("ResetTransports ran %d times for a reload that changed no backend", resets)
	}

	moved := cfgFixture("a.example")
	moved.Domains[0].Backend = "127.0.0.1:10"
	cfgPublish(t, moved, modeReload)
	if resets != 1 {
		t.Errorf("ResetTransports ran %d times after a backend change, want 1", resets)
	}
}

// WAVE 8: the per-domain transports are configured in publish, not build, so
// a configuration refused in build must not have touched them. Configure in
// build leaked a refused config's backend_tls_skip_verify onto the domains
// still running -- exactly the half-published state the pipeline exists to
// prevent.
func TestRefusedReloadDoesNotConfigureTransports(t *testing.T) {
	cfgIsolate(t)

	configures, resets := 0, 0
	previousConfigure, previousReset := configureTransports, resetTransports
	configureTransports = func(string, transport.Options) { configures++ }
	resetTransports = func(map[string]struct{}) { resets++ }
	t.Cleanup(func() { configureTransports, resetTransports = previousConfigure, previousReset })

	cfgPublish(t, cfgFixture("a.example"), modeStartup)
	before := configures
	if before != 1 {
		t.Fatalf("startup configured %d transports, want 1", before)
	}

	// A certificate path validate never reads, so the refusal must land in
	// build -- the stage Configure used to leak from.
	refused := cfgFixture("a.example")
	refused.Proxy.Cloudflare = false
	refused.Domains[0].Certificate = "does-not-exist.pem"
	refused.Domains[0].Key = "does-not-exist.key"
	cfgWrite(t, refused)

	err := Reload()
	if err == nil {
		t.Fatal("Reload accepted a configuration with an unloadable certificate")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("Reload failed in the wrong stage (%v); the test must refuse in build, not validate", err)
	}

	if configures != before {
		t.Errorf("the refused reload (re)configured %d transports; a refused config must not touch the running ones", configures-before)
	}
	if resets != 0 {
		t.Errorf("the refused reload reset the transports %d times", resets)
	}
}

func TestPublishReloadKeepsTheWatchedDomain(t *testing.T) {
	cfgIsolate(t)

	cfgPublish(t, cfgFixture("a.example", "b.example"), modeStartup)

	proxy.WatchedDomain = "b.example"
	cfgPublish(t, cfgFixture("a.example", "b.example"), modeReload)
	if proxy.WatchedDomain != "b.example" {
		t.Errorf("WatchedDomain = %q, want the operator's choice to survive a reload", proxy.WatchedDomain)
	}

	// `domain` with no argument means "list them all"; a reload must not drag
	// the operator back into a single-domain view.
	proxy.WatchedDomain = ""
	cfgPublish(t, cfgFixture("a.example", "b.example"), modeReload)
	if proxy.WatchedDomain != "" {
		t.Errorf("WatchedDomain = %q, want list mode to survive a reload", proxy.WatchedDomain)
	}

	// Watching a domain that the reload deleted has to fall back to something
	// real: printStats renders stage 0 as "domain not found".
	proxy.WatchedDomain = "b.example"
	cfgPublish(t, cfgFixture("a.example"), modeReload)
	if proxy.WatchedDomain != "a.example" {
		t.Errorf("WatchedDomain = %q, want a fallback to a live domain", proxy.WatchedDomain)
	}
}

func TestPublishRepublishesDomainSettings(t *testing.T) {
	cfgIsolate(t)

	cfgPublish(t, cfgFixture("a.example"), modeStartup)

	next := cfgFixture("a.example")
	next.Domains[0].BypassStage1 = 4242
	next.Domains[0].FirewallRules = []domains.JsonRule{
		{Expression: `http.path eq "/js"`, Action: "+2"},
	}
	cfgPublish(t, next, modeReload)

	settings := cfgSettings(t, "a.example")
	if settings.BypassStage1 != 4242 {
		t.Errorf("BypassStage1 = %d, want the reloaded 4242", settings.BypassStage1)
	}
	if len(settings.CustomRules) != 1 || settings.CustomRules[0].Action != "+2" {
		t.Errorf("CustomRules = %+v, want the reloaded rule", settings.CustomRules)
	}
	if len(settings.RawCustomRules) != 1 || settings.RawCustomRules[0].Expression != `http.path eq "/js"` {
		t.Errorf("RawCustomRules = %+v, want the reloaded rule", settings.RawCustomRules)
	}
}

// ---------------------------------------------------------------------------
// Reload
// ---------------------------------------------------------------------------

func TestReloadReadsTheFile(t *testing.T) {
	cfgIsolate(t)

	cfgPublish(t, cfgFixture("a.example"), modeStartup)

	next := cfgFixture("a.example", "b.example")
	cfgWrite(t, next)

	if err := Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if len(domains.Domains) != 2 {
		t.Errorf("domains.Domains = %v, want both domains from the file", domains.Domains)
	}
	if domains.DomainsData["b.example"].Stage2Difficulty != 4 {
		t.Errorf("Stage2Difficulty = %d, want 4", domains.DomainsData["b.example"].Stage2Difficulty)
	}
}

// A refused reload must leave the running proxy EXACTLY as it was. This is the
// property the pipeline exists for: the old code decoded straight into
// the published snapshot, so a malformed or rejected file was already live.
func TestReloadRefusalPublishesNothing(t *testing.T) {
	cases := []struct {
		name  string
		write func(t *testing.T)
	}{
		{"malformed json", func(t *testing.T) {
			if err := os.WriteFile(ConfigPath, []byte("{not json"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing file", func(t *testing.T) {
			if err := os.Remove(ConfigPath); err != nil {
				t.Fatal(err)
			}
		}},
		{"changed secret", func(t *testing.T) {
			cfg := cfgFixture("a.example", "gone.example")
			cfg.Proxy.Secrets["cookie"] = "CHANGE_ME"
			cfgWrite(t, cfg)
		}},
		{"zero domains", func(t *testing.T) {
			cfgWrite(t, cfgFixture())
		}},
		{"uncompilable rule", func(t *testing.T) {
			cfg := cfgFixture("a.example")
			cfg.Domains[0].FirewallRules = []domains.JsonRule{{Expression: "http.path eq", Action: "1"}}
			cfgWrite(t, cfg)
		}},
		{"missing certificate", func(t *testing.T) {
			cfg := cfgFixture("a.example")
			cfg.Proxy.Cloudflare = false
			cfg.Domains[0].Certificate = "nope.crt"
			cfg.Domains[0].Key = "nope.key"
			cfgWrite(t, cfg)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgIsolate(t)

			good := cfgFixture("a.example", "gone.example")
			cfgWrite(t, good)
			if err := Reload(); err != nil {
				t.Fatalf("baseline Reload: %v", err)
			}
			resetTransports = func(map[string]struct{}) { t.Error("a refused reload reset the transports") }

			wantConfig := domains.Current()
			wantDomains := append([]string(nil), domains.Domains...)
			wantData := domains.DomainsData["a.example"]
			wantSettings := cfgSettings(t, "a.example")
			wantCookie := proxy.CookieSecret
			wantWindow := proxy.RatelimitWindow

			tc.write(t)

			if err := Reload(); err == nil {
				t.Fatal("Reload accepted a config it must refuse")
			}

			if domains.Current() != wantConfig {
				t.Error("domains.Config was replaced by a refused reload")
			}
			if len(domains.Domains) != len(wantDomains) {
				t.Errorf("domains.Domains = %v, want %v", domains.Domains, wantDomains)
			}
			if _, ok := domains.DomainsData["gone.example"]; !ok {
				t.Error("a refused reload deleted a live domain")
			}
			if !reflect.DeepEqual(domains.DomainsData["a.example"], wantData) {
				t.Error("a refused reload rewrote DomainsData")
			}
			if got := cfgSettings(t, "a.example"); got.DomainProxy != wantSettings.DomainProxy {
				t.Error("a refused reload republished DomainSettings")
			}
			if proxy.CookieSecret != wantCookie || proxy.RatelimitWindow != wantWindow {
				t.Error("a refused reload published proxy-wide settings")
			}
		})
	}
}

func TestReloadIsIdempotent(t *testing.T) {
	cfgIsolate(t)

	cfgWrite(t, cfgFixture("a.example", "b.example"))
	if err := Reload(); err != nil {
		t.Fatalf("first Reload: %v", err)
	}
	first := domains.DomainsData["a.example"]

	if err := Reload(); err != nil {
		t.Fatalf("second Reload: %v", err)
	}
	if !reflect.DeepEqual(domains.DomainsData["a.example"], first) {
		t.Errorf("a second identical reload changed DomainsData:\n got %+v\nwant %+v", domains.DomainsData["a.example"], first)
	}
	if len(domains.Domains) != 2 {
		t.Errorf("domains.Domains = %v, want two entries and no duplicates", domains.Domains)
	}
}
