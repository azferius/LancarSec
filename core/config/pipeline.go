package config

// The configuration pipeline.
//
// There is exactly ONE code path from config.json to the running proxy:
//
//	parse -> normalise -> validate -> build -> publish
//
// `Load` (startup) and `Reload` (the terminal `reload`/`add` commands) are both
// thin wrappers around it; see init.go. Before wave 4 they were two hand-copied
// implementations that had already drifted apart in eight places, the worst of
// which left every reloaded domain with Stage2Difficulty 0.
//
// The invariant that makes a hot reload safe is:
//
//	EVERYTHING THAT CAN FAIL HAPPENS BEFORE ANYTHING IS PUBLISHED.
//
// parse/normalise/validate/build touch no global state at all - they work on a
// freshly allocated *domains.Configuration and produce an unreachable `staged`
// value. `publish` is the only function in the package that writes a global,
// and it cannot fail. A config.json with a bad certificate path, an
// uncompilable firewall rule or a CHANGE_ME secret therefore leaves the running
// proxy completely untouched.

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/azferius/lancarsec/core/domains"
	"github.com/azferius/lancarsec/core/firewall"
	"github.com/azferius/lancarsec/core/gofilter"
	"github.com/azferius/lancarsec/core/proxy"
	"github.com/azferius/lancarsec/core/transport"
	"github.com/azferius/lancarsec/core/utils"
)

const (
	// ConfigPath is the file every stage of the pipeline reads.
	ConfigPath = "config.json"

	// DebugDomain is the pseudo-domain the proxy registers for itself. It is
	// never listed in config.json and must survive every reload.
	DebugDomain = "debug"

	// defaultStage2Difficulty is how many hex characters of the stage-2 token
	// the client has to brute-force when the operator did not pick a number.
	// A zero here is what made the reloaded stage-2 challenge print the exact
	// answer it demanded: middleware.go slices `token[:len(token)-difficulty]`.
	defaultStage2Difficulty = 5

	// stage2TokenLength is len(utils.Encrypt(...)) - a hex-encoded BLAKE3-256
	// digest. The difficulty is subtracted from it, so it has to stay below.
	stage2TokenLength = 64

	// minRatelimitWindow is the floor applied to proxy.ratelimit_time.
	minRatelimitWindow = 10
)

// errNoDomains is a sentinel so the startup path can tell "the operator has not
// configured a domain yet" (which is a prompt) from "this config is broken"
// (which is a refusal). A reload never prompts: see Reload in init.go.
var errNoDomains = errors.New("no domains configured")

// resetTransports drops cached per-domain transports and closes the idle
// connections they pooled, so a domain removed from config.json does not leave
// keep-alives to a backend that is no longer configured.
//
// It is a variable only so the publish tests can count calls; production never
// reassigns it. This is a test seam, not the wiring mechanism -- core/config
// depends on core/transport directly, which is what keeps the graph honest.
var resetTransports = transport.Reset

// mode distinguishes the two entry points. It only ever affects which domain
// the terminal UI watches - every other stage is identical by construction.
type mode int

const (
	modeStartup mode = iota
	modeReload
)

// stagedDomain is one fully built, not-yet-published domain: every fallible
// step (rule compilation, certificate loading, backend URL construction) has
// already succeeded by the time one of these exists.
type stagedDomain struct {
	name       string
	difficulty int
	settings   domains.DomainSettings
}

// staged is the complete output of the build stage. Nothing in here is
// reachable from a serving goroutine until publish runs.
type staged struct {
	cfg     *domains.Configuration
	domains []stagedDomain
}

// ---------------------------------------------------------------------------
// stage 1: parse
// ---------------------------------------------------------------------------

// parse reads config.json into a NEW Configuration. It deliberately does not
// decode into domains.Config: the old code did, which meant a half-decoded or
// malformed document was already live for every in-flight request before
// anything had been checked. The decoder error is returned, not discarded.
func parse(path string) (*domains.Configuration, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	cfg := &domains.Configuration{}
	if err := json.NewDecoder(file).Decode(cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// ---------------------------------------------------------------------------
// stage 2: normalise
// ---------------------------------------------------------------------------

// normalise fills in defaults and canonicalises fields. It is idempotent, and
// validate runs against its output, so both entry points get identical
// defaulting - that is the actual fix for the Stage2Difficulty divergence.
func normalise(cfg *domains.Configuration) {
	if cfg.Proxy.RatelimitWindow < minRatelimitWindow {
		cfg.Proxy.RatelimitWindow = minRatelimitWindow
	}

	for i := range cfg.Domains {
		domain := &cfg.Domains[i]

		domain.Name = strings.TrimSpace(domain.Name)
		domain.Backend = strings.TrimSpace(domain.Backend)

		domain.Scheme = strings.ToLower(strings.TrimSpace(domain.Scheme))
		if domain.Scheme == "" {
			domain.Scheme = "http"
		}

		if domain.Stage2Difficulty == 0 {
			domain.Stage2Difficulty = defaultStage2Difficulty
		}
	}
}

// ---------------------------------------------------------------------------
// stage 3: validate
// ---------------------------------------------------------------------------

// validate rejects a configuration the proxy cannot serve safely. It runs on
// both entry points: a reload that would have installed a CHANGE_ME secret used
// to be accepted silently, because ReloadConfig never carried these checks.
func validate(cfg *domains.Configuration) error {
	for _, secret := range []struct {
		name  string
		value string
	}{
		{"cookie secret", cfg.Proxy.Secrets["cookie"]},
		{"javascript secret", cfg.Proxy.Secrets["javascript"]},
		{"captcha secret", cfg.Proxy.Secrets["captcha"]},
		{"admin secret", cfg.Proxy.AdminSecret},
		{"api secret", cfg.Proxy.APISecret},
	} {
		if strings.Contains(secret.value, "CHANGE_ME") {
			return fmt.Errorf("proxy %s still contains CHANGE_ME", secret.name)
		}
	}

	if len(cfg.Domains) == 0 {
		return errNoDomains
	}

	seen := make(map[string]struct{}, len(cfg.Domains))
	for i, domain := range cfg.Domains {
		if domain.Name == "" {
			return fmt.Errorf("domain %d has no name", i)
		}
		// checkAttack returns early for this name, so a domain called "debug"
		// would silently never escalate a stage - it would look configured and
		// be completely unprotected.
		if domain.Name == DebugDomain {
			return fmt.Errorf("domain %d uses the reserved name %q", i, DebugDomain)
		}
		// A duplicate would silently overwrite the first entry in DomainsMap
		// while appearing twice in domains.Domains, which desyncs the two
		// tables the request path indexes.
		if _, dup := seen[domain.Name]; dup {
			return fmt.Errorf("domain %q is configured more than once", domain.Name)
		}
		seen[domain.Name] = struct{}{}

		if domain.Backend == "" {
			return fmt.Errorf("domain %q has no backend", domain.Name)
		}
		if domain.Scheme != "http" && domain.Scheme != "https" {
			return fmt.Errorf("domain %q has scheme %q, want \"http\" or \"https\"", domain.Name, domain.Scheme)
		}
		// middleware.go slices token[:len(token)-difficulty]; anything outside
		// this range either hands the client the whole answer or panics the
		// request handler.
		if domain.Stage2Difficulty < 1 || domain.Stage2Difficulty >= stage2TokenLength {
			return fmt.Errorf("domain %q has stage2Difficulty %d, want 1..%d", domain.Name, domain.Stage2Difficulty, stage2TokenLength-1)
		}

		for j, rule := range domain.FirewallRules {
			if err := validateAction(rule.Action); err != nil {
				return fmt.Errorf("domain %q firewall rule %d: %w", domain.Name, j, err)
			}
		}
	}

	return nil
}

// validateAction rejects rule actions firewall.EvalFirewallRule cannot execute.
// The grammar it implements is "n" (absolute), "+n" and "-n"; anything else was
// previously accepted at load and then either logged to stdout on every single
// matching request ("+abc") or panicked the request handler the first time the
// rule matched ("", which slices Action[:1] out of range).
func validateAction(action string) error {
	digits := action
	if digits != "" && (digits[0] == '+' || digits[0] == '-') {
		digits = digits[1:]
	}
	if _, err := strconv.ParseUint(digits, 10, 31); err != nil {
		return fmt.Errorf("action %q is not a suspicion expression; want \"n\", \"+n\" or \"-n\"", action)
	}
	return nil
}

// ---------------------------------------------------------------------------
// stage 4: build
// ---------------------------------------------------------------------------

// build turns a validated configuration into ready-to-publish domain state.
// This is the last stage that can fail. Everything it allocates is private
// until publish hands it over.
func build(cfg *domains.Configuration) (*staged, error) {
	out := &staged{
		cfg:     cfg,
		domains: make([]stagedDomain, 0, len(cfg.Domains)),
	}

	for _, domain := range cfg.Domains {

		firewallRules := make([]domains.Rule, 0, len(domain.FirewallRules))
		for index, fwRule := range domain.FirewallRules {
			filter, err := compileFilter(fwRule.Expression)
			if err != nil {
				return nil, fmt.Errorf("domain %q firewall rule %d: %w", domain.Name, index, err)
			}
			firewallRules = append(firewallRules, domains.Rule{
				Filter: filter,
				Action: fwRule.Action,
			})
		}

		dProxy := httputil.NewSingleHostReverseProxy(&url.URL{
			Scheme: domain.Scheme,
			Host:   domain.Backend,
		})
		dProxy.Transport = &transport.RoundTripper{}

		// Cloudflare terminates TLS, so no keypair is needed (or configured).
		cert := tls.Certificate{}
		if !cfg.Proxy.Cloudflare {
			loaded, err := tls.LoadX509KeyPair(domain.Certificate, domain.Key)
			if err != nil {
				return nil, fmt.Errorf("domain %q certificate: %w", domain.Name, err)
			}
			cert = loaded
		}

		out.domains = append(out.domains, stagedDomain{
			name:       domain.Name,
			difficulty: domain.Stage2Difficulty,
			settings: domains.DomainSettings{
				Name: domain.Name,

				CustomRules:    firewallRules,
				RawCustomRules: domain.FirewallRules,

				DomainProxy:        dProxy,
				DomainCertificates: cert,
				DomainWebhooks: domains.WebhookSettings{
					URL:            domain.Webhook.URL,
					Name:           domain.Webhook.Name,
					Avatar:         domain.Webhook.Avatar,
					AttackStartMsg: domain.Webhook.AttackStartMsg,
					AttackStopMsg:  domain.Webhook.AttackStopMsg,
				},

				BypassStage1:        domain.BypassStage1,
				BypassStage2:        domain.BypassStage2,
				DisableBypassStage3: domain.DisableBypassStage3,
				DisableRawStage3:    domain.DisableRawStage3,
				DisableBypassStage2: domain.DisableBypassStage2,
				DisableRawStage2:    domain.DisableRawStage2,
			},
		})
	}

	return out, nil
}

// compileFilter compiles one rule expression into a gofilter.Filter.
//
// core/gofilter is vendored verbatim (see its README) and does not survive
// every input: a `matches` operand that is not a quoted string reaches
// regexp.Compile(val.(string)) on a non-string, and NewFilter has no recover.
// A single config typo therefore killed the process - at startup, and worse, on
// a live reload of a proxy that was serving. Containing the panic at the
// pipeline's one call site keeps the vendored parser byte-identical to upstream
// and turns "one typo takes the proxy down" into "the reload is refused".
func compileFilter(expression string) (filter *gofilter.Filter, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			filter = nil
			err = fmt.Errorf("cannot compile %q: %v", expression, recovered)
		}
	}()
	return gofilter.NewFilter(expression)
}

// ---------------------------------------------------------------------------
// stage 5: publish
// ---------------------------------------------------------------------------

// publish installs a built configuration. It is the ONLY function in this
// package that writes global state, and it cannot fail.
//
// WAVE 7: this is the single function that has to change. Replace the
// `domains.Config = s.cfg` assignment with the atomic.Pointer store and the
// firewall.Mutex section with whatever guards the domain tables then. The
// merge/converge logic below is orthogonal to the publish mechanism and should
// survive untouched - it is what preserves mitigation state across a reload, so
// it has to keep happening between reading the old tables and installing the
// new ones.
func publish(s *staged, m mode) {
	previous := domains.Config

	// --- process-wide settings -------------------------------------------
	domains.Config = s.cfg
	proxy.Cloudflare = s.cfg.Proxy.Cloudflare

	proxy.CookieSecret = s.cfg.Proxy.Secrets["cookie"]
	proxy.JSSecret = s.cfg.Proxy.Secrets["javascript"]
	proxy.CaptchaSecret = s.cfg.Proxy.Secrets["captcha"]
	// ReloadConfig used to skip these two entirely, so rotating either secret
	// required a full restart.
	proxy.AdminSecret = s.cfg.Proxy.AdminSecret
	proxy.APISecret = s.cfg.Proxy.APISecret

	// A zero timeout means "keep the built-in default", on both paths.
	if s.cfg.Proxy.Timeout.Idle != 0 {
		proxy.IdleTimeout = s.cfg.Proxy.Timeout.Idle
		proxy.IdleTimeoutDuration = time.Duration(proxy.IdleTimeout).Abs() * time.Second
	}
	if s.cfg.Proxy.Timeout.Read != 0 {
		proxy.ReadTimeout = s.cfg.Proxy.Timeout.Read
		proxy.ReadTimeoutDuration = time.Duration(proxy.ReadTimeout).Abs() * time.Second
	}
	if s.cfg.Proxy.Timeout.ReadHeader != 0 {
		proxy.ReadHeaderTimeout = s.cfg.Proxy.Timeout.ReadHeader
		proxy.ReadHeaderTimeoutDuration = time.Duration(proxy.ReadHeaderTimeout).Abs() * time.Second
	}
	if s.cfg.Proxy.Timeout.Write != 0 {
		proxy.WriteTimeout = s.cfg.Proxy.Timeout.Write
		proxy.WriteTimeoutDuration = time.Duration(proxy.WriteTimeout).Abs() * time.Second
	}

	if len(s.cfg.Proxy.Colors) != 0 {
		utils.SetColor(s.cfg.Proxy.Colors)
	}

	// ReloadConfig never re-read the window, so `reload` could not change it.
	proxy.RatelimitWindow = s.cfg.Proxy.RatelimitWindow
	proxy.IPRatelimit = s.cfg.Proxy.Ratelimits["requests"]
	proxy.FPRatelimit = s.cfg.Proxy.Ratelimits["unknownFingerprint"]
	proxy.FailChallengeRatelimit = s.cfg.Proxy.Ratelimits["challengeFailures"]
	proxy.FailRequestRatelimit = s.cfg.Proxy.Ratelimits["noRequestsSent"]

	// --- domain tables ----------------------------------------------------
	names := make([]string, 0, len(s.domains))
	keep := make(map[string]struct{}, len(s.domains)+1)
	for _, domain := range s.domains {
		names = append(names, domain.name)
		keep[domain.name] = struct{}{}
	}
	keep[DebugDomain] = struct{}{}

	converged := false

	firewall.Mutex.Lock()

	for _, domain := range s.domains {
		domains.DomainsData[domain.name] = mergeDomainData(domains.DomainsData[domain.name], domain)
		domains.DomainsMap.Store(domain.name, domain.settings)
	}

	// Converge to the file: a domain deleted from config.json kept serving to
	// its old backend until the next restart, because reload only ever added.
	for name := range domains.DomainsData {
		if _, wanted := keep[name]; wanted {
			continue
		}
		delete(domains.DomainsData, name)
		domains.DomainsMap.Delete(name)
		converged = true
	}
	// DomainsMap can hold entries DomainsData never had (an earlier publish
	// that was interrupted, or a test), so sweep it independently.
	domains.DomainsMap.Range(func(key, _ any) bool {
		name, ok := key.(string)
		if !ok {
			domains.DomainsMap.Delete(key)
			converged = true
			return true
		}
		if _, wanted := keep[name]; !wanted {
			domains.DomainsMap.Delete(key)
			converged = true
		}
		return true
	})

	ensureDebugDomain()

	domains.Domains = names

	firewall.Mutex.Unlock()

	// Drop pooled backend connections whenever a domain went away or moved, so
	// the removed domain's idle keep-alives go with it.
	if converged || backendsChanged(previous, s.cfg) {
		resetTransports()
	}

	// --- terminal UI ------------------------------------------------------
	// names[0] is safe: validate() guarantees at least one domain.
	switch {
	case m == modeStartup:
		proxy.WatchedDomain = names[0]
	case proxy.WatchedDomain == "" || proxy.WatchedDomain == DebugDomain:
		// `domain` with no argument means "list them all"; a reload must not
		// silently drag the operator back into a single-domain view.
	default:
		if _, wanted := keep[proxy.WatchedDomain]; !wanted {
			proxy.WatchedDomain = names[0]
		}
	}
}

// mergeDomainData carries live mitigation state across a publish.
//
// A reload during an attack used to reset Stage to 1 and zero every counter,
// throwing away the escalation the proxy had just earned. Everything the
// monitor owns (stage, stage lock, attack flags, cooldown, counters, peaks,
// logs) is preserved for a domain that still exists; only the two fields the
// configuration owns are overwritten.
//
// For a domain that did not exist before, `prev` is the zero DomainData and the
// Stage < 1 branch below produces exactly the fresh state Load used to build.
func mergeDomainData(prev domains.DomainData, domain stagedDomain) domains.DomainData {
	next := prev

	next.Name = domain.name
	next.Stage2Difficulty = domain.difficulty

	if next.Stage < 1 {
		// Stage 0 is the "domain not found" sentinel the terminal UI prints;
		// a real domain must never sit on it.
		next.Stage = 1
		next.StageManuallySet = false
	}
	if next.LastLogs == nil {
		next.LastLogs = []domains.DomainLog{}
	}
	if next.RequestLogger == nil {
		next.RequestLogger = []domains.RequestLog{}
	}

	return next
}

// ensureDebugDomain registers the pseudo-domain without disturbing it if it is
// already there. Reload never registered it at all, so it only existed because
// nothing ever deleted it.
//
// Callers must hold firewall.Mutex.
func ensureDebugDomain() {
	if _, ok := domains.DomainsMap.Load(DebugDomain); !ok {
		domains.DomainsMap.Store(DebugDomain, domains.DomainSettings{Name: DebugDomain})
	}
	if _, ok := domains.DomainsData[DebugDomain]; !ok {
		domains.DomainsData[DebugDomain] = domains.DomainData{
			Name:          DebugDomain,
			Stage:         0,
			LastLogs:      []domains.DomainLog{},
			RequestLogger: []domains.RequestLog{},
		}
	}
}

// backendsChanged reports whether any domain now points somewhere else. A nil
// previous config means nothing was ever published, so there is nothing pooled.
func backendsChanged(previous, next *domains.Configuration) bool {
	if previous == nil {
		return false
	}
	if len(previous.Domains) != len(next.Domains) {
		return true
	}

	old := make(map[string]string, len(previous.Domains))
	for _, domain := range previous.Domains {
		old[domain.Name] = domain.Scheme + "://" + domain.Backend
	}
	for _, domain := range next.Domains {
		if old[domain.Name] != domain.Scheme+"://"+domain.Backend {
			return true
		}
	}
	return false
}
