package config

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"lancarsec/core/domains"
	"lancarsec/core/firewall"
	"lancarsec/core/proxy"
	"lancarsec/core/transport"
	"lancarsec/core/trusted"
	"lancarsec/core/utils"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kor44/gofilter"
)

// Mode controls which side-effects happen when applying a config.
// Startup runs strict validation and one-shot initialization (fingerprints,
// trusted CIDR loader, debug domain, version check); Reload skips those and
// only re-applies the fields that are safe to rotate at runtime.
type Mode int

const (
	ModeStartup Mode = iota
	ModeReload
)

// Apply reads config.json and wires the result into the runtime state.
// Both config.Load and the monitor-triggered reload call this, which is the
// fix for the historical divergence between the two code paths.
func Apply(mode Mode) {
	file, err := os.Open("config.json")
	if err != nil {
		if os.IsNotExist(err) && mode == ModeStartup {
			Generate()
			file, err = os.Open("config.json")
			if err != nil {
				panic(err)
			}
		} else {
			panic(err)
		}
	}
	defer file.Close()

	// Decode into a fresh configuration, then publish atomically so no
	// middleware request can observe a half-populated global during reload.
	cfg := &domains.Configuration{}
	if err := json.NewDecoder(file).Decode(cfg); err != nil {
		panic(err)
	}
	domains.StoreConfig(cfg)

	applyProxyFields(mode)
	applyTimeouts()
	applyRateLimits()
	if err := trusted.Load(); err != nil {
		panic("[ " + utils.PrimaryColor("!") + " ] [ Error Loading Trusted Proxy CIDRs: " + utils.PrimaryColor(err.Error()) + " ]")
	}

	if mode == ModeStartup {
		fmt.Println("Loading Fingerprints ...")
		loadFingerprintMap("global/fingerprints/known_fingerprints.json", firewall.StoreKnown)
		loadFingerprintMap("global/fingerprints/bot_fingerprints.json", firewall.StoreBot)
		loadFingerprintMap("global/fingerprints/malicious_fingerprints.json", firewall.StoreForbidden)
	}

	cfg = domains.LoadConfig()
	domainNames := make([]string, 0, len(cfg.Domains))
	activeDomains := map[string]struct{}{}
	for i := range cfg.Domains {
		domainNames = append(domainNames, cfg.Domains[i].Name)
		activeDomains[cfg.Domains[i].Name] = struct{}{}
		buildDomain(&cfg.Domains[i])
	}
	domains.StoreDomainNames(domainNames)
	pruneRemovedDomains(activeDomains)

	// Publish blocklists (global + per-domain) to the firewall package so
	// the middleware hot path can evaluate lock-free via atomic.Pointer.
	perDomainBlock := map[string][]domains.BlockEntry{}
	perDomainPath := map[string][]domains.PathRateLimit{}
	for _, d := range cfg.Domains {
		if len(d.Blocklist) > 0 {
			perDomainBlock[d.Name] = d.Blocklist
		}
		if len(d.PathRateLimits) > 0 {
			perDomainPath[d.Name] = d.PathRateLimits
		}
	}
	firewall.RebuildBlocklists(domains.LoadConfig().Proxy.Blocklist, perDomainBlock)
	firewall.RebuildPathLimits(perDomainPath)

	// GeoLite2-ASN lookup is best-effort. If the .mmdb is missing the
	// reader stays nil and ASN-typed blocklist entries silently no-op.
	if err := firewall.LoadASN(); err != nil {
		fmt.Println("[ " + utils.PrimaryColor("!") + " ] [ Warning: ASN DB load failed: " + err.Error() + " ]")
	}

	if mode == ModeStartup {
		registerDebugDomain()
		if err := VersionCheck(); err != nil {
			panic("[ " + utils.PrimaryColor("!") + " ] [ " + err.Error() + " ]")
		}
	}

	if len(domainNames) == 0 {
		if mode == ModeStartup {
			AddDomain()
			Apply(ModeStartup)
		}
		return
	}

	if mode == ModeStartup || proxy.GetWatchedDomain() == "" {
		proxy.SetWatchedDomain(domainNames[0])
	}
}

// loadFingerprintMap decodes a JSON fingerprint file and publishes it via the
// supplied atomic store hook. Panics on startup errors so the operator is not
// quietly served an empty ruleset.
func loadFingerprintMap(path string, publish func(map[string]string)) {
	m := map[string]string{}
	if err := LoadFingerprints(path, &m); err != nil {
		panic("[ " + utils.PrimaryColor("!") + " ] [ " + err.Error() + " ]")
	}
	publish(m)
}

func applyProxyFields(mode Mode) {
	proxy.Cloudflare = domains.LoadConfig().Proxy.Cloudflare
	proxy.CloudflareFullSSL = domains.LoadConfig().Proxy.CloudflareFullSSL
	proxy.CloudflareEnforceOrigin = domains.LoadConfig().Proxy.CloudflareEnforceOrigin
	proxy.HideVersionHeader = domains.LoadConfig().Proxy.HideVersionHeader
	if proxy.CloudflareFullSSL && !proxy.Cloudflare {
		panic("[ " + utils.PrimaryColor("!") + " ] [ cloudflare_full_ssl requires cloudflare to also be true ]")
	}
	if proxy.CloudflareEnforceOrigin && !proxy.Cloudflare {
		panic("[ " + utils.PrimaryColor("!") + " ] [ cloudflare_enforce_origin requires cloudflare to also be true ]")
	}

	proxy.CookieSecret = domains.LoadConfig().Proxy.Secrets["cookie"]
	proxy.JSSecret = domains.LoadConfig().Proxy.Secrets["javascript"]
	proxy.CaptchaSecret = domains.LoadConfig().Proxy.Secrets["captcha"]
	proxy.AdminSecret = domains.LoadConfig().Proxy.AdminSecret
	proxy.APISecret = domains.LoadConfig().Proxy.APISecret

	if mode == ModeStartup {
		// Refuse to start with any placeholder secret. Reload is lenient so a
		// running proxy isn't killed by a user editing an unrelated field.
		checkSecret("Cookie Secret", proxy.CookieSecret)
		checkSecret("JS Secret", proxy.JSSecret)
		checkSecret("Captcha Secret", proxy.CaptchaSecret)
		checkSecret("Admin Secret", proxy.AdminSecret)
		checkSecret("API Secret", proxy.APISecret)
	}

	if len(domains.LoadConfig().Proxy.Colors) != 0 {
		utils.SetColor(domains.LoadConfig().Proxy.Colors)
	}
}

func checkSecret(name, value string) {
	if strings.Contains(value, "CHANGE_ME") {
		panic("[ " + utils.PrimaryColor("!") + " ] [ " + name + " Contains 'CHANGE_ME', Refusing To Load ]")
	}
}

func applyTimeouts() {
	t := domains.LoadConfig().Proxy.Timeout
	if t.Idle != 0 {
		proxy.IdleTimeout = t.Idle
		proxy.IdleTimeoutDuration = time.Duration(proxy.IdleTimeout).Abs() * time.Second
	}
	if t.Read != 0 {
		proxy.ReadTimeout = t.Read
		proxy.ReadTimeoutDuration = time.Duration(proxy.ReadTimeout).Abs() * time.Second
	}
	if t.ReadHeader != 0 {
		proxy.ReadHeaderTimeout = t.ReadHeader
		proxy.ReadHeaderTimeoutDuration = time.Duration(proxy.ReadHeaderTimeout).Abs() * time.Second
	}
	if t.Write != 0 {
		proxy.WriteTimeout = t.Write
		proxy.WriteTimeoutDuration = time.Duration(proxy.WriteTimeout).Abs() * time.Second
	}
}

func applyRateLimits() {
	if domains.LoadConfig().Proxy.RatelimitWindow < 10 {
		domains.LoadConfig().Proxy.RatelimitWindow = 10
	}
	proxy.RatelimitWindow = domains.LoadConfig().Proxy.RatelimitWindow
	proxy.IPRatelimit = domains.LoadConfig().Proxy.Ratelimits["requests"]
	proxy.FPRatelimit = domains.LoadConfig().Proxy.Ratelimits["unknownFingerprint"]
	proxy.FailChallengeRatelimit = domains.LoadConfig().Proxy.Ratelimits["challengeFailures"]
	proxy.FailRequestRatelimit = domains.LoadConfig().Proxy.Ratelimits["noRequestsSent"]
}

func buildDomain(d *domains.Domain) {
	firewallRules := make([]domains.Rule, 0, len(d.FirewallRules))
	for idx, fwRule := range d.FirewallRules {
		rule, err := gofilter.NewFilter(fwRule.Expression)
		if err != nil {
			panic("[ " + utils.PrimaryColor("!") + " ] [ Error Loading Custom Firewall Rules For " + d.Name + " ( Rule " + strconv.Itoa(idx) + " ) : " + utils.PrimaryColor(err.Error()) + " ]")
		}
		firewallRules = append(firewallRules, domains.Rule{Filter: rule, Action: fwRule.Action})
	}

	dProxy := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: d.Scheme, Host: d.Backend})
	dProxy.Transport = &transport.RoundTripper{}
	verifyBackendTLS := backendTLSVerify(d)
	transport.Register(d.Name, transport.Config{
		BackendTLSVerify: &verifyBackendTLS,
		MaxIdleConns:     d.MaxIdleConns,
		MaxConnsPerHost:  d.MaxConnsPerHost,
	})

	var cert tls.Certificate
	if !proxy.Cloudflare || proxy.CloudflareFullSSL {
		var certErr error
		cert, certErr = tls.LoadX509KeyPair(d.Certificate, d.Key)
		if certErr != nil {
			panic("[ " + utils.PrimaryColor("!") + " ] [ " + utils.PrimaryColor("Error Loading Certificates: "+certErr.Error()) + " ]")
		}
	}

	domains.DomainsMap.Store(d.Name, domains.DomainSettings{
		Name:               d.Name,
		CustomRules:        firewallRules,
		RawCustomRules:     d.FirewallRules,
		DomainProxy:        dProxy,
		DomainCertificates: cert,
		DomainWebhooks: domains.WebhookSettings{
			URL:            d.Webhook.URL,
			Name:           d.Webhook.Name,
			Avatar:         d.Webhook.Avatar,
			AttackStartMsg: d.Webhook.AttackStartMsg,
			AttackStopMsg:  d.Webhook.AttackStopMsg,
		},
		BypassStage1:        d.BypassStage1,
		BypassStage2:        d.BypassStage2,
		DisableBypassStage3: d.DisableBypassStage3,
		DisableRawStage3:    d.DisableRawStage3,
		DisableBypassStage2: d.DisableBypassStage2,
		DisableRawStage2:    d.DisableRawStage2,
	})

	if d.Stage2Difficulty == 0 {
		d.Stage2Difficulty = 5
	}
	if d.Stage2Difficulty < 0 {
		d.Stage2Difficulty = 5
	}
	if d.Stage2Difficulty > firewall.MaxDifficulty {
		d.Stage2Difficulty = firewall.MaxDifficulty
	}

	firewall.DataMu.Lock()
	defer firewall.DataMu.Unlock()
	dd, exists := domains.DomainsData[d.Name]
	if !exists {
		dd = domains.DomainData{
			Stage:         1,
			LastLogs:      []domains.DomainLog{},
			RequestLogger: []domains.RequestLog{},
		}
	}
	dd.Name = d.Name
	dd.Stage2Difficulty = d.Stage2Difficulty
	if dd.Stage <= 0 {
		dd.Stage = 1
	}
	if dd.LastLogs == nil {
		dd.LastLogs = []domains.DomainLog{}
	}
	if dd.RequestLogger == nil {
		dd.RequestLogger = []domains.RequestLog{}
	}
	domains.DomainsData[d.Name] = dd
}

func backendTLSVerify(d *domains.Domain) bool {
	verify := true
	if d.BackendTLSVerify != nil {
		verify = *d.BackendTLSVerify
	}
	if d.BackendTLSInsecure {
		verify = false
	}
	return verify
}

func registerDebugDomain() {
	domains.DomainsMap.Store("debug", domains.DomainSettings{Name: "debug"})
	firewall.DataMu.Lock()
	defer firewall.DataMu.Unlock()
	domains.DomainsData["debug"] = domains.DomainData{
		Name:          "debug",
		Stage:         0,
		LastLogs:      []domains.DomainLog{},
		RequestLogger: []domains.RequestLog{},
	}
}

func pruneRemovedDomains(active map[string]struct{}) {
	domains.DomainsMap.Range(func(k, _ any) bool {
		name, ok := k.(string)
		if !ok || name == "debug" {
			return true
		}
		if _, keep := active[name]; !keep {
			domains.DomainsMap.Delete(k)
		}
		return true
	})

	firewall.DataMu.Lock()
	for name := range domains.DomainsData {
		if name == "debug" {
			continue
		}
		if _, keep := active[name]; !keep {
			delete(domains.DomainsData, name)
		}
	}
	firewall.DataMu.Unlock()
}
