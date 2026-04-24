package dashboard

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"lancarsec/core/config"
	"lancarsec/core/domains"
	"lancarsec/core/firewall"
	"lancarsec/core/proxy"
)

// sessionCookie is the HttpOnly cookie name holding the session token.
const sessionCookie = "lancarsec_session"

// IsAuthenticated reports whether the request carries a valid session.
// Used by middleware to gate dashboard/API routes.
func IsAuthenticated(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", false
	}
	return SessionUser(c.Value)
}

// HandleLogin serves the login form (GET) or validates credentials and sets
// a session cookie (POST). On success it 302s to the overview page.
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		renderLogin(w, "")
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			renderLogin(w, "Malformed login form.")
			return
		}
		ok, user := VerifyCredentials(r.PostForm.Get("username"), r.PostForm.Get("password"))
		if !ok {
			// Fixed delay to blunt login brute-forcing. Bcrypt cost 12 already
			// costs ~200 ms, but an explicit floor makes it consistent.
			time.Sleep(300 * time.Millisecond)
			renderLogin(w, "Invalid credentials.")
			return
		}
		token := CreateSession(user)
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookie,
			Value:    token,
			Path:     "/_lancarsec",
			HttpOnly: true,
			Secure:   requestIsSecure(r),
			SameSite: http.SameSiteStrictMode,
			Expires:  time.Now().Add(24 * time.Hour),
		})
		http.Redirect(w, r, "/_lancarsec/dashboard/overview", http.StatusFound)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// HandleLogout revokes the session and clears the cookie. Accepts POST only
// to protect against CSRF-triggered logouts.
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		RevokeSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/_lancarsec",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   requestIsSecure(r),
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/_lancarsec/login", http.StatusFound)
}

// HandlePage renders one of the dashboard tabs. tab must be one of
// "overview", "rules", "logs", "analytics", "settings".
func HandlePage(tab string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := IsAuthenticated(r)
		if !ok {
			http.Redirect(w, r, "/_lancarsec/login", http.StatusFound)
			return
		}

		domain := r.URL.Query().Get("domain")
		list := domainList()
		if domain == "" {
			// Default to the global view so the operator lands on the
			// cross-domain overview rather than being silently pinned to
			// one configured domain.
			http.Redirect(w, r, "/_lancarsec/dashboard/"+tab+"?domain="+AllDomainsSentinel, http.StatusFound)
			return
		}

		data := pageData(titleFor(tab), tab, domain, user, list)

		var t *template.Template
		switch tab {
		case "overview":
			t = tmplOverview
		case "rules":
			t = tmplRules
		case "logs":
			t = tmplLogs
		case "analytics":
			t = tmplAnalytics
		case "settings":
			t = tmplSettings
		case "blocklist":
			t = tmplBlocklist
		default:
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		if err := t.ExecuteTemplate(w, "layout", data); err != nil {
			http.Error(w, "template error", http.StatusInternalServerError)
		}
	}
}

func renderLogin(w http.ResponseWriter, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = tmplLogin.Execute(w, loginData{CSS: template.CSS(baseCSS), Error: errMsg})
}

func titleFor(tab string) string {
	switch tab {
	case "overview":
		return "Overview"
	case "rules":
		return "Firewall Rules"
	case "blocklist":
		return "Blocklist"
	case "logs":
		return "Logs"
	case "analytics":
		return "Analytics"
	case "settings":
		return "Settings"
	}
	return "Dashboard"
}

func domainList() []string {
	cfg := domains.LoadConfig()
	if cfg == nil {
		return nil
	}
	out := make([]string, 0, len(cfg.Domains))
	for _, d := range cfg.Domains {
		out = append(out, d.Name)
	}
	return out
}

// domainListWithGlobal is what the sidebar renders — a pseudo-entry for the
// aggregate view is prepended so the operator can always pick "All domains"
// from any page. The sentinel travels through the URL as ?domain=__all.
func domainListWithGlobal() []string {
	list := domainList()
	return append([]string{AllDomainsSentinel}, list...)
}

// ------------- API handlers (JSON) -------------

// statsFor returns the live state snapshot for a domain. When domain is the
// AllDomainsSentinel, delegates to aggregateStats for the global rollup.
// Shared by the overview page JSON poll and the SSE stream.
func statsFor(domain string) map[string]any {
	if IsGlobal(domain) {
		return aggregateStats()
	}
	firewall.DataMu.RLock()
	d := domains.DomainsData[domain]
	firewall.DataMu.RUnlock()

	ctr := domains.CountersFor(domain)
	return map[string]any{
		"domain":        domain,
		"is_global":     false,
		"stage":         d.Stage,
		"stage_locked":  d.StageManuallySet,
		"rps":           d.RequestsPerSecond,
		"rps_bypassed":  d.RequestsBypassedPerSecond,
		"rps_blocked":   d.RequestsPerSecond - d.RequestsBypassedPerSecond,
		"peak_rps":      d.PeakRequestsPerSecond,
		"total":         ctr.Total.Load(),
		"bypassed":      ctr.Bypassed.Load(),
		"cpu":           proxy.CpuUsage,
		"ram":           proxy.RamUsage,
		"bypass_attack": d.BypassAttack,
		"raw_attack":    d.RawAttack,
		"logs":          serializeLogs(d.LastLogs),
	}
}

func serializeLogs(logs []domains.DomainLog) []map[string]any {
	out := make([]map[string]any, 0, len(logs))
	for _, l := range logs {
		out = append(out, map[string]any{
			"time":        l.Time,
			"ip":          l.IP,
			"engine":      l.BrowserFP,
			"bot":         l.BotFP,
			"fingerprint": l.TLSFP,
			"user_agent":  l.Useragent,
			"path":        l.Path,
		})
	}
	return out
}

// HandleStream is the Server-Sent Events endpoint that pushes a stats
// snapshot once per second while the client is connected. Switching from
// HTTP-poll to SSE keeps the round-trip count bounded under an open
// dashboard without needing WebSocket upgrade logic.
func HandleStream(w http.ResponseWriter, r *http.Request) {
	if _, ok := IsAuthenticated(r); !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "missing domain", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	send := func() {
		payload, err := json.Marshal(statsFor(domain))
		if err != nil {
			return
		}
		fmt.Fprintf(w, "event: stats\ndata: %s\n\n", payload)
		flusher.Flush()
	}
	send() // fire once immediately so the UI doesn't wait a full tick
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			send()
		}
	}
}

// HandleStatsJSON is a plain JSON fallback for clients that can't use SSE
// (test tools, curl, anything without EventSource).
func HandleStatsJSON(w http.ResponseWriter, r *http.Request) {
	if _, ok := IsAuthenticated(r); !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "missing domain", http.StatusBadRequest)
		return
	}
	writeJSON(w, statsFor(domain))
}

// HandleRules GET returns the current rule set for a domain; POST appends a
// new rule; the DELETE-via-URL variant removes by index.
func HandleRules(w http.ResponseWriter, r *http.Request, domain string) {
	if _, ok := IsAuthenticated(r); !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	settingsVal, exists := domains.DomainsMap.Load(domain)
	if !exists {
		http.Error(w, "unknown domain", http.StatusNotFound)
		return
	}
	settings := settingsVal.(domains.DomainSettings)
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]any{"rules": settings.RawCustomRules})
	case http.MethodPost:
		var newRule domains.JsonRule
		if err := json.NewDecoder(r.Body).Decode(&newRule); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if err := appendRule(domain, newRule); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		config.Apply(config.ModeReload)
		writeJSON(w, map[string]any{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// HandleRuleDelete removes a rule by position (0-indexed), persists the
// config, then triggers a reload so the change is applied live without a
// restart.
func HandleRuleDelete(w http.ResponseWriter, r *http.Request, domain string, index int) {
	if _, ok := IsAuthenticated(r); !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if err := deleteRuleAt(domain, index); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	config.Apply(config.ModeReload)
	writeJSON(w, map[string]any{"ok": true})
}

// HandleStage locks/unlocks the stage for a domain from the Overview page.
// Posting {"stage": 0} resumes auto; 1-3 force-locks.
func HandleStage(w http.ResponseWriter, r *http.Request, domain string) {
	if _, ok := IsAuthenticated(r); !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body struct{ Stage int }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	firewall.DataMu.Lock()
	d := domains.DomainsData[domain]
	if body.Stage <= 0 {
		d.Stage = 1
		d.StageManuallySet = false
	} else {
		d.Stage = body.Stage
		d.StageManuallySet = true
	}
	domains.DomainsData[domain] = d
	firewall.DataMu.Unlock()
	writeJSON(w, map[string]any{"ok": true, "stage": d.Stage})
}

// HandleLogsDelete clears the log tail for one domain.
func HandleLogsDelete(w http.ResponseWriter, r *http.Request, domain string) {
	if _, ok := IsAuthenticated(r); !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	firewall.DataMu.Lock()
	d := domains.DomainsData[domain]
	d.LastLogs = nil
	domains.DomainsData[domain] = d
	firewall.DataMu.Unlock()
	writeJSON(w, map[string]any{"ok": true})
}

// HandleAnalytics returns the RequestLogger samples for charting.
func HandleAnalytics(w http.ResponseWriter, r *http.Request, domain string) {
	if _, ok := IsAuthenticated(r); !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if IsGlobal(domain) {
		writeJSON(w, aggregateAnalytics())
		return
	}
	firewall.DataMu.RLock()
	d := domains.DomainsData[domain]
	firewall.DataMu.RUnlock()

	samples := make([]map[string]any, 0, len(d.RequestLogger))
	for _, s := range d.RequestLogger {
		cpuF, _ := strconv.ParseFloat(s.CpuUsage, 64)
		samples = append(samples, map[string]any{
			"t":       s.Time.Format("15:04:05"),
			"total":   s.Total,
			"allowed": s.Allowed,
			"cpu":     cpuF,
		})
	}
	writeJSON(w, map[string]any{
		"domain":        domain,
		"samples":       samples,
		"peak_rps":      d.PeakRequestsPerSecond,
		"peak_bypassed": d.PeakRequestsBypassedPerSecond,
		"bypass_attack": d.BypassAttack,
		"raw_attack":    d.RawAttack,
	})
}

// HandleSettings returns a redacted view of the live configuration for the
// settings page. Secret material is replaced with the string "•••••".
func HandleSettings(w http.ResponseWriter, r *http.Request) {
	if _, ok := IsAuthenticated(r); !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	cfg := domains.LoadConfig()
	if cfg == nil {
		http.Error(w, "no config", http.StatusInternalServerError)
		return
	}
	redacted := redactConfig(cfg)
	raw, _ := json.MarshalIndent(redacted, "", "  ")
	domList := make([]map[string]string, 0, len(cfg.Domains))
	for _, d := range cfg.Domains {
		domList = append(domList, map[string]string{
			"name":    d.Name,
			"backend": d.Backend,
			"scheme":  d.Scheme,
		})
	}
	writeJSON(w, map[string]any{
		"cloudflare":                cfg.Proxy.Cloudflare,
		"cloudflare_full_ssl":       cfg.Proxy.CloudflareFullSSL,
		"cloudflare_enforce_origin": cfg.Proxy.CloudflareEnforceOrigin,
		"hide_version_header":       cfg.Proxy.HideVersionHeader,
		"timeout_idle":              cfg.Proxy.Timeout.Idle,
		"timeout_read":              cfg.Proxy.Timeout.Read,
		"timeout_write":             cfg.Proxy.Timeout.Write,
		"timeout_readheader":        cfg.Proxy.Timeout.ReadHeader,
		"ratelimit_window":          cfg.Proxy.RatelimitWindow,
		"rl_requests":               cfg.Proxy.Ratelimits["requests"],
		"rl_unknown_fingerprint":    cfg.Proxy.Ratelimits["unknownFingerprint"],
		"rl_challenge_failures":     cfg.Proxy.Ratelimits["challengeFailures"],
		"rl_no_requests":            cfg.Proxy.Ratelimits["noRequestsSent"],
		"domains":                   domList,
		"raw":                       string(raw),
	})
}

// HandleReload triggers a hot config reload. Posts only, auth required.
func HandleReload(w http.ResponseWriter, r *http.Request) {
	if _, ok := IsAuthenticated(r); !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	config.Apply(config.ModeReload)
	writeJSON(w, map[string]any{"ok": true})
}

// ------------- helpers -------------

// requestIsSecure reports whether the request reached LancarSec over TLS or
// through a TLS-terminating proxy (Cloudflare) so we can flip the session
// cookie's Secure flag appropriately. Plain HTTP localhost development
// wouldn't be able to hold a Secure cookie otherwise.
func requestIsSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	if strings.Contains(r.Header.Get("Cf-Visitor"), "https") {
		return true
	}
	return false
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

// redactConfig returns a shallow copy of the configuration with secrets
// blanked so the Settings page's raw JSON view doesn't disclose them.
func redactConfig(cfg *domains.Configuration) *domains.Configuration {
	clone := *cfg
	clone.Proxy.AdminSecret = redact(cfg.Proxy.AdminSecret)
	clone.Proxy.APISecret = redact(cfg.Proxy.APISecret)
	secrets := map[string]string{}
	for k, v := range cfg.Proxy.Secrets {
		secrets[k] = redact(v)
	}
	clone.Proxy.Secrets = secrets
	domList := make([]domains.Domain, len(cfg.Domains))
	copy(domList, cfg.Domains)
	for i := range domList {
		domList[i].Key = redact(domList[i].Key)
	}
	clone.Domains = domList
	return &clone
}

func redact(s string) string {
	if s == "" {
		return ""
	}
	if len(s) < 4 {
		return "•••"
	}
	return s[:2] + strings.Repeat("•", len(s)-4) + s[len(s)-2:]
}
