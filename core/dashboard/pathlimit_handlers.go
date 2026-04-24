package dashboard

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"lancarsec/core/config"
	"lancarsec/core/domains"
	"lancarsec/core/store"
)

// HandlePathLimits GET returns the per-domain path rate limits; POST
// appends a new one. Delete is routed via HandlePathLimitDelete. Manage
// permission required for writes; view for reads.
func HandlePathLimits(w http.ResponseWriter, r *http.Request, domain string) {
	s := requireSession(w, r)
	if s == nil {
		return
	}
	if IsGlobal(domain) {
		http.Error(w, "path rate limits are per-domain; pick a specific domain", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !requireView(w, r, s, domain) {
			return
		}
		writeJSON(w, map[string]any{"domain": domain, "entries": loadPathLimits(domain)})
	case http.MethodPost:
		if !requireManage(w, r, s, domain) {
			return
		}
		var body domains.PathRateLimit
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if err := validatePathLimit(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := appendPathLimit(domain, body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		config.Apply(config.ModeReload)
		store.LogEvent(r.Context(), s.Username, s.UserID, "pathlimit_add", domain, clientIP(r), body)
		writeJSON(w, map[string]any{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// HandlePathLimitDelete removes one PathRateLimit by index for a domain.
func HandlePathLimitDelete(w http.ResponseWriter, r *http.Request, domain string, index int) {
	s := requireSession(w, r)
	if s == nil {
		return
	}
	if !requireManage(w, r, s, domain) {
		return
	}
	if err := deletePathLimitAt(domain, index); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	config.Apply(config.ModeReload)
	store.LogEvent(r.Context(), s.Username, s.UserID, "pathlimit_delete", domain, clientIP(r),
		map[string]any{"index": index})
	writeJSON(w, map[string]any{"ok": true})
}

func loadPathLimits(domain string) []domains.PathRateLimit {
	cfg := domains.LoadConfig()
	if cfg == nil {
		return nil
	}
	for _, d := range cfg.Domains {
		if d.Name == domain {
			return d.PathRateLimits
		}
	}
	return nil
}

// validatePathLimit rejects obviously broken rules before they hit the
// config file. The deeper compile-time validation (regex parse, glob shape)
// happens in firewall.compilePathLimit; a malformed rule there simply
// silently drops instead of failing the whole config reload.
func validatePathLimit(e domains.PathRateLimit) error {
	if e.Match == "" {
		return errors.New("match is required")
	}
	if e.Limit <= 0 {
		return errors.New("limit must be > 0")
	}
	// Match prefix is optional but must be one of the known kinds when set.
	if idx := strings.Index(e.Match, ":"); idx > 0 {
		kind := e.Match[:idx]
		switch kind {
		case "prefix", "exact", "regex", "path":
		default:
			return errors.New("match prefix must be prefix: / exact: / regex: / path:")
		}
	}
	if e.Method != "" && !isValidMethod(e.Method) {
		return errors.New("method must be blank or a valid HTTP verb")
	}
	if e.Action != "" && e.Action != "block" && e.Action != "challenge" {
		return errors.New("action must be block or challenge")
	}
	return nil
}

func isValidMethod(m string) bool {
	switch strings.ToUpper(m) {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return true
	}
	return false
}
