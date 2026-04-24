package dashboard

import (
	"encoding/json"
	"net/http"

	"lancarsec/core/config"
	"lancarsec/core/domains"
	"lancarsec/core/store"
)

// HandleBlocklist GET returns the active blocklist for a scope (global or a
// domain name), POST appends a new entry. Expects JSON {type, value, reason,
// expires}. After mutate, a config.Apply(ModeReload) is triggered so the
// change takes effect live.
func HandleBlocklist(w http.ResponseWriter, r *http.Request, scope string) {
	s := requireSession(w, r)
	if s == nil {
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !requireView(w, r, s, scope) {
			return
		}
		writeJSON(w, map[string]any{"scope": scope, "entries": loadBlockEntries(scope)})
	case http.MethodPost:
		if !requireManage(w, r, s, scope) {
			return
		}
		var body domains.BlockEntry
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		body.AddedBy = s.Username
		if err := validateBlockEntry(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := appendBlock(scope, body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		config.Apply(config.ModeReload)
		store.LogEvent(r.Context(), s.Username, s.UserID, "block_add", scopeForAudit(scope), clientIP(r), body)
		writeJSON(w, map[string]any{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// HandleBlockDelete removes a block entry by index at the named scope.
func HandleBlockDelete(w http.ResponseWriter, r *http.Request, scope string, index int) {
	s := requireSession(w, r)
	if s == nil {
		return
	}
	if !requireManage(w, r, s, scope) {
		return
	}
	if err := deleteBlockAt(scope, index); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	config.Apply(config.ModeReload)
	store.LogEvent(r.Context(), s.Username, s.UserID, "block_delete", scopeForAudit(scope), clientIP(r), map[string]any{"index": index})
	writeJSON(w, map[string]any{"ok": true})
}

// scopeForAudit turns the blocklist scope string into a clean value for the
// audit log's domain column: "global" / __all collapse to empty so the
// filter can match global rows uniformly.
func scopeForAudit(scope string) string {
	if scope == "global" || scope == AllDomainsSentinel {
		return ""
	}
	return scope
}

func loadBlockEntries(scope string) []domains.BlockEntry {
	cfg := domains.LoadConfig()
	if cfg == nil {
		return nil
	}
	if scope == "global" || scope == AllDomainsSentinel {
		return cfg.Proxy.Blocklist
	}
	for _, d := range cfg.Domains {
		if d.Name == scope {
			return d.Blocklist
		}
	}
	return nil
}

// validateBlockEntry rejects obviously invalid entries before they're
// persisted. Deeper parse-validation happens at blocklist-compile time
// (in firewall.compile) where a malformed CIDR or regex is simply dropped;
// surfacing the error here lets the UI show actionable feedback.
func validateBlockEntry(e domains.BlockEntry) error {
	switch e.Type {
	case "ip", "cidr", "ua_contains", "ua_regex", "asn":
	default:
		return errBadField("type must be ip|cidr|ua_contains|ua_regex|asn")
	}
	if e.Value == "" {
		return errBadField("value is required")
	}
	return nil
}

type blockErr string

func (b blockErr) Error() string { return string(b) }
func errBadField(msg string) error { return blockErr(msg) }
