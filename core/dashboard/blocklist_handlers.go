package dashboard

import (
	"encoding/json"
	"net/http"

	"lancarsec/core/config"
	"lancarsec/core/domains"
)

// HandleBlocklist GET returns the active blocklist for a scope (global or a
// domain name), POST appends a new entry. Expects JSON {type, value, reason,
// expires}. After mutate, a config.Apply(ModeReload) is triggered so the
// change takes effect live.
func HandleBlocklist(w http.ResponseWriter, r *http.Request, scope string) {
	user, ok := IsAuthenticated(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]any{"scope": scope, "entries": loadBlockEntries(scope)})
	case http.MethodPost:
		var body domains.BlockEntry
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		body.AddedBy = user
		if err := validateBlockEntry(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := appendBlock(scope, body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		config.Apply(config.ModeReload)
		writeJSON(w, map[string]any{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// HandleBlockDelete removes a block entry by index at the named scope.
func HandleBlockDelete(w http.ResponseWriter, r *http.Request, scope string, index int) {
	if _, ok := IsAuthenticated(r); !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if err := deleteBlockAt(scope, index); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	config.Apply(config.ModeReload)
	writeJSON(w, map[string]any{"ok": true})
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
