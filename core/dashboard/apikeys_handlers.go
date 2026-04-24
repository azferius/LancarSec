package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"lancarsec/core/store"
)

// HandleAPIKeysList returns keys. Superadmins see every key; regular users
// see only their own (used for a future self-service "My keys" page).
func HandleAPIKeysList(w http.ResponseWriter, r *http.Request) {
	s := requireSession(w, r)
	if s == nil {
		return
	}
	var keys []*store.APIKey
	var err error
	if s.Role == store.RoleSuperAdmin {
		keys, err = store.ListAPIKeys(r.Context(), 0)
	} else {
		keys, err = store.ListAPIKeys(r.Context(), s.UserID)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Flatten to wire format so the frontend gets field names it expects.
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]any{
			"id":           k.ID,
			"user_id":      k.UserID,
			"username":     k.Username,
			"name":         k.Name,
			"prefix":       k.Prefix,
			"scopes":       k.Scopes,
			"created_at":   k.CreatedAt,
			"last_used_at": k.LastUsedAt,
			"revoked":      k.Revoked,
		})
	}
	writeJSON(w, map[string]any{"keys": out})
}

// HandleAPIKeyCreate issues a new key for the logged-in user (or for an
// arbitrary user when superadmin specifies user_id). Responds with the
// plaintext exactly once — the UI prompts the operator to copy it.
func HandleAPIKeyCreate(w http.ResponseWriter, r *http.Request) {
	s := requireSession(w, r)
	if s == nil {
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		UserID int64  `json:"user_id"`
		Name   string `json:"name"`
		Scopes string `json:"scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if body.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	target := body.UserID
	if target <= 0 || s.Role != store.RoleSuperAdmin {
		// Non-superadmins can only create keys for themselves.
		target = s.UserID
	}
	plaintext, id, err := store.CreateAPIKey(r.Context(), target, body.Name, body.Scopes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	store.LogEvent(r.Context(), s.Username, s.UserID, "apikey_create", "", clientIP(r),
		map[string]any{"key_id": id, "target_user": target, "name": body.Name})
	writeJSON(w, map[string]any{
		"ok":        true,
		"id":        id,
		"plaintext": plaintext,
		"note":      "Copy this key now. It cannot be retrieved later.",
	})
}

// HandleAPIKeyRevoke flips the row to revoked. Superadmins can revoke any
// key; regular users can only revoke their own.
func HandleAPIKeyRevoke(w http.ResponseWriter, r *http.Request, keyID int64) {
	s := requireSession(w, r)
	if s == nil {
		return
	}
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.Role != store.RoleSuperAdmin {
		// Fetch the key to make sure the operator owns it.
		keys, err := store.ListAPIKeys(r.Context(), s.UserID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		owned := false
		for _, k := range keys {
			if k.ID == keyID {
				owned = true
				break
			}
		}
		if !owned {
			forbid(w, "cannot revoke a key you don't own")
			return
		}
	}
	if err := store.RevokeAPIKey(r.Context(), keyID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	store.LogEvent(r.Context(), s.Username, s.UserID, "apikey_revoke", "", clientIP(r),
		map[string]any{"key_id": keyID})
	writeJSON(w, map[string]any{"ok": true})
}

// sessionFromAPIKey attempts to synthesize a session from an Authorization:
// Bearer header. Returns nil if the header is absent or invalid so the
// caller falls back to cookie-based session auth. Used so scripts / CI
// pipelines can hit /api/dashboard/* without needing the browser cookie
// flow.
func sessionFromAPIKey(r *http.Request) *store.Session {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return nil
	}
	token := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	k, role, err := store.ResolveAPIKey(context.Background(), token)
	if err != nil {
		return nil
	}
	return &store.Session{
		Token:    token, // not a real session token, just a placeholder
		UserID:   k.UserID,
		Username: k.Username,
		Role:     role,
	}
}
