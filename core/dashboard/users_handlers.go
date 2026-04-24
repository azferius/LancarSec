package dashboard

import (
	"encoding/json"
	"net/http"
	"strconv"

	"lancarsec/core/store"
)

// HandleUsersList returns every user plus their domain grants. Superadmin
// only. Used by the user management page to render the table.
func HandleUsersList(w http.ResponseWriter, r *http.Request) {
	s := requireSession(w, r)
	if s == nil {
		return
	}
	if !requireSuperAdmin(w, s) {
		return
	}
	users, err := store.ListUsers(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	enriched := make([]map[string]any, 0, len(users))
	for _, u := range users {
		grants, _ := store.ListGrants(r.Context(), u.ID)
		domainsList := make([]map[string]string, 0, len(grants))
		for _, g := range grants {
			domainsList = append(domainsList, map[string]string{
				"domain":     g.Domain,
				"permission": g.Permission,
			})
		}
		enriched = append(enriched, map[string]any{
			"id":            u.ID,
			"username":      u.Username,
			"email":         u.Email,
			"role":          u.Role,
			"created_at":    u.CreatedAt,
			"last_login_at": u.LastLoginAt,
			"disabled":      u.Disabled,
			"domains":       domainsList,
		})
	}
	writeJSON(w, map[string]any{"users": enriched})
}

// HandleUserCreate POSTs {username, email, password, role}. Validates and
// inserts; returns the new user id.
func HandleUserCreate(w http.ResponseWriter, r *http.Request) {
	s := requireSession(w, r)
	if s == nil {
		return
	}
	if !requireSuperAdmin(w, s) {
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Username, Email, Password, Role string
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	id, err := store.CreateUser(r.Context(), body.Username, body.Email, body.Password, body.Role)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	store.LogEvent(r.Context(), s.Username, s.UserID, "user_create", "", clientIP(r),
		map[string]any{"new_user": body.Username, "role": body.Role})
	writeJSON(w, map[string]any{"ok": true, "id": id})
}

// HandleUserUpdate PATCH-ish: body carries whichever of {role, password,
// disabled} is being changed. Returns the final state so the UI can refresh
// a single row without re-listing.
func HandleUserUpdate(w http.ResponseWriter, r *http.Request, userID int64) {
	s := requireSession(w, r)
	if s == nil {
		return
	}
	if !requireSuperAdmin(w, s) {
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Role     string `json:"role,omitempty"`
		Password string `json:"password,omitempty"`
		Disabled *bool  `json:"disabled,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if body.Role != "" {
		if err := store.UpdateRole(r.Context(), userID, body.Role); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		store.LogEvent(r.Context(), s.Username, s.UserID, "user_update_role", "", clientIP(r),
			map[string]any{"user_id": userID, "role": body.Role})
	}
	if body.Password != "" {
		if err := store.SetPassword(r.Context(), userID, body.Password); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		store.LogEvent(r.Context(), s.Username, s.UserID, "user_password_reset", "", clientIP(r),
			map[string]any{"user_id": userID})
	}
	if body.Disabled != nil {
		var err error
		if *body.Disabled {
			err = store.DisableUser(r.Context(), userID)
		} else {
			err = store.EnableUser(r.Context(), userID)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		action := "user_enable"
		if *body.Disabled {
			action = "user_disable"
		}
		store.LogEvent(r.Context(), s.Username, s.UserID, action, "", clientIP(r),
			map[string]any{"user_id": userID})
	}
	writeJSON(w, map[string]any{"ok": true})
}

// HandleUserDelete removes the row (cascades sessions, grants, api_keys).
func HandleUserDelete(w http.ResponseWriter, r *http.Request, userID int64) {
	s := requireSession(w, r)
	if s == nil {
		return
	}
	if !requireSuperAdmin(w, s) {
		return
	}
	if userID == s.UserID {
		http.Error(w, "cannot delete yourself", http.StatusBadRequest)
		return
	}
	if err := store.DeleteUser(r.Context(), userID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	store.LogEvent(r.Context(), s.Username, s.UserID, "user_delete", "", clientIP(r),
		map[string]any{"user_id": userID})
	writeJSON(w, map[string]any{"ok": true})
}

// HandleUserGrant POST /users/<id>/grants with {domain, permission}.
// Single-shot upsert; sends DELETE to the same URL + index for revoke.
func HandleUserGrant(w http.ResponseWriter, r *http.Request, userID int64) {
	s := requireSession(w, r)
	if s == nil {
		return
	}
	if !requireSuperAdmin(w, s) {
		return
	}
	switch r.Method {
	case http.MethodPost:
		var body struct {
			Domain, Permission string
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if err := store.GrantDomain(r.Context(), userID, body.Domain, body.Permission, s.UserID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		store.LogEvent(r.Context(), s.Username, s.UserID, "grant_add", body.Domain, clientIP(r),
			map[string]any{"user_id": userID, "permission": body.Permission})
		writeJSON(w, map[string]any{"ok": true})
	case http.MethodDelete:
		domain := r.URL.Query().Get("domain")
		if domain == "" {
			http.Error(w, "missing domain", http.StatusBadRequest)
			return
		}
		if err := store.RevokeDomain(r.Context(), userID, domain); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		store.LogEvent(r.Context(), s.Username, s.UserID, "grant_revoke", domain, clientIP(r),
			map[string]any{"user_id": userID})
		writeJSON(w, map[string]any{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// HandleAudit returns paged audit events. Superadmin only. Query params:
// ?domain, ?action, ?user_id, ?limit (default 200, max 1000).
func HandleAudit(w http.ResponseWriter, r *http.Request) {
	s := requireSession(w, r)
	if s == nil {
		return
	}
	if !requireSuperAdmin(w, s) {
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}
	userID, _ := strconv.ParseInt(q.Get("user_id"), 10, 64)
	events, err := store.ListAudit(r.Context(), store.AuditFilter{
		Domain: q.Get("domain"),
		Action: q.Get("action"),
		UserID: userID,
		Limit:  limit,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"events": events})
}

// HandleSelfPassword lets a logged-in user change their own password
// without needing superadmin. Requires the current password to match.
func HandleSelfPassword(w http.ResponseWriter, r *http.Request) {
	s := requireSession(w, r)
	if s == nil {
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Current, New string
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if _, err := store.VerifyLogin(r.Context(), s.Username, body.Current); err != nil {
		http.Error(w, "current password mismatch", http.StatusForbidden)
		return
	}
	if err := store.SetPassword(r.Context(), s.UserID, body.New); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	store.LogEvent(r.Context(), s.Username, s.UserID, "self_password_change", "", clientIP(r), nil)
	writeJSON(w, map[string]any{"ok": true})
}
