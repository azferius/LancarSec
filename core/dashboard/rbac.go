package dashboard

import (
	"context"
	"net/http"

	"lancarsec/core/store"
)

// requireSession shortcuts the common prologue for every page / API
// handler: resolve the session or send a 401. Returns nil + writes a
// response on failure, caller should just `return`.
func requireSession(w http.ResponseWriter, r *http.Request) *store.Session {
	s, ok := SessionFrom(r)
	if !ok {
		// Pages redirect; APIs 401. The accept header is the cleanest
		// discriminator — the dashboard fetch() calls request JSON.
		if wantsJSON(r) {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			http.Redirect(w, r, "/_lancarsec/login", http.StatusFound)
		}
		return nil
	}
	return s
}

func wantsJSON(r *http.Request) bool {
	return r.Header.Get("Accept") == "application/json" ||
		r.URL.Path == "/_lancarsec/api/dashboard" ||
		containsSub(r.URL.Path, "/api/")
}

// requireManage gates a write to a specific domain. Returns false (and
// writes 403) if the user lacks the manage permission. Superadmins pass.
// Scope "global" or the __all sentinel requires superadmin.
func requireManage(w http.ResponseWriter, r *http.Request, s *store.Session, scope string) bool {
	if scope == "global" || scope == AllDomainsSentinel {
		if s.Role != store.RoleSuperAdmin {
			forbid(w, "superadmin required for global scope")
			return false
		}
		return true
	}
	ok, err := store.HasAccess(context.Background(), s.Role, s.UserID, scope, store.PermManage)
	if err != nil {
		http.Error(w, "access check failed", http.StatusInternalServerError)
		return false
	}
	if !ok {
		forbid(w, "manage permission required for "+scope)
		return false
	}
	return true
}

// requireView gates a read on a specific domain. Same rules as
// requireManage, but the viewer role is enough.
func requireView(w http.ResponseWriter, r *http.Request, s *store.Session, scope string) bool {
	if scope == "global" || scope == AllDomainsSentinel {
		// All authenticated users can see the global aggregate — it only
		// summarizes what they'd already see per domain. Per-domain panels
		// in global mode are filtered separately by the handler.
		return true
	}
	ok, err := store.HasAccess(context.Background(), s.Role, s.UserID, scope, store.PermView)
	if err != nil {
		http.Error(w, "access check failed", http.StatusInternalServerError)
		return false
	}
	if !ok {
		forbid(w, "view permission required for "+scope)
		return false
	}
	return true
}

// requireSuperAdmin denies non-superadmin access. Used for user management,
// API key admin, and audit log viewing.
func requireSuperAdmin(w http.ResponseWriter, s *store.Session) bool {
	if s.Role != store.RoleSuperAdmin {
		forbid(w, "superadmin required")
		return false
	}
	return true
}

func forbid(w http.ResponseWriter, msg string) {
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(msg))
}

func containsSub(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
