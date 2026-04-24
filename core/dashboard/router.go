package dashboard

import (
	"net/http"
	"strconv"
	"strings"
)

// Serve dispatches any request whose path starts with /_lancarsec/dashboard,
// /_lancarsec/login, /_lancarsec/logout, or /_lancarsec/api/dashboard to the
// appropriate handler. Returns true if the request was handled so the
// middleware knows to stop further processing.
func Serve(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path

	switch {
	case p == "/_lancarsec/login":
		HandleLogin(w, r)
		return true
	case p == "/_lancarsec/logout":
		HandleLogout(w, r)
		return true
	case p == "/_lancarsec/dashboard" || p == "/_lancarsec/dashboard/":
		if _, ok := IsAuthenticated(r); !ok {
			http.Redirect(w, r, "/_lancarsec/login", http.StatusFound)
		} else {
			http.Redirect(w, r, "/_lancarsec/dashboard/overview", http.StatusFound)
		}
		return true
	case strings.HasPrefix(p, "/_lancarsec/dashboard/"):
		tab := strings.TrimPrefix(p, "/_lancarsec/dashboard/")
		HandlePage(tab)(w, r)
		return true
	case p == "/_lancarsec/api/dashboard/stream":
		HandleStream(w, r)
		return true
	case p == "/_lancarsec/api/dashboard/settings":
		HandleSettings(w, r)
		return true
	case p == "/_lancarsec/api/dashboard/reload":
		HandleReload(w, r)
		return true
	case p == "/_lancarsec/api/dashboard/users":
		if r.Method == http.MethodGet {
			HandleUsersList(w, r)
		} else {
			HandleUserCreate(w, r)
		}
		return true
	case strings.HasPrefix(p, "/_lancarsec/api/dashboard/users/"):
		return serveUserAPI(w, r, strings.TrimPrefix(p, "/_lancarsec/api/dashboard/users/"))
	case p == "/_lancarsec/api/dashboard/audit":
		HandleAudit(w, r)
		return true
	case p == "/_lancarsec/api/dashboard/self/password":
		HandleSelfPassword(w, r)
		return true
	case p == "/_lancarsec/api/dashboard/apikeys":
		if r.Method == http.MethodGet {
			HandleAPIKeysList(w, r)
		} else {
			HandleAPIKeyCreate(w, r)
		}
		return true
	case strings.HasPrefix(p, "/_lancarsec/api/dashboard/apikeys/"):
		id, err := strconv.ParseInt(strings.TrimPrefix(p, "/_lancarsec/api/dashboard/apikeys/"), 10, 64)
		if err != nil {
			http.Error(w, "bad id", http.StatusBadRequest)
			return true
		}
		HandleAPIKeyRevoke(w, r, id)
		return true
	case strings.HasPrefix(p, "/_lancarsec/api/dashboard/blocklist/"):
		return serveBlockAPI(w, r, strings.TrimPrefix(p, "/_lancarsec/api/dashboard/blocklist/"))
	case strings.HasPrefix(p, "/_lancarsec/api/dashboard/pathlimit/"):
		return servePathLimitAPI(w, r, strings.TrimPrefix(p, "/_lancarsec/api/dashboard/pathlimit/"))
	case strings.HasPrefix(p, "/_lancarsec/api/dashboard/domain/"):
		return serveDomainAPI(w, r, strings.TrimPrefix(p, "/_lancarsec/api/dashboard/domain/"))
	}
	return false
}

// serveUserAPI dispatches /api/dashboard/users/<id>[/grants] — GET/POST on
// the id root updates the user row; /grants is the domain-access sub-
// resource (POST grants, DELETE revokes).
func serveUserAPI(w http.ResponseWriter, r *http.Request, rest string) bool {
	parts := strings.SplitN(rest, "/", 2)
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		http.Error(w, "bad user id", http.StatusBadRequest)
		return true
	}
	if len(parts) == 1 {
		if r.Method == http.MethodDelete {
			HandleUserDelete(w, r, id)
			return true
		}
		HandleUserUpdate(w, r, id)
		return true
	}
	if parts[1] == "grants" {
		HandleUserGrant(w, r, id)
		return true
	}
	http.NotFound(w, r)
	return true
}

// servePathLimitAPI dispatches /api/dashboard/pathlimit/<domain>[/<index>].
func servePathLimitAPI(w http.ResponseWriter, r *http.Request, rest string) bool {
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return true
	}
	domain := parts[0]
	if len(parts) == 1 {
		HandlePathLimits(w, r, domain)
		return true
	}
	if r.Method == http.MethodDelete {
		idx, err := strconv.Atoi(parts[1])
		if err != nil {
			http.Error(w, "bad index", http.StatusBadRequest)
			return true
		}
		HandlePathLimitDelete(w, r, domain, idx)
		return true
	}
	http.NotFound(w, r)
	return true
}

// serveBlockAPI dispatches /api/dashboard/blocklist/<scope>[/<index>] where
// scope is "global" or a domain name. A trailing integer routes DELETE to the
// indexed entry; absence of the integer routes GET/POST to the collection.
func serveBlockAPI(w http.ResponseWriter, r *http.Request, rest string) bool {
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return true
	}
	scope := parts[0]
	if len(parts) == 1 {
		HandleBlocklist(w, r, scope)
		return true
	}
	if r.Method == http.MethodDelete {
		idx, err := strconv.Atoi(parts[1])
		if err != nil {
			http.Error(w, "bad index", http.StatusBadRequest)
			return true
		}
		HandleBlockDelete(w, r, scope, idx)
		return true
	}
	http.NotFound(w, r)
	return true
}

// serveDomainAPI handles the /api/dashboard/domain/<name>/<resource> routes.
// Split out so the switch in Serve stays readable.
func serveDomainAPI(w http.ResponseWriter, r *http.Request, rest string) bool {
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 2 {
		http.NotFound(w, r)
		return true
	}
	domain := parts[0]
	resource := parts[1]
	tail := ""
	if len(parts) == 3 {
		tail = parts[2]
	}

	switch resource {
	case "rules":
		if tail == "" {
			HandleRules(w, r, domain)
			return true
		}
		if r.Method == http.MethodDelete {
			idx, err := strconv.Atoi(tail)
			if err != nil {
				http.Error(w, "bad index", http.StatusBadRequest)
				return true
			}
			HandleRuleDelete(w, r, domain, idx)
			return true
		}
	case "stage":
		HandleStage(w, r, domain)
		return true
	case "logs":
		if r.Method == http.MethodDelete {
			HandleLogsDelete(w, r, domain)
			return true
		}
	case "analytics":
		HandleAnalytics(w, r, domain)
		return true
	case "stats":
		HandleStatsJSON(w, r)
		return true
	}
	http.NotFound(w, r)
	return true
}
