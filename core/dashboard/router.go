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
	case strings.HasPrefix(p, "/_lancarsec/api/dashboard/domain/"):
		return serveDomainAPI(w, r, strings.TrimPrefix(p, "/_lancarsec/api/dashboard/domain/"))
	}
	return false
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
