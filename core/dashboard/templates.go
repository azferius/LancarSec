package dashboard

import (
	_ "embed"
	"html/template"
	"strings"
)

// All dashboard templates are embedded into the binary so the operator only
// needs to ship the lancarsec executable — no "forgot to copy assets/"
// mistakes, no filesystem permissions to get right. Each page template is
// parsed together with layout.html via html/template.

//go:embed templates/base.css
var baseCSS string

//go:embed templates/layout.html
var layoutTmpl string

//go:embed templates/overview.html
var overviewTmpl string

//go:embed templates/rules.html
var rulesTmpl string

//go:embed templates/logs.html
var logsTmpl string

//go:embed templates/analytics.html
var analyticsTmpl string

//go:embed templates/settings.html
var settingsTmpl string

//go:embed templates/blocklist.html
var blocklistTmpl string

//go:embed templates/login.html
var loginTmpl string

// layoutData is what every page template receives. Individual page scripts
// read the Domain field to scope their fetches.
type layoutData struct {
	Title       string
	CSS         template.CSS
	Tab         string
	Domain      string
	Domains     []string
	User        string
	UserInitial string
	Role        string
}

type loginData struct {
	CSS   template.CSS
	Error string
}

var (
	tmplOverview  *template.Template
	tmplRules     *template.Template
	tmplLogs      *template.Template
	tmplAnalytics *template.Template
	tmplSettings  *template.Template
	tmplBlocklist *template.Template
	tmplLogin     *template.Template
)

func init() {
	parse := func(page string) *template.Template {
		return template.Must(template.New("").Parse(layoutTmpl + page))
	}
	tmplOverview = parse(overviewTmpl)
	tmplRules = parse(rulesTmpl)
	tmplLogs = parse(logsTmpl)
	tmplAnalytics = parse(analyticsTmpl)
	tmplSettings = parse(settingsTmpl)
	tmplBlocklist = parse(blocklistTmpl)
	tmplLogin = template.Must(template.New("login").Parse(loginTmpl))
}

// pageData builds the shared layout context. Callers fill Title/Tab/Domain
// and reuse the rest from the authenticated session + current config.
func pageData(title, tab, domain, user string, domains []string) layoutData {
	initial := "?"
	if user != "" {
		initial = strings.ToUpper(user[:1])
	}
	return layoutData{
		Title:       title,
		CSS:         template.CSS(baseCSS),
		Tab:         tab,
		Domain:      domain,
		Domains:     domains,
		User:        user,
		UserInitial: initial,
	}
}
