package transport

import (
	"html"
	"strings"
)

// errorStyles is the same visual language as the challenge pages
// (server/challenges.go): dark gradient background, glass card, subtle
// accent gradient on the brand dot. Kept in its own constant so updates to
// one surface don't drift out of step with the other.
const errorStyles = `
*,*::before,*::after{box-sizing:border-box}
body{margin:0;min-height:100vh;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
 background:radial-gradient(1200px 600px at 50% -10%,#1e293b 0%,#0f172a 60%,#020617 100%);
 color:#e2e8f0;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px}
.card{width:100%;max-width:560px;background:rgba(15,23,42,.72);backdrop-filter:blur(20px) saturate(150%);
 -webkit-backdrop-filter:blur(20px) saturate(150%);border:1px solid rgba(148,163,184,.15);
 border-radius:16px;padding:40px 32px;box-shadow:0 20px 60px -20px rgba(0,0,0,.6),0 0 0 1px rgba(255,255,255,.05) inset}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:24px;color:#94a3b8;font-size:13px;font-weight:500;letter-spacing:.02em}
.brand-dot{width:8px;height:8px;border-radius:50%;background:linear-gradient(135deg,#f97316,#ef4444);box-shadow:0 0 12px rgba(239,68,68,.6)}
.pill{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;
 background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.3);color:#fca5a5;font-size:11px;
 font-weight:500;letter-spacing:.02em;margin-bottom:20px}
h1{margin:0 0 8px;font-size:22px;font-weight:600;color:#f8fafc;letter-spacing:-.01em}
.status-line{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:13px;color:#fca5a5;margin:0 0 18px}
p.lead{margin:0 0 24px;font-size:14px;line-height:1.55;color:#94a3b8}
.upstream{margin:0 0 24px;padding:14px 16px;background:rgba(15,23,42,.6);border:1px solid rgba(148,163,184,.15);
 border-radius:10px;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:12px;
 color:#cbd5e1;line-height:1.5;max-height:180px;overflow:auto;white-space:pre-wrap;word-break:break-word}
.actions{display:flex;gap:10px;flex-wrap:wrap}
button.retry,a.retry{flex:1;padding:12px 16px;background:linear-gradient(135deg,#3b82f6,#2563eb);
 color:white;border:none;border-radius:8px;font-weight:500;font-size:14px;cursor:pointer;
 transition:transform .1s,box-shadow .15s;text-align:center;text-decoration:none;
 font-family:inherit}
button.retry:hover,a.retry:hover{box-shadow:0 4px 16px rgba(59,130,246,.35)}
button.retry:active,a.retry:active{transform:translateY(1px)}
.footer{margin-top:28px;padding-top:20px;border-top:1px solid rgba(148,163,184,.1);
 display:flex;justify-content:space-between;align-items:center;font-size:11px;color:#64748b}
.footer a{color:#94a3b8;text-decoration:none}
.footer a:hover{color:#cbd5e1}
`

// renderConnectErrorPage is rendered when the RoundTripper couldn't reach
// the backend at all (dial refused, DNS failed, timeout). errMsg is the
// server-filtered error string.
func renderConnectErrorPage(errMsg string) string {
	safe := html.EscapeString(strings.TrimSpace(errMsg))
	if safe == "" {
		safe = "unknown"
	}
	var b strings.Builder
	b.Grow(3072)
	b.WriteString(`<!doctype html><html lang=en><head><meta charset=UTF-8><meta name=viewport content="width=device-width,initial-scale=1"><meta name=robots content="noindex,nofollow"><title>502 · Backend unreachable</title>`)
	b.WriteString(`<style>`)
	b.WriteString(errorStyles)
	b.WriteString(`</style></head><body><main class=card>`)
	b.WriteString(`<div class=brand><span class=brand-dot></span><span>LANCARSEC · UPSTREAM ERROR</span></div>`)
	b.WriteString(`<div class=pill>Backend unreachable</div>`)
	b.WriteString(`<h1>The origin server didn't respond</h1>`)
	b.WriteString(`<p class="status-line">502 Bad Gateway · `)
	b.WriteString(safe)
	b.WriteString(`</p>`)
	b.WriteString(`<p class=lead>LancarSec received your request but couldn't reach the upstream service. This is usually a temporary issue on the origin side, not something you did. Try again in a moment.</p>`)
	b.WriteString(`<div class=actions><a class=retry href="javascript:location.reload()">Reload page</a></div>`)
	b.WriteString(`<div class=footer><span>Security by <a href="https://sec.splay.id" target=_blank rel=noopener><strong>LancarSec</strong></a></span><span>502</span></div>`)
	b.WriteString(`</main></body></html>`)
	return b.String()
}

// renderUpstreamErrorPage is rendered when the backend accepted the request
// but returned a 5xx response. status is the HTTP status (e.g. "503 Service
// Unavailable"); errBody is the raw response body, already size-limited
// upstream. May be empty — renderer handles both.
func renderUpstreamErrorPage(status string, errBody string) string {
	var b strings.Builder
	b.Grow(3072)
	b.WriteString(`<!doctype html><html lang=en><head><meta charset=UTF-8><meta name=viewport content="width=device-width,initial-scale=1"><meta name=robots content="noindex,nofollow"><title>Upstream ` + html.EscapeString(status) + `</title>`)
	b.WriteString(`<style>`)
	b.WriteString(errorStyles)
	b.WriteString(`</style></head><body><main class=card>`)
	b.WriteString(`<div class=brand><span class=brand-dot></span><span>LANCARSEC · UPSTREAM ERROR</span></div>`)
	b.WriteString(`<div class=pill>Upstream returned an error</div>`)
	b.WriteString(`<h1>The origin server reported a problem</h1>`)
	b.WriteString(`<p class="status-line">`)
	b.WriteString(html.EscapeString(status))
	b.WriteString(`</p>`)
	b.WriteString(`<p class=lead>LancarSec forwarded your request successfully, but the upstream service returned an error. Contact the site operator if this continues.</p>`)
	if strings.TrimSpace(errBody) != "" {
		b.WriteString(`<div class=upstream>`)
		b.WriteString(html.EscapeString(errBody))
		b.WriteString(`</div>`)
	}
	b.WriteString(`<div class=actions><a class=retry href="javascript:location.reload()">Reload page</a></div>`)
	b.WriteString(`<div class=footer><span>Security by <a href="https://sec.splay.id" target=_blank rel=noopener><strong>LancarSec</strong></a></span><span>`)
	b.WriteString(html.EscapeString(status))
	b.WriteString(`</span></div>`)
	b.WriteString(`</main></body></html>`)
	return b.String()
}
