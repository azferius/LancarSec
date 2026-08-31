// Package transport owns the reverse-proxy RoundTripper and the per-domain
// *http.Transport registry.
//
// It was extracted verbatim from core/server/serve.go in wave 4. The only edge
// between core/config and core/server was core/config/init.go assigning
// &server.RoundTripper{}, which made core/server unable to import core/config
// and stranded ReloadConfig in core/server/monitor.go as a divergent copy of
// config.Load. Pulling this into a leaf package removes that edge.
//
// It imports nothing from this module by design. Keep it that way: a leaf is
// what keeps core/config -> core/transport the only edge here.
//
// Wave 8 rebuilt the response path:
//   - error pages are rendered into a fresh buffer per call (the old pooled
//     *bytes.Buffer aliased its contents into every in-flight response),
//   - backend 5xx responses keep their real status instead of being masked
//     as 200, and the backend-controlled body/status line are HTML-escaped
//     before they reach the srcdoc iframe -- the body double-escaped, because
//     a browser entity-decodes the attribute value and then parses it as
//     HTML, so a single escape would still execute the payload in the
//     same-origin iframe -- and dropped entirely unless the domain opts in
//     via RoundTripper.PassBackendErrors,
//   - backend TLS is verified by default; a per-domain clone with
//     InsecureSkipVerify is only created when the operator opts out
//     (config: proxy.backend_tls_skip_verify),
//   - a broken backend answers 502, not 200.
package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"
)

const (
	// poolBufSize matches http.ReverseProxy's default buffer size.
	poolBufSize = 32 * 1024

	// maxErrorBody caps how much of a backend 5xx body is read for the
	// error-page iframe.
	maxErrorBody = 1024 * 1024
)

var (
	transportMap = sync.Map{}
	bufPool      = sync.Pool{
		New: func() any {
			return make([]byte, poolBufSize)
		},
	}
)

// Options is the per-domain upstream-transport configuration.
type Options struct {
	// SkipVerify disables backend certificate verification for this domain.
	SkipVerify bool
}

// RoundTripper is the RoundTripper installed on every domain's reverse proxy.
// It renders the backend-error pages and applies per-domain transport tuning.
type RoundTripper struct {
	// PassBackendErrors forwards the backend's 5xx response body to the
	// client inside the error-page iframe. Default false: the body is
	// dropped, because it is backend-controlled content the proxy would
	// otherwise be echoing to browsers.
	PassBackendErrors bool
}

// Reset drops every cached per-domain transport except the names in keep, and
// closes the idle connections they pooled, so a domain removed from
// config.json does not leave keep-alives to a backend that is no longer
// configured alive for the lifetime of the process.
//
// The unified reload path passes the new config's domain names: publish has
// already registered fresh transports for them, and they must survive the
// sweep.
func Reset(keep map[string]struct{}) {
	transportMap.Range(func(k, v any) bool {
		if _, wanted := keep[k.(string)]; wanted {
			return true
		}
		transportMap.Delete(k)
		v.(*http.Transport).CloseIdleConnections()
		return true
	})
	defaultTransport.CloseIdleConnections()
}

// Configure installs a per-domain *http.Transport cloned from
// defaultTransport with opts applied. Re-configuring a domain closes the
// replaced transport's idle connections.
func Configure(domain string, opts Options) {
	fresh := defaultTransport.Clone()
	fresh.TLSClientConfig.InsecureSkipVerify = opts.SkipVerify
	if old, loaded := transportMap.Swap(domain, fresh); loaded {
		old.(*http.Transport).CloseIdleConnections()
	}
}

// BufferPool returns an httputil.BufferPool for ReverseProxy body copies,
// backed by this package's sync.Pool.
func BufferPool() httputil.BufferPool {
	return bufferPoolAdapter{}
}

type bufferPoolAdapter struct{}

// Get must return a slice with len > 0: io.CopyBuffer panics on a
// zero-length buffer.
func (bufferPoolAdapter) Get() []byte { return bufPool.Get().([]byte) }

// Put returns a buffer to the pool, reslicing whatever the caller handed
// back to the pool's canonical size.
func (bufferPoolAdapter) Put(b []byte) {
	if cap(b) >= poolBufSize {
		bufPool.Put(b[:poolBufSize])
	}
}

func (rt *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	//Use per-domain Proxy Read Timeout
	resp, err := getTripperForDomain(req.Host).RoundTrip(req)

	//Connection to backend failed. Render an error page.
	if err != nil {
		return htmlResponse(http.StatusBadGateway, dialErrorPage(err)), nil
	}

	//Connection was successful, got a 5xx response tho
	if resp.StatusCode > 499 && resp.StatusCode < 600 {
		page, pageErr := rt.backendErrorPage(resp)
		if pageErr != nil {
			// WAVE 8: the backend's body could not be read, so fall back to
			// the generic error page (keeping the backend's real status)
			// rather than surfacing a half-read body or failing the round
			// trip, which ReverseProxy would answer with its own bare 502.
			return generic5xxPage(resp.StatusCode, resp.Status), nil
		}
		return page, nil
	}

	return resp, nil
}

// dialErrorPage keeps the historical token filter (drop tokens containing a
// dot -- IPs, hostnames -- a slash -- paths, URLs -- or a [..] pair -- socket
// addresses) so resolver internals do not leak into the page, and HTML-escapes
// what remains before it is written into the title and the h1.
func dialErrorPage(err error) []byte {
	var msg strings.Builder
	for _, str := range strings.Split(err.Error(), " ") {
		if !strings.Contains(str, ".") && !strings.Contains(str, "/") && !(strings.Contains(str, "[") && strings.Contains(str, "]")) {
			msg.WriteString(str + " ")
		}
	}
	return errorPage(
		"Error: "+html.EscapeString(msg.String()),
		"<h1>Error: "+html.EscapeString(msg.String())+"</h1>"+
			"<p>Sorry, there was an error connecting to the backend. That's all we know.</p>",
	)
}

// backendErrorPage renders the 5xx page. The real status code reaches the
// client (the old code masked every 5xx as 200, so uptime checks and caches
// saw a healthy backend), and every backend-controlled string is escaped
// before it lands in the page.
//
// The backend's body is forwarded only when the domain opts in via
// PassBackendErrors, and only inside the error-page iframe. A srcdoc
// attribute's value is entity-decoded and then parsed as HTML by the browser,
// so the body is escaped TWICE: one round would resurrect the very tags it
// escaped, inside a same-origin iframe.
func (rt *RoundTripper) backendErrorPage(resp *http.Response) (*http.Response, error) {
	errBody, errErr := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	resp.Body.Close()
	if errErr != nil {
		return nil, errErr
	}

	if len(errBody) == 0 || !rt.PassBackendErrors {
		return generic5xxPage(resp.StatusCode, resp.Status), nil
	}

	var doc bytes.Buffer
	doc.Write(errBody)
	if len(errBody) == maxErrorBody {
		doc.WriteString("<p>( Error message truncated. )</p>")
	}
	page := errorPage("Error: "+html.EscapeString(resp.Status),
		"<p>Sorry, the backend returned this error.</p>"+
			`<iframe width="100%" height="25%" style="border:1px ridge lightgrey; border-radius: 5px;" srcdoc="`+
			html.EscapeString(html.EscapeString(doc.String()))+`"></iframe>`)
	return htmlResponse(resp.StatusCode, page), nil
}

// generic5xxPage is the 5xx page without the backend's body: the default
// rendering, and the fallback when the body could not be read. statusText is
// backend-controlled (it is the backend's reason phrase) and is escaped.
func generic5xxPage(status int, statusText string) *http.Response {
	return htmlResponse(status, errorPage("Error: "+html.EscapeString(statusText),
		"<h1>"+html.EscapeString(statusText)+"</h1>"+
			"<p>Sorry, the backend returned an error. That's all we know.</p>"))
}

const pageCSS = `body{font-family:'Helvetica Neue',sans-serif;color:#333;margin:0;padding:0}.container{display:flex;align-items:center;justify-content:center;height:100vh;background:#fafafa}.error-box{width:600px;padding:20px;background:#fff;border-radius:5px;box-shadow:0 2px 4px rgba(0,0,0,.1)}.error-box h1{font-size:36px;margin-bottom:20px}.error-box p{font-size:16px;line-height:1.5;margin-bottom:20px}.error-box p.description{font-style:italic;color:#666}.error-box a{display:inline-block;padding:10px 20px;background:#00b8d4;color:#fff;border-radius:5px;text-decoration:none;font-size:16px}`

// errorPage renders one page into a fresh buffer. Never pool this: the
// response body hands the buffer's contents to the client, so a recycled
// buffer aliases every in-flight error response.
func errorPage(title, body string) []byte {
	var page bytes.Buffer
	page.WriteString(`<!DOCTYPE html><html><head><title>`)
	page.WriteString(title)
	page.WriteString(`</title><style>`)
	page.WriteString(pageCSS)
	page.WriteString(`</style></head><body><div class=container><div class=error-box>`)
	page.WriteString(body)
	page.WriteString(`<a onclick="location.reload()">Reload page</a></div></div></body></html>`)
	return page.Bytes()
}

func htmlResponse(status int, page []byte) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:        http.Header{"Content-Type": {"text/html; charset=utf-8"}},
		ContentLength: int64(len(page)),
		Body:          io.NopCloser(bytes.NewReader(page)),
	}
}

var defaultTransport = &http.Transport{
	DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext(ctx, network, addr)
	},
	TLSHandshakeTimeout: 10 * time.Second,
	// Backend certificates are verified. Only proxy.backend_tls_skip_verify
	// (an explicit operator opt-out) produces a transport that skips it.
	TLSClientConfig: &tls.Config{},
	IdleConnTimeout: 90 * time.Second,
	// The old singleton capped every host at 10 conns total and kept only the
	// stdlib-default 2 idle per host, forcing constant re-dials under load.
	MaxIdleConns:          100,
	MaxIdleConnsPerHost:   100,
	ResponseHeaderTimeout: 30 * time.Second,
}

func getTripperForDomain(domain string) *http.Transport {
	if transport, ok := transportMap.Load(domain); ok {
		return transport.(*http.Transport)
	}
	// Unknown hosts get the default transport. The old LoadOrStore stored it
	// into the map under every host ever seen -- including scan traffic --
	// so the map grew without bound.
	return defaultTransport
}
