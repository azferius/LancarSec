package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config holds per-domain transport knobs. Zero values fall back to sensible
// defaults. BackendTLSVerify=true enables proper certificate verification for
// upstream connections; by default this is off (preserves prior behavior for
// self-signed local backends).
type Config struct {
	BackendTLSVerify bool
	MaxIdleConns     int
	MaxConnsPerHost  int
	DialTimeout      time.Duration
	IdleConnTimeout  time.Duration
}

var (
	registry   = sync.Map{} // domain -> *http.Transport
	bufferPool = sync.Pool{
		New: func() any { return &bytes.Buffer{} },
	}
)

// Register builds an *http.Transport for the domain using cfg and stores it
// in the registry. Idempotent: a new transport replaces any prior entry, so a
// config reload reflects immediately on next request.
func Register(domain string, cfg Config) {
	dialTimeout := cfg.DialTimeout
	if dialTimeout == 0 {
		dialTimeout = 5 * time.Second
	}
	idleTimeout := cfg.IdleConnTimeout
	if idleTimeout == 0 {
		idleTimeout = 90 * time.Second
	}
	maxIdle := cfg.MaxIdleConns
	if maxIdle == 0 {
		maxIdle = 10
	}
	maxConns := cfg.MaxConnsPerHost
	if maxConns == 0 {
		maxConns = 10
	}

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{
				Timeout:   dialTimeout,
				KeepAlive: 30 * time.Second,
			}).DialContext(ctx, network, addr)
		},
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: !cfg.BackendTLSVerify},
		IdleConnTimeout:     idleTimeout,
		MaxIdleConns:        maxIdle,
		MaxConnsPerHost:     maxConns,
	}
	registry.Store(domain, tr)
}

func forDomain(domain string) *http.Transport {
	if tr, ok := registry.Load(domain); ok {
		return tr.(*http.Transport)
	}
	// Fallback transport with safe defaults so a missing Register never panics.
	Register(domain, Config{})
	tr, _ := registry.Load(domain)
	return tr.(*http.Transport)
}

// RoundTripper is the custom transport wired into each domain's reverse proxy.
// It renders a friendly error page on dial failure or 5xx upstream response
// instead of surfacing the raw backend error.
type RoundTripper struct{}

func (rt *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	buffer := bufferPool.Get().(*bytes.Buffer)
	buffer.Reset()
	defer bufferPool.Put(buffer)

	resp, err := forDomain(req.Host).RoundTrip(req)

	if err != nil {
		errStrs := strings.Split(err.Error(), " ")
		errMsg := ""
		for _, str := range errStrs {
			if !strings.Contains(str, ".") && !strings.Contains(str, "/") && !(strings.Contains(str, "[") && strings.Contains(str, "]")) {
				errMsg += str + " "
			}
		}

		buffer.WriteString(`<!DOCTYPE html><html><head><title>Error: `)
		buffer.WriteString(errMsg)
		buffer.WriteString(`</title><style>body{font-family:'Helvetica Neue',sans-serif;color:#333;margin:0;padding:0}.container{display:flex;align-items:center;justify-content:center;height:100vh;background:#fafafa}.error-box{width:600px;padding:20px;background:#fff;border-radius:5px;box-shadow:0 2px 4px rgba(0,0,0,.1)}.error-box h1{font-size:36px;margin-bottom:20px}.error-box p{font-size:16px;line-height:1.5;margin-bottom:20px}.error-box p.description{font-style:italic;color:#666}.error-box a{display:inline-block;padding:10px 20px;background:#00b8d4;color:#fff;border-radius:5px;text-decoration:none;font-size:16px}</style><div class=container><div class=error-box><h1>Error: `)
		buffer.WriteString(errMsg)
		buffer.WriteString(`</h1><p>Sorry, there was an error connecting to the backend. That's all we know.</p><a onclick="location.reload()">Reload page</a></div></div></body></html>`)

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(append([]byte(nil), buffer.Bytes()...))),
		}, nil
	}

	if resp.StatusCode > 499 && resp.StatusCode < 600 {
		limitReader := io.LimitReader(resp.Body, 1024*1024)
		errBody, errErr := io.ReadAll(limitReader)
		resp.Body.Close()

		errMsg := ""
		if errErr == nil && len(errBody) > 0 {
			errMsg = string(errBody)
			if int64(len(errBody)) == 1024*1024 {
				errMsg += `<p>( Error message truncated. )</p>`
			}
		}

		if errErr == nil && len(errBody) != 0 {
			buffer.WriteString(`<!DOCTYPE html><html><head><title>Error: `)
			buffer.WriteString(resp.Status)
			buffer.WriteString(`</title><style>body{font-family:'Helvetica Neue',sans-serif;color:#333;margin:0;padding:0}.container{display:flex;align-items:center;justify-content:center;height:100vh;background:#fafafa}.error-box{width:600px;padding:20px;background:#fff;border-radius:5px;box-shadow:0 2px 4px rgba(0,0,0,.1)}.error-box h1{font-size:36px;margin-bottom:20px}.error-box p{font-size:16px;line-height:1.5;margin-bottom:20px}.error-box p.description{font-style:italic;color:#666}.error-box a{display:inline-block;padding:10px 20px;background:#00b8d4;color:#fff;border-radius:5px;text-decoration:none;font-size:16px}</style><div class=container><div class=error-box><h1>Error:`)
			buffer.WriteString(`</h1><p>Sorry, the backend returned this error.</p><iframe width="100%" height="25%" style="border:1px ridge lightgrey; border-radius: 5px;"srcdoc="`)
			buffer.WriteString(errMsg)
			buffer.WriteString(`"></iframe><a onclick="location.reload()">Reload page</a></div></div></body></html>`)
		} else {
			buffer.WriteString(`<!DOCTYPE html><html><head><title>Error: `)
			buffer.WriteString(resp.Status)
			buffer.WriteString(`</title><style>body{font-family:'Helvetica Neue',sans-serif;color:#333;margin:0;padding:0}.container{display:flex;align-items:center;justify-content:center;height:100vh;background:#fafafa}.error-box{width:600px;padding:20px;background:#fff;border-radius:5px;box-shadow:0 2px 4px rgba(0,0,0,.1)}.error-box h1{font-size:36px;margin-bottom:20px}.error-box p{font-size:16px;line-height:1.5;margin-bottom:20px}.error-box p.description{font-style:italic;color:#666}.error-box a{display:inline-block;padding:10px 20px;background:#00b8d4;color:#fff;border-radius:5px;text-decoration:none;font-size:16px}</style><div class=container><div class=error-box><h1>`)
			buffer.WriteString(resp.Status)
			buffer.WriteString(`</h1><p>Sorry, the backend returned an error. That's all we know.</p><a onclick="location.reload()">Reload page</a></div></div></body></html>`)
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(append([]byte(nil), buffer.Bytes()...))),
		}, nil
	}

	return resp, nil
}
