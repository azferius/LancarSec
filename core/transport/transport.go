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
// defaults. BackendTLSVerify defaults to true when nil; pass false only for
// trusted self-signed local backends.
type Config struct {
	BackendTLSVerify *bool
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
	verifyBackendTLS := true
	if cfg.BackendTLSVerify != nil {
		verifyBackendTLS = *cfg.BackendTLSVerify
	}

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{
				Timeout:   dialTimeout,
				KeepAlive: 30 * time.Second,
			}).DialContext(ctx, network, addr)
		},
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: !verifyBackendTLS},
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
		filtered := strings.Builder{}
		for _, str := range errStrs {
			// Drop IP addresses, file paths, and bracketed IPv6 from the
			// surfaced error so we don't leak backend topology to the client.
			if strings.Contains(str, ".") || strings.Contains(str, "/") || strings.ContainsAny(str, "[]") {
				continue
			}
			filtered.WriteString(str)
			filtered.WriteByte(' ')
		}
		buffer.WriteString(renderConnectErrorPage(filtered.String()))
		return &http.Response{
			StatusCode: http.StatusBadGateway,
			Header:     http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
			Body:       io.NopCloser(bytes.NewReader(append([]byte(nil), buffer.Bytes()...))),
		}, nil
	}

	if resp.StatusCode > 499 && resp.StatusCode < 600 {
		limitReader := io.LimitReader(resp.Body, 1024*1024)
		errBody, errErr := io.ReadAll(limitReader)
		resp.Body.Close()

		body := ""
		if errErr == nil {
			body = string(errBody)
			if int64(len(errBody)) == 1024*1024 {
				body += "\n\n[…truncated…]"
			}
		}
		buffer.WriteString(renderUpstreamErrorPage(resp.Status, body))

		return &http.Response{
			StatusCode: resp.StatusCode,
			Header:     http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
			Body:       io.NopCloser(bytes.NewReader(append([]byte(nil), buffer.Bytes()...))),
		}, nil
	}

	return resp, nil
}
