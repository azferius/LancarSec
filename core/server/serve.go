package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"lancarsec/core/domains"
	"lancarsec/core/firewall"
	"lancarsec/core/pnc"
	"lancarsec/core/proxy"
	"net/http"
	"sync"

	"golang.org/x/net/http2"
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		return &bytes.Buffer{}
	},
}

// Servers kept at package level so Shutdown can drain them on SIGTERM.
var (
	serverMu   sync.Mutex
	httpServer *http.Server
	tlsServer  *http.Server
)

func Serve() {

	defer pnc.PanicHndl()

	// Mode matrix:
	//   cloudflare=false                  -> Origin mode   : :80 redirect + :443 HTTPS w/ user cert + TLS fingerprinting
	//   cloudflare=true, fullSSL=false    -> Flexible mode : :80 HTTP only, Cloudflare terminates client TLS
	//   cloudflare=true, fullSSL=true     -> Full SSL mode : :80 HTTP + :443 HTTPS w/ user cert, still trusts Cf headers
	switch {
	case proxy.Cloudflare && !proxy.CloudflareFullSSL:
		serveCloudflareFlexible()
	case proxy.Cloudflare && proxy.CloudflareFullSSL:
		serveCloudflareFullSSL()
	default:
		serveOrigin()
	}
}

func serveCloudflareFlexible() {
	service := &http.Server{
		IdleTimeout:       proxy.IdleTimeoutDuration,
		ReadTimeout:       proxy.ReadTimeoutDuration,
		WriteTimeout:      proxy.WriteTimeoutDuration,
		ReadHeaderTimeout: proxy.ReadHeaderTimeoutDuration,
		Addr:              ":80",
		MaxHeaderBytes:    1 << 20,
	}

	http2.ConfigureServer(service, h2Server())
	service.SetKeepAlivesEnabled(true)
	service.Handler = http.HandlerFunc(Middleware)

	serverMu.Lock()
	httpServer = service
	serverMu.Unlock()

	if err := service.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		panic(err)
	}
}

// serveOrigin is direct-to-client mode (no CDN in front). TLS fingerprinting
// is enabled via GetConfigForClient, and the peek listener captures raw
// ClientHello bytes so JA4 can be computed to spec.
func serveOrigin() {
	service, serviceH := buildTLSServers(true)
	runPlusRedirectPeek(service, serviceH)
}

// serveCloudflareFullSSL runs HTTPS on :443 with the user's cert so Cloudflare
// can use Full/Strict SSL, while still treating Cloudflare as a trusted proxy
// for header-based real IP resolution. TLS fingerprinting stays off because
// Cloudflare terminates the client TLS and re-handshakes with us.
func serveCloudflareFullSSL() {
	service, serviceH := buildTLSServers(false)
	runPlusRedirect(service, serviceH)
}

func buildTLSServers(withFingerprint bool) (*http.Server, *http.Server) {
	service := &http.Server{
		IdleTimeout:       proxy.IdleTimeoutDuration,
		ReadTimeout:       proxy.ReadTimeoutDuration,
		WriteTimeout:      proxy.WriteTimeoutDuration,
		ReadHeaderTimeout: proxy.ReadHeaderTimeoutDuration,
		ConnState:         firewall.OnStateChange,
		Addr:              ":80",
		MaxHeaderBytes:    1 << 20,
	}

	tlsCfg := &tls.Config{
		GetCertificate: domains.GetCertificate,
		Renegotiation:  tls.RenegotiateOnceAsClient,
		// Refuse deprecated versions so attackers cannot force a downgrade
		// to TLS 1.0/1.1 (BEAST, CRIME, Lucky13, etc.).
		MinVersion: tls.VersionTLS12,
	}
	if withFingerprint {
		tlsCfg.GetConfigForClient = firewall.Fingerprint
	}

	serviceH := &http.Server{
		IdleTimeout:       proxy.IdleTimeoutDuration,
		ReadTimeout:       proxy.ReadTimeoutDuration,
		WriteTimeout:      proxy.WriteTimeoutDuration,
		ReadHeaderTimeout: proxy.ReadHeaderTimeoutDuration,
		ConnState:         firewall.OnStateChange,
		Addr:              ":443",
		TLSConfig:         tlsCfg,
		MaxHeaderBytes:    1 << 20,
	}

	http2.ConfigureServer(service, h2Server())
	http2.ConfigureServer(serviceH, h2Server())
	return service, serviceH
}

// h2Server returns HTTP/2 server config with attack-resistant limits. Default
// Go values are generous; explicit caps harden against CVE-style stream
// abuse (rapid-reset, continuation flood, etc.) that Go's mitigations already
// address but benefit from being made concrete.
func h2Server() *http2.Server {
	return &http2.Server{
		MaxConcurrentStreams:         100,
		MaxReadFrameSize:             16 * 1024, // RFC-permitted minimum that realistic clients use
		PermitProhibitedCipherSuites: false,
		IdleTimeout:                  proxy.IdleTimeoutDuration,
	}
}

// runPlusRedirectPeek is used by serveOrigin — it runs the TLS server via a
// peekListener so we capture raw ClientHello bytes for spec-compliant JA4.
func runPlusRedirectPeek(service *http.Server, serviceH *http.Server) {
	wireRedirect(service, serviceH)

	serverMu.Lock()
	httpServer = service
	tlsServer = serviceH
	serverMu.Unlock()

	go func() {
		defer pnc.PanicHndl()
		if err := listenAndServeTLSPeek(serviceH); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()

	if err := service.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		panic(err)
	}
}

func wireRedirect(service, serviceH *http.Server) {
	service.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firewall.DataMu.RLock()
		_, domainFound := domains.DomainsData[r.Host]
		firewall.DataMu.RUnlock()

		if !domainFound {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "LancarSec: "+r.Host+" does not exist. If you are the owner please check your config.json if you believe this is a mistake")
			return
		}

		// Bump TotalRequests with an exclusive lock; this is the redirect
		// path so we don't race with middleware here.
		firewall.DataMu.Lock()
		d := domains.DomainsData[r.Host]
		d.TotalRequests++
		domains.DomainsData[r.Host] = d
		firewall.DataMu.Unlock()

		http.Redirect(w, r, "https://"+r.Host+r.URL.Path+r.URL.RawQuery, http.StatusMovedPermanently)
	})
	service.SetKeepAlivesEnabled(true)
	serviceH.Handler = http.HandlerFunc(Middleware)
}

func runPlusRedirect(service *http.Server, serviceH *http.Server) {
	service.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firewall.DataMu.RLock()
		domainData, domainFound := domains.DomainsData[r.Host]
		firewall.DataMu.RUnlock()

		if !domainFound {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "LancarSec: "+r.Host+" does not exist. If you are the owner please check your config.json if you believe this is a mistake")
			return
		}

		firewall.DataMu.Lock()
		domainData = domains.DomainsData[r.Host]
		domainData.TotalRequests++
		domains.DomainsData[r.Host] = domainData
		firewall.DataMu.Unlock()

		http.Redirect(w, r, "https://"+r.Host+r.URL.Path+r.URL.RawQuery, http.StatusMovedPermanently)
	})

	service.SetKeepAlivesEnabled(true)
	serviceH.Handler = http.HandlerFunc(Middleware)

	serverMu.Lock()
	httpServer = service
	tlsServer = serviceH
	serverMu.Unlock()

	go func() {
		defer pnc.PanicHndl()
		if err := serviceH.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()

	if err := service.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		panic(err)
	}
}

// Shutdown drains both HTTP servers, waiting up to the context deadline for
// in-flight requests to complete. Idempotent: servers not yet started are
// skipped.
func Shutdown(ctx context.Context) {
	serverMu.Lock()
	h, t := httpServer, tlsServer
	serverMu.Unlock()

	var wg sync.WaitGroup
	if h != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = h.Shutdown(ctx)
		}()
	}
	if t != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = t.Shutdown(ctx)
		}()
	}
	wg.Wait()
}
