package server

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"

	"github.com/azferius/lancarsec/core/domains"
	"github.com/azferius/lancarsec/core/firewall"
	"github.com/azferius/lancarsec/core/pnc"
	"github.com/azferius/lancarsec/core/proxy"

	"golang.org/x/net/http2"
)

var bufferPool = sync.Pool{
	New: func() any {
		return &bytes.Buffer{}
	},
}

func Serve() {

	defer pnc.PanicHndl()

	if domains.Current().Proxy.Cloudflare {

		// WAVE 8: http2.ConfigureServer used to be applied to this plain-:80
		// listener. Cloudflare terminates TLS in front of it, the listener is
		// plain HTTP/1.1, and an h2 config on a server with no TLSConfig can
		// never negotiate h2 -- it configured nothing and discarded its error.
		service := &http.Server{
			IdleTimeout:       proxy.IdleTimeoutDuration,
			ReadTimeout:       proxy.ReadTimeoutDuration,
			WriteTimeout:      proxy.WriteTimeoutDuration,
			ReadHeaderTimeout: proxy.ReadHeaderTimeoutDuration,
			Addr:              ":80",
			MaxHeaderBytes:    1 << 20,
		}

		service.SetKeepAlivesEnabled(true)
		service.Handler = http.HandlerFunc(Middleware)

		if err := service.ListenAndServe(); err != nil {
			panic(err)
		}
	} else {

		service := &http.Server{
			IdleTimeout:       proxy.IdleTimeoutDuration,
			ReadTimeout:       proxy.ReadTimeoutDuration,
			WriteTimeout:      proxy.WriteTimeoutDuration,
			ReadHeaderTimeout: proxy.ReadHeaderTimeoutDuration,
			ConnState:         firewall.OnStateChange,
			Addr:              ":80",
			MaxHeaderBytes:    1 << 20,
		}
		serviceH := &http.Server{
			IdleTimeout:       proxy.IdleTimeoutDuration,
			ReadTimeout:       proxy.ReadTimeoutDuration,
			WriteTimeout:      proxy.WriteTimeoutDuration,
			ReadHeaderTimeout: proxy.ReadHeaderTimeoutDuration,
			ConnState:         firewall.OnStateChange,
			Addr:              ":443",
			TLSConfig:         tlsServerConfig(),
			MaxHeaderBytes:    1 << 20,
		}

		// WAVE 8: this used to run on both the plain :80 listener and :443,
		// discarding the error both times. h2 can only be negotiated over TLS,
		// so it is configured once, where TLS actually terminates, and the
		// error is handled.
		if err := http2.ConfigureServer(serviceH, &http2.Server{}); err != nil {
			panic(err)
		}

		service.Handler = http.HandlerFunc(handlePort80)

		service.SetKeepAlivesEnabled(true)
		serviceH.Handler = http.HandlerFunc(Middleware)

		go func() {
			defer pnc.PanicHndl()
			if err := serviceH.ListenAndServeTLS("", ""); err != nil {
				panic(err)
			}
		}()

		if err := service.ListenAndServe(); err != nil {
			panic(err)
		}
	}
}

// tlsServerConfig builds the :443 listener's TLS configuration.
//
// WAVE 8: MinVersion now pins TLS 1.2 -- 1.0/1.1 were previously negotiable on
// every listener. Renegotiation used to be set to tls.RenegotiateOnceAsClient,
// which is a *client-side* option; on a server config it did nothing.
func tlsServerConfig() *tls.Config {
	return &tls.Config{
		GetConfigForClient: firewall.Fingerprint,
		GetCertificate:     domains.GetCertificate,
		MinVersion:         tls.VersionTLS12,
	}
}

// handlePort80 answers a plain-:80 request in direct (non-Cloudflare) mode.
//
// WAVE 8: this handler used to take firewall.Mutex.Lock() to bump the
// domain's TotalRequests on an unauthenticated, pre-firewall path -- a DoS
// lever any attacker could hold for free, and a double count besides, since
// the redirected HTTPS request is counted again by Middleware. Counting lives
// in Middleware only now.
func handlePort80(w http.ResponseWriter, r *http.Request) {
	firewall.Mutex.RLock()
	_, domainFound := domains.DomainsData[r.Host]
	firewall.Mutex.RUnlock()

	if !domainFound {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "LancarSec: "+r.Host+" does not exist. If you are the owner please check your config.json if you believe this is a mistake")
		return
	}

	redirectTLS(w, r)
}

// redirectTLS sends the client to the same request on :443.
//
// WAVE 8: the target used to be "https://"+r.Host+r.URL.Path+r.URL.RawQuery,
// which glued the query onto the path with no '?' -- /search?q=x redirected to
// /searchq=x -- and used 301, which browsers cache and cannot be undone. The
// target is now built with net/url and the redirect is 307 so the request
// method survives the hop.
func redirectTLS(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, port, err := net.SplitHostPort(host); err == nil && port == "80" {
		host = h
	}

	target := url.URL{Scheme: "https", Host: host, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	http.Redirect(w, r, target.String(), http.StatusTemporaryRedirect)
}
