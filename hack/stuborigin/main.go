// Command stuborigin is a deliberately trivial HTTP origin for the LancarSec
// load harness.
//
// Its only job is to be so fast and so boring that any number the harness
// produces describes LancarSec and not the backend. It allocates the response
// body exactly once at startup, serves it from that single []byte on every
// request, sets an explicit Content-Length so nothing gets chunked, and does no
// per-request logging, parsing, or allocation.
//
// Usage:
//
//	go run ./hack/stuborigin -listen 127.0.0.1:8080 -size 1024
//
// Flags of note:
//
//	-size    response body size in bytes; sweep this to find where the proxy's
//	         copy path rather than its decision path becomes the bottleneck.
//	-delay   artificial per-request latency. Default 0. Use it only when you
//	         deliberately want to model a slow backend (for example to see how
//	         many in-flight requests LancarSec holds open); leave it at 0 for
//	         every throughput or memory measurement.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

func main() {
	var (
		listen      = flag.String("listen", "127.0.0.1:8080", "host:port to listen on")
		size        = flag.Int("size", 1024, "response body size in bytes")
		status      = flag.Int("status", 200, "HTTP status code to return")
		contentType = flag.String("content-type", "text/plain; charset=utf-8", "Content-Type header to return")
		delay       = flag.Duration("delay", 0, "artificial per-request delay (e.g. 5ms); 0 disables")
		stats       = flag.Bool("stats", true, "print a once-per-second request counter to stderr")
	)
	flag.Parse()

	if *size < 0 {
		fmt.Fprintln(os.Stderr, "stuborigin: -size must not be negative")
		os.Exit(2)
	}
	if *status < 100 || *status > 599 {
		fmt.Fprintln(os.Stderr, "stuborigin: -status must be a valid HTTP status code")
		os.Exit(2)
	}

	// Build the body once. A repeating printable pattern rather than zeroes so
	// that a truncated or mangled response is obvious when you eyeball it.
	const pattern = "lancarsec-stub-origin-"
	body := make([]byte, *size)
	for i := range body {
		body[i] = pattern[i%len(pattern)]
	}
	contentLength := strconv.Itoa(len(body))

	var served atomic.Uint64

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if *delay > 0 {
			time.Sleep(*delay)
		}
		h := w.Header()
		h.Set("Content-Type", *contentType)
		h.Set("Content-Length", contentLength)
		h.Set("X-Stub-Origin", "1")
		w.WriteHeader(*status)
		if r.Method != http.MethodHead {
			_, _ = w.Write(body)
		}
		served.Add(1)
	})

	srv := &http.Server{
		Handler: handler,
		// Generous, because the harness is the only client and we never want
		// the origin to be the thing that drops a connection.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
		// Discard net/http's own connection-error chatter; at load-test rates
		// it is pure noise and the writes themselves cost measurable time.
		ErrorLog: log.New(discard{}, "", 0),
	}
	srv.SetKeepAlivesEnabled(true)

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stuborigin: listen %s: %v\n", *listen, err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "stuborigin: listening on %s, %d byte body, status %d, delay %s\n",
		ln.Addr(), len(body), *status, *delay)

	if *stats {
		go func() {
			var prev uint64
			t := time.NewTicker(time.Second)
			defer t.Stop()
			for range t.C {
				now := served.Load()
				fmt.Fprintf(os.Stderr, "stuborigin: %d req/s (%d total)\n", now-prev, now)
				prev = now
			}
		}()
	}

	if err := srv.Serve(ln); err != nil {
		fmt.Fprintf(os.Stderr, "stuborigin: serve: %v\n", err)
		os.Exit(1)
	}
}

// discard is an io.Writer that throws everything away. io.Discard would do, but
// this keeps the import list to what the handler itself needs.
type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
