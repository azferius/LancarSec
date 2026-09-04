package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// resetServing isolates the package-level listener registry, which Serve writes
// to and Shutdown drains.
func resetServing(t *testing.T) {
	t.Helper()
	servingMu.Lock()
	prev := serving
	serving = nil
	servingMu.Unlock()
	t.Cleanup(func() {
		servingMu.Lock()
		serving = prev
		servingMu.Unlock()
	})
}

// trackedServer starts a real listener on a loopback port and registers it the
// way Serve does. It returns the server and its address.
func trackedServer(t *testing.T, h http.Handler) (*http.Server, string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: h}
	track(srv)

	go func() {
		if err := srv.Serve(ln); listenFatal(err) {
			t.Errorf("Serve: %v", err)
		}
	}()
	return srv, ln.Addr().String()
}

// WAVE 13: there was no shutdown path at all — main blocked on a bare
// `select{}`. What this pins is the property that makes a graceful stop worth
// having: a request already in flight when the signal arrives runs to
// completion and its response is delivered intact.
func TestShutdownDrainsInFlightRequests(t *testing.T) {
	resetServing(t)

	started := make(chan struct{})
	release := make(chan struct{})

	_, addr := trackedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release // still running when Shutdown is called
		_, _ = w.Write([]byte("drained"))
	}))

	type result struct {
		body string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := http.Get("http://" + addr + "/slow")
		if err != nil {
			done <- result{err: err}
			return
		}
		defer resp.Body.Close()
		buf := make([]byte, 16)
		n, _ := resp.Body.Read(buf)
		done <- result{body: string(buf[:n])}
	}()

	<-started

	shutdownReturned := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		shutdownReturned <- Shutdown(ctx)
	}()

	// Shutdown must NOT return while the handler is still running.
	select {
	case err := <-shutdownReturned:
		close(release)
		t.Fatalf("Shutdown returned while a request was still in flight (err=%v)", err)
	case <-time.After(200 * time.Millisecond):
	}

	close(release)

	if err := <-shutdownReturned; err != nil {
		t.Errorf("Shutdown: %v", err)
	}

	got := <-done
	if got.err != nil {
		t.Fatalf("the in-flight request failed instead of being drained: %v", got.err)
	}
	if got.body != "drained" {
		t.Errorf("body = %q, want %q: the response was truncated by the shutdown", got.body, "drained")
	}
}

// After Shutdown the listener is closed, so a NEW connection is refused rather
// than accepted and left hanging.
func TestShutdownStopsAcceptingNewConnections(t *testing.T) {
	resetServing(t)

	_, addr := trackedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))

	// Prove it was serving first, or the assertion below proves nothing.
	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("precondition: server was not serving: %v", err)
	}
	resp.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	if resp, err := http.Get("http://" + addr + "/"); err == nil {
		resp.Body.Close()
		t.Error("the listener still accepted a request after Shutdown")
	}
}

// Every tracked listener is shut down, not just the first: direct mode runs
// :80 and :443 side by side, and a drain that stopped at the first one would
// leave the TLS listener serving after the operator asked it to stop.
func TestShutdownStopsEveryTrackedListener(t *testing.T) {
	resetServing(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	_, addrA := trackedServer(t, handler)
	_, addrB := trackedServer(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	for _, addr := range []string{addrA, addrB} {
		if resp, err := http.Get("http://" + addr + "/"); err == nil {
			resp.Body.Close()
			t.Errorf("listener %s survived Shutdown", addr)
		}
	}
}

// A drain that cannot finish inside the deadline reports the deadline error
// rather than blocking forever or claiming success. main exits non-zero on it.
func TestShutdownReportsAnExpiredDeadline(t *testing.T) {
	resetServing(t)

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	started := make(chan struct{})
	var once sync.Once

	_, addr := trackedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		<-release
	}))

	go func() { //nolint:errcheck // the request is abandoned on purpose
		resp, err := http.Get("http://" + addr + "/hang")
		if err == nil {
			resp.Body.Close()
		}
	}()
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := Shutdown(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Shutdown = %v, want context.DeadlineExceeded when a request outlives the grace period", err)
	}
}

// Shutdown with nothing started, and a second Shutdown, are both no-ops. The
// process must not fail to stop because it never managed to start.
func TestShutdownWithNothingRunningIsANoOp(t *testing.T) {
	resetServing(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := Shutdown(ctx); err != nil {
		t.Errorf("Shutdown with no listeners = %v, want nil", err)
	}

	trackedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	if err := Shutdown(ctx); err != nil {
		t.Errorf("first Shutdown = %v, want nil", err)
	}
	if err := Shutdown(ctx); err != nil {
		t.Errorf("second Shutdown = %v, want nil", err)
	}
}

// listenFatal is what keeps a clean drain from panicking the process: every
// ListenAndServe returns http.ErrServerClosed after Shutdown, and Serve panics
// on a fatal listener error.
func TestListenFatalIgnoresServerClosed(t *testing.T) {
	if listenFatal(nil) {
		t.Error("listenFatal(nil) = true")
	}
	if listenFatal(http.ErrServerClosed) {
		t.Error("listenFatal(ErrServerClosed) = true: a clean shutdown would panic the process")
	}
	if !listenFatal(errors.New("address already in use")) {
		t.Error("listenFatal(bind error) = false: a listener that never came up would be silent")
	}
}
