package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// isolateTransport wipes the transport registry when the test ends, so the
// per-domain state one test installs cannot leak into another.
func isolateTransport(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		transportMap.Range(func(k, _ any) bool {
			transportMap.Delete(k)
			return true
		})
	})
}

func failingTransport(msg string) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errors.New(msg)
		},
	}
}

func TestDialFailureAnswers502WithEscapedError(t *testing.T) {
	isolateTransport(t)
	// "<img src=x>" holds no dot, path separator or bracket pair, so its
	// tokens survive the token filter -- it is the surviving-text case, and
	// it must arrive escaped. "<script>alert(1)</script>" is one token and
	// its closing tag holds a path separator, so the filter drops it whole.
	transportMap.Store("dialfail.test", failingTransport("boom [10.0.0.1]:443 evil <script>alert(1)</script> <img src=x>"))

	req := httptest.NewRequest("GET", "http://dialfail.test/", nil)
	resp, err := (&RoundTripper{}).RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("StatusCode = %d, want 502 (the old code masked the failure as 200)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	page := string(body)

	if !strings.Contains(page, "boom") {
		t.Errorf("page lost the readable error text: %q", page)
	}
	// Hostnames, IPs and socket addresses are filtered by the token filter.
	if strings.Contains(page, "10.0.0.1") {
		t.Errorf("page leaked the dial address: %q", page)
	}
	// Everything that survives the filter is HTML-escaped.
	if strings.Contains(page, "<script>") || strings.Contains(page, "<img") {
		t.Errorf("page carried unescaped backend error text: %q", page)
	}
	// WAVE 8 (assertion flipped): the old assertion wanted "&lt;script&gt;" on
	// the page, but the token filter drops any token holding a path
	// separator and a closing tag's "</script>" is exactly that -- so that
	// token never reaches the page at all, escaped or otherwise. The pin for
	// the filter-surviving text is "&lt;img": present, and only escaped.
	if !strings.Contains(page, "&lt;img") {
		t.Errorf("error text that survives the token filter must arrive HTML-escaped: %q", page)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if resp.ContentLength != int64(len(page)) {
		t.Errorf("ContentLength = %d, want %d", resp.ContentLength, len(page))
	}
}

func TestBackend5xxKeepsRealStatus(t *testing.T) {
	isolateTransport(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		w.Write([]byte(`xss "><img src=x onerror=alert(1)>`))
	}))
	defer srv.Close()
	transportMap.Store("backend.test", srv.Client().Transport.(*http.Transport))

	req := httptest.NewRequest("GET", srv.URL, nil)
	req.Host = "backend.test"

	// PassBackendErrors off (the default): the body is dropped and the real
	// status is kept.
	resp, err := (&RoundTripper{}).RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("StatusCode = %d, want the backend's 503 (the old code masked it as 200)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "onerror") {
		t.Errorf("the opted-out backend body was still forwarded: %q", body)
	}
	if strings.Contains(string(body), "srcdoc") {
		t.Errorf("default rendering must not embed the backend body: %q", body)
	}

	// PassBackendErrors on: the body reaches the iframe, escaped.
	resp2, err := (&RoundTripper{PassBackendErrors: true}).RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip (opted in): %v", err)
	}
	if resp2.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("StatusCode = %d, want 503", resp2.StatusCode)
	}
	body2, _ := io.ReadAll(resp2.Body)
	page2 := string(body2)
	if !strings.Contains(page2, "srcdoc=") {
		t.Errorf("opted-in page has no iframe: %q", page2)
	}
	// WAVE 8 (assertion flipped): a srcdoc attribute's value is entity-decoded
	// and then parsed as HTML by the browser, so a single escape round
	// resurrects the tags it escaped inside the same-origin iframe. The body
	// is therefore escaped TWICE, and the page must carry the double-escaped
	// form. "onerror=alert" itself holds no escapable characters, so its
	// literal presence proves nothing either way -- the tag markers are what
	// pins the escape depth.
	if strings.Contains(page2, `"><img`) || strings.Contains(page2, "&lt;img") {
		t.Errorf("backend body is not double-escaped; the tags would execute inside the same-origin srcdoc iframe: %q", page2)
	}
	if !strings.Contains(page2, "&amp;lt;img") {
		t.Errorf("double-escaped body missing: %q", page2)
	}
}

func TestBackend5xxWithEmptyBodyShowsGenericPage(t *testing.T) {
	isolateTransport(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(502)
	}))
	defer srv.Close()
	transportMap.Store("empty.test", srv.Client().Transport.(*http.Transport))

	req := httptest.NewRequest("GET", srv.URL, nil)
	req.Host = "empty.test"

	resp, err := (&RoundTripper{PassBackendErrors: true}).RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("StatusCode = %d, want 502", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "srcdoc") {
		t.Errorf("an empty backend body still produced an iframe: %q", body)
	}
}

// The generic page is what a 5xx gets when the backend's body is not
// forwarded (the default) and the fallback when the body cannot be read. Its
// title and heading carry the backend's reason phrase, which is
// backend-controlled.
func TestGeneric5xxPageKeepsStatusAndEscapesReasonPhrase(t *testing.T) {
	resp := generic5xxPage(http.StatusServiceUnavailable, `503 <script>alert(1)</script> Service Unavailable`)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("StatusCode = %d, want the backend's real 503", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	page := string(body)
	if strings.Contains(page, "<script>") {
		t.Errorf("backend-controlled reason phrase reached the page unescaped: %q", page)
	}
	if !strings.Contains(page, "&lt;script&gt;") {
		t.Errorf("reason phrase dropped instead of escaped: %q", page)
	}
}

func TestSequentialErrorBodiesAreNotAliased(t *testing.T) {
	isolateTransport(t)
	transportMap.Store("alias.test", failingTransport("boom"))

	mkReq := httptest.NewRequest("GET", "http://alias.test/", nil)
	rt := &RoundTripper{}

	// The old code rendered into one pooled buffer and handed a reader over
	// its still-referenced contents; the deferred Put then recycled the same
	// memory under the next response.
	var pages []string
	for i := 0; i < 2; i++ {
		resp, err := rt.RoundTrip(mkReq)
		if err != nil {
			t.Fatalf("RoundTrip %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		pages = append(pages, string(body))
	}
	for i, page := range pages {
		if !strings.Contains(page, "boom") {
			t.Errorf("response %d lost its page contents: %q", i, page)
		}
	}
	if pages[0] != pages[1] {
		t.Error("two identical sequential errors produced different pages")
	}
}

func TestBufferPoolGetReturnsUsableBuffer(t *testing.T) {
	ad := BufferPool()
	buf := ad.Get()
	if len(buf) != poolBufSize {
		t.Fatalf("Get returned len %d, want %d (io.CopyBuffer panics on an empty buffer)", len(buf), poolBufSize)
	}

	dst := &bytes.Buffer{}
	src := struct{ io.Reader }{strings.NewReader("payload")}
	n, err := io.CopyBuffer(dst, src, buf)
	if err != nil {
		t.Fatalf("CopyBuffer: %v", err)
	}
	if n != int64(len("payload")) || dst.String() != "payload" {
		t.Fatalf("CopyBuffer copied %d bytes %q", n, dst.String())
	}

	ad.Put(buf[:1]) // callers may hand back a resliced buffer
	if got := ad.Get(); len(got) != poolBufSize {
		t.Fatalf("Get after Put returned len %d, want %d", len(got), poolBufSize)
	}
}

func TestConfigurePerDomainSkipsVerifyIndependently(t *testing.T) {
	isolateTransport(t)

	Configure("verified.test", Options{})
	Configure("optedout.test", Options{SkipVerify: true})

	verified := getTripperForDomain("verified.test")
	optedout := getTripperForDomain("optedout.test")

	if verified == optedout {
		t.Fatal("two differently configured domains share one transport")
	}
	if verified.TLSClientConfig == optedout.TLSClientConfig {
		t.Fatal("the two transports share one TLSClientConfig; flipping one flips both")
	}
	if optedout.TLSClientConfig.InsecureSkipVerify != true {
		t.Error("opted-out domain still verifies backend certificates")
	}
	if verified.TLSClientConfig.InsecureSkipVerify != false {
		t.Error("default behaviour verifies backend certificates")
	}

	// Unconfigured hosts get the shared default, which verifies.
	if fallback := getTripperForDomain("unknown.test"); fallback != defaultTransport {
		t.Errorf("unknown host got %v, want the default transport", fallback)
	}
	if defaultTransport.TLSClientConfig.InsecureSkipVerify {
		t.Error("the default transport skips backend certificate verification")
	}
}

func TestResetKeepsOnlyTheCurrentConfig(t *testing.T) {
	isolateTransport(t)

	Configure("kept.test", Options{})
	Configure("dropped.test", Options{})

	Reset(map[string]struct{}{"kept.test": {}})

	if _, ok := transportMap.Load("kept.test"); !ok {
		t.Error("Reset dropped a transport the current config still uses")
	}
	if _, ok := transportMap.Load("dropped.test"); ok {
		t.Error("Reset kept a transport whose domain is gone from the config")
	}
}
