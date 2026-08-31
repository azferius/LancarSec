package firewall

import (
	"crypto/tls"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// test doubles
// ---------------------------------------------------------------------------

// fakeAddr lets each synthetic ClientHello land on its own key in the
// package-global Connections map. net.Pipe's own RemoteAddr is the constant
// "pipe", which would make every case collide.
type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

// fakeConn is a real net.Pipe end (so Close actually does something) with a
// controllable RemoteAddr and a close counter. Fingerprint only ever calls
// RemoteAddr() and, on the invalid-TLS path, Close().
type fakeConn struct {
	net.Conn
	addr   fakeAddr
	closes atomic.Int32
}

func (c *fakeConn) RemoteAddr() net.Addr { return c.addr }

func (c *fakeConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

func newFakeConn(t *testing.T, addr string) *fakeConn {
	t.Helper()
	local, remote := net.Pipe()
	t.Cleanup(func() {
		_ = local.Close()
		_ = remote.Close()
	})
	return &fakeConn{Conn: local, addr: fakeAddr(addr)}
}

// withCleanConnections swaps the package-global Connections map for a fresh one
// and restores the original in t.Cleanup, so these tests never leak state into
// each other or into the rest of the package. Fingerprint writes under Mutex,
// so the swap is done under the same lock.
func withCleanConnections(t *testing.T) {
	t.Helper()
	Mutex.Lock()
	saved := Connections
	Connections = map[string]string{}
	Mutex.Unlock()

	t.Cleanup(func() {
		Mutex.Lock()
		Connections = saved
		Mutex.Unlock()
	})
}

// readConnection reads Connections through the same mutex Fingerprint writes
// under, so `go test -race` stays clean.
func readConnection(addr string) (string, bool) {
	Mutex.RLock()
	defer Mutex.RUnlock()
	v, ok := Connections[addr]
	return v, ok
}

func connectionCount() int {
	Mutex.RLock()
	defer Mutex.RUnlock()
	return len(Connections)
}

// ---------------------------------------------------------------------------
// golden fingerprints
// ---------------------------------------------------------------------------

// TestFingerprintGolden pins the EXACT string Fingerprint writes into
// Connections for a set of synthetic ClientHellos.
//
// Two formatting facts drive every expectation below, and neither is obvious
// from reading fingerprint.go:
//
//   - clientHello.CipherSuites is []uint16 and clientHello.SupportedPoints is
//     []uint8, so `fmt.Sprintf("0x%x", v)` renders a plain hex number.
//   - clientHello.SupportedCurves is []tls.CurveID, which implements
//     fmt.Stringer -- and fmt uses Stringer for the %x verb too. So a curve is
//     rendered as the HEX ENCODING OF ITS NAME: tls.X25519 becomes
//     0x583235353139 ("X25519"), and an unrecognised curve id N becomes the hex
//     of "CurveID(N)". That is why the KnownFingerprints table in
//     fingerprint.go is full of long 0x4375727665... runs.
//
// A future wave that swaps %x for an explicit uint16 conversion, or that stops
// using tls.CurveID, will change every one of these strings.
func TestFingerprintGolden(t *testing.T) {
	tests := []struct {
		name   string
		hello  tls.ClientHelloInfo
		want   string
		known  string // expected KnownFingerprints/BotFingerprints label, "" if none
		reason string
	}{
		{
			// Chrome/Chromium sends a GREASE value in the first cipher slot and
			// the first curve slot. The GREASE-pattern filter removes exactly
			// those two values, so the output byte-matches the shipped
			// "Chromium Old" entry both before and after the wave 11 prep fix:
			// index-0 truncation and pattern filtering agree whenever the
			// only GREASE values sit in slot 0.
			//
			// FLIPPED (wave 4, fingerprint embedding): this key is labelled
			// "Chromium Old" in the bundled global/fingerprints data, not
			// "Chromium". The hardcoded fallback table this test was written
			// against called it "Chromium"; that fallback is gone, and in any
			// production deployment the network fetch had already relabelled it
			// this way at every boot. The bundle carries a second, newer key
			// under the plain "Chromium" label for current Chrome builds.
			name: "chrome-like hello with GREASE in the first slot",
			hello: tls.ClientHelloInfo{
				CipherSuites: []uint16{
					0x0a0a, // GREASE
					0x1301, 0x1302, 0x1303,
					0xc02b, 0xc02f, 0xc02c, 0xc030,
					0xcca9, 0xcca8, 0xc013, 0xc014,
					0x009c, 0x009d, 0x002f, 0x0035,
				},
				SupportedCurves: []tls.CurveID{
					tls.CurveID(0x0a0a), // GREASE
					tls.X25519, tls.CurveP256, tls.CurveP384,
				},
				SupportedPoints: []uint8{0},
			},
			want: "0x1301,0x1302,0x1303,0xc02b,0xc02f,0xc02c,0xc030,0xcca9,0xcca8," +
				"0xc013,0xc014,0x9c,0x9d,0x2f,0x35," +
				"0x583235353139,0x437572766550323536,0x437572766550333834,0x0,",
			known:  "Chromium Old",
			reason: "the two GREASE values are all that is filtered; the real suites and curves survive",
		},
		{
			// FLIPPED (wave 11 prep, GREASE fix): Firefox does NOT send GREASE,
			// and the old index-0 truncation threw away its first REAL cipher
			// (0x1301, TLS_AES_128_GCM_SHA256) and first REAL curve (X25519)
			// regardless. The shipped "Firefox" entry in KnownFingerprints had
			// itself been generated from that lossy output, so the table agreed
			// with the code -- but the fingerprint was strictly weaker than it
			// needed to be: any client differing from Firefox ONLY in its first
			// cipher suite or first curve was indistinguishable from Firefox.
			//
			// The derivation now filters GREASE by pattern instead of slicing,
			// so both real elements survive, and the shipped "Firefox" key was
			// regenerated to this exact string in the same commit. Without the
			// regeneration every real Firefox hello would have slid into the
			// unknown-fingerprint ratelimit (R3, `if browser == ""` in
			// core/server/middleware.go) and `ip.fingerprint` rules written
			// against the old key would have gone dead.
			name: "firefox-like hello without GREASE keeps its first cipher and curve",
			hello: tls.ClientHelloInfo{
				CipherSuites: []uint16{
					0x1301, 0x1303, 0x1302,
					0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030,
					0xc00a, 0xc009, 0xc013, 0xc014,
					0x009c, 0x009d, 0x002f, 0x0035,
				},
				SupportedCurves: []tls.CurveID{
					tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521,
					tls.CurveID(256), tls.CurveID(257), // ffdhe2048 / ffdhe3072
				},
				SupportedPoints: []uint8{0},
			},
			want: "0x1301,0x1303,0x1302,0xc02b,0xc02f,0xcca9,0xcca8,0xc02c,0xc030," +
				"0xc00a,0xc009,0xc013,0xc014,0x9c,0x9d,0x2f,0x35," +
				"0x583235353139,0x437572766550323536,0x437572766550333834,0x437572766550353231," +
				"0x437572766549442832353629,0x437572766549442832353729,0x0,",
			known:  "Firefox",
			reason: "no GREASE, so nothing is filtered and the full hello is fingerprinted",
		},
		{
			// Safari on iOS. Like Chrome it sends GREASE in the first cipher and
			// first curve slot, which the pattern filter removes, so the output
			// byte-matches the shipped "Safari" entry both before and after the
			// wave 11 prep fix.
			//
			// The `known` assertion below is the point of this case: these labels
			// are the VALUES operators write rules against (`ip.bot eq "Safari"`),
			// so a relabel during table maintenance silently breaks live configs
			// with no error anywhere -- iPhone traffic simply stops matching the
			// rule that was written for it and gets whatever the new label's
			// rules say instead. Regenerating or hand-editing these tables is
			// routine, and a swapped label is invisible in review.
			name: "safari/ios hello maps to the Safari label",
			hello: tls.ClientHelloInfo{
				CipherSuites: []uint16{
					0x0a0a, // GREASE
					0x1301, 0x1302, 0x1303,
					0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8,
					0xc00a, 0xc009, 0xc014, 0xc013,
					0x009d, 0x009c, 0x0035, 0x002f,
					0xc008, 0xc012, 0x000a,
				},
				SupportedCurves: []tls.CurveID{
					tls.CurveID(0x0a0a), // GREASE
					tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521,
				},
				SupportedPoints: []uint8{0},
			},
			want: "0x1301,0x1302,0x1303,0xc02c,0xc02b,0xcca9,0xc030,0xc02f,0xcca8," +
				"0xc00a,0xc009,0xc014,0xc013,0x9d,0x9c,0x35,0x2f,0xc008,0xc012,0xa," +
				"0x583235353139,0x437572766550323536,0x437572766550333834," +
				"0x437572766550353231,0x0,",
			known:  "Safari",
			reason: "iOS Safari sends GREASE, which the pattern filter removes wherever it sits",
		},
		{
			// FLIPPED (wave 11 prep, GREASE fix): the three slice expressions in
			// Fingerprint used to be asymmetrical --
			//
			//     CipherSuites[1:]     -> drop the first element
			//     SupportedCurves[1:]  -> drop the first element
			//     SupportedPoints[:1]  -> keep ONLY the first element
			//
			// [:1] contradicted the comment above the loops ("ignore first
			// elements") and handed every multi-format client one byte of
			// signal, always the same one. The fix is deliberately NOT the
			// naive [1:] this test once predicted -- that would have traded a
			// head-take for a tail-take and dropped 0x0, a REAL format
			// (uncompressed), while keeping 0x1 and 0x2 that no browser sends.
			// All three lists are GREASE-filtered now, so every non-GREASE
			// point format is emitted and no real signal is dropped.
			name: "multiple point formats: every non-GREASE format is emitted",
			hello: tls.ClientHelloInfo{
				CipherSuites:    []uint16{0x0a0a, 0x1301, 0x1302},
				SupportedCurves: []tls.CurveID{tls.CurveID(0x0a0a), tls.X25519},
				SupportedPoints: []uint8{0, 1, 2},
			},
			want:   "0x1301,0x1302,0x583235353139,0x0,0x1,0x2,",
			reason: "0x0, 0x1 and 0x2 are all real formats, so all three are emitted",
		},
		{
			// An empty curve list contributes nothing: the range loop simply
			// does not run.
			name: "empty SupportedCurves contributes nothing",
			hello: tls.ClientHelloInfo{
				CipherSuites:    []uint16{0x0a0a, 0x1301, 0x1302},
				SupportedCurves: []tls.CurveID{},
				SupportedPoints: []uint8{0},
			},
			want:   "0x1301,0x1302,0x0,",
			reason: "ranging over an empty slice writes nothing",
		},
		{
			name: "nil SupportedCurves behaves the same as empty",
			hello: tls.ClientHelloInfo{
				CipherSuites:    []uint16{0x0a0a, 0x1301, 0x1302},
				SupportedCurves: nil,
				SupportedPoints: []uint8{0},
			},
			want:   "0x1301,0x1302,0x0,",
			reason: "ranging over a nil slice writes nothing",
		},
		{
			name: "empty SupportedPoints contributes nothing",
			hello: tls.ClientHelloInfo{
				CipherSuites:    []uint16{0x0a0a, 0x1301, 0x1302},
				SupportedCurves: []tls.CurveID{tls.CurveID(0x0a0a), tls.X25519},
				SupportedPoints: []uint8{},
			},
			want:   "0x1301,0x1302,0x583235353139,",
			reason: "ranging over an empty slice writes nothing",
		},
		{
			// FLIPPED (wave 11 prep, GREASE fix): [1:] on a length-1 curve list
			// erased the only element it had. A lone REAL curve is signal, not
			// padding, so the GREASE filter keeps it.
			name: "single-element SupportedCurves survives the GREASE filter",
			hello: tls.ClientHelloInfo{
				CipherSuites:    []uint16{0x0a0a, 0x1301},
				SupportedCurves: []tls.CurveID{tls.X25519},
				SupportedPoints: []uint8{0},
			},
			want:   "0x1301,0x583235353139,0x0,",
			reason: "the lone X25519 is not GREASE, so it is emitted",
		},
		{
			// FLIPPED (wave 11 prep, GREASE fix): a hello offering exactly ONE
			// cipher suite had it erased by [1:]; every such client -- regardless
			// of WHICH suite it offered -- collapsed onto the same fingerprint,
			// keyed only by its curves and point formats, and two different
			// single-suite scanners were literally indistinguishable. The only
			// suite is real, so the filter keeps it.
			//
			// This now derives the SAME string as the previous case, which is
			// correct: the two hellos differ only by a GREASE value, which
			// carries no fingerprint signal.
			name: "single-element CipherSuites survives the GREASE filter",
			hello: tls.ClientHelloInfo{
				CipherSuites:    []uint16{0x1301},
				SupportedCurves: []tls.CurveID{tls.CurveID(0x0a0a), tls.X25519},
				SupportedPoints: []uint8{0},
			},
			want:   "0x1301,0x583235353139,0x0,",
			reason: "the only suite is not GREASE, so it is emitted",
		},
		{
			// FLIPPED (wave 11 prep, GREASE fix): one suite, one curve and no
			// points used to truncate to a completely EMPTY fingerprint, and
			// Connections mapped the peer to "" -- the same value an
			// unfingerprinted peer would look up as a miss. Nothing in this
			// hello is GREASE, so everything is kept and the fingerprint is no
			// longer empty. The only way to derive "" today is a hello whose
			// EVERY element is GREASE, which the following case pins.
			name: "a hello with only real elements is never empty",
			hello: tls.ClientHelloInfo{
				CipherSuites:    []uint16{0x1301},
				SupportedCurves: []tls.CurveID{tls.X25519},
				SupportedPoints: nil,
			},
			want:   "0x1301,0x583235353139,",
			reason: "no element is GREASE, so nothing is dropped",
		},
		{
			// The residual path to an empty fingerprint after the wave 11 prep
			// fix: a hello whose every element is GREASE. No real client sends
			// one -- GREASE always accompanies real values -- but this is the
			// one hello that still derives "", which is why the table
			// validators keep rejecting an empty KEY.
			name: "an all-GREASE hello is the only remaining empty fingerprint",
			hello: tls.ClientHelloInfo{
				CipherSuites:    []uint16{0x0a0a, 0x1a1a},
				SupportedCurves: []tls.CurveID{tls.CurveID(0xfafa)},
				SupportedPoints: []uint8{0x0a},
			},
			want:   "",
			reason: "every element matches the GREASE pattern",
		},
		{
			// Sanity check that suite values above 0x00ff render without any
			// zero padding, and values below render without a leading zero.
			//
			// FLIPPED (wave 11 prep, GREASE fix): the old want was
			// "0x5,0xff,0x100,0xf," because index-0 truncation discarded
			// 0xffff as collateral. 0xffff is NOT GREASE -- its bytes are
			// equal but its low nibble is 0xf, not 0xa -- so the pattern
			// filter keeps it, which is exactly the point: a value must be
			// dropped only when it matches the GREASE pattern, never because
			// of where it sits.
			name: "hex rendering has no zero padding",
			hello: tls.ClientHelloInfo{
				CipherSuites:    []uint16{0xffff, 0x0005, 0x00ff, 0x0100},
				SupportedCurves: nil,
				SupportedPoints: []uint8{0x0f},
			},
			want:   "0xffff,0x5,0xff,0x100,0xf,",
			reason: "%x is unpadded, and 0xffff's low nibble is f so it is not GREASE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withCleanConnections(t)

			addr := "203.0.113.7:44321"
			conn := newFakeConn(t, addr)
			hello := tt.hello
			hello.Conn = conn

			cfg, err := Fingerprint(&hello)
			if cfg != nil || err != nil {
				t.Fatalf("Fingerprint returned (%v, %v), want (nil, nil)", cfg, err)
			}
			if n := conn.closes.Load(); n != 0 {
				t.Errorf("Fingerprint closed the connection %d time(s) on the valid path, want 0", n)
			}

			got, ok := readConnection(addr)
			if !ok {
				t.Fatalf("Connections[%q] was not written (%s)", addr, tt.reason)
			}
			if got != tt.want {
				t.Errorf("fingerprint mismatch (%s)\n got: %q\nwant: %q", tt.reason, got, tt.want)
			}
			if n := connectionCount(); n != 1 {
				t.Errorf("Connections has %d entries, want exactly 1", n)
			}

			if tt.known != "" {
				if label := KnownFingerprints[got]; label != tt.known {
					t.Errorf("KnownFingerprints[%q] = %q, want %q "+
						"(the shipped table must stay byte-compatible with what Fingerprint produces)",
						got, label, tt.known)
				}
			}
		})
	}
}

// TestFingerprintEmptyCipherSuites pins the "invalid TLS" early-return path:
// the connection is CLOSED and nothing is recorded.
//
// The len() > 0 guard remains the invalid-TLS gate. Since the wave 11 prep
// (GREASE fix) the derivation ranges over the full lists rather than slicing
// them, so an empty list can no longer panic -- but a hello with NO cipher
// suites is refused outright regardless, and that contract is what this test
// pins. If a future wave removes or reorders the guard, that is the behaviour
// it breaks.
func TestFingerprintEmptyCipherSuites(t *testing.T) {
	cases := []struct {
		name   string
		suites []uint16
	}{
		{name: "nil CipherSuites", suites: nil},
		{name: "empty CipherSuites", suites: []uint16{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withCleanConnections(t)

			addr := "198.51.100.4:1234"
			conn := newFakeConn(t, addr)

			hello := tls.ClientHelloInfo{
				CipherSuites:    tc.suites,
				SupportedCurves: []tls.CurveID{tls.X25519, tls.CurveP256},
				SupportedPoints: []uint8{0},
				Conn:            conn,
			}

			cfg, err := Fingerprint(&hello)
			if cfg != nil || err != nil {
				t.Fatalf("Fingerprint returned (%v, %v), want (nil, nil)", cfg, err)
			}

			// The Close is deferred, so it has already run by the time
			// Fingerprint returns.
			if n := conn.closes.Load(); n != 1 {
				t.Errorf("connection closed %d time(s), want exactly 1", n)
			}
			if _, ok := readConnection(addr); ok {
				t.Errorf("Connections[%q] was written on the invalid-TLS path; want no entry", addr)
			}
			if n := connectionCount(); n != 0 {
				t.Errorf("Connections has %d entries, want 0", n)
			}
		})
	}
}

// TestFingerprintOverwritesSameRemoteAddr pins that Connections is keyed purely
// on "ip:port" and that a second handshake from the same key overwrites the
// first. Real OS port reuse after a socket closes means this key is not stable
// over time -- which is why OnStateChange has to delete entries at all.
func TestFingerprintOverwritesSameRemoteAddr(t *testing.T) {
	withCleanConnections(t)

	addr := "192.0.2.10:5555"

	first := tls.ClientHelloInfo{
		CipherSuites:    []uint16{0x0a0a, 0x1301},
		SupportedPoints: []uint8{0},
		Conn:            newFakeConn(t, addr),
	}
	if _, err := Fingerprint(&first); err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if got, _ := readConnection(addr); got != "0x1301,0x0," {
		t.Fatalf("first fingerprint = %q", got)
	}

	second := tls.ClientHelloInfo{
		CipherSuites:    []uint16{0x0a0a, 0x1302, 0x1303},
		SupportedPoints: []uint8{0},
		Conn:            newFakeConn(t, addr),
	}
	if _, err := Fingerprint(&second); err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if got, _ := readConnection(addr); got != "0x1302,0x1303,0x0," {
		t.Errorf("second fingerprint = %q, want the first entry to be overwritten", got)
	}
	if n := connectionCount(); n != 1 {
		t.Errorf("Connections has %d entries, want 1", n)
	}
}

// TestFingerprintConcurrentWrites is the -race tripwire for the Connections map.
// Fingerprint takes firewall.Mutex around a plain map write; wave 7 replaces
// that global RWMutex with sharding or a sync.Map, and this test is what proves
// the replacement is still safe.
func TestFingerprintConcurrentWrites(t *testing.T) {
	withCleanConnections(t)

	const goroutines = 32

	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		conn := newFakeConn(t, "192.0.2.1:"+strconv.Itoa(40000+i))
		go func() {
			defer wg.Done()
			<-start
			hello := tls.ClientHelloInfo{
				CipherSuites:    []uint16{0x0a0a, 0x1301, 0x1302},
				SupportedCurves: []tls.CurveID{tls.CurveID(0x0a0a), tls.X25519},
				SupportedPoints: []uint8{0},
				Conn:            conn,
			}
			if _, err := Fingerprint(&hello); err != nil {
				t.Errorf("Fingerprint: %v", err)
			}
		}()
	}

	close(start)
	wg.Wait()

	if n := connectionCount(); n != goroutines {
		t.Errorf("Connections has %d entries, want %d", n, goroutines)
	}

	Mutex.RLock()
	defer Mutex.RUnlock()
	for k, v := range Connections {
		if v != "0x1301,0x1302,0x583235353139,0x0," {
			t.Errorf("Connections[%q] = %q, want the shared fingerprint", k, v)
		}
	}
}

// TestGREASEPattern pins the GREASE detector itself, element by element.
//
// The 16-bit pattern is RFC 8701's: both bytes equal and the low nibble 0xa,
// i.e. 0x0a0a, 0x1a1a, ... 0xfafa. The near-misses matter as much as the
// hits: 0xffff (low nibble 0xf), 0x0a0b (low nibble 0xb), 0x0a1a / 0x1a0a /
// 0x0100 (bytes differ) and every real suite below must all SURVIVE
// filtering -- a false positive here would silently rewrite a legitimate
// fingerprint, which is the same class of defect the [1:] truncation had.
// The single-byte analogue for ec_point_formats (0x?a) cannot misfire on the
// formats browsers actually send (0, 1, 2).
func TestGREASEPattern(t *testing.T) {
	sixteen := []struct {
		v    uint16
		want bool
	}{
		{0x0a0a, true},
		{0x1a1a, true},
		{0x2a2a, true},
		{0xaaaa, true},
		{0xfafa, true},
		{0x0a1a, false}, // bytes differ
		{0x1a0a, false}, // bytes differ
		{0x0a0b, false}, // low nibble is b
		{0x0a00, false}, // low byte is 0x00
		{0x0100, false}, // bytes differ
		{0x1301, false}, // TLS_AES_128_GCM_SHA256 -- must never be filtered
		{0x1302, false}, // TLS_AES_256_GCM_SHA384
		{0x1303, false}, // TLS_CHACHA20_POLY1305_SHA256
		{0x009c, false}, // RSA_AES_128_GCM_SHA256
		{0xc02b, false}, // ECDHE_ECDSA_AES128_GCM_SHA256
		{0x00ff, false}, // empty renegotiation info
		{0xffff, false}, // low nibble is f
	}
	for _, tc := range sixteen {
		if got := isGREASE(tc.v); got != tc.want {
			t.Errorf("isGREASE(0x%04x) = %v, want %v", tc.v, got, tc.want)
		}
	}

	single := []struct {
		v    uint8
		want bool
	}{
		{0x0a, true},
		{0x1a, true},
		{0xfa, true},
		{0x00, false}, // uncompressed -- the format every browser sends
		{0x01, false}, // ansiX962 compressed prime
		{0x02, false}, // ansiX962 compressed char2
		{0x0b, false}, // low nibble is b
	}
	for _, tc := range single {
		if got := isGREASE8(tc.v); got != tc.want {
			t.Errorf("isGREASE8(0x%02x) = %v, want %v", tc.v, got, tc.want)
		}
	}
}

// TestFingerprintGREASEIsPositionAgnostic pins the property the old [1:]
// slicing could not deliver: a GREASE value ANYWHERE in a list -- first,
// middle, last -- is skipped, and every real element survives. The two hellos
// below carry the same signal and MUST derive the same fingerprint; with the
// index-0 truncation the second one kept its mid-list GREASE in the output and
// lost its leading real suite and curve instead. This is the round trip that
// also proves a GREASE-sending hello and a non-GREASE hello fingerprint
// identically whenever -- and only whenever -- their real signal matches.
func TestFingerprintGREASEIsPositionAgnostic(t *testing.T) {
	withCleanConnections(t)

	base := tls.ClientHelloInfo{
		CipherSuites:    []uint16{0x1301, 0x1302, 0x1303},
		SupportedCurves: []tls.CurveID{tls.X25519, tls.CurveP256},
		SupportedPoints: []uint8{0, 1},
	}
	greased := tls.ClientHelloInfo{
		CipherSuites: []uint16{
			0x0a0a, // leading GREASE, the one position [1:] happened to handle
			0x1301,
			0x1a1a, // mid-list GREASE, which [1:] kept in the output
			0x1302, 0x1303,
			0xfafa, // trailing GREASE
		},
		SupportedCurves: []tls.CurveID{
			tls.CurveID(0x0a0a), tls.X25519, tls.CurveID(0x1a1a), tls.CurveP256,
		},
		SupportedPoints: []uint8{0x0a, 0, 0x1a, 1, 0xfa},
	}
	want := "0x1301,0x1302,0x1303,0x583235353139,0x437572766550323536,0x0,0x1,"

	for _, tc := range []struct {
		name  string
		addr  string
		hello tls.ClientHelloInfo
	}{
		{"no GREASE", "203.0.113.7:44321", base},
		{"GREASE in first, middle and last positions", "203.0.113.7:44322", greased},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := newFakeConn(t, tc.addr)
			hello := tc.hello
			hello.Conn = conn

			cfg, err := Fingerprint(&hello)
			if cfg != nil || err != nil {
				t.Fatalf("Fingerprint returned (%v, %v), want (nil, nil)", cfg, err)
			}

			got, ok := readConnection(tc.addr)
			if !ok {
				t.Fatalf("Connections[%q] was not written", tc.addr)
			}
			if got != want {
				t.Errorf("fingerprint = %q, want %q; GREASE must be skipped wherever it "+
					"sits and every real element kept", got, want)
			}
		})
	}
}

// TestRegeneratedFirefoxFamilyKeysAreReachable round-trips every
// known_fingerprints.json key that wave 11 prep (GREASE fix) regenerated,
// proving the shipped keys are still derivable -- the same guarantee
// TestForbiddenFingerprintIsIntact provides for the block list. A key that
// nothing derives can never match anything: it reads as a populated table
// while Firefox-family traffic silently slides into the unknown-fingerprint
// ratelimit, with no error anywhere.
//
// The hellos are the inverse of the regeneration. Firefox-family clients send
// no GREASE, so each regenerated key is the pre-fix key with its first REAL
// cipher (0x1301, TLS_AES_128_GCM_SHA256) and first REAL curve (X25519,
// rendered as its CurveID-String() hex 0x583235353139) put back -- the
// elements the old index-0 truncation had discarded. If a future wave changes
// the derivation again, these round trips fail and the keys must be
// regenerated in the same commit, exactly as the Firefox golden case above
// prescribes.
func TestRegeneratedFirefoxFamilyKeysAreReachable(t *testing.T) {
	cases := []struct {
		label string
		hello tls.ClientHelloInfo
	}{
		{
			label: "Firefox",
			hello: tls.ClientHelloInfo{
				CipherSuites: []uint16{
					0x1301, 0x1303, 0x1302,
					0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030,
					0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
				},
				SupportedCurves: []tls.CurveID{
					tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521,
					tls.CurveID(256), tls.CurveID(257),
				},
				SupportedPoints: []uint8{0},
			},
		},
		{
			// Firefox-Dev ships the same TLS defaults minus 0xc00a/0xc009.
			label: "Firefox-Dev",
			hello: tls.ClientHelloInfo{
				CipherSuites: []uint16{
					0x1301, 0x1303, 0x1302,
					0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030,
					0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
				},
				SupportedCurves: []tls.CurveID{
					tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521,
					tls.CurveID(256), tls.CurveID(257),
				},
				SupportedPoints: []uint8{0},
			},
		},
		{
			// Tor Browser is Firefox ESR; the long Tor key is the Firefox list
			// plus trailing 0x000a (3DES), which Tor keeps for legacy relays.
			label: "Tor",
			hello: tls.ClientHelloInfo{
				CipherSuites: []uint16{
					0x1301, 0x1303, 0x1302,
					0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030,
					0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035, 0x000a,
				},
				SupportedCurves: []tls.CurveID{
					tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521,
					tls.CurveID(256), tls.CurveID(257),
				},
				SupportedPoints: []uint8{0},
			},
		},
		{
			// The short Tor key: a Tor build without the 3DES-era suites.
			label: "Tor",
			hello: tls.ClientHelloInfo{
				CipherSuites: []uint16{
					0x1301, 0x1303, 0x1302,
					0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0x009c, 0x009d,
				},
				SupportedCurves: []tls.CurveID{
					tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521,
					tls.CurveID(256), tls.CurveID(257),
				},
				SupportedPoints: []uint8{0},
			},
		},
	}

	withCleanConnections(t)
	for i, tc := range cases {
		uniqueAddr := "203.0.113.7:" + strconv.Itoa(44320+i)
		conn := newFakeConn(t, uniqueAddr)
		hello := tc.hello
		hello.Conn = conn

		cfg, err := Fingerprint(&hello)
		if cfg != nil || err != nil {
			t.Fatalf("%s: Fingerprint returned (%v, %v), want (nil, nil)", tc.label, cfg, err)
		}

		got, ok := readConnection(uniqueAddr)
		if !ok {
			t.Fatalf("%s: Connections[%q] was not written", tc.label, uniqueAddr)
		}
		if label := KnownFingerprints[got]; label != tc.label {
			t.Errorf("%s: hello derives %q, which maps to %q in KnownFingerprints; "+
				"the regenerated key and the derivation have drifted", tc.label, got, label)
		}
		if label := ForbiddenFingerprints[got]; label != "" {
			t.Errorf("%s: hello derives %q, which is BLOCKED as %q; the regeneration "+
				"collided with the block list", tc.label, got, label)
		}
	}
}

// TestFingerprintTablesAreWellFormed pins two properties of the shipped
// fingerprint tables that a regeneration in a later wave must not break.
func TestFingerprintTablesAreWellFormed(t *testing.T) {
	tables := map[string]map[string]string{
		"KnownFingerprints":     KnownFingerprints,
		"BotFingerprints":       BotFingerprints,
		"ForbiddenFingerprints": ForbiddenFingerprints,
	}

	for name, table := range tables {
		if len(table) == 0 {
			t.Errorf("%s is empty", name)
		}
		for fp, label := range table {
			if fp == "" {
				t.Errorf("%s has an empty fingerprint key mapping to %q; an empty "+
					"fingerprint is exactly what an all-GREASE hello produces", name, label)
			}
			// Fingerprint always emits a trailing comma after every element, so
			// every table key must end in one.
			if !strings.HasSuffix(fp, ",") {
				t.Errorf("%s key %q does not end in a comma; Fingerprint always "+
					"appends one, so this entry can never match", name, fp)
			}
		}
	}

	// FLIPPED (wave 4, fingerprint embedding). The hardcoded fallback table had
	// a BotFingerprints entry whose key began with a stray "(" --
	//
	//     "(0xcca9,0xcca8,..."  -> "Host-Tracker (page-speed)"
	//
	// Fingerprint never emits a leading "(", so that entry was dead and the bot
	// was silently unclassified. The bundled data carries the same signature
	// with the paren removed, so the entry is now reachable. Asserted in the
	// negative so a regression that reintroduces the typo -- or a hand-edit that
	// pastes the old fallback back in -- fails here.
	//
	// The generic loop above already rejects any key without a trailing comma;
	// this is the leading-junk half of the same class, which that loop cannot
	// see.
	const deadKeyPrefix = "(0xcca9,"
	for fp := range BotFingerprints {
		if strings.HasPrefix(fp, deadKeyPrefix) {
			t.Errorf("BotFingerprints key %q begins with %q; Fingerprint never emits a leading "+
				"paren, so this entry can never match and that bot goes unclassified",
				fp, deadKeyPrefix)
		}
	}

	// FLIPPED (wave 4, fingerprint embedding). The two long crawler
	// fingerprints -- "Unsolicited Cralwer" (typo) and "Unsolicited Crawler" --
	// are no longer in BotFingerprints at all. The bundled data promotes both to
	// ForbiddenFingerprints, which means they are now HARD-BLOCKED rather than
	// merely labelled. That is a real behaviour change; see the report for wave
	// 4.
	botLabels := map[string]bool{}
	for _, label := range BotFingerprints {
		botLabels[label] = true
	}
	if botLabels["Unsolicited Cralwer"] || botLabels["Unsolicited Crawler"] {
		t.Error("the Unsolicited Crawler signatures are expected to live in ForbiddenFingerprints " +
			"(hard block), not BotFingerprints (label only); if a wave moved them back, that " +
			"un-blocks those crawlers and this assertion must be flipped again")
	}

	// BUG (a later wave should flip this): the bundled ForbiddenFingerprints
	// carries two misspelled labels, "Unsolicited Cralwer" alongside the correct
	// "Unsolicited Crawler", and "Exploit Cralwer" alongside "Exploit-Crawler".
	// Labels are what operators compare against in firewall rules, so a rule
	// written as `ip.bot eq "Unsolicited Crawler"` still misses half the
	// signatures it was meant to name. Pinned so the typos stay visible in a
	// diff; fixing them is a data change, not a code change.
	forbiddenLabels := map[string]bool{}
	for _, label := range ForbiddenFingerprints {
		forbiddenLabels[label] = true
	}
	for _, typo := range []string{"Unsolicited Cralwer", "Exploit Cralwer"} {
		if !forbiddenLabels[typo] {
			t.Errorf("expected the misspelled ForbiddenFingerprints label %q to still be present; "+
				"if a wave fixed the typo, update this assertion and TestFingerprintTableLabels "+
				"in the same commit", typo)
		}
	}
	if !forbiddenLabels["Unsolicited Crawler"] {
		t.Error(`expected the correctly spelled label "Unsolicited Crawler" to still be present`)
	}
}

// TestFingerprintTableLabels pins the exact multiset of labels each shipped
// table publishes.
//
// Labels are not cosmetic: they are the string values operators compare against
// in firewall rules (`ip.bot eq "Safari"`, `ip.bot eq "Curl"`). Renaming one, or
// accidentally duplicating an existing name onto a second key -- exactly what a
// copy-paste during table regeneration produces -- silently reclassifies a whole
// client population with no error and no log line. The COUNT matters as much as
// the set: relabelling "Safari" to "Chromium" leaves the set of distinct labels
// looking almost right while making the Safari rule dead and folding iPhones in
// with desktop Chrome.
//
// If a wave legitimately adds, removes, or renames a fingerprint, update this
// table in the same commit so the reclassification is visible in the diff.
func TestFingerprintTableLabels(t *testing.T) {
	tables := []struct {
		name  string
		table map[string]string
		want  map[string]int
	}{
		// FLIPPED (wave 4, fingerprint embedding). All three want-sets below were
		// written against the hardcoded fallback tables in fingerprint.go. Those
		// are gone; the tables now come from the embedded global/fingerprints
		// bundle, which is what a production deployment was already running --
		// the old startup fetch overwrote the fallbacks with exactly this data
		// on every successful boot. The per-entry delta is recorded in the wave
		// 4 report.
		{
			name:  "KnownFingerprints",
			table: KnownFingerprints,
			want: map[string]int{
				"Chromium":     1,
				"Chromium Old": 1, // the key the old fallback called plain "Chromium"
				"Firefox":      1,
				"Firefox-Dev":  1,
				"Edge":         1,
				"Tor":          2, // two Tor builds share the label, deliberately
				"Safari":       1,
				"Dalvik":       1,
			},
		},
		{
			name:  "BotFingerprints",
			table: BotFingerprints,
			want: map[string]int{
				"Checkhost":                 1,
				"Host-Tracker (http)":       1,
				"Host-Tracker (page-speed)": 1, // key no longer has the dead leading "("
				"Postman":                   1,
				"Curl":                      1,
				"Aio-http":                  1,
				"DataForSeo":                1,
				"Python-Requests":           1,
				"Python-HttpLib":            1,
				"Go-Http-Client":            1,
				"GoogleBot":                 1,
				"Baiduspider/2.0":           1,
				"Loadster":                  1,
				"CensysInspect/1.1":         1,
				"InternetMeasurement/1.0":   1,
				"Zgrab Scanner":             1,
				// "Unsolicited Cralwer"/"Unsolicited Crawler" moved to
				// ForbiddenFingerprints -- they are hard-blocked now, not labelled.
			},
		},
		{
			// This table hard-blocks. It grew from 1 entry to 8, so the change
			// here is the one with teeth: see TestForbiddenFingerprintIsIntact,
			// which still pins the original Http-Flood (1) key byte-for-byte.
			name:  "ForbiddenFingerprints",
			table: ForbiddenFingerprints,
			want: map[string]int{
				"Http-Flood (1)":      1,
				"Http-Flood (2)":      1,
				"Headless Browser":    2,
				"Exploit-Crawler":     1,
				"Exploit Cralwer":     1, // sic -- pinned typo, see above
				"Unsolicited Crawler": 1,
				"Unsolicited Cralwer": 1, // sic -- pinned typo, see above
			},
		},
	}

	for _, tt := range tables {
		t.Run(tt.name, func(t *testing.T) {
			got := map[string]int{}
			for _, label := range tt.table {
				got[label]++
			}
			for label, wantN := range tt.want {
				if got[label] != wantN {
					t.Errorf("%s has %d entries labelled %q, want %d",
						tt.name, got[label], label, wantN)
				}
			}
			for label, gotN := range got {
				if _, ok := tt.want[label]; !ok {
					t.Errorf("%s has %d unexpected entries labelled %q; if this label was "+
						"added or renamed deliberately, update this test in the same commit",
						tt.name, gotN, label)
				}
			}
			// FLIPPED (wave 4, fingerprint embedding): this compared the entry
			// count against the number of DISTINCT labels, which only agreed
			// while every label was unique. The embedded tables share a label
			// across two keys twice ("Tor", "Headless Browser"), so the total
			// must be the sum of the wanted counts. Summing is strictly
			// stronger: the old form would have accepted a table that dropped
			// one Tor key and duplicated another label to compensate.
			wantTotal := 0
			for _, n := range tt.want {
				wantTotal += n
			}
			if len(tt.table) != wantTotal {
				t.Errorf("%s has %d entries, want %d", tt.name, len(tt.table), wantTotal)
			}
		})
	}
}

// httpFloodFingerprint is the Http-Flood (1) key in ForbiddenFingerprints,
// transcribed verbatim from the hardcoded table that core/firewall/fingerprint.go
// used to carry.
//
// FLIPPED (wave 4, fingerprint embedding): it is no longer the ONLY key. The
// embedded bundle ships 8 entries where the fallback shipped 1. The key itself
// is byte-identical across both, which is the point of keeping this constant --
// it proves the one signature the fork inherited survived the switch to
// embedded data unchanged.
//
// ForbiddenFingerprints is the only table that gates OUTRIGHT BLOCKING. A
// single transposed hex digit in this key -- the classic way a hand-edited or
// regenerated table goes wrong -- does not break anything loudly. It just means
// the TLS signature the proxy ships to hard-block an HTTP flood never matches
// again, and the flood is served. There is no error and no log line.
const httpFloodFingerprint = "0x1303,0x1302,0xc02f,0xc02b,0xc030,0xc02c,0x9e,0xc027,0x67,0xc028," +
	"0x6b,0x9f,0xcca9,0xcca8,0xccaa,0xc0af,0xc0ad,0xc0a3,0xc09f,0xc05d,0xc061,0xc053," +
	"0xc0ae,0xc0ac,0xc0a2,0xc09e,0xc05c,0xc060,0xc052,0xc024,0xc023,0xc00a,0xc014,0x39," +
	"0xc009,0xc013,0x33,0x9d,0xc0a1,0xc09d,0xc051,0x9c,0xc0a0,0xc09c,0xc050,0x3d,0x3c," +
	"0x35,0x2f,0xff," +
	"0x437572766550323536,0x4375727665494428333029,0x437572766550353231," +
	"0x437572766550333834,0x437572766549442832353629,0x437572766549442832353729," +
	"0x437572766549442832353829,0x437572766549442832353929,0x437572766549442832363029," +
	"0x0,"

// TestForbiddenFingerprintIsIntact pins the shipped block-list key exactly, both
// as a literal and end to end through Fingerprint.
//
// The literal assertion catches a corrupted key; the round trip proves the key
// is still REACHABLE -- that a ClientHello with these parameters actually
// produces this string, so the entry can fire at all. Together they mean a
// one-digit edit on either side (the table or the fingerprint derivation) fails
// the suite instead of quietly disarming the block list.
func TestForbiddenFingerprintIsIntact(t *testing.T) {
	t.Run("the shipped key is byte-exact", func(t *testing.T) {
		// FLIPPED (wave 4, fingerprint embedding): 1 -> 8. The count is pinned
		// rather than dropped so that silently shrinking the block list -- the
		// failure the discarded fetch error used to produce -- still fails here.
		if n := len(ForbiddenFingerprints); n != 8 {
			t.Fatalf("ForbiddenFingerprints has %d entries, want exactly 8; "+
				"if a wave added one, extend this test rather than deleting it", n)
		}
		label, ok := ForbiddenFingerprints[httpFloodFingerprint]
		if !ok {
			shipped := make([]string, 0, len(ForbiddenFingerprints))
			for k, v := range ForbiddenFingerprints {
				shipped = append(shipped, v+" -> "+k)
			}
			sort.Strings(shipped)
			t.Fatalf("the Http-Flood (1) block-list key changed.\nwant: %q\nshipped:\n  %s\n"+
				"ForbiddenFingerprints is the only table that hard-blocks: a single altered "+
				"digit disarms this entry silently.",
				httpFloodFingerprint, strings.Join(shipped, "\n  "))
		}
		if label != "Http-Flood (1)" {
			t.Errorf("ForbiddenFingerprints[httpFloodFingerprint] = %q, want %q", label, "Http-Flood (1)")
		}
	})

	t.Run("a matching hello still derives that key", func(t *testing.T) {
		withCleanConnections(t)

		const addr = "203.0.113.66:31337"
		conn := newFakeConn(t, addr)

		// The leading GREASE values are filtered out by pattern, not by index,
		// and are placeholders for whatever the flood tool actually sent
		// first; every element after them is the real signature. Because they
		// match the GREASE pattern wherever they sit, this round trip derives
		// the shipped key identically before and after the wave 11 prep fix.
		hello := tls.ClientHelloInfo{
			CipherSuites: []uint16{
				0x0a0a, // GREASE, filtered wherever it sits
				0x1303, 0x1302, 0xc02f, 0xc02b, 0xc030, 0xc02c, 0x009e, 0xc027, 0x0067, 0xc028,
				0x006b, 0x009f, 0xcca9, 0xcca8, 0xccaa, 0xc0af, 0xc0ad, 0xc0a3, 0xc09f, 0xc05d,
				0xc061, 0xc053, 0xc0ae, 0xc0ac, 0xc0a2, 0xc09e, 0xc05c, 0xc060, 0xc052, 0xc024,
				0xc023, 0xc00a, 0xc014, 0x0039, 0xc009, 0xc013, 0x0033, 0x009d, 0xc0a1, 0xc09d,
				0xc051, 0x009c, 0xc0a0, 0xc09c, 0xc050, 0x003d, 0x003c, 0x0035, 0x002f, 0x00ff,
			},
			SupportedCurves: []tls.CurveID{
				tls.CurveID(0x0a0a), // GREASE, filtered wherever it sits
				tls.CurveP256,
				tls.CurveID(30),
				tls.CurveP521,
				tls.CurveP384,
				tls.CurveID(256), tls.CurveID(257), tls.CurveID(258),
				tls.CurveID(259), tls.CurveID(260),
			},
			SupportedPoints: []uint8{0},
			Conn:            conn,
		}

		if _, err := Fingerprint(&hello); err != nil {
			t.Fatalf("Fingerprint: %v", err)
		}

		got, ok := readConnection(addr)
		if !ok {
			t.Fatalf("Connections[%q] was not written", addr)
		}
		if got != httpFloodFingerprint {
			t.Fatalf("Fingerprint derived a string that no longer matches the shipped "+
				"block-list key\n got: %q\nwant: %q", got, httpFloodFingerprint)
		}
		if label := ForbiddenFingerprints[got]; label != "Http-Flood (1)" {
			t.Errorf("ForbiddenFingerprints[derived] = %q, want %q; the flood signature the "+
				"proxy ships to hard-block would be served instead of blocked", label, "Http-Flood (1)")
		}
	})
}

// TestOnStateChangeEvictsFingerprint pins the other half of the Connections
// lifecycle: entries written by Fingerprint are removed when the connection is
// hijacked or closed, and are NOT removed on any other state transition.
//
// This matters for wave 7: if the eviction is dropped or the key derivation
// changes, Connections grows without bound under an attack, one entry per
// source port.
func TestOnStateChangeEvictsFingerprint(t *testing.T) {
	states := []struct {
		name    string
		state   http.ConnState
		evicted bool
	}{
		{name: "StateNew keeps the entry", state: http.StateNew, evicted: false},
		{name: "StateActive keeps the entry", state: http.StateActive, evicted: false},
		{name: "StateIdle keeps the entry", state: http.StateIdle, evicted: false},
		{name: "StateHijacked evicts", state: http.StateHijacked, evicted: true},
		{name: "StateClosed evicts", state: http.StateClosed, evicted: true},
	}

	for _, tt := range states {
		t.Run(tt.name, func(t *testing.T) {
			withCleanConnections(t)

			addr := "192.0.2.99:7000"
			conn := newFakeConn(t, addr)

			hello := tls.ClientHelloInfo{
				CipherSuites:    []uint16{0x0a0a, 0x1301},
				SupportedPoints: []uint8{0},
				Conn:            conn,
			}
			if _, err := Fingerprint(&hello); err != nil {
				t.Fatalf("Fingerprint: %v", err)
			}
			if _, ok := readConnection(addr); !ok {
				t.Fatalf("precondition failed: Connections[%q] missing", addr)
			}

			OnStateChange(conn, tt.state)

			_, ok := readConnection(addr)
			if tt.evicted && ok {
				t.Errorf("Connections[%q] still present after %s, want it evicted", addr, tt.name)
			}
			if !tt.evicted && !ok {
				t.Errorf("Connections[%q] was evicted on %s, want it kept", addr, tt.name)
			}
		})
	}
}

// TestOnStateChangeEvictionHoldsTheMutex proves the eviction actually takes
// firewall.Mutex, rather than merely proving the entry ends up gone.
//
// Why an assertion on the LOCK and not just on the map: Connections is a plain
// Go map. Fingerprint writes it from a TLS-handshake goroutine; OnStateChange
// deletes from it on every connection close. Those two run concurrently by
// construction -- net/http calls ConnState from the connection's own serve
// goroutine while other connections are still handshaking. An unsynchronised
// delete racing a write is not a lost update, it is
// `fatal error: concurrent map writes`, which net/http's per-handler recover
// cannot catch. The process dies, and it dies hardest exactly when connection
// churn peaks: during an attack.
//
// A test that only checks "the key is gone afterwards" passes with the
// Lock/Unlock pair deleted, because a single-goroutine delete needs no lock.
// So this test holds the mutex itself and requires OnStateChange to BLOCK:
//
//   - correct code blocks on Mutex.Lock() and can never signal while we hold it,
//     so the "finished early" branch is unreachable -- no flake in that direction;
//   - code with the lock removed deletes immediately and signals.
//
// The goroutine announces itself before calling OnStateChange, so the wait
// covers only the handful of instructions between that announcement and the
// delete.
//
// Wave 7 replaces this global RWMutex with sharding or a sync.Map. That is a
// fine change -- but it must keep eviction and insertion mutually excluded, and
// if it does, this test needs rewriting against the new primitive rather than
// deleting.
func TestOnStateChangeEvictionHoldsTheMutex(t *testing.T) {
	withCleanConnections(t)

	const addr = "192.0.2.77:8100"
	conn := newFakeConn(t, addr)

	hello := tls.ClientHelloInfo{
		CipherSuites:    []uint16{0x0a0a, 0x1301},
		SupportedPoints: []uint8{0},
		Conn:            conn,
	}
	if _, err := Fingerprint(&hello); err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if _, ok := readConnection(addr); !ok {
		t.Fatalf("precondition failed: Connections[%q] missing", addr)
	}

	started := make(chan struct{})
	finished := make(chan struct{})

	// Take the lock the eviction must contend for. releaseOnce guards against a
	// double Unlock on the failure paths, and the defer makes sure the lock is
	// released even if the test aborts via t.Fatalf (which runs deferred calls).
	var releaseOnce sync.Once
	Mutex.Lock()
	release := func() { releaseOnce.Do(func() { Mutex.Unlock() }) }
	defer release()

	go func() {
		close(started)
		OnStateChange(conn, http.StateClosed)
		close(finished)
	}()

	<-started

	select {
	case <-finished:
		release()
		t.Fatalf("OnStateChange evicted Connections[%q] while the test held firewall.Mutex; "+
			"the eviction must take the lock, because it races Fingerprint's write to the "+
			"same map on every connection close", addr)
	case <-time.After(250 * time.Millisecond):
		// Expected: blocked on Mutex.Lock().
	}

	// Entry must still be there -- nothing can have deleted it under our lock.
	if _, ok := Connections[addr]; !ok {
		release()
		t.Fatalf("Connections[%q] disappeared while the test held firewall.Mutex", addr)
	}

	release()

	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("OnStateChange never completed after firewall.Mutex was released")
	}

	if _, ok := readConnection(addr); ok {
		t.Errorf("Connections[%q] still present after StateClosed, want it evicted", addr)
	}
}

// TestOnStateChangeConcurrentWithFingerprint is the -race tripwire for the pair
// of operations that actually collide in production: a delete on one connection
// while another connection is being fingerprinted.
//
// Under `go test -race` this fails immediately if either side drops its lock.
// Without -race it is still worth running: the Go runtime's own
// concurrent-map-writes detector fires on the same access pattern. Treat
// TestOnStateChangeEvictionHoldsTheMutex as the deterministic assertion and this
// as the belt-and-braces one.
func TestOnStateChangeConcurrentWithFingerprint(t *testing.T) {
	withCleanConnections(t)

	const (
		goroutines = 16
		iterations = 50
	)

	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		conn := newFakeConn(t, "192.0.2.2:"+strconv.Itoa(50000+i))
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < iterations; j++ {
				hello := tls.ClientHelloInfo{
					CipherSuites:    []uint16{0x0a0a, 0x1301, 0x1302},
					SupportedPoints: []uint8{0},
					Conn:            conn,
				}
				if _, err := Fingerprint(&hello); err != nil {
					t.Errorf("Fingerprint: %v", err)
					return
				}
				OnStateChange(conn, http.StateClosed)
			}
		}()
	}

	close(start)
	wg.Wait()

	// Every goroutine ends on an eviction, so the map must drain completely.
	if n := connectionCount(); n != 0 {
		t.Errorf("Connections has %d entries after every connection closed, want 0", n)
	}
}
