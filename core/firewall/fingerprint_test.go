package firewall

import (
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
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
			// the first curve slot. Dropping index 0 is exactly right here --
			// this is the case the "ignore first elements" comment was written
			// for -- and the result byte-matches the "Chromium" entry that
			// fingerprint.go ships.
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
			known:  "Chromium",
			reason: "GREASE occupies index 0, so dropping it recovers the real suite list",
		},
		{
			// BUG (a later wave should flip this): Firefox does NOT send GREASE.
			// Index 0 of its cipher list is a genuine suite (0x1301,
			// TLS_AES_128_GCM_SHA256) and index 0 of its curve list is a genuine
			// curve (X25519) -- and the code throws both away regardless. The
			// shipped "Firefox" entry in KnownFingerprints was itself generated
			// from this lossy output, so the two agree, but the fingerprint is
			// strictly weaker than it needs to be: any client differing from
			// Firefox ONLY in its first cipher suite or first curve is
			// indistinguishable from Firefox today.
			//
			// When a wave switches to GREASE-pattern filtering (drop 0x?a?a
			// values) instead of blind index-0 truncation, this expectation must
			// gain a leading "0x1301," and a "0x583235353139," before the curves,
			// and the KnownFingerprints table must be regenerated with it.
			name: "firefox-like hello without GREASE loses a real cipher and a real curve",
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
			want: "0x1303,0x1302,0xc02b,0xc02f,0xcca9,0xcca8,0xc02c,0xc030," +
				"0xc00a,0xc009,0xc013,0xc014,0x9c,0x9d,0x2f,0x35," +
				"0x437572766550323536,0x437572766550333834,0x437572766550353231," +
				"0x437572766549442832353629,0x437572766549442832353729,0x0,",
			known:  "Firefox",
			reason: "no GREASE, so index-0 truncation discards signal",
		},
		{
			// BUG (a later wave should flip this): the three slice expressions in
			// Fingerprint are NOT symmetrical.
			//
			//     CipherSuites[1:]     -> drop the first element
			//     SupportedCurves[1:]  -> drop the first element
			//     SupportedPoints[:1]  -> keep ONLY the first element
			//
			// The comment directly above them says "ignore first elements of
			// arrays", which describes [1:] and contradicts [:1]. In practice
			// ec_point_formats is almost always the single byte 0x00, so the two
			// readings coincide and the defect hides -- but a client that offers
			// several point formats contributes exactly one byte of signal, and
			// always the same one. This case forces the asymmetry into the open
			// with three point formats: only 0x0 appears.
			//
			// If a wave "fixes" [:1] to [1:], this expectation flips from
			// "...,0x0," to "...,0x1,0x2,".
			name: "multiple point formats: [:1] keeps the first instead of dropping it",
			hello: tls.ClientHelloInfo{
				CipherSuites:    []uint16{0x0a0a, 0x1301, 0x1302},
				SupportedCurves: []tls.CurveID{tls.CurveID(0x0a0a), tls.X25519},
				SupportedPoints: []uint8{0, 1, 2},
			},
			want:   "0x1301,0x1302,0x583235353139,0x0,",
			reason: "SupportedPoints[:1] is a head-take, not a tail-take",
		},
		{
			// len(SupportedCurves) == 0 is guarded, so [1:] is never evaluated
			// and the curve section is simply absent.
			name: "empty SupportedCurves contributes nothing",
			hello: tls.ClientHelloInfo{
				CipherSuites:    []uint16{0x0a0a, 0x1301, 0x1302},
				SupportedCurves: []tls.CurveID{},
				SupportedPoints: []uint8{0},
			},
			want:   "0x1301,0x1302,0x0,",
			reason: "the len() > 0 guard skips the whole curve loop",
		},
		{
			name: "nil SupportedCurves behaves the same as empty",
			hello: tls.ClientHelloInfo{
				CipherSuites:    []uint16{0x0a0a, 0x1301, 0x1302},
				SupportedCurves: nil,
				SupportedPoints: []uint8{0},
			},
			want:   "0x1301,0x1302,0x0,",
			reason: "nil slices have len 0",
		},
		{
			name: "empty SupportedPoints contributes nothing",
			hello: tls.ClientHelloInfo{
				CipherSuites:    []uint16{0x0a0a, 0x1301, 0x1302},
				SupportedCurves: []tls.CurveID{tls.CurveID(0x0a0a), tls.X25519},
				SupportedPoints: []uint8{},
			},
			want:   "0x1301,0x1302,0x583235353139,",
			reason: "the len() > 0 guard skips the point loop",
		},
		{
			// A single curve is entirely consumed by the [1:] truncation.
			name: "single-element SupportedCurves is erased by [1:]",
			hello: tls.ClientHelloInfo{
				CipherSuites:    []uint16{0x0a0a, 0x1301},
				SupportedCurves: []tls.CurveID{tls.X25519},
				SupportedPoints: []uint8{0},
			},
			want:   "0x1301,0x0,",
			reason: "[1:] on a length-1 slice yields an empty slice, not a panic",
		},
		{
			// BUG (a later wave should flip this): a hello offering exactly ONE
			// cipher suite survives the len() > 0 guard, then [1:] erases the
			// only suite it had. Every such client -- regardless of WHICH suite
			// it offered -- collapses onto the same fingerprint, keyed only by
			// its curves and point formats. Two different single-suite scanners
			// are literally indistinguishable.
			name: "single-element CipherSuites is erased by [1:] (no panic)",
			hello: tls.ClientHelloInfo{
				CipherSuites:    []uint16{0x1301},
				SupportedCurves: []tls.CurveID{tls.CurveID(0x0a0a), tls.X25519},
				SupportedPoints: []uint8{0},
			},
			want:   "0x583235353139,0x0,",
			reason: "[1:] on a length-1 slice is legal Go and yields an empty slice",
		},
		{
			// The degenerate end of the same defect: one suite, one curve, no
			// points leaves the fingerprint completely EMPTY. Connections then
			// maps this peer to "", which is the same value an unfingerprinted
			// peer would look up as a miss.
			name: "everything truncated away yields an empty fingerprint string",
			hello: tls.ClientHelloInfo{
				CipherSuites:    []uint16{0x1301},
				SupportedCurves: []tls.CurveID{tls.X25519},
				SupportedPoints: nil,
			},
			want:   "",
			reason: "all three sections truncate to nothing",
		},
		{
			// Sanity check that suite values above 0x00ff render without any
			// zero padding, and values below render without a leading zero.
			name: "hex rendering has no zero padding",
			hello: tls.ClientHelloInfo{
				CipherSuites:    []uint16{0xffff, 0x0005, 0x00ff, 0x0100},
				SupportedCurves: nil,
				SupportedPoints: []uint8{0x0f},
			},
			want:   "0x5,0xff,0x100,0xf,",
			reason: "%x is unpadded",
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
// Note this is also what stops CipherSuites[1:] from panicking on a zero-length
// slice -- the guard, not the slice expression, is doing the work. If a future
// wave removes or reorders that guard, [1:] on an empty slice panics inside the
// TLS handshake callback.
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
					"fingerprint is exactly what a fully-truncated hello produces", name, label)
			}
			// Fingerprint always emits a trailing comma after every element, so
			// every table key must end in one.
			if !strings.HasSuffix(fp, ",") {
				t.Errorf("%s key %q does not end in a comma; Fingerprint always "+
					"appends one, so this entry can never match", name, fp)
			}
		}
	}

	// BUG (a later wave should flip this): BotFingerprints contains an entry
	// whose key begins with a stray "(" --
	//
	//     "(0xcca9,0xcca8,..."  -> "Host-Tracker (page-speed)"
	//
	// Fingerprint never emits a leading "(", so this entry is dead: that bot is
	// silently unclassified. Pinned here so the typo is visible in a diff when
	// the tables are regenerated.
	const deadKeyPrefix = "(0xcca9,"
	found := false
	for fp := range BotFingerprints {
		if strings.HasPrefix(fp, deadKeyPrefix) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the malformed BotFingerprints key starting %q to still be present; "+
			"if a wave fixed it, delete this assertion", deadKeyPrefix)
	}

	// BUG (a later wave should flip this): the two long crawler fingerprints are
	// labelled "Unsolicited Cralwer" (typo) and "Unsolicited Crawler". Any
	// operator rule written as `ip.bot eq "Unsolicited Crawler"` therefore misses
	// half the crawlers it was meant to catch.
	labels := map[string]bool{}
	for _, label := range BotFingerprints {
		labels[label] = true
	}
	if !labels["Unsolicited Cralwer"] {
		t.Error(`expected the misspelled bot label "Unsolicited Cralwer" to still be present; ` +
			`if a wave fixed the typo, delete this assertion`)
	}
	if !labels["Unsolicited Crawler"] {
		t.Error(`expected the correctly spelled bot label "Unsolicited Crawler" to still be present`)
	}
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
