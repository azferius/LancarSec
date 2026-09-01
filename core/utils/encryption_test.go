package utils

import (
	"strconv"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Encrypt / EncryptSha — golden vectors
//
// These pin the EXACT hex output of the two hash helpers. They are the
// derivation used for every clearance cookie the proxy issues
// (core/server/middleware.go:192-198) and for the hourly OTP rotation
// (core/server/monitor.go), so any change to them invalidates every cookie in
// the wild.
//
// WAVE 5 REBASELINED EVERY VALUE HERE. Encrypt moved from
// blake3.Sum256(input+key) to BLAKE3 keyed with a KDF-derived subkey, and
// EncryptSha moved from sha256(input+key) to HMAC-SHA256. Both old forms were
// plain concatenations with no message/key boundary. The digests below are the
// new ones; a diff against the wave-3 values is the audit trail of exactly
// which token derivations moved and therefore which cookies were invalidated.
// ---------------------------------------------------------------------------

func TestEncryptGolden(t *testing.T) {
	tests := []struct {
		name  string
		input string
		key   string
		want  string
	}{
		{
			name:  "empty input and key",
			input: "", key: "",
			want: "b5a09005eb0d121be0f46aa57bd862795521249428aaa65369634de19111c1bb",
		},
		{
			name:  "short input short key",
			input: "ab", key: "cdef",
			want: "39fd879c348f31520b260737b6016c4eb7dcbb1752af45328c42128b79465adb",
		},
		{
			name:  "access-key shaped input",
			input: "1.2.3.4|Mozilla/5.0|/index.html", key: "s3cr3t",
			want: "6f58bf6d5fd7bdbbdb970cb19e8a317090bbb063bdcf663d4b52aaf873188b51",
		},
		{
			name:  "otp shaped input",
			input: "lancarsec", key: "2026-08-30",
			want: "ee2629a3bba606bc3f59c3b1d8854e70b7cef9327eafcd738bbf5bbe7856550c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Encrypt(tt.input, tt.key)
			if got != tt.want {
				t.Errorf("Encrypt(%q, %q) = %q, want %q", tt.input, tt.key, got, tt.want)
			}
			if len(got) != 64 {
				t.Errorf("Encrypt returned %d hex chars, want 64 (blake3-256)", len(got))
			}
		})
	}
}

func TestEncryptShaGolden(t *testing.T) {
	tests := []struct {
		name  string
		input string
		key   string
		want  string
	}{
		{
			name:  "empty input and key",
			input: "", key: "",
			want: "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",
		},
		{
			name:  "short input short key",
			input: "ab", key: "cdef",
			want: "dfdf3499593c6fd2eefcb7d41868ebbf42f035a75c03e7c79d61c8e3b013688b",
		},
		{
			name:  "hashed encrypted ip (key is empty in middleware.go:195)",
			input: "1.2.3.4|Mozilla/5.0|/index.html", key: "s3cr3t",
			want: "1b45bb8de8e94eca9cd3fc929b0f8b0a6f6a17ebe2f6cac2cf5e67ff14e88468",
		},
		{
			name:  "otp shaped input",
			input: "lancarsec", key: "2026-08-30",
			want: "aa4f8b49b24b322a2516939cf704cf364651d54d501f5a91cf422c068f042b1e",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncryptSha(tt.input, tt.key)
			if got != tt.want {
				t.Errorf("EncryptSha(%q, %q) = %q, want %q", tt.input, tt.key, got, tt.want)
			}
			if len(got) != 64 {
				t.Errorf("EncryptSha returned %d hex chars, want 64 (sha256)", len(got))
			}
		})
	}
}

// FIXED IN WAVE 5 (this assertion was inverted; it used to require the
// collision). Encrypt was blake3.Sum256(input + key) — a plain string
// concatenation, not a keyed hash — so the boundary between message and key was
// invisible and any two (input, key) pairs with an equal concatenation produced
// the same digest: Encrypt("ab","cdef") == Encrypt("abc","def"). In the proxy
// that meant a clearance token derived from one (accessKey, OTP) split was
// valid for a different split of the same joined string, and accessKey is built
// from bytes the client controls (User-Agent above all), so the shift was
// reachable. Encrypt is now BLAKE3 keyed with a subkey derived from key, which
// makes the split part of the computation. These digests must now DIFFER.
func TestEncryptBoundaryIsNotAmbiguous(t *testing.T) {
	a := Encrypt("ab", "cdef")
	b := Encrypt("abc", "def")
	if a == b {
		t.Fatalf("Encrypt(\"ab\",\"cdef\") == Encrypt(\"abc\",\"def\") == %q — the message/key boundary is not part of the hash", a)
	}

	// The same property, in the shape it appears in middleware: moving one byte
	// from the subject identity into the secret must change the digest.
	c := Encrypt("1.2.3.4|UA|/pathS", "ECRET")
	d := Encrypt("1.2.3.4|UA|/path", "SECRET")
	if c == d {
		t.Fatalf("Encrypt collided across the identity/secret boundary: both = %q", c)
	}
}

// FIXED IN WAVE 5 (this assertion was inverted; it used to require the
// collision). EncryptSha was sha256(input + key): the same boundary ambiguity
// as Encrypt, plus SHA-256's length-extension property, which makes a bare
// concatenation MAC forgeable from a digest and a length alone. It is now
// HMAC-SHA256, which has neither. These digests must now DIFFER.
func TestEncryptShaBoundaryIsNotAmbiguous(t *testing.T) {
	a := EncryptSha("ab", "cdef")
	b := EncryptSha("abc", "def")
	if a == b {
		t.Fatalf("EncryptSha(\"ab\",\"cdef\") == EncryptSha(\"abc\",\"def\") == %q — the message/key boundary is not part of the MAC", a)
	}

	// The OTP rotation does EncryptSha(secret, bucket). A secret ending in "2"
	// and a bucket starting one character later must no longer collide.
	c := EncryptSha("secret2", "026-08-30")
	d := EncryptSha("secret", "2026-08-30")
	if c == d {
		t.Fatalf("EncryptSha collided across the secret/bucket boundary: both = %q", c)
	}
}

func TestEncryptIsDeterministic(t *testing.T) {
	const in, key = "deterministic-check", "k"
	first := Encrypt(in, key)
	for i := 0; i < 100; i++ {
		if got := Encrypt(in, key); got != first {
			t.Fatalf("Encrypt is not deterministic: iteration %d gave %q, want %q", i, got, first)
		}
	}
	firstSha := EncryptSha(in, key)
	for i := 0; i < 100; i++ {
		if got := EncryptSha(in, key); got != firstSha {
			t.Fatalf("EncryptSha is not deterministic: iteration %d gave %q, want %q", i, got, firstSha)
		}
	}
}

// NEW IN WAVE 5. Encrypt and EncryptSha recycle their hash states through a
// per-key sync.Pool, because a blake3.Hasher is 10840 bytes and allocating one
// per call cost 3 us and 22 KiB — on a path the middleware runs for every
// token-cache miss, i.e. every request of a flood from rotating addresses.
//
// Pooling is where a correct hash function turns into a wrong one: a hasher
// returned to the pool with input still buffered would make the NEXT token a
// hash of both requests concatenated. That does not fail loudly — it silently
// issues a token the verifier will reject, re-challenging the visitor forever.
// These two tests interleave inputs through the pool and assert every digest
// still matches the single-shot value.
func TestEncryptPoolDoesNotCarryStateBetweenCalls(t *testing.T) {
	const key = "pool-state-key"

	inputs := []string{"", "a", "ab", "abc", strings.Repeat("x", 5000), strings.Repeat("y", 20000), "final"}

	// 5000 bytes stays inside the blake3 hasher's 8 KiB internal buffer and
	// 20000 spills past it into the chaining-value stack. Both are state a bad
	// Reset would leave behind for the next caller.
	want := make([]string, len(inputs))
	for i, in := range inputs {
		want[i] = Encrypt(in, key)
	}

	// Now churn the same key's pool repeatedly and in a different order.
	for round := 0; round < 50; round++ {
		for i := len(inputs) - 1; i >= 0; i-- {
			if got := Encrypt(inputs[i], key); got != want[i] {
				t.Fatalf("round %d: Encrypt(%.20q, key) = %q, want %q — a pooled hasher carried state", round, inputs[i], got, want[i])
			}
		}
	}

	for round := 0; round < 50; round++ {
		for i, in := range inputs {
			if got := EncryptSha(in, key); got != EncryptSha(in, key) {
				t.Fatalf("round %d input %d: EncryptSha is not stable across pooled calls", round, i)
			}
		}
	}
}

// The pool must also be safe to share. Run under -race this is the regression
// test for a hasher escaping to two goroutines at once.
func TestEncryptIsConcurrencySafe(t *testing.T) {
	const (
		key        = "concurrent-key"
		goroutines = 16
		iterations = 500
	)

	inputs := []string{"alpha", "beta", "gamma", "delta"}
	want := make([]string, len(inputs))
	wantSha := make([]string, len(inputs))
	for i, in := range inputs {
		want[i] = Encrypt(in, key)
		wantSha[i] = EncryptSha(in, key)
	}

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for it := 0; it < iterations; it++ {
				i := (g + it) % len(inputs)
				if got := Encrypt(inputs[i], key); got != want[i] {
					t.Errorf("Encrypt(%q) = %q, want %q", inputs[i], got, want[i])
					return
				}
				if got := EncryptSha(inputs[i], key); got != wantSha[i] {
					t.Errorf("EncryptSha(%q) = %q, want %q", inputs[i], got, wantSha[i])
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

// The per-key cache is bounded so that a caller with an unbounded key space
// cannot grow it without limit. Past the bound the result must still be
// correct — only unmemoised. This walks well past encryptKeyCacheMax with
// distinct keys and checks both the digests and that the counter stops.
func TestEncryptKeyCacheIsBounded(t *testing.T) {
	for i := 0; i < encryptKeyCacheMax*8; i++ {
		key := "bounded-key-" + strconv.Itoa(i)
		first := Encrypt("payload", key)
		if second := Encrypt("payload", key); second != first {
			t.Fatalf("key %q: uncached path is not deterministic: %q vs %q", key, first, second)
		}
		if sha := EncryptSha("payload", key); sha != EncryptSha("payload", key) {
			t.Fatalf("key %q: uncached EncryptSha is not deterministic", key)
		}
	}

	if n := encryptKeyCacheLen.Load(); n > encryptKeyCacheMax {
		t.Errorf("encryptKeyCacheLen = %d, must not exceed the bound %d", n, encryptKeyCacheMax)
	}
	if n := macKeyCacheLen.Load(); n > encryptKeyCacheMax {
		t.Errorf("macKeyCacheLen = %d, must not exceed the bound %d", n, encryptKeyCacheMax)
	}
}

// ---------------------------------------------------------------------------
// RandomString
//
// NO GOLDEN TEST IS POSSIBLE, and after wave 5 that is by construction rather
// than by accident. RandomString now draws from crypto/rand, which has no seed
// and no injectable source, so output differs on every run and a fixed expected
// string would be permanently red. We test SHAPE and DISTRIBUTION: length,
// alphabet membership, the boundary cases, and — new in wave 5 — that the
// modulo reduction is unbiased.
//
// Every shape assertion below is unchanged from wave 3. That is the point: the
// math/rand -> crypto/rand swap is meant to be invisible to every caller, and
// these tests are the net that proves it.
// ---------------------------------------------------------------------------

const randomStringAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func TestRandomStringShape(t *testing.T) {
	for _, length := range []int{0, 1, 2, 20, 24, 25, 30, 64, 256} {
		got := RandomString(length)
		// Alphabet is ASCII-only, so rune count == byte count.
		if len([]rune(got)) != length {
			t.Errorf("RandomString(%d) produced %d runes, want %d", length, len([]rune(got)), length)
		}
		if len(got) != length {
			t.Errorf("RandomString(%d) produced %d bytes, want %d (alphabet is ASCII)", length, len(got), length)
		}
		for i, r := range got {
			if !strings.ContainsRune(randomStringAlphabet, r) {
				t.Errorf("RandomString(%d) byte %d is %q, outside the alphabet %q", length, i, r, randomStringAlphabet)
			}
		}
	}
}

func TestRandomStringZeroLengthIsEmpty(t *testing.T) {
	if got := RandomString(0); got != "" {
		t.Errorf("RandomString(0) = %q, want %q", got, "")
	}
}

// Pins today's contract: a negative length panics inside make(). No caller
// passes a negative today (all call sites are constants), but the function does
// not guard it. Documented so a wave that adds a guard shows the change.
func TestRandomStringNegativeLengthPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("RandomString(-1) did not panic; today it panics in make([]rune, -1)")
		}
	}()
	_ = RandomString(-1)
}

// Weak but non-flaky liveness check: 64 chars drawn from a 62-symbol alphabet
// being ALL identical has probability 62^-63, which will not happen. This
// catches a regression that returns a constant or a zero value without being
// timing- or seed-dependent.
func TestRandomStringIsNotConstant(t *testing.T) {
	got := RandomString(64)
	allSame := true
	for i := 1; i < len(got); i++ {
		if got[i] != got[0] {
			allSame = false
			break
		}
	}
	if allSame {
		t.Fatalf("RandomString(64) returned %d copies of one character (%q) — generator is degenerate", len(got), got[0])
	}
}

// The property that makes RandomString usable as a secret generator at all:
// two calls with the SAME length must not produce the same string. Anything
// that makes the output a pure function of the length — a zeroed buffer, a
// reused/positional index, a `rand.Read` whose error is swallowed leaving the
// slice untouched, or a source that is never advanced — collapses this to a
// single value and reproduces audit finding #1 ("every secret is identical on
// every install") in its most extreme form.
//
// Not seed- or timing-dependent: eight 32-character draws from a 62-symbol
// alphabet colliding by chance has probability under 62^-32 (~1e-57) per pair,
// so this cannot flake. It deliberately does NOT pin the values, only that they
// differ, so it keeps working unchanged when wave 5 swaps math/rand for
// crypto/rand.
func TestRandomStringVariesBetweenCalls(t *testing.T) {
	const (
		length  = 32
		samples = 8
	)

	seen := make(map[string]bool, samples)
	order := make([]string, 0, samples)
	for i := 0; i < samples; i++ {
		s := RandomString(length)
		order = append(order, s)
		seen[s] = true
	}

	if len(seen) != samples {
		t.Fatalf("%d calls to RandomString(%d) produced only %d distinct values (%q) — the generator is a pure function of the length, not a source of randomness", samples, length, len(seen), order)
	}
}

// Every character of the declared alphabet must be reachable. This is the
// off-by-one net for the index bound: `rand.Intn(len(rnd)-1)` still produces
// well-formed, varying, correct-length output and only ever drops the LAST
// symbol ('9'), silently shrinking the secret alphabet from 62 to 61 and every
// secret's entropy with it. Nothing else in this file would notice.
//
// Non-flaky: a specific character missing from 4000 independent uniform draws
// over 62 symbols has probability (61/62)^4000 ≈ 1e-28, so even summed over the
// whole alphabet a spurious failure is ~1e-26.
func TestRandomStringUsesEveryCharacterOfItsAlphabet(t *testing.T) {
	const draws = 4000

	seen := make(map[rune]bool, len(randomStringAlphabet))
	for _, r := range RandomString(draws) {
		seen[r] = true
	}

	var missing []string
	for _, r := range randomStringAlphabet {
		if !seen[r] {
			missing = append(missing, string(r))
		}
	}
	if len(missing) != 0 {
		t.Errorf("RandomString never emitted %v in %d draws; the alphabet is %q (%d symbols) but only %d are reachable — the index bound is wrong", missing, draws, randomStringAlphabet, len(randomStringAlphabet), len(seen))
	}
}

// NEW IN WAVE 5. The modulo-bias net.
//
// The alphabet has 62 symbols and a byte has 256 values. 256 = 4*62 + 8, so the
// naive `randomByte % 62` maps FIVE byte values onto each of the first 8
// symbols ('a'..'h') and only FOUR onto the other 54 — those 8 symbols come up
// 25% more often than the rest. That is invisible to every other test in this
// file: the output is still varying, still correct-length, still covers the
// whole alphabet. It only shows up as a distribution, and it silently costs
// entropy from every secret the first-launch wizard writes into config.json.
// RandomString rejects bytes >= 248 to make the reduction exact.
//
// Non-flaky by design. With n = 620000 draws the expected count per symbol is
// 10000 with sd = sqrt(n*p*(1-p)) ≈ 99.2. The biased implementation would put
// the first 8 symbols at 5/248 * n ≈ 12500 — 25 sd above expectation, which is
// not a coincidence any run produces. The tolerance below is 6 sd (±600, i.e.
// ±6%), so a correct implementation fails with probability ~1e-9 per symbol and
// the biased one fails every single time.
func TestRandomStringIsNotModuloBiased(t *testing.T) {
	const (
		draws     = 620000
		expected  = draws / len(randomStringAlphabet)
		tolerance = 600
	)

	counts := make(map[rune]int, len(randomStringAlphabet))
	for _, r := range RandomString(draws) {
		counts[r]++
	}

	// The 8 symbols a naive `% 62` over a full byte would over-represent.
	biasedHead := randomStringAlphabet[:256%len(randomStringAlphabet)]

	for _, r := range randomStringAlphabet {
		got := counts[r]
		if got < expected-tolerance || got > expected+tolerance {
			note := ""
			if strings.ContainsRune(biasedHead, r) {
				note = " (this symbol is in the head of the alphabet that an unrejected `byte % 62` over-weights by 25%)"
			}
			t.Errorf("symbol %q appeared %d times in %d draws, want %d±%d%s", r, got, draws, expected, tolerance, note)
		}
	}
}

// NEW IN WAVE 5. RandomString reads crypto/rand in chunks and rejects samples,
// so the accepted-sample bookkeeping has an off-by-one shape that a
// single-length test would miss: a chunk boundary landing exactly on the last
// needed character, or a rejection run at the end of a chunk, both force the
// refill loop. Sweeping every length from 0 to 200 exercises every remainder of
// the chunk size and asserts the invariant that matters — the result is exactly
// `length` characters, all in the alphabet, with no zero byte left behind by a
// short read.
func TestRandomStringChunkRefillBoundaries(t *testing.T) {
	for length := 0; length <= 200; length++ {
		got := RandomString(length)
		if len(got) != length {
			t.Fatalf("RandomString(%d) returned %d bytes", length, len(got))
		}
		for i := 0; i < len(got); i++ {
			if !strings.ContainsRune(randomStringAlphabet, rune(got[i])) {
				t.Fatalf("RandomString(%d) byte %d = %q, outside the alphabet — a refill left an unwritten slot", length, i, got[i])
			}
		}
	}
}
