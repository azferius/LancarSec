package utils

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Encrypt / EncryptSha — golden vectors
//
// These pin the EXACT hex output of the two hash helpers as they behave today.
// They are the derivation used for every clearance cookie the proxy issues
// (core/server/middleware.go:192-198) and for the hourly OTP rotation
// (core/server/monitor.go:650-652), so any change to them invalidates every
// cookie in the wild. Wave 5 moves Encrypt to keyed BLAKE3 and EncryptSha to
// HMAC-SHA256; when it does, every `want` in these two tables changes and the
// reviewer sees exactly which token derivations moved.
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
			want: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
		},
		{
			name:  "short input short key",
			input: "ab", key: "cdef",
			want: "b34b56076712fd7fb9c067245a6c85e16174b3ef2e35df7b56b7f164e5c36446",
		},
		{
			name:  "access-key shaped input",
			input: "1.2.3.4|Mozilla/5.0|/index.html", key: "s3cr3t",
			want: "6ab033f8a48ba816adb280b20cd0622f6e92359d4700765d2202da7df4dfa342",
		},
		{
			name:  "otp shaped input",
			input: "lancarsec", key: "2026-08-30",
			want: "8866887ecdc8d2c0cd0616b39167c20dfa2e8a49a027b799f380bc9e45b931c8",
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
			want: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:  "short input short key",
			input: "ab", key: "cdef",
			want: "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721",
		},
		{
			name:  "hashed encrypted ip (key is empty in middleware.go:195)",
			input: "1.2.3.4|Mozilla/5.0|/index.html", key: "s3cr3t",
			want: "e223573ac0f1cc0696d8aa612f5bbd529f6060f1181847378a911ff2171c8e3e",
		},
		{
			name:  "otp shaped input",
			input: "lancarsec", key: "2026-08-30",
			want: "6e51b60e52309a6d87fb35d52dc3fd38f655723f71091dc7b2eb027e4e29243d",
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

// BUG (wave 5 flips this): Encrypt is blake3(input + key) — a plain string
// concatenation, not a keyed hash. The boundary between message and key is
// therefore invisible to the hash, so any two (input, key) pairs whose
// concatenation is equal produce the same digest. Encrypt("ab","cdef") ==
// Encrypt("abc","def"). In the proxy this means a clearance token derived from
// one (accessKey, OTP) split is valid for a different split of the same joined
// string — an attacker who controls part of accessKey can shift bytes across
// the boundary and reuse a token. When wave 5 moves to keyed BLAKE3, these two
// digests MUST differ and this test flips to a `==` failure / `!=` assertion.
func TestEncryptLengthExtensionAmbiguityCollides(t *testing.T) {
	a := Encrypt("ab", "cdef")
	b := Encrypt("abc", "def")
	if a != b {
		t.Fatalf("expected today's concatenation collision: Encrypt(\"ab\",\"cdef\")=%q != Encrypt(\"abc\",\"def\")=%q", a, b)
	}

	// The same defect, in the shape it actually appears in middleware: the
	// subject identity and the secret are concatenated, so moving one byte from
	// the identity into the secret is undetectable.
	c := Encrypt("1.2.3.4|UA|/pathS", "ECRET")
	d := Encrypt("1.2.3.4|UA|/path", "SECRET")
	if c != d {
		t.Fatalf("expected today's boundary collision: %q != %q", c, d)
	}
}

// BUG (wave 5 flips this): EncryptSha is sha256(input + key), same defect class
// as Encrypt above, and additionally sha256 is length-extendable so a raw
// concatenation MAC is forgeable. Wave 5 replaces it with HMAC-SHA256, after
// which these digests must differ.
func TestEncryptShaConcatenationAmbiguityCollides(t *testing.T) {
	a := EncryptSha("ab", "cdef")
	b := EncryptSha("abc", "def")
	if a != b {
		t.Fatalf("expected today's concatenation collision: EncryptSha(\"ab\",\"cdef\")=%q != EncryptSha(\"abc\",\"def\")=%q", a, b)
	}

	// monitor.go:650 does EncryptSha(secret, date). A secret ending in "2" and a
	// date starting one char later hash identically.
	c := EncryptSha("secret2", "026-08-30")
	d := EncryptSha("secret", "2026-08-30")
	if c != d {
		t.Fatalf("expected today's secret/date boundary collision: %q != %q", c, d)
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

// ---------------------------------------------------------------------------
// RandomString
//
// NO GOLDEN TEST IS POSSIBLE. RandomString uses the top-level math/rand
// generator. Under Go 1.20+ that global source is seeded from the OS at
// program start (the Go 1.19 behaviour of an implicit seed of 1 — audit
// finding #1 — no longer applies), so output differs on every run and a fixed
// expected string would be permanently red. There is also no seeding hook to
// pin it with, because RandomString takes no source argument and the package
// exposes no way to inject one. So we test SHAPE only: length, alphabet
// membership, and the boundary cases.
//
// Note for wave 5: it is still math/rand, i.e. a non-cryptographic PRNG whose
// state is recoverable from enough output, and it is still what generates
// AdminSecret / APISecret / the three challenge secrets in
// core/config/generate.go:24-35. Wave 5 moves it to crypto/rand; when it does,
// these shape assertions should all continue to hold unchanged, which is
// exactly what makes them useful as a regression net.
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

// ---------------------------------------------------------------------------
// HashToInt
// ---------------------------------------------------------------------------

func TestHashToIntGolden(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{name: "hex zeros", in: "00", want: 7},
		{name: "hex ff", in: "ff", want: 10},
		{name: "longer string, only first two bytes read", in: "abcdef", want: 1},
		{name: "letters", in: "zz", want: 5},
		{name: "raw NUL bytes", in: "\x00\x00", want: 1},
		{name: "raw 0xff bytes (65535 % 15 == 0)", in: "\xff\xff", want: 1},
		{name: "digit then letter", in: "0a", want: 11},
		{name: "digit then f", in: "9f", want: 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HashToInt(tt.in); got != tt.want {
				t.Errorf("HashToInt(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

// HashToInt builds a uint16 and then does int(subset)%15 + 1. Because subset is
// unsigned, the modulo can never be negative, so the result is always in
// [1, 15] — it CANNOT return 0 or a negative. Pinned across the whole 16-bit
// input space so a future change to signed arithmetic (which would let %15 go
// negative and return 0 or -14..0) is caught.
func TestHashToIntRangeIsOneToFifteenNeverNegative(t *testing.T) {
	for hi := 0; hi < 256; hi++ {
		for lo := 0; lo < 256; lo++ {
			in := string([]byte{byte(hi), byte(lo)})
			got := HashToInt(in)
			if got < 1 || got > 15 {
				t.Fatalf("HashToInt(%q) = %d, outside the pinned range [1,15]", in, got)
			}
		}
	}
}

// Pins that only the first two BYTES of the argument influence the result —
// everything after index 1 is discarded. This is why the function is a weak
// bucketing primitive, not a hash.
func TestHashToIntIgnoresEverythingAfterTheSecondByte(t *testing.T) {
	base := HashToInt("ab")
	for _, suffix := range []string{"", "c", "cdef", strings.Repeat("z", 128)} {
		if got := HashToInt("ab" + suffix); got != base {
			t.Errorf("HashToInt(%q) = %d, want %d — only the first two bytes should matter today", "ab"+suffix, got, base)
		}
	}
}

// Pins today's contract: HashToInt indexes hash[0] and hash[1] with no length
// check, so any argument shorter than 2 bytes panics with an index-out-of-range
// runtime error. It is currently unreachable (the function has no callers in
// the tree), but the panic is the contract until a wave adds a guard.
func TestHashToIntPanicsOnShortInput(t *testing.T) {
	for _, in := range []string{"", "a"} {
		t.Run("len"+string(rune('0'+len(in))), func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Fatalf("HashToInt(%q) did not panic; today it indexes hash[0]/hash[1] unguarded", in)
				}
			}()
			_ = HashToInt(in)
		})
	}
}

func TestHashToIntIsDeterministic(t *testing.T) {
	const in = "deadbeef"
	first := HashToInt(in)
	for i := 0; i < 100; i++ {
		if got := HashToInt(in); got != first {
			t.Fatalf("HashToInt is not deterministic: iteration %d gave %d, want %d", i, got, first)
		}
	}
}
