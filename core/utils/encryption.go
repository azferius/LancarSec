package utils

import (
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"sync"
	"sync/atomic"

	"github.com/zeebo/blake3"
)

// encryptKeyContext is the BLAKE3 key-derivation context for Encrypt. It is a
// hardcoded constant, as the BLAKE3 spec requires of a KDF context.
const encryptKeyContext = "github.com/azferius/lancarsec core/utils Encrypt v1"

// encryptKeyCacheMax bounds how many distinct keys keep a hasher pool.
//
// In production the key space is exactly the three challenge OTPs, which rotate
// together once an hour, so a handful of entries covers every call. The bound
// exists so that a future caller passing an unbounded key space cannot turn
// this cache into a memory-growth DoS: past the limit the slow path still
// returns a correct hasher, it just does not memoise it.
const encryptKeyCacheMax = 16

var (
	encryptKeyCacheLen atomic.Int64

	// encryptKeyCache maps a key string to a pool of blake3 hashers already
	// keyed for it. A blake3.Hasher is 10840 bytes — it carries an 8 KiB input
	// buffer — so allocating one per call costs ~1.9 us and 10.8 KiB. On this
	// proxy Encrypt runs on every token-cache miss, and a flood from rotating
	// source addresses misses on every request by construction, so a per-call
	// allocation would be a self-inflicted memory-pressure amplifier exactly
	// when the proxy is under attack. Hasher.Reset keeps the key and clears
	// only the input state, which is what makes a pool per key correct.
	encryptKeyCache sync.Map // string -> *sync.Pool of *blake3.Hasher
)

// encryptHasher returns a hasher keyed for key, ready to write to, along with
// the pool to return it to (nil if it is not pooled).
func encryptHasher(key string) (*blake3.Hasher, *sync.Pool) {
	if v, ok := encryptKeyCache.Load(key); ok {
		pool := v.(*sync.Pool)
		hasher := pool.Get().(*blake3.Hasher)
		hasher.Reset()
		return hasher, pool
	}

	// BLAKE3's keyed mode takes a fixed 32-byte key, but every caller here
	// passes a variable-length string, so the caller's key goes through BLAKE3's
	// KDF mode first. The context string is a domain separator: a subkey derived
	// here can never collide with one derived elsewhere from the same material.
	var subKey [32]byte
	blake3.DeriveKey(encryptKeyContext, []byte(key), subKey[:])

	newHasher := func() *blake3.Hasher {
		hasher, err := blake3.NewKeyed(subKey[:])
		if err != nil {
			// Unreachable: NewKeyed only rejects keys that are not 32 bytes,
			// and subKey is a [32]byte. Panicking beats returning a silently
			// unkeyed digest, which would still look like a valid token.
			panic("utils.Encrypt: blake3.NewKeyed rejected a 32-byte key: " + err.Error())
		}
		return hasher
	}

	if encryptKeyCacheLen.Load() >= encryptKeyCacheMax {
		return newHasher(), nil
	}

	pool := &sync.Pool{New: func() any { return newHasher() }}
	if actual, loaded := encryptKeyCache.LoadOrStore(key, pool); loaded {
		pool = actual.(*sync.Pool)
	} else {
		encryptKeyCacheLen.Add(1)
	}
	return newHasher(), pool
}

// Encrypt is a keyed hash of input under key.
//
// It used to be blake3.Sum256(input + key) — a plain concatenation, which makes
// the boundary between message and key invisible to the hash: Encrypt("ab",
// "cdef") and Encrypt("abc", "def") produced the same digest. Every clearance
// token the proxy issues is Encrypt(accessKey, OTP), and accessKey is built
// from attacker-influenced bytes (IP, TLS fingerprint, User-Agent), so an
// attacker able to shift one byte across that boundary got a token that was
// valid for a different (accessKey, OTP) split. Keying the hash properly makes
// the split part of the computation, so no such shift exists.
func Encrypt(input string, key string) string {
	hasher, pool := encryptHasher(key)
	hasher.WriteString(input)

	var digest [32]byte
	sum := hasher.Sum(digest[:0])

	if pool != nil {
		pool.Put(hasher)
	}

	return hex.EncodeToString(sum)
}

// macKeyCache pools HMAC states per key, for the same reason encryptKeyCache
// pools blake3 hashers: hmac.New builds two SHA-256 states and both padded key
// blocks on every call, and hash.Hash.Reset restores the keyed initial state,
// so a pooled MAC is reusable for its own key. In this tree EncryptSha is
// called with the empty key (the stage-2 challenge value, on every token-cache
// miss) and with the three configured challenge secrets, so the key space is
// four entries.
var (
	macKeyCacheLen atomic.Int64
	macKeyCache    sync.Map // string -> *sync.Pool of hash.Hash
)

func macHasher(key string) (hash.Hash, *sync.Pool) {
	if v, ok := macKeyCache.Load(key); ok {
		pool := v.(*sync.Pool)
		mac := pool.Get().(hash.Hash)
		mac.Reset()
		return mac, pool
	}

	// hmac.New copies the key, so retaining it in the closure is safe even if
	// the caller's backing array is reused.
	keyBytes := []byte(key)
	newMAC := func() hash.Hash { return hmac.New(sha256.New, keyBytes) }

	if macKeyCacheLen.Load() >= encryptKeyCacheMax {
		return newMAC(), nil
	}

	pool := &sync.Pool{New: func() any { return newMAC() }}
	if actual, loaded := macKeyCache.LoadOrStore(key, pool); loaded {
		pool = actual.(*sync.Pool)
	} else {
		macKeyCacheLen.Add(1)
	}
	return newMAC(), pool
}

// EncryptSha is HMAC-SHA256 of input under key.
//
// It used to be sha256(input + key), which had the same message/key boundary
// ambiguity as Encrypt above and, because SHA-256 is a Merkle-Damgard
// construction, was additionally length-extendable: given sha256(input+key) and
// len(input+key) an attacker can compute sha256(input+key+padding+suffix)
// without knowing key. HMAC is the standard construction that has neither
// property. This is the derivation behind the hourly OTP rotation
// (core/server/monitor.go) and behind the stage-2 proof-of-work challenge
// value, both of which are secret-keyed and were therefore both affected.
func EncryptSha(input string, key string) string {
	mac, pool := macHasher(key)
	mac.Write([]byte(input))

	var digest [sha256.Size]byte
	sum := mac.Sum(digest[:0])

	if pool != nil {
		pool.Put(mac)
	}

	return hex.EncodeToString(sum)
}

// randomAlphabet is the symbol set RandomString draws from. 62 symbols,
// so ~5.95 bits per character.
const randomAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// randomRejectAbove is the exclusive upper bound for a uniformly random byte to
// be usable as an index into randomAlphabet.
//
// 256 is not a multiple of 62 (256 = 4*62 + 8), so the naive `b % 62` maps five
// distinct byte values onto each of the first 8 symbols ('a'..'h') and only
// four onto the remaining 54. That skew is ~25% extra weight on 8 of 62 symbols
// and it costs real entropy from every secret and every captcha the proxy
// generates. Rejecting the 8 values at the top of the byte range (248..255)
// leaves exactly 248 = 4*62 values, which is a whole number of full cycles, so
// the modulo is exactly uniform.
const randomRejectAbove = 256 - (256 % len(randomAlphabet)) // 248

// RandomString returns a cryptographically random string of the given length,
// drawn uniformly from randomAlphabet.
//
// This is the ONLY randomness source for the five proxy secrets generated by
// core/config/generate.go (admin secret, API secret, and the cookie/javascript/
// captcha challenge secrets) and for the captcha token in core/api. It used to
// draw from the top-level math/rand generator. Even with Go 1.20+ auto-seeding
// that is a linear PRNG: an observer who collects enough output recovers the
// internal state and can then predict every subsequent draw. Since a single
// process generates all five secrets from one stream, and the captcha tokens
// are served to anybody who asks, that observation channel was open by design.
// crypto/rand has no recoverable state.
//
// A negative length panics inside make, which is the pre-existing contract; no
// call site passes one.
func RandomString(length int) string {
	res := make([]byte, length)
	if length == 0 {
		return ""
	}

	// Over-read by a quarter so the common case needs exactly one syscall:
	// the rejection rate is 8/256 = 3.125%, so length*1.25+8 bytes covers
	// length accepted samples with overwhelming probability.
	buf := make([]byte, length+length/4+8)

	filled := 0
	for filled < length {
		if _, err := crand.Read(buf); err != nil {
			// crypto/rand.Read does not fail on any supported platform, and a
			// failure here would mean silently emitting a zeroed — that is,
			// constant — secret. Refuse instead.
			panic("utils.RandomString: crypto/rand failed: " + err.Error())
		}
		for _, b := range buf {
			if int(b) >= randomRejectAbove {
				continue
			}
			res[filled] = randomAlphabet[int(b)%len(randomAlphabet)]
			filled++
			if filled == length {
				break
			}
		}
	}

	return string(res)
}

func HashToInt(hash string) int {
	subset := (uint16(hash[0]) << 8) | uint16(hash[1])
	return int(subset)%15 + 1
}
