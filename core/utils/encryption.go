package utils

import (
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"github.com/zeebo/blake3"
)

// Encrypt derives a stable token from input and key using keyed BLAKE3.
// Keyed mode beats the previous `blake3(input + key)` concatenation: for the
// old form, Encrypt("ab", "cdef") == Encrypt("abc", "def") because the hash
// input is identical — an attacker with partial control over either argument
// could probe boundary behavior. Keyed BLAKE3 binds the key into the hasher
// state, eliminating that class of collision.
func Encrypt(input string, key string) string {
	keyBytes := deriveKey32([]byte(key))
	h, err := blake3.NewKeyed(keyBytes)
	if err != nil {
		// NewKeyed only fails on wrong key length, which deriveKey32 prevents.
		h = blake3.New()
	}
	h.Write([]byte(input))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:32])
}

// deriveKey32 turns a user-supplied secret of arbitrary length into a 32-byte
// key suitable for keyed BLAKE3.
func deriveKey32(secret []byte) []byte {
	sum := sha256.Sum256(secret)
	return sum[:]
}

// EncryptSha now uses HMAC-SHA256 rather than raw sha256(input + key). HMAC
// is the standard keyed construction and is constant-time against key length
// side channels on common stdlib implementations.
func EncryptSha(input string, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(input))
	return hex.EncodeToString(mac.Sum(nil))
}

// RandomString draws from crypto/rand so generated secrets aren't predictable
// from process start time or PRNG state. Used for admin/api/cookie secret
// generation in config.Generate.
func RandomString(length int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	buf := make([]byte, length)
	raw := make([]byte, length)
	if _, err := cryptorand.Read(raw); err != nil {
		// crypto/rand.Read only fails on catastrophic OS RNG errors; refusing
		// to start is safer than shipping a weak secret.
		panic("crypto/rand read failed: " + err.Error())
	}
	for i, b := range raw {
		buf[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(buf)
}

// RandomUint32 returns a uniformly random uint32 from crypto/rand. Used where
// captcha image generation needs unpredictable offsets an attacker can't
// precompute from a deterministic math/rand seed.
func RandomUint32() uint32 {
	var b [4]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		panic("crypto/rand read failed: " + err.Error())
	}
	return binary.BigEndian.Uint32(b[:])
}

// RandomIntN returns a uniformly random integer in [0, n). n must be > 0.
func RandomIntN(n int) int {
	if n <= 0 {
		return 0
	}
	return int(RandomUint32()) % n
}

func HashToInt(hash string) int {
	subset := (uint16(hash[0]) << 8) | uint16(hash[1])
	return int(subset)%15 + 1
}
