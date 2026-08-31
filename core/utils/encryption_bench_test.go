package utils

import "testing"

// Benchmarks for the three token-derivation primitives, added by wave 5.
//
// Encrypt is called by core/server/middleware.go on every token-cache MISS, and
// a flood from rotating source addresses misses on every request by
// construction — so this is a hot path precisely when the proxy is under
// attack, which is the only time it matters. Wave 7 measures the middleware
// path; these measure the primitive underneath it so a regression can be
// attributed.
//
// Reproduce with:
//
//	go test ./core/utils/ -run '^$' -bench BenchmarkEncrypt -benchmem -count 5
//
// The value to protect: the naive keyed-BLAKE3 implementation — a
// blake3.NewKeyed per call — measured 3083 ns/op and 21984 B/op on a Ryzen
// 5700X, because a blake3.Hasher carries an 8 KiB input buffer and is 10840
// bytes. Pooling hashers per key brings that to ~168 ns/op and 128 B/op. If a
// future change drops the pool, this benchmark is where it shows up.

var benchSink string

func BenchmarkEncrypt(b *testing.B) {
	const (
		accessKey = "1.2.3.4t13d1516h2_8daaf6152771_b0da82dd1658Mozilla/5.02026-08-31-13"
		otp       = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchSink = Encrypt(accessKey, otp)
	}
}

func BenchmarkEncryptParallel(b *testing.B) {
	const (
		accessKey = "1.2.3.4t13d1516h2_8daaf6152771_b0da82dd1658Mozilla/5.02026-08-31-13"
		otp       = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		var local string
		for pb.Next() {
			local = Encrypt(accessKey, otp)
		}
		benchSink = local
	})
}

func BenchmarkEncryptSha(b *testing.B) {
	// The shape middleware uses for the stage-2 challenge value: an empty key.
	const token = "9d1a4c0b7e2f6a8d3b5c1e7f0a2d4b6c8e0f1a3c5d7e9b1d3f5a7c9e1b3d5f70"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchSink = EncryptSha(token, "")
	}
}

func BenchmarkRandomString24(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchSink = RandomString(24)
	}
}
