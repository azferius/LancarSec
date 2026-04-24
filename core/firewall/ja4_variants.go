package firewall

import (
	"fmt"

	"lancarsec/core/tlsparse"
)

// ComputeJA4R produces the JA4_r ("raw") variant: same prefix as canonical
// JA4 but the cipher and extension hashes are replaced by the actual
// comma-separated hex lists in their original wire order. GREASE is stripped
// per spec; SNI (0x0000) and ALPN (0x0010) are excluded from the extension
// list (mirroring JA4 canonical), and signature algorithms are appended after
// "_" in original order.
//
// Format:
//
//	q|t + tlsver + sni + cipher_count + ext_count + alpn _ <ciphers_raw> _ <exts_raw>_<sigalgs_raw>
//
// JA4_r is harder to spoof than JA4 because reordering ciphers (a common
// uTLS-style spoof technique) changes the raw output but not the sorted
// sha256 hash. Threat hunters use JA4_r when JA4 collisions become noisy.
func ComputeJA4R(hello *tlsparse.ClientHello) string {
	prefix, ciphers, extsForHash, sigAlgs := ja4Components(hello)
	return fmt.Sprintf("%s_%s_%s_%s",
		prefix,
		joinHex(ciphers),
		joinHex(extsForHash),
		joinHex(sigAlgs),
	)
}

// ComputeJA4O produces the JA4_o ("original order") variant: same shape as
// canonical JA4 (sha256[:12] hashes) but the cipher and extension lists are
// hashed in their original wire order rather than sorted. Captures
// reordering of ciphers/extensions that JA4 canonical would coalesce.
func ComputeJA4O(hello *tlsparse.ClientHello) string {
	prefix, ciphers, extsForHash, sigAlgs := ja4Components(hello)
	cipherHash := sha256First12(joinHex(ciphers))
	extHash := sha256First12(joinHex(extsForHash) + "_" + joinHex(sigAlgs))
	return fmt.Sprintf("%s_%s_%s", prefix, cipherHash, extHash)
}

// ja4Components returns the shared prefix and the (GREASE-stripped) cipher,
// extension-for-hash, and signature-algorithm slices used by every JA4
// variant. Callers decide whether to sort, hash, or emit raw. Extensions
// returned here exclude SNI (0x0000) and ALPN (0x0010) per FoxIO spec —
// canonical JA4 includes them in the count but not in the hash.
func ja4Components(hello *tlsparse.ClientHello) (prefix string, ciphers, extsForHash, sigAlgs []uint16) {
	proto := "t"
	tlsVer := versionCode(hello.TLSVersion())
	sni := "i"
	if hello.SNI != "" {
		sni = "d"
	}
	ciphers = stripGrease(hello.Ciphers)
	extensions := stripGrease(hello.Extensions)
	sigAlgs = stripGrease(hello.SigAlgs)
	cipherCount := twoDigit(len(ciphers))
	extCount := twoDigit(len(extensions))
	alpn := alpnCode(hello.ALPN)
	prefix = fmt.Sprintf("%s%s%s%s%s%s", proto, tlsVer, sni, cipherCount, extCount, alpn)
	extsForHash = filterExt(extensions, 0x0000, 0x0010)
	return
}
