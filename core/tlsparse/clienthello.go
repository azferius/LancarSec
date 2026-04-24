// Package tlsparse provides a minimal TLS ClientHello parser built on
// cryptobyte. Go's crypto/tls hands us a filtered ClientHelloInfo at the
// fingerprint callback; to compute a spec-compliant JA4 we need the raw
// extension list, signature algorithms, and ALPN values straight from the
// wire. This package parses exactly what we need, nothing more.
package tlsparse

import (
	"encoding/binary"

	"golang.org/x/crypto/cryptobyte"
)

// ClientHello carries the subset of ClientHello fields we care about for
// fingerprinting. Fields appear in ClientHello wire order where possible.
type ClientHello struct {
	LegacyVersion   uint16
	Ciphers         []uint16
	Extensions      []uint16
	SigAlgs         []uint16
	SupportedVers   []uint16
	SupportedGroups []uint16
	ALPN            []string
	SNI             string
}

// ParseRecord parses a full TLS record starting at the record-type byte
// (0x16 for handshake). Returns the parsed ClientHello on success.
func ParseRecord(data []byte) (*ClientHello, bool) {
	if len(data) < 5 || data[0] != 0x16 {
		return nil, false
	}
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLen {
		return nil, false
	}
	return ParseHandshake(data[5 : 5+recordLen])
}

// ParseHandshake parses a single handshake message expected to be a
// ClientHello (type 0x01). Accepts the bytes AFTER the TLS record header.
func ParseHandshake(data []byte) (*ClientHello, bool) {
	s := cryptobyte.String(data)

	var msgType uint8
	var body cryptobyte.String
	if !s.ReadUint8(&msgType) || msgType != 0x01 {
		return nil, false
	}
	if !s.ReadUint24LengthPrefixed(&body) {
		return nil, false
	}

	hello := &ClientHello{}

	// legacy_version + random (32 bytes)
	if !body.ReadUint16(&hello.LegacyVersion) {
		return nil, false
	}
	if !body.Skip(32) {
		return nil, false
	}

	// legacy_session_id
	var sid cryptobyte.String
	if !body.ReadUint8LengthPrefixed(&sid) {
		return nil, false
	}

	// cipher_suites
	var ciphers cryptobyte.String
	if !body.ReadUint16LengthPrefixed(&ciphers) {
		return nil, false
	}
	for !ciphers.Empty() {
		var c uint16
		if !ciphers.ReadUint16(&c) {
			return nil, false
		}
		hello.Ciphers = append(hello.Ciphers, c)
	}

	// legacy_compression_methods
	var comp cryptobyte.String
	if !body.ReadUint8LengthPrefixed(&comp) {
		return nil, false
	}

	// Extensions are present in every modern ClientHello but the struct
	// allows absence, so handle that cleanly.
	if body.Empty() {
		return hello, true
	}
	var exts cryptobyte.String
	if !body.ReadUint16LengthPrefixed(&exts) {
		return nil, false
	}

	for !exts.Empty() {
		var extType uint16
		var extData cryptobyte.String
		if !exts.ReadUint16(&extType) {
			return nil, false
		}
		if !exts.ReadUint16LengthPrefixed(&extData) {
			return nil, false
		}
		hello.Extensions = append(hello.Extensions, extType)

		switch extType {
		case 0x0000: // server_name
			parseSNI(extData, hello)
		case 0x000a: // supported_groups (named_curves)
			parseUint16List(extData, &hello.SupportedGroups)
		case 0x000d: // signature_algorithms
			parseUint16List(extData, &hello.SigAlgs)
		case 0x0010: // application_layer_protocol_negotiation
			parseALPN(extData, hello)
		case 0x002b: // supported_versions
			parseSupportedVersions(extData, hello)
		}
	}

	return hello, true
}

func parseSNI(extData cryptobyte.String, hello *ClientHello) {
	var list cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&list) {
		return
	}
	for !list.Empty() {
		var nameType uint8
		var name cryptobyte.String
		if !list.ReadUint8(&nameType) {
			return
		}
		if !list.ReadUint16LengthPrefixed(&name) {
			return
		}
		if nameType == 0 && hello.SNI == "" {
			hello.SNI = string(name)
		}
	}
}

func parseUint16List(extData cryptobyte.String, out *[]uint16) {
	var list cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&list) {
		return
	}
	for !list.Empty() {
		var v uint16
		if !list.ReadUint16(&v) {
			return
		}
		*out = append(*out, v)
	}
}

func parseALPN(extData cryptobyte.String, hello *ClientHello) {
	var list cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&list) {
		return
	}
	for !list.Empty() {
		var name cryptobyte.String
		if !list.ReadUint8LengthPrefixed(&name) {
			return
		}
		hello.ALPN = append(hello.ALPN, string(name))
	}
}

func parseSupportedVersions(extData cryptobyte.String, hello *ClientHello) {
	// In ClientHello, supported_versions is a 1-byte-length-prefixed list.
	var list cryptobyte.String
	if !extData.ReadUint8LengthPrefixed(&list) {
		return
	}
	for !list.Empty() {
		var v uint16
		if !list.ReadUint16(&v) {
			return
		}
		hello.SupportedVers = append(hello.SupportedVers, v)
	}
}

// TLSVersion reports the highest non-GREASE TLS version the client advertises,
// preferring supported_versions (0x002b) when present (TLS 1.3 moves the real
// version here and leaves legacy_version at 0x0303).
func (h *ClientHello) TLSVersion() uint16 {
	if len(h.SupportedVers) > 0 {
		var max uint16
		for _, v := range h.SupportedVers {
			if IsGrease(v) {
				continue
			}
			if v > max {
				max = v
			}
		}
		if max != 0 {
			return max
		}
	}
	return h.LegacyVersion
}

// IsGrease tests for RFC 8701 GREASE values: 0x?a?a where both bytes equal and
// the low nibble is 0xa.
func IsGrease(v uint16) bool {
	hi, lo := byte(v>>8), byte(v)
	return hi == lo && lo&0x0f == 0x0a
}
