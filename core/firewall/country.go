package firewall

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"

	"github.com/oschwald/maxminddb-golang"
)

// countryDBPath is the default lookup path for MaxMind's GeoLite2-Country.mmdb
// (free, register at maxmind.com). Resolved relative to the working
// directory so the same binary works across deployments. Operators who
// already have the ASN .mmdb in global/geoip just drop the Country .mmdb
// alongside it.
const countryDBPath = "global/geoip/GeoLite2-Country.mmdb"

// countryDB carries the live reader. Published via atomic.Pointer so
// reload can swap in a fresher .mmdb without restarting. nil pointer means
// the operator never configured GeoIP-Country; blocklist evaluation simply
// skips the country check in that case.
var countryDB atomic.Pointer[maxminddb.Reader]

// countryRecord is the subset of MaxMind's Country record we care about.
// We only need the ISO 3166-1 alpha-2 code; the human-readable names live
// in the Country.Names map but operators ban by code so we ignore them.
type countryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
}

// LoadCountry opens the MaxMind .mmdb at countryDBPath if present and
// publishes the reader. Absence is non-fatal: LancarSec boots normally,
// country-typed blocklist entries just never match. Called from
// config.Apply alongside LoadASN at startup and reload.
func LoadCountry() error {
	if _, err := os.Stat(countryDBPath); err != nil {
		if prev := countryDB.Swap(nil); prev != nil {
			_ = prev.Close()
		}
		return nil
	}
	reader, err := maxminddb.Open(countryDBPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", countryDBPath, err)
	}
	if prev := countryDB.Swap(reader); prev != nil {
		_ = prev.Close()
	}
	return nil
}

// ResolveCountry returns the ISO 3166-1 alpha-2 country code (uppercase)
// for an IP, or "" when the reader isn't configured or the lookup misses.
// Falls back to RegisteredCountry when the geolocated Country is empty —
// some IPs (mostly mobile / cloud) carry only a registration country, and
// that's the field a blocklist rule typically targets anyway.
func ResolveCountry(ip string) string {
	r := countryDB.Load()
	if r == nil {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	var rec countryRecord
	if err := r.Lookup(parsed, &rec); err != nil {
		return ""
	}
	code := rec.Country.ISOCode
	if code == "" {
		code = rec.RegisteredCountry.ISOCode
	}
	return strings.ToUpper(code)
}

// CountryLoaded reports whether a Country .mmdb is currently loaded. The
// dashboard surfaces this so operators know why their country blocklist
// entries are not firing.
func CountryLoaded() bool {
	return countryDB.Load() != nil
}
