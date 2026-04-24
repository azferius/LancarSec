package firewall

import (
	"fmt"
	"net"
	"os"
	"sync/atomic"

	"github.com/oschwald/maxminddb-golang"
)

// asnDBPath is the default lookup path for MaxMind's GeoLite2-ASN.mmdb
// (free, register at maxmind.com). Operators can override via config later
// if they keep the file elsewhere. We resolve it relative to the working
// directory so the same binary works across deployments.
const asnDBPath = "global/geoip/GeoLite2-ASN.mmdb"

// asnDB carries the live reader. Published via atomic.Pointer so reload
// can swap in a fresher .mmdb without restarting. nil pointer means the
// operator never configured GeoIP; blocklist evaluation simply skips the
// asn check in that case.
var asnDB atomic.Pointer[maxminddb.Reader]

// asnRecord is the subset of MaxMind's ASN record we care about.
type asnRecord struct {
	ASN    uint   `maxminddb:"autonomous_system_number"`
	ASOrg  string `maxminddb:"autonomous_system_organization"`
}

// LoadASN opens the MaxMind .mmdb at asnDBPath if present and publishes
// the reader. Absence is non-fatal: LancarSec boots normally, ASN-typed
// blocklist entries just never match. Called from config.Apply at startup
// and reload.
func LoadASN() error {
	if _, err := os.Stat(asnDBPath); err != nil {
		// File missing — clear any prior reader so stale data doesn't linger.
		if prev := asnDB.Swap(nil); prev != nil {
			_ = prev.Close()
		}
		return nil
	}
	reader, err := maxminddb.Open(asnDBPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", asnDBPath, err)
	}
	if prev := asnDB.Swap(reader); prev != nil {
		_ = prev.Close()
	}
	return nil
}

// ResolveASN returns the autonomous system number (as decimal string) for
// an IP, or "" when the reader isn't configured or the lookup doesn't hit.
// Hot-path: runs on every request in middleware.Evaluate, so the nil-check
// is front-loaded.
func ResolveASN(ip string) string {
	r := asnDB.Load()
	if r == nil {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	var rec asnRecord
	if err := r.Lookup(parsed, &rec); err != nil || rec.ASN == 0 {
		return ""
	}
	return itoa(int(rec.ASN))
}

// ResolveASNOrg returns the human-readable organization (e.g. "CLOUDFLARENET")
// for an IP. Used by the dashboard to show the ASN name next to the number.
func ResolveASNOrg(ip string) (uint, string) {
	r := asnDB.Load()
	if r == nil {
		return 0, ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0, ""
	}
	var rec asnRecord
	if err := r.Lookup(parsed, &rec); err != nil {
		return 0, ""
	}
	return rec.ASN, rec.ASOrg
}

// ASNLoaded reports whether an .mmdb is currently loaded. The dashboard
// surfaces this so operators know why their ASN blocklist entries are
// not firing.
func ASNLoaded() bool {
	return asnDB.Load() != nil
}
