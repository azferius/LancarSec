package firewall

import (
	"lancarsec/core/pnc"
	"lancarsec/core/proxy"
	"strconv"
	"time"
)

// ClearProxyCache periodically drops the IP/captcha caches when the proxy is
// idle or close to memory pressure. Keeping cache growth bounded during
// sustained low-CPU attacks is what prevents OOM at hour-long timescales.
func ClearProxyCache() {
	defer pnc.PanicHndl()

	for {
		cpuUsage, err := strconv.ParseFloat(proxy.GetCPUUsage(), 32)
		if err != nil {
			cpuUsage = 0
		}
		memUsage, err := strconv.ParseFloat(proxy.GetRAMUsage(), 32)
		if err != nil {
			memUsage = 0
		}

		// CacheIps is a sync.Map; eviction doesn't need any external lock.
		// The CPU/mem gate keeps us from thrashing under active challenge.
		if (cpuUsage < 15 && memUsage > 25) || memUsage > 95 {
			CacheIps.Range(func(key, _ any) bool {
				CacheIps.Delete(key)
				return true
			})
		}

		// Captchas always get TTL-swept, independent of memory pressure.
		// Old entries are never useful — the cookie they match has expired.
		sweepCaptchaCache()

		time.Sleep(2 * time.Minute)
	}
}
