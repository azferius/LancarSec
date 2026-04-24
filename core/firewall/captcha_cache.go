package firewall

import (
	"sync"
	"time"
)

// captchaEntry is one cached (captcha-image, mask-image) pair with its
// insertion time so the evictor can expire old entries without having to
// walk the entire CacheImgs sync.Map on every request.
type captchaEntry struct {
	payload  [2]string
	insertedAt time.Time
}

// CaptchaCacheTTL is how long a rendered captcha pair stays usable before
// we discard it. 2 minutes matches the cookie/ratelimit window and is
// comfortably longer than a human needs to solve the puzzle.
const CaptchaCacheTTL = 2 * time.Minute

var (
	captchaCacheMu sync.Mutex
	captchaCache   = map[string]*captchaEntry{}
)

// StoreCaptcha records a fresh (captcha, mask) pair under the given secret
// part. Replaces any previous entry for the same key.
func StoreCaptcha(secret string, captcha, mask string) {
	captchaCacheMu.Lock()
	captchaCache[secret] = &captchaEntry{
		payload:    [2]string{captcha, mask},
		insertedAt: time.Now(),
	}
	captchaCacheMu.Unlock()
}

// LoadCaptcha returns the cached pair for secret if it exists and hasn't
// expired. Returns (_, _, false) on miss so the caller re-renders.
func LoadCaptcha(secret string) (captcha, mask string, ok bool) {
	captchaCacheMu.Lock()
	defer captchaCacheMu.Unlock()
	entry, found := captchaCache[secret]
	if !found {
		return "", "", false
	}
	if time.Since(entry.insertedAt) > CaptchaCacheTTL {
		delete(captchaCache, secret)
		return "", "", false
	}
	return entry.payload[0], entry.payload[1], true
}

// sweepCaptchaCache expires everything older than TTL. Called on a timer
// from ClearProxyCache so memory stays bounded even if most captchas are
// never solved.
func sweepCaptchaCache() {
	cutoff := time.Now().Add(-CaptchaCacheTTL)
	captchaCacheMu.Lock()
	for k, e := range captchaCache {
		if e.insertedAt.Before(cutoff) {
			delete(captchaCache, k)
		}
	}
	captchaCacheMu.Unlock()
}
