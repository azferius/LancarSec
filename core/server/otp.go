package server

import (
	"lancarsec/core/pnc"
	"lancarsec/core/proxy"
	"lancarsec/core/utils"
	"time"
)

// generateOTPSecrets refreshes the per-stage OTPs every hour. Rotating the
// OTP is what forces attackers to solve a fresh challenge rather than replay
// an old cookie value.
//
// The bucket string is YYYY-MM-DD-HH so independent proxy instances agree as
// long as their clocks do. The old implementation used YYYY-MM-DD, which
// meant a user who passed the challenge at 23:59 got forced back through
// the challenge 60 seconds later. Hourly buckets keep re-challenge pressure
// identical on average but eliminate the daily cliff.
func generateOTPSecrets() {
	defer pnc.PanicHndl()

	for {
		bucket := time.Now().UTC().Format("2006-01-02-15")
		proxy.CookieOTP = utils.EncryptSha(proxy.CookieSecret, bucket)
		proxy.JSOTP = utils.EncryptSha(proxy.JSSecret, bucket)
		proxy.CaptchaOTP = utils.EncryptSha(proxy.CaptchaSecret, bucket)

		// Sleep until the next hour boundary, not a fixed 1 h, so all
		// instances rotate in lockstep regardless of startup time.
		now := time.Now()
		nextHour := now.Truncate(time.Hour).Add(time.Hour)
		time.Sleep(time.Until(nextHour))
	}
}
