package server

import (
	"testing"
	"time"

	"github.com/azferius/lancarsec/core/proxy"
	"github.com/azferius/lancarsec/core/utils"
)

// NEW IN WAVE 5.
//
// generateOTPSecrets used to derive its key from time.Now().Format("2006-01-02")
// — a LOCAL calendar date — and then sleep a flat hour from whenever the
// process happened to start. Two consequences, both operational:
//
//  1. Two instances behind one load balancer rotated at different wall-clock
//     instants (whenever each was last restarted). A client that the balancer
//     moved between them derived its token under instance A's OTP and failed
//     instance B's check, so it was re-challenged on every switch. The upstream
//     comment above the function acknowledged this and proposed "start them
//     within the same timeframe" as the mitigation — which is not one.
//  2. A LOCAL date means two instances in different timezones use different
//     keys for most of the day, not just around the boundary.
//
// The bucket is now aligned to the UTC wall-clock hour, so it is a pure
// function of the instant. Any two instances, started at any time, in any
// timezone, agree.

func otpSaveSecrets(t *testing.T) {
	t.Helper()
	oldCookie, oldJS, oldCaptcha := proxy.CookieSecret, proxy.JSSecret, proxy.CaptchaSecret
	oldSet := proxy.LoadOTP()
	t.Cleanup(func() {
		proxy.CookieSecret, proxy.JSSecret, proxy.CaptchaSecret = oldCookie, oldJS, oldCaptcha
		proxy.StoreOTP(*oldSet)
	})
	proxy.CookieSecret = "cookie-secret"
	proxy.JSSecret = "js-secret"
	proxy.CaptchaSecret = "captcha-secret"
}

func TestPublishOTPDerivesFromTheAlignedUTCHour(t *testing.T) {
	otpSaveSecrets(t)

	instant := time.Date(2026, 8, 31, 13, 42, 17, 500, time.UTC)
	publishOTP(instant)

	got := proxy.LoadOTP()
	if got.Hour != "2026-08-31-13" {
		t.Fatalf("Hour = %q, want %q", got.Hour, "2026-08-31-13")
	}
	if want := utils.EncryptSha(proxy.CookieSecret, got.Hour); got.Cookie != want {
		t.Errorf("Cookie = %q, want EncryptSha(cookieSecret, bucket) = %q", got.Cookie, want)
	}
	if want := utils.EncryptSha(proxy.JSSecret, got.Hour); got.JS != want {
		t.Errorf("JS = %q, want %q", got.JS, want)
	}
	if want := utils.EncryptSha(proxy.CaptchaSecret, got.Hour); got.Captcha != want {
		t.Errorf("Captcha = %q, want %q", got.Captcha, want)
	}
}

// The bucket is a pure function of the INSTANT, not of the location. This is
// the property the old local-date form did not have, and it is what lets a
// fleet agree.
func TestPublishOTPIsIndependentOfLocation(t *testing.T) {
	otpSaveSecrets(t)

	instant := time.Date(2026, 8, 31, 13, 42, 17, 0, time.UTC)

	// A location that is deliberately not a whole number of hours from UTC, so
	// a bug that formats in local time cannot accidentally agree.
	kathmandu := time.FixedZone("Asia/Kathmandu", 5*3600+45*60)
	honolulu := time.FixedZone("Pacific/Honolulu", -10*3600)

	publishOTP(instant)
	utc := *proxy.LoadOTP()

	publishOTP(instant.In(kathmandu))
	np := *proxy.LoadOTP()

	publishOTP(instant.In(honolulu))
	hi := *proxy.LoadOTP()

	if utc != np || utc != hi {
		t.Fatalf("the OTP set depends on the reader's timezone:\n  UTC       %+v\n  Kathmandu %+v\n  Honolulu  %+v", utc, np, hi)
	}
}

// Everything inside one aligned hour maps to one bucket; the instant the hour
// turns over, the bucket does too. A rotation keyed off process start would
// fail this: it would cut somewhere in the middle of an hour.
func TestPublishOTPBucketTurnsOverExactlyOnTheHour(t *testing.T) {
	otpSaveSecrets(t)

	base := time.Date(2026, 8, 31, 13, 0, 0, 0, time.UTC)

	within := []time.Time{
		base,
		base.Add(time.Second),
		base.Add(30 * time.Minute),
		base.Add(time.Hour - time.Nanosecond),
	}
	publishOTP(base)
	want := *proxy.LoadOTP()
	for _, at := range within {
		publishOTP(at)
		if got := *proxy.LoadOTP(); got != want {
			t.Errorf("at %s the set changed inside the hour: %+v, want %+v", at, got, want)
		}
	}

	publishOTP(base.Add(time.Hour))
	if got := *proxy.LoadOTP(); got == want {
		t.Fatal("the set did not change when the wall-clock hour turned over")
	} else if got.Hour != "2026-08-31-14" {
		t.Errorf("Hour = %q, want %q", got.Hour, "2026-08-31-14")
	}
}

// A day boundary and a UTC-midnight/local-midnight mismatch are the two places
// a date-string bug shows up, so pin them explicitly.
func TestPublishOTPCrossesMidnightCleanly(t *testing.T) {
	otpSaveSecrets(t)

	publishOTP(time.Date(2026, 8, 31, 23, 59, 59, 0, time.UTC))
	before := proxy.LoadOTP().Hour
	publishOTP(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	after := proxy.LoadOTP().Hour

	if before != "2026-08-31-23" {
		t.Errorf("before midnight: Hour = %q, want %q", before, "2026-08-31-23")
	}
	if after != "2026-09-01-00" {
		t.Errorf("after midnight: Hour = %q, want %q", after, "2026-09-01-00")
	}
}

// nextOTPRotation must land just past the NEXT hour boundary regardless of
// where in the hour it is called from — that is what "aligned" means, as
// opposed to the old flat `time.Sleep(1 * time.Hour)` which just repeated the
// process's start offset forever.
func TestNextOTPRotationLandsJustPastTheHourBoundary(t *testing.T) {
	base := time.Date(2026, 8, 31, 13, 0, 0, 0, time.UTC)

	for _, offset := range []time.Duration{
		0,
		time.Nanosecond,
		time.Second,
		17*time.Minute + 42*time.Second,
		time.Hour - time.Second,
		time.Hour - time.Nanosecond,
	} {
		at := base.Add(offset)
		d := nextOTPRotation(at)

		if d <= 0 {
			t.Fatalf("nextOTPRotation(%s) = %s, must be positive or the loop spins", at, d)
		}

		landing := at.Add(d)
		boundary := base.Add(time.Hour)
		if landing.Before(boundary) {
			t.Errorf("from %s the rotation wakes at %s, BEFORE the %s boundary — it would re-publish the outgoing bucket and then sleep a full further hour", at, landing, boundary)
		}
		if landing.Sub(boundary) > otpRotationSkew {
			t.Errorf("from %s the rotation wakes at %s, %s past the boundary (skew budget is %s)", at, landing, landing.Sub(boundary), otpRotationSkew)
		}
		if got := landing.UTC().Format(proxy.OTPBucketLayout); got != "2026-08-31-14" {
			t.Errorf("from %s the rotation wakes inside bucket %q, want %q", at, got, "2026-08-31-14")
		}
	}
}

// The rotation must never SKIP a bucket. Walking the loop one tick at a time
// from an arbitrary starting instant, each tick must publish the bucket for the
// instant it woke at, and the instant it schedules must fall in the very next
// bucket — never two buckets on.
//
// This is the net for reading the clock twice inside the loop. With
// publishOTP(time.Now()) followed by nextOTPRotation(time.Now()), a tick that
// starts at 12:59:59.999 publishes the 12:00 set and then schedules from
// 13:00:00.001 for 14:00 — the 13:00 bucket is never published at all, and for
// a full hour every client is challenged against an OTP the proxy is no longer
// issuing. Passing one instant to both halves is what makes that impossible,
// and this test walks a tick that starts a hair before a boundary to prove it.
func TestRotateOTPOnceNeverSkipsABucket(t *testing.T) {
	otpSaveSecrets(t)

	starts := []time.Time{
		time.Date(2026, 8, 31, 13, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 31, 13, 37, 12, 0, time.UTC),
		// A hair before the boundary: the shape that breaks under a second
		// clock read.
		time.Date(2026, 8, 31, 13, 59, 59, int(time.Millisecond), time.UTC),
		time.Date(2026, 8, 31, 23, 59, 59, int(999*time.Millisecond), time.UTC),
	}

	for _, start := range starts {
		now := start
		want := now.UTC().Truncate(time.Hour)

		for tick := 0; tick < 26; tick++ {
			d := rotateOTPOnce(now)

			if got := proxy.LoadOTP().Hour; got != want.Format(proxy.OTPBucketLayout) {
				t.Fatalf("from %s tick %d published bucket %q, want %q", start, tick, got, want.Format(proxy.OTPBucketLayout))
			}

			now = now.Add(d)
			want = want.Add(time.Hour)

			if got := now.UTC().Truncate(time.Hour); !got.Equal(want) {
				t.Fatalf("from %s tick %d wakes at %s, in bucket %s — want the next bucket %s (a bucket was skipped)", start, tick, now, got, want)
			}
		}
	}
}

// The sleep must not depend on the caller's timezone either: the boundary is a
// UTC hour boundary, and a location offset by a fraction of an hour must not
// shift it.
func TestNextOTPRotationIsIndependentOfLocation(t *testing.T) {
	at := time.Date(2026, 8, 31, 13, 20, 0, 0, time.UTC)
	kathmandu := time.FixedZone("Asia/Kathmandu", 5*3600+45*60)

	if got, want := nextOTPRotation(at.In(kathmandu)), nextOTPRotation(at); got != want {
		t.Fatalf("nextOTPRotation depends on the location: %s in Kathmandu vs %s in UTC", got, want)
	}
}
