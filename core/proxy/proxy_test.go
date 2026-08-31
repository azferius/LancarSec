package proxy

import (
	"strconv"
	"strings"
	"sync"
	"testing"
)

// NEW IN WAVE 5.
//
// Before wave 5 the three challenge OTPs and the hour-bucket string were four
// unsynchronised package variables: written by the rotation goroutine in
// core/server/monitor.go and read on the request hot path with nothing between
// them. Two separate defects lived there. The first is a plain data race — a
// Go string is two machine words, so a reader could observe the pointer of one
// value beside the length of another. The second is subtler and survives even
// on a machine where the individual writes happen to be atomic: the four values
// were written one at a time, so a request arriving mid-rotation could pair the
// NEW hour bucket with the OLD cookie OTP and derive a token that neither the
// issuing nor the verifying side agrees with. They are now one immutable struct
// behind one atomic.Pointer.

func TestLoadOTPIsNeverNil(t *testing.T) {
	// The zero value must be usable: LoadOTP is on the request hot path and
	// callers dereference it without a nil check.
	if got := LoadOTP(); got == nil {
		t.Fatal("LoadOTP returned nil before any StoreOTP — the hot path would nil-deref")
	}
}

func TestStoreOTPPublishes(t *testing.T) {
	restore := LoadOTP()
	t.Cleanup(func() { StoreOTP(*restore) })

	want := OTP{Hour: "2026-08-31-13", Cookie: "c", JS: "j", Captcha: "k"}
	StoreOTP(want)

	got := LoadOTP()
	if *got != want {
		t.Fatalf("LoadOTP() = %+v, want %+v", *got, want)
	}
}

// The published set must be immutable from the caller's side: StoreOTP copies,
// so a caller that reuses and mutates its local struct cannot retroactively
// change what live requests are reading.
func TestStoreOTPCopiesItsArgument(t *testing.T) {
	restore := LoadOTP()
	t.Cleanup(func() { StoreOTP(*restore) })

	arg := OTP{Hour: "h1", Cookie: "c1", JS: "j1", Captcha: "k1"}
	StoreOTP(arg)
	published := LoadOTP()

	arg.Cookie = "mutated"
	arg.Hour = "mutated"

	if published.Cookie != "c1" || published.Hour != "h1" {
		t.Fatalf("mutating the argument after StoreOTP changed the published set: %+v", *published)
	}
}

// The property the atomic.Pointer exists for: a reader NEVER sees a mix of two
// generations. Every field of a loaded set must come from the same StoreOTP
// call. A per-field publish (four separate variables, or four separate atomics)
// fails this; one pointer swap cannot.
//
// Run under -race this is also the regression test for the raw data race.
func TestLoadOTPNeverSeesATornSet(t *testing.T) {
	restore := LoadOTP()
	t.Cleanup(func() { StoreOTP(*restore) })

	const generations = 2000

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < generations; i++ {
			n := strconv.Itoa(i)
			StoreOTP(OTP{
				Hour:    "hour-" + n,
				Cookie:  "cookie-" + n,
				JS:      "js-" + n,
				Captcha: "captcha-" + n,
			})
		}
		close(stop)
	}()

	for reader := 0; reader < 4; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				got := LoadOTP()
				if !strings.HasPrefix(got.Hour, "hour-") {
					// The set published before the writer's first generation.
					continue
				}
				gen := strings.TrimPrefix(got.Hour, "hour-")
				if got.Cookie != "cookie-"+gen || got.JS != "js-"+gen || got.Captcha != "captcha-"+gen {
					t.Errorf("torn OTP set: %+v — fields came from different generations", *got)
					return
				}
			}
		}()
	}

	wg.Wait()
}

// The deprecated mirrors (CurrHourStr/CookieOTP/JSOTP/CaptchaOTP) were deleted
// in wave 7: middleware reads LoadOTP directly, so there is nothing left to
// keep in step. This test would have caught a partial migration leaving a
// stale reader behind; its absence is now the state being asserted.
