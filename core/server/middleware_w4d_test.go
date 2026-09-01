package server

// WAVE 9 W4 (CONC-02/AUTHZ-05/CRYPTO-04) pin: the request path must read
// config exclusively through ONE domains.Current() load. A reload running
// concurrently with traffic therefore swaps the whole configuration at once -
// never a new threshold beside an old secret - and the race detector sees no
// unsynchronized access to any mirror global from the middleware.
//
// The reloader alternates two snapshots that differ in every value the
// decision path reads (ratelimit thresholds, admin secret); the traffic
// goroutines only assert the request is served. What this test pins is that
// `-race` stays silent, not which snapshot wins - either is a consistent
// configuration.

import (
	"net/http"
	"sync"
	"testing"

	"github.com/azferius/lancarsec/core/domains"
)

func TestMiddlewareServesTrafficThroughConcurrentRepublishes(t *testing.T) {
	env := mwNewEnv(t)
	env.mwSetStage(0)

	base := domains.Current()
	cfgA, cfgB := *base, *base
	cfgA.Proxy.Ratelimits = map[string]int{"requests": 500, "unknownFingerprint": 150, "challengeFailures": 40, "noRequestsSent": 10}
	cfgA.Proxy.AdminSecret = "w4d-admin-secret-aaaa"
	cfgB.Proxy.Ratelimits = map[string]int{"requests": 501, "unknownFingerprint": 151, "challengeFailures": 41, "noRequestsSent": 11}
	cfgB.Proxy.AdminSecret = "w4d-admin-secret-bbbb"

	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				domains.Publish(&cfgA)
				domains.Publish(&cfgB)
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				rec := mwDo(mwRequest("/"))
				if rec.Code != http.StatusOK {
					t.Errorf("status = %d, want 200", rec.Code)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
}
