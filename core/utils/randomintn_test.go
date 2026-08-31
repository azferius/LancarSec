package utils

import "testing"

// RandomIntN is the captcha's obfuscation source; a bias here is a bias in
// where the answer gets drawn.
func TestRandomIntNIsInRangeAndUnbiased(t *testing.T) {
	for _, n := range []int{1, 2, 3, 62, 90, 255, 1000} {
		counts := make([]int, n)
		const draws = 20000
		for range draws {
			v := RandomIntN(n)
			if v < 0 || v >= n {
				t.Fatalf("RandomIntN(%d) = %d, out of range", n, v)
			}
			counts[v]++
		}
		if n > 1 && n <= 255 {
			// A chi-square would be better, but a crude envelope catches the
			// failure mode that matters: modulo bias piles ~25% extra weight
			// onto the low indices.
			want := draws / n
			for i, got := range counts {
				if got < want/2 || got > want*2 {
					t.Errorf("RandomIntN(%d): value %d drawn %d times, want ~%d", n, i, got, want)
				}
			}
		}
	}
}

func TestRandomIntNPanicsOnNonPositive(t *testing.T) {
	for _, n := range []int{0, -1} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("RandomIntN(%d) did not panic; math/rand.Intn did, and call sites rely on it", n)
				}
			}()
			RandomIntN(n)
		}()
	}
}
