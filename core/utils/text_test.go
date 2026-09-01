package utils

import (
	"strings"
	"testing"

	"github.com/azferius/lancarsec/core/domains"
)

// saveColorsString restores the package-level ColorsString global after a test.
// Almost everything in text.go reads it, and it is mutable process-wide state.
func saveColorsString(t *testing.T) {
	t.Helper()
	prev := ColorsString
	t.Cleanup(func() { ColorsString = prev })
}

// saveDomainsData restores the package-level domains.DomainsData map. AddLogs
// and ClearLogs mutate it in place, so a test that touches it must put it back.
func saveDomainsData(t *testing.T) {
	t.Helper()
	prev := domains.DomainsData
	restore := make(map[string]domains.DomainData, len(prev))
	for k, v := range prev {
		restore[k] = v
	}
	t.Cleanup(func() { domains.DomainsData = restore })
	domains.DomainsData = map[string]domains.DomainData{}
}

// ---------------------------------------------------------------------------
// StageToString
// ---------------------------------------------------------------------------

func TestStageToString(t *testing.T) {
	tests := []struct {
		name string
		in   int
		want string
	}{
		{name: "stage 1", in: 1, want: "1"},
		{name: "stage 2", in: 2, want: "2"},
		{name: "stage 3", in: 3, want: "3"},
		{name: "stage 4", in: 4, want: "4"},

		// FIXED IN WAVE 5 (this case used to expect "5+"). The old switch had no
		// case for 0, so susLv 0 — the WHITELIST verdict — fell through to the
		// default and rendered as "5+", the same token as a blocked request.
		// susLvStr is appended to the token cache key at
		// core/server/middleware.go:196, so a whitelisted request and an
		// escalated one shared a cache entry and the block was bypassable. See
		// TestStageToStringIsCollisionFreeForCacheKeys below and the doc comment
		// on StageToString for the full exploit path.
		{name: "susLv 0 is its own bucket", in: 0, want: "0"},

		{name: "stage 5 is 5+", in: 5, want: "5+"},
		{name: "stage 6 is 5+", in: 6, want: "5+"},
		{name: "stage 99 is 5+", in: 99, want: "5+"},

		// FIXED IN WAVE 5 (these cases used to expect "5+"). Same defect on the
		// other side: negatives also fell into the default. gofilter rules can
		// lower susLv, so a negative level is reachable, and it too shared the
		// blocked bucket.
		{name: "negative stage is its own bucket", in: -1, want: "-1"},
		{name: "large negative is its own bucket", in: -1000, want: "-1000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StageToString(tt.in); got != tt.want {
				t.Errorf("StageToString(%d) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// NEW IN WAVE 5. StageToString's output is a component of the token cache key
// (core/server/middleware.go:196 does CacheIps.Load(accessKey + susLvStr)), so
// two suspicion levels that render to the same string share a cache entry.
//
// The only levels that may legally share are 5 and above: that branch returns
// before CacheIps.Store is ever reached, so no entry exists for them to
// collide on, and the string is purely a display value there. Every level that
// CAN reach the cache — 4 and below, including 0 and negatives — must map to a
// distinct string. This is the assertion that would have caught the original
// defect directly, rather than through its downstream effect in middleware.
func TestStageToStringIsCollisionFreeForCacheKeys(t *testing.T) {
	seen := make(map[string]int)
	for stage := -1000; stage <= 4; stage++ {
		got := StageToString(stage)
		if prev, dup := seen[got]; dup {
			t.Fatalf("StageToString(%d) and StageToString(%d) both render as %q — they would share a token cache key", prev, stage, got)
		}
		seen[got] = stage
	}

	// And no cacheable level may land in the blocked bucket's string.
	for stage := -1000; stage <= 4; stage++ {
		if got := StageToString(stage); got == "5+" {
			t.Fatalf("StageToString(%d) = %q — a cacheable level shares the blocked bucket's key", stage, got)
		}
	}

	// 5 and above deliberately still share one string.
	for _, stage := range []int{5, 6, 99, 1 << 20} {
		if got := StageToString(stage); got != "5+" {
			t.Errorf("StageToString(%d) = %q, want %q", stage, got, "5+")
		}
	}
}

// ---------------------------------------------------------------------------
// TrimTime — the 10-second bucket helper the sliding-window ratelimit depends
// on (core/server/monitor.go:47, 213, 596, 607, 618).
// ---------------------------------------------------------------------------

func TestTrimTime(t *testing.T) {
	tests := []struct {
		name string
		in   int
		want int
	}{
		{name: "zero", in: 0, want: 0},
		{name: "one below the first boundary", in: 1, want: 0},
		{name: "nine, last of bucket 0", in: 9, want: 0},
		{name: "exactly ten, first of bucket 10", in: 10, want: 10},
		{name: "eleven", in: 11, want: 10},
		{name: "fifteen rounds down not to nearest", in: 15, want: 10},
		{name: "nineteen, last of bucket 10", in: 19, want: 10},
		{name: "exactly twenty", in: 20, want: 20},
		{name: "unix-ish timestamp", in: 1767225599, want: 1767225590},
		{name: "unix-ish timestamp on a boundary", in: 1767225600, want: 1767225600},

		// BUG (a later wave may flip these): TrimTime is integer division, and
		// Go truncates toward zero rather than flooring. For NEGATIVE
		// timestamps the bucket therefore rounds UP (toward zero), not down, so
		// the buckets around t=0 are asymmetric: [-9..9] all collapse into a
		// single 19-second-wide bucket 0, and every negative bucket is offset
		// by one from its positive mirror. Unreachable today because the only
		// caller feeds it a Unix second count, but it is the current contract.
		// A floor-based rewrite would make TrimTime(-1) == -10.
		{name: "minus one truncates toward zero", in: -1, want: 0},
		{name: "minus nine truncates toward zero", in: -9, want: 0},
		{name: "minus ten is exact", in: -10, want: -10},
		{name: "minus eleven truncates toward zero", in: -11, want: -10},
		{name: "minus fifteen truncates toward zero", in: -15, want: -10},
		{name: "minus twenty is exact", in: -20, want: -20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TrimTime(tt.in); got != tt.want {
				t.Errorf("TrimTime(%d) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

// Structural invariants the sliding window relies on: the result is always a
// multiple of 10, is idempotent, and (for non-negative input) never exceeds the
// input.
func TestTrimTimeInvariants(t *testing.T) {
	for i := 0; i < 1000; i++ {
		got := TrimTime(i)
		if got%10 != 0 {
			t.Fatalf("TrimTime(%d) = %d, not a multiple of 10", i, got)
		}
		if got > i {
			t.Fatalf("TrimTime(%d) = %d, which is greater than the input", i, got)
		}
		if i-got >= 10 {
			t.Fatalf("TrimTime(%d) = %d, bucket is wider than 10", i, got)
		}
		if again := TrimTime(got); again != got {
			t.Fatalf("TrimTime is not idempotent: TrimTime(%d) = %d", got, again)
		}
	}
}

// ---------------------------------------------------------------------------
// SetColor / PrimaryColor
// ---------------------------------------------------------------------------

func TestPrimaryColorUsesTheDefaultColorsString(t *testing.T) {
	saveColorsString(t)
	ColorsString = "0;31"
	got := PrimaryColor("hello")
	want := "\033[0;31mhello\033[0m"
	if got != want {
		t.Errorf("PrimaryColor(%q) = %q, want %q", "hello", got, want)
	}
}

func TestSetColorAndPrimaryColor(t *testing.T) {
	saveColorsString(t)

	tests := []struct {
		name         string
		colorMap     []string
		wantColors   string
		wantWrapped  string
		wrappedInput string
	}{
		{
			name:         "single component",
			colorMap:     []string{"31"},
			wantColors:   "31",
			wrappedInput: "x",
			wantWrapped:  "\033[31mx\033[0m",
		},
		{
			name:         "two components joined with semicolon",
			colorMap:     []string{"0", "31"},
			wantColors:   "0;31",
			wrappedInput: "x",
			wantWrapped:  "\033[0;31mx\033[0m",
		},
		{
			name:         "three components (256-colour form)",
			colorMap:     []string{"38", "5", "208"},
			wantColors:   "38;5;208",
			wrappedInput: "x",
			wantWrapped:  "\033[38;5;208mx\033[0m",
		},
		{
			// Wave 2 rewrote SetColor as strings.Join. The old hand-rolled loop
			// panicked (or produced a stray leading separator) on an empty
			// slice; strings.Join returns "". The resulting escape sequence
			// "\033[m" is the ANSI "reset" default — degraded output, but not a
			// crash. Pinned so the empty-slice path stays non-panicking.
			name:         "empty slice yields empty colour string, no panic",
			colorMap:     []string{},
			wantColors:   "",
			wrappedInput: "x",
			wantWrapped:  "\033[mx\033[0m",
		},
		{
			// nil behaves identically to an empty slice under strings.Join.
			name:         "nil slice yields empty colour string, no panic",
			colorMap:     nil,
			wantColors:   "",
			wrappedInput: "x",
			wantWrapped:  "\033[mx\033[0m",
		},
		{
			// SetColor does no validation: any string is joined verbatim, and
			// PrimaryColor splices it straight into the escape sequence. A
			// caller-controlled colour map is therefore a terminal-escape
			// injection primitive. Pinned as current behaviour.
			name:         "components are not validated or escaped",
			colorMap:     []string{"0", "31m\033[2J"},
			wantColors:   "0;31m\033[2J",
			wrappedInput: "x",
			wantWrapped:  "\033[0;31m\033[2Jmx\033[0m",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetColor(tt.colorMap)
			if ColorsString != tt.wantColors {
				t.Errorf("after SetColor(%q), ColorsString = %q, want %q", tt.colorMap, ColorsString, tt.wantColors)
			}
			if got := PrimaryColor(tt.wrappedInput); got != tt.wantWrapped {
				t.Errorf("PrimaryColor(%q) = %q, want %q", tt.wrappedInput, got, tt.wantWrapped)
			}
		})
	}
}

func TestPrimaryColorPassesInputThroughUnescaped(t *testing.T) {
	saveColorsString(t)
	ColorsString = "0;31"

	// PrimaryColor does not sanitise its argument either — it is wrapped
	// verbatim. Every log line in FormatLogs runs the client-controlled
	// User-Agent and path through this, so a hostile UA can emit raw ANSI into
	// the operator's terminal. Current contract, pinned.
	hostile := "\033[2J\033[Hpwned"
	got := PrimaryColor(hostile)
	want := "\033[0;31m" + hostile + "\033[0m"
	if got != want {
		t.Errorf("PrimaryColor(%q) = %q, want %q", hostile, got, want)
	}
}

// ---------------------------------------------------------------------------
// FormatLogs — pure given a DomainLog (plus the ColorsString global).
// ---------------------------------------------------------------------------

func TestFormatLogs(t *testing.T) {
	saveColorsString(t)
	ColorsString = "0;31"

	tests := []struct {
		name string
		log  domains.DomainLog
		want string
	}{
		{
			name: "known browser fingerprint takes the green branch",
			log: domains.DomainLog{
				Time:      "12:00:00",
				IP:        "1.2.3.4",
				BrowserFP: "Chrome",
				TLSFP:     "tls-ignored",
				Useragent: "UA",
				Path:      "/p",
			},
			want: "[ \033[0;31m12:00:00\033[0m ] > \033[35m1.2.3.4\033[0m - \033[32mChrome\033[0m - \033[0;31mUA\033[0m - \033[0;31m/p\033[0m",
		},
		{
			name: "bot fingerprint also takes the green branch",
			log: domains.DomainLog{
				Time:      "12:00:01",
				IP:        "1.2.3.5",
				BotFP:     "curl",
				TLSFP:     "tls-ignored",
				Useragent: "UA",
				Path:      "/p",
			},
			want: "[ \033[0;31m12:00:01\033[0m ] > \033[35m1.2.3.5\033[0m - \033[32mcurl\033[0m - \033[0;31mUA\033[0m - \033[0;31m/p\033[0m",
		},
		{
			// Both set: the branch concatenates BrowserFP and BotFP with no
			// separator, so "Chrome"+"curl" renders as "Chromecurl". Current
			// contract.
			name: "browser and bot fingerprints concatenate with no separator",
			log: domains.DomainLog{
				Time:      "12:00:02",
				IP:        "1.2.3.6",
				BrowserFP: "Chrome",
				BotFP:     "curl",
				Useragent: "UA",
				Path:      "/p",
			},
			want: "[ \033[0;31m12:00:02\033[0m ] > \033[35m1.2.3.6\033[0m - \033[32mChromecurl\033[0m - \033[0;31mUA\033[0m - \033[0;31m/p\033[0m",
		},
		{
			name: "no fingerprint falls back to the red UNK branch with the raw TLS fp",
			log: domains.DomainLog{
				Time:      "12:00:03",
				IP:        "1.2.3.7",
				TLSFP:     "771,4865-4866,0-11-10",
				Useragent: "UA",
				Path:      "/p",
			},
			want: "[ \033[0;31m12:00:03\033[0m ] > \033[35m1.2.3.7\033[0m - \033[31mUNK (771,4865-4866,0-11-10)\033[0m - \033[0;31mUA\033[0m - \033[0;31m/p\033[0m",
		},
		{
			name: "zero value log renders the UNK branch with empty fields",
			log:  domains.DomainLog{},
			want: "[ \033[0;31m\033[0m ] > \033[35m\033[0m - \033[31mUNK ()\033[0m - \033[0;31m\033[0m - \033[0;31m\033[0m",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatLogs(tt.log); got != tt.want {
				t.Errorf("FormatLogs() =\n%q\nwant\n%q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AddLogs / ClearLogs — copy-modify-write over the domains.DomainsData global.
// ---------------------------------------------------------------------------

func TestAddLogsAppendsInOrder(t *testing.T) {
	saveDomainsData(t)
	domains.DomainsData["example.com"] = domains.DomainData{Name: "example.com"}

	AddLogs(domains.DomainLog{Path: "/first"}, "example.com")
	AddLogs(domains.DomainLog{Path: "/second"}, "example.com")

	got := domains.DomainsData["example.com"].LastLogs
	if len(got) != 2 {
		t.Fatalf("LastLogs has %d entries, want 2", len(got))
	}
	if got[0].Path != "/first" || got[1].Path != "/second" {
		t.Errorf("LastLogs = %+v, want /first then /second", got)
	}
}

// Pins today's contract: AddLogs reads domains.DomainsData[domainName] with no
// existence check. For an unknown domain that read yields the zero DomainData,
// the log is appended to it, and the zero-valued entry is WRITTEN BACK into the
// map — so calling AddLogs for a domain that was never configured silently
// creates a map entry with an empty Name and zeroed thresholds rather than
// erroring. This is the map-growth path a wave that adds a guard would remove.
func TestAddLogsCreatesAnEntryForAnUnknownDomain(t *testing.T) {
	saveDomainsData(t)

	if _, ok := domains.DomainsData["never-configured.example"]; ok {
		t.Fatal("test precondition failed: domain already present")
	}
	AddLogs(domains.DomainLog{Path: "/x"}, "never-configured.example")

	entry, ok := domains.DomainsData["never-configured.example"]
	if !ok {
		t.Fatal("AddLogs did not create a map entry for an unknown domain; today it does")
	}
	if entry.Name != "" {
		t.Errorf("created entry Name = %q, want %q (zero DomainData)", entry.Name, "")
	}
	if len(entry.LastLogs) != 1 || entry.LastLogs[0].Path != "/x" {
		t.Errorf("created entry LastLogs = %+v, want one entry with Path /x", entry.LastLogs)
	}
}

func TestClearLogsNilsTheSliceAndReturnsTheUpdatedData(t *testing.T) {
	saveDomainsData(t)
	domains.DomainsData["example.com"] = domains.DomainData{
		Name:     "example.com",
		Stage:    3,
		LastLogs: []domains.DomainLog{{Path: "/a"}, {Path: "/b"}},
	}

	returned := ClearLogs("example.com")

	if returned.LastLogs != nil {
		t.Errorf("returned LastLogs = %+v, want nil", returned.LastLogs)
	}
	if returned.Stage != 3 || returned.Name != "example.com" {
		t.Errorf("ClearLogs mutated unrelated fields: %+v", returned)
	}
	if stored := domains.DomainsData["example.com"]; stored.LastLogs != nil {
		t.Errorf("stored LastLogs = %+v, want nil", stored.LastLogs)
	}
}

// ---------------------------------------------------------------------------
// EvalYN
// ---------------------------------------------------------------------------

func TestEvalYN(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		defVal bool
		want   bool
	}{
		{name: "y", in: "y", defVal: false, want: true},
		{name: "yes", in: "yes", defVal: false, want: true},
		{name: "true", in: "true", defVal: false, want: true},
		{name: "n", in: "n", defVal: true, want: false},
		{name: "no", in: "no", defVal: true, want: false},
		{name: "false", in: "false", defVal: true, want: false},
		{name: "empty falls back to default true", in: "", defVal: true, want: true},
		{name: "empty falls back to default false", in: "", defVal: false, want: false},
		{name: "garbage falls back to default true", in: "maybe", defVal: true, want: true},
		{name: "garbage falls back to default false", in: "maybe", defVal: false, want: false},

		// EvalYN is case SENSITIVE — the switch compares against lowercase
		// literals only. It happens to work because its only production caller
		// (AskBool) feeds it ReadTerminal(), which lowercases. Any future
		// caller that does not lowercase silently gets the default instead of
		// the user's answer. Pinned as current behaviour.
		{name: "uppercase Y is not recognised, falls back to default", in: "Y", defVal: false, want: false},
		{name: "uppercase YES is not recognised, falls back to default", in: "YES", defVal: false, want: false},
		{name: "uppercase N is not recognised, falls back to default", in: "N", defVal: true, want: true},
		{name: "mixed case True is not recognised", in: "True", defVal: false, want: false},

		// No trimming either: a trailing space defeats the match.
		{name: "trailing whitespace is not trimmed", in: "y ", defVal: false, want: false},
		{name: "leading whitespace is not trimmed", in: " y", defVal: false, want: false},

		// "1" / "0" are not accepted despite "true" / "false" being.
		{name: "numeric 1 is not recognised", in: "1", defVal: false, want: false},
		{name: "numeric 0 is not recognised", in: "0", defVal: true, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EvalYN(tt.in, tt.defVal); got != tt.want {
				t.Errorf("EvalYN(%q, %v) = %v, want %v", tt.in, tt.defVal, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Package-level globals
// ---------------------------------------------------------------------------

func TestColorsStringDefault(t *testing.T) {
	// Pins the shipped default so a change to the TUI's base colour is visible
	// in a diff. Every test that mutates ColorsString restores it via
	// t.Cleanup, so this reads the package default regardless of test ordering.
	saveColorsString(t)
	if ColorsString != "0;31" {
		t.Errorf("ColorsString default = %q, want %q (a test above may have leaked state)", ColorsString, "0;31")
	}
	if !strings.HasPrefix(PrimaryColor("x"), "\033[") {
		t.Errorf("PrimaryColor no longer emits an ANSI escape: %q", PrimaryColor("x"))
	}
}
