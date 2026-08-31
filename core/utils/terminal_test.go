package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/azferius/lancarsec/core/domains"
	"github.com/azferius/lancarsec/core/firewall"
	"github.com/azferius/lancarsec/core/proxy"
)

// ---------------------------------------------------------------------------
// Test harness for the interactive wizard helpers.
//
// ReadTerminal/AskBool/AskInt/AskString read os.Stdin and write os.Stdout, both
// of which are process-global. Every test here swaps them for temp files and
// restores them via t.Cleanup, and none of them call t.Parallel, so the
// swapping is serialised. A regular file (not a pipe) is used for stdin so the
// reads are byte-for-byte deterministic rather than dependent on how a pipe
// happens to chunk.
// ---------------------------------------------------------------------------

// withStdin replaces os.Stdin with a temp file containing content.
func withStdin(t *testing.T, content string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing fake stdin: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening fake stdin: %v", err)
	}

	prev := os.Stdin
	os.Stdin = f
	t.Cleanup(func() {
		os.Stdin = prev
		f.Close()
	})
}

// muteStdout redirects os.Stdout to a temp file so the wizard's ANSI prompts do
// not pollute the test log, and returns a reader for what was written.
func muteStdout(t *testing.T) func() string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "stdout")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating fake stdout: %v", err)
	}

	prev := os.Stdout
	os.Stdout = f
	t.Cleanup(func() {
		os.Stdout = prev
		f.Close()
	})

	return func() string {
		if err := f.Sync(); err != nil {
			t.Fatalf("syncing fake stdout: %v", err)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading fake stdout: %v", err)
		}
		return string(b)
	}
}

// ---------------------------------------------------------------------------
// ReadTerminal
// ---------------------------------------------------------------------------

func TestReadTerminal(t *testing.T) {
	tests := []struct {
		name  string
		stdin string
		want  string
	}{
		{name: "plain line", stdin: "hello\n", want: "hello"},
		{name: "lowercases the answer", stdin: "YES\n", want: "yes"},
		{name: "mixed case", stdin: "ExAmPlE.CoM\n", want: "example.com"},
		{name: "trailing newline is stripped", stdin: "abc\n", want: "abc"},
		{name: "crlf is stripped too", stdin: "abc\r\n", want: "abc"},
		{name: "empty line", stdin: "\n", want: ""},
		{name: "immediate EOF yields empty string", stdin: "", want: ""},

		// ReadTerminal does NOT trim spaces — only the line terminator. Every
		// caller compares against exact literals, so a stray space silently
		// becomes "not recognised".
		{name: "surrounding whitespace is preserved", stdin: "  y  \n", want: "  y  "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withStdin(t, tt.stdin)
			if got := ReadTerminal(); got != tt.want {
				t.Errorf("ReadTerminal() = %q, want %q", got, tt.want)
			}
		})
	}
}

// BUG (a later wave flips this): ReadTerminal constructs a NEW bufio.Scanner on
// every call and throws it away after one line. Against an interactive TTY that
// is harmless because reads are line-buffered, but against a file or a pipe —
// i.e. any non-interactive run of the first-launch wizard, such as
// `lancarsec < answers.txt` or a Docker build feeding it a heredoc — the first
// Scan() fills a 64 KiB buffer with the WHOLE input and the buffer is discarded
// with the scanner. Every question after the first therefore sees EOF and
// silently takes its default value, which is how an operator ends up with a
// config they did not answer for. Pinned as current behaviour; when the scanner
// is hoisted to a package-level reader, the second read below returns "second"
// and this assertion flips.
func TestReadTerminalDiscardsEverythingAfterTheFirstLine(t *testing.T) {
	withStdin(t, "first\nsecond\nthird\n")

	if got := ReadTerminal(); got != "first" {
		t.Fatalf("first ReadTerminal() = %q, want %q", got, "first")
	}
	if got := ReadTerminal(); got != "" {
		t.Errorf("second ReadTerminal() = %q, want %q — today the buffered remainder is thrown away with the scanner", got, "")
	}
	if got := ReadTerminal(); got != "" {
		t.Errorf("third ReadTerminal() = %q, want %q", got, "")
	}
}

// ---------------------------------------------------------------------------
// AskBool / AskInt / AskString
//
// Consequence of the scanner defect above: each of these can only be exercised
// with a single line of input per test.
// ---------------------------------------------------------------------------

func TestAskBool(t *testing.T) {
	tests := []struct {
		name       string
		stdin      string
		defaultVal bool
		want       bool
	}{
		{name: "yes", stdin: "yes\n", defaultVal: false, want: true},
		{name: "y", stdin: "y\n", defaultVal: false, want: true},
		{name: "no", stdin: "no\n", defaultVal: true, want: false},
		{name: "uppercase is lowercased by ReadTerminal then matches", stdin: "YES\n", defaultVal: false, want: true},
		{name: "empty line takes the default", stdin: "\n", defaultVal: true, want: true},
		{name: "EOF takes the default", stdin: "", defaultVal: true, want: true},
		{name: "unrecognised answer takes the default", stdin: "banana\n", defaultVal: false, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			saveColorsString(t)
			ColorsString = "0;31"
			muteStdout(t)
			withStdin(t, tt.stdin)

			if got := AskBool("Enable?", tt.defaultVal); got != tt.want {
				t.Errorf("AskBool(%q) with stdin %q = %v, want %v", "Enable?", tt.stdin, got, tt.want)
			}
		})
	}
}

func TestAskString(t *testing.T) {
	tests := []struct {
		name       string
		stdin      string
		defaultVal string
		want       string
	}{
		{name: "answer is returned", stdin: "example.com\n", defaultVal: "default.com", want: "example.com"},
		{name: "answer is lowercased by ReadTerminal", stdin: "EXAMPLE.COM\n", defaultVal: "d", want: "example.com"},
		{name: "empty line takes the default", stdin: "\n", defaultVal: "default.com", want: "default.com"},
		{name: "EOF takes the default", stdin: "", defaultVal: "default.com", want: "default.com"},

		// Because ReadTerminal lowercases unconditionally, AskString CANNOT
		// return a value containing an uppercase letter. That silently mangles
		// every case-sensitive answer the wizard collects — most notably the
		// Discord webhook URL and the TLS certificate path
		// (core/utils/domain.go:16-26), which are case-sensitive on Linux.
		{name: "a case-sensitive path answer is destroyed", stdin: "/etc/ssl/MyCert.PEM\n", defaultVal: "", want: "/etc/ssl/mycert.pem"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			saveColorsString(t)
			ColorsString = "0;31"
			muteStdout(t)
			withStdin(t, tt.stdin)

			if got := AskString("Name?", tt.defaultVal); got != tt.want {
				t.Errorf("AskString with stdin %q = %q, want %q", tt.stdin, got, tt.want)
			}
		})
	}
}

func TestAskInt(t *testing.T) {
	tests := []struct {
		name       string
		stdin      string
		defaultVal int
		want       int
	}{
		{name: "number is parsed", stdin: "250\n", defaultVal: 75, want: 250},
		{name: "zero is parsed, not treated as empty", stdin: "0\n", defaultVal: 75, want: 0},
		{name: "negative number is accepted without validation", stdin: "-5\n", defaultVal: 75, want: -5},
		{name: "empty line takes the default", stdin: "\n", defaultVal: 75, want: 75},
		{name: "EOF takes the default", stdin: "", defaultVal: 75, want: 75},

		// AskInt recurses on an unparseable answer. Against a file/pipe the
		// recursive ReadTerminal hits EOF, returns "", and the default is
		// taken — so it terminates. Against a TTY that never sends EOF it would
		// loop until a number is given. Pinned so a rewrite to a bounded loop
		// keeps the same terminating behaviour.
		{name: "garbage recurses then hits EOF and takes the default", stdin: "banana\n", defaultVal: 75, want: 75},
		{name: "float is not an int, recurses to the default", stdin: "12.5\n", defaultVal: 75, want: 75},
		{name: "number with a trailing space is not parseable", stdin: "250 \n", defaultVal: 75, want: 75},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			saveColorsString(t)
			ColorsString = "0;31"
			muteStdout(t)
			withStdin(t, tt.stdin)

			if got := AskInt("How many?", tt.defaultVal); got != tt.want {
				t.Errorf("AskInt with stdin %q = %d, want %d", tt.stdin, got, tt.want)
			}
		})
	}
}

// The table above pins only AskInt's RETURN VALUE for an unparseable answer,
// and that value is 75 whether the function recurses (today) or gives up and
// returns the default immediately. Both routes produce the same number, so the
// table cannot tell them apart — and "delete the recursion, just return
// defaultVal" is the obvious shape of a bounded-loop rewrite.
//
// The difference is observable on stdout: recursing means the question is asked
// a SECOND time, and it is that second (empty, EOF) answer that prints the
// "Using Default Value" notice. An AskInt that returns the default straight from
// the error branch asks once and never prints the notice — silently accepting a
// ratelimit threshold the operator never confirmed. AskInt supplies every
// threshold in the first-launch wizard (BypassStage1, BypassStage2 and the four
// disable thresholds), so "did the operator actually answer this?" is the whole
// point of the prompt.
func TestAskIntRePromptsAfterAnUnparseableAnswerInsteadOfSilentlyDefaulting(t *testing.T) {
	saveColorsString(t)
	ColorsString = "0;31"
	read := muteStdout(t)
	withStdin(t, "banana\n")

	const question = "At How Many Bypassing Requests Per Second Would You Like To Activate Stage 2?"
	if got := AskInt(question, 75); got != 75 {
		t.Fatalf("AskInt = %d, want 75", got)
	}

	out := read()
	if !strings.Contains(out, "The Provided Answer Is Not A Number!") {
		t.Errorf("the rejection notice was not printed; stdout = %q", out)
	}
	if n := strings.Count(out, question); n != 2 {
		t.Errorf("the question was printed %d time(s), want 2 — AskInt must re-ask after an unparseable answer, not return the default from the error branch; stdout = %q", n, out)
	}
	if !strings.Contains(out, "Using Default Value 75") {
		t.Errorf("the default-value notice was not printed, so the 75 was never announced to the operator — AskInt returned it straight out of the error branch; stdout = %q", out)
	}
}

func TestAskHelpersEmitThePromptAndTheDefaultNotice(t *testing.T) {
	saveColorsString(t)
	ColorsString = "0;31"
	read := muteStdout(t)
	withStdin(t, "\n")

	AskString("What Is The Name Of Your Domain", "example.com")

	out := read()
	if !strings.Contains(out, "What Is The Name Of Your Domain") {
		t.Errorf("prompt was not printed; stdout = %q", out)
	}
	if !strings.Contains(out, "Using Default Value example.com") {
		t.Errorf("default-value notice was not printed; stdout = %q", out)
	}
	if !strings.Contains(out, "\033[0;31m") {
		t.Errorf("prompt was not wrapped in the primary colour; stdout = %q", out)
	}
}

// ---------------------------------------------------------------------------
// MoveInputLine / ClearScreen — pure ANSI writers over proxy.MaxLogLength.
// ---------------------------------------------------------------------------

func saveProxyTUIGlobals(t *testing.T) {
	t.Helper()
	prevWidth, prevLen := proxy.TWidth, proxy.MaxLogLength
	t.Cleanup(func() {
		proxy.TWidth = prevWidth
		proxy.MaxLogLength = prevLen
	})
}

func TestMoveInputLineWritesTheExpectedEscapes(t *testing.T) {
	saveColorsString(t)
	saveProxyTUIGlobals(t)
	ColorsString = "0;31"
	proxy.MaxLogLength = 10
	read := muteStdout(t)

	MoveInputLine()

	// Row is 12 + MaxLogLength. \033[u restores and \033[s saves the cursor.
	want := "\033[22;1H\n[ \033[0;31mCommand\033[0m ]: \033[u\033[s"
	if got := read(); got != want {
		t.Errorf("MoveInputLine wrote %q, want %q", got, want)
	}
}

func TestClearScreenWritesOneEraseLinePerRow(t *testing.T) {
	read := muteStdout(t)

	ClearScreen(2)

	got := read()
	// Saves the cursor, then erases rows 1..(9+length-1) == 1..10.
	if !strings.HasPrefix(got, "\033[s") {
		t.Errorf("ClearScreen did not save the cursor first: %q", got)
	}
	if n := strings.Count(got, "\033[K"); n != 10 {
		t.Errorf("ClearScreen(2) erased %d rows, want 10 (rows 1..9+length-1)", n)
	}
	if !strings.Contains(got, "\033[1;1H\033[K") || !strings.Contains(got, "\033[10;1H\033[K") {
		t.Errorf("ClearScreen(2) did not cover rows 1 and 10: %q", got)
	}
	if strings.Contains(got, "\033[11;1H") {
		t.Errorf("ClearScreen(2) erased row 11, which is past its range: %q", got)
	}
}

// ClearScreen's loop is `for j := 1; j < 9+length; j++`, so a length of -8 or
// below erases nothing at all. Pinned because monitor.go derives the argument
// from configuration.
func TestClearScreenWithNonPositiveLength(t *testing.T) {
	for _, length := range []int{0, -8, -100} {
		read := muteStdout(t)
		ClearScreen(length)
		got := read()
		wantRows := 9 + length - 1
		if wantRows < 0 {
			wantRows = 0
		}
		if n := strings.Count(got, "\033[K"); n != wantRows {
			t.Errorf("ClearScreen(%d) erased %d rows, want %d", length, n, wantRows)
		}
	}
}

// ---------------------------------------------------------------------------
// ReadLogs
// ---------------------------------------------------------------------------

func TestReadLogsPrintsEveryLogAndTrimsTheOverflow(t *testing.T) {
	saveColorsString(t)
	saveDomainsData(t)
	saveProxyTUIGlobals(t)
	ColorsString = "0;31"
	proxy.TWidth = 500
	proxy.MaxLogLength = 2

	domains.DomainsData["example.com"] = domains.DomainData{
		Name: "example.com",
		LastLogs: []domains.DomainLog{
			{Time: "1", IP: "1.1.1.1", BrowserFP: "Chrome", Useragent: "UA", Path: "/a"},
			{Time: "2", IP: "2.2.2.2", BrowserFP: "Chrome", Useragent: "UA", Path: "/b"},
			{Time: "3", IP: "3.3.3.3", BrowserFP: "Chrome", Useragent: "UA", Path: "/c"},
			{Time: "4", IP: "4.4.4.4", BrowserFP: "Chrome", Useragent: "UA", Path: "/d"},
		},
	}

	read := muteStdout(t)
	ReadLogs("example.com")
	out := read()

	// MaxLogLength is 2 and there are 4 logs, so the two oldest are dropped
	// from the stored slice.
	stored := domains.DomainsData["example.com"].LastLogs
	if len(stored) != 2 {
		t.Fatalf("stored LastLogs has %d entries after trimming, want 2", len(stored))
	}
	if stored[0].Path != "/c" || stored[1].Path != "/d" {
		t.Errorf("stored LastLogs = %+v, want the two newest (/c, /d)", stored)
	}

	if strings.Contains(out, "1.1.1.1") || strings.Contains(out, "2.2.2.2") {
		t.Errorf("ReadLogs printed a trimmed log line: %q", out)
	}
	if !strings.Contains(out, "3.3.3.3") || !strings.Contains(out, "4.4.4.4") {
		t.Errorf("ReadLogs did not print the retained log lines: %q", out)
	}
	// Rows start at 11 + i.
	if !strings.Contains(out, "\033[11;1H") || !strings.Contains(out, "\033[12;1H") {
		t.Errorf("ReadLogs did not position the rows at 11 and 12: %q", out)
	}
}

func TestReadLogsWithNoLogsStillMovesTheInputLine(t *testing.T) {
	saveColorsString(t)
	saveDomainsData(t)
	saveProxyTUIGlobals(t)
	ColorsString = "0;31"
	proxy.TWidth = 200
	proxy.MaxLogLength = 5

	domains.DomainsData["example.com"] = domains.DomainData{Name: "example.com"}

	read := muteStdout(t)
	ReadLogs("example.com")

	if got := read(); !strings.Contains(got, "Command") {
		t.Errorf("ReadLogs did not call MoveInputLine: %q", got)
	}
}

// Pins today's contract: the truncation branch is
//
//	parsedOut[:len(parsedOut)-(len(parsedOut)+4-proxy.TWidth)]
//
// which simplifies to parsedOut[:TWidth-4]. When the terminal width is under 4
// that index is NEGATIVE and the slice expression panics with
// "slice bounds out of range". proxy.TWidth is populated from the real terminal
// size, and is 0 whenever the size query fails or the process has no TTY (under
// systemd, Docker, or nohup) — so on any headless deployment the very first log
// line panics the monitor goroutine. Pinned as the current behaviour; a wave
// that clamps the width flips this to a non-panicking assertion.
func TestReadLogsPanicsWhenTerminalWidthIsTooSmall(t *testing.T) {
	saveColorsString(t)
	saveDomainsData(t)
	saveProxyTUIGlobals(t)
	ColorsString = "0;31"
	proxy.TWidth = 0
	proxy.MaxLogLength = 10

	domains.DomainsData["example.com"] = domains.DomainData{
		Name:     "example.com",
		LastLogs: []domains.DomainLog{{Time: "1", IP: "1.1.1.1", BrowserFP: "Chrome", Useragent: "UA", Path: "/a"}},
	}

	muteStdout(t)

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("ReadLogs with proxy.TWidth == 0 did not panic; today the truncation slice index goes negative")
		}
	}()
	ReadLogs("example.com")
}

// The truncation itself: with a width large enough to be legal but smaller than
// the line, the output is cut to TWidth-4 bytes and " ..." is appended.
func TestReadLogsTruncatesLongLines(t *testing.T) {
	saveColorsString(t)
	saveDomainsData(t)
	saveProxyTUIGlobals(t)
	ColorsString = "0;31"
	proxy.TWidth = 40
	proxy.MaxLogLength = 10

	log := domains.DomainLog{Time: "1", IP: "1.1.1.1", BrowserFP: "Chrome", Useragent: strings.Repeat("U", 200), Path: "/a"}
	domains.DomainsData["example.com"] = domains.DomainData{Name: "example.com", LastLogs: []domains.DomainLog{log}}

	read := muteStdout(t)
	ReadLogs("example.com")
	out := read()

	if !strings.Contains(out, " ...") {
		t.Errorf("long line was not truncated: %q", out)
	}
	// The cut is on BYTES, at TWidth-4, and it happens after the ANSI escapes
	// have already been spliced in — so the visible width is nowhere near
	// TWidth and a truncation can land in the middle of an escape sequence or a
	// multi-byte rune. Pinned via the exact prefix that survives.
	want := FormatLogs(log)[:proxy.TWidth-4]
	if !strings.Contains(out, want+" ...") {
		t.Errorf("truncated output does not contain the expected %d-byte prefix\ngot:  %q\nwant prefix: %q", proxy.TWidth-4, out, want)
	}
}

// The truncation branch is `if len(parsedOut)+4 > proxy.TWidth`, a STRICT
// greater-than: a line that exactly fills the terminal is printed whole. The
// existing tests only exercise the far side of that boundary (a 200-char UA
// against a 40-column terminal) and the illegal side (TWidth 0), so relaxing
// the comparison to >= — the single most common way a width threshold drifts
// — changes nothing they assert. Both sides are pinned here.
func TestReadLogsTruncationBoundaryIsStrictlyGreaterThan(t *testing.T) {
	saveColorsString(t)
	saveDomainsData(t)
	saveProxyTUIGlobals(t)
	ColorsString = "0;31"
	proxy.MaxLogLength = 10

	log := domains.DomainLog{Time: "1", IP: "1.1.1.1", BrowserFP: "Chrome", Useragent: "UA", Path: "/a"}
	line := FormatLogs(log)

	// The `[-] ` gutter is 4 columns, so a line of exactly len(line)+4 columns
	// is the widest one that still fits.
	exactFit := len(line) + 4

	t.Run("a line that exactly fills the terminal is printed whole", func(t *testing.T) {
		domains.DomainsData["example.com"] = domains.DomainData{Name: "example.com", LastLogs: []domains.DomainLog{log}}
		proxy.TWidth = exactFit

		read := muteStdout(t)
		ReadLogs("example.com")
		out := read()

		if strings.Contains(out, " ...") {
			t.Errorf("with TWidth == len(line)+4 == %d the line was truncated; the comparison is `> TWidth`, not `>= TWidth`\ngot: %q", exactFit, out)
		}
		if !strings.Contains(out, line) {
			t.Errorf("the full log line was not printed\ngot:  %q\nwant: %q", out, line)
		}
	})

	t.Run("one column narrower truncates", func(t *testing.T) {
		domains.DomainsData["example.com"] = domains.DomainData{Name: "example.com", LastLogs: []domains.DomainLog{log}}
		proxy.TWidth = exactFit - 1

		read := muteStdout(t)
		ReadLogs("example.com")
		out := read()

		if !strings.Contains(out, " ...") {
			t.Errorf("with TWidth == len(line)+3 == %d the line was NOT truncated\ngot: %q", exactFit-1, out)
		}
		if !strings.Contains(out, line[:proxy.TWidth-4]+" ...") {
			t.Errorf("the truncated prefix is wrong\ngot:  %q\nwant prefix: %q", out, line[:proxy.TWidth-4])
		}
	})
}

// ---------------------------------------------------------------------------
// ReadLogs — locking.
//
// ReadLogs reads (and, when the log slice has overflowed, WRITES)
// domains.DomainsData, the map the request hot path mutates on every request.
// Both accesses are guarded by firewall.Mutex today. Neither guard is visible
// to any single-threaded assertion: drop the RLock and the function still
// returns the same bytes; downgrade the write's Lock to an RLock and it still
// compiles, still reads as "locked" in review, and still passes every test
// above — while in production it is a concurrent map write against the
// middleware, which is an unrecoverable Go runtime fatal error, not a panic the
// proxy can survive.
//
// Both tests below prove the lock is really taken by holding firewall.Mutex in
// the conflicting mode from the test goroutine and asserting ReadLogs BLOCKS.
// The "still blocked" direction cannot flake — while the conflicting lock is
// held, correct code can never finish, no matter how slow the machine is.
// ---------------------------------------------------------------------------

// blockWindow is how long a correctly-locked ReadLogs is required to stay
// blocked. Generous on purpose: it only bounds how long an UNLOCKED (mutated)
// ReadLogs has to run to completion, and that path does a few map reads and a
// handful of writes to a temp file.
const blockWindow = 500 * time.Millisecond

// runReadLogsInBackground starts ReadLogs in a goroutine and returns a channel
// closed when it returns, plus a func that waits for it. It does not return
// until the goroutine is actually scheduled and about to call ReadLogs, so the
// blockWindow measures ReadLogs and not the scheduler.
func runReadLogsInBackground(t *testing.T, domain string) (<-chan struct{}, func()) {
	t.Helper()

	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		close(started)
		ReadLogs(domain)
	}()
	<-started

	return done, func() {
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("ReadLogs never returned after the lock was released")
		}
	}
}

// ReadLogs must take firewall.Mutex for READING before it touches
// domains.DomainsData. MaxLogLength is set above the log count so the overflow
// branch (and its separate write lock) is never reached — the only lock in play
// is the RLock at the top of the function.
func TestReadLogsTakesTheReadLockBeforeReadingDomainsData(t *testing.T) {
	saveColorsString(t)
	saveDomainsData(t)
	saveProxyTUIGlobals(t)
	ColorsString = "0;31"
	proxy.TWidth = 500
	proxy.MaxLogLength = 10 // 1 log, no overflow: the write branch is skipped

	domains.DomainsData["example.com"] = domains.DomainData{
		Name:     "example.com",
		LastLogs: []domains.DomainLog{{Time: "1", IP: "1.1.1.1", BrowserFP: "Chrome", Useragent: "UA", Path: "/a"}},
	}
	muteStdout(t)

	firewall.Mutex.Lock()
	unlocked := false
	defer func() {
		if !unlocked {
			firewall.Mutex.Unlock()
		}
	}()

	done, wait := runReadLogsInBackground(t, "example.com")

	select {
	case <-done:
		t.Fatal("ReadLogs ran to completion while firewall.Mutex was held for WRITING — it is reading domains.DomainsData without taking the read lock, racing every request the middleware is serving")
	case <-time.After(blockWindow):
		// Still blocked on the read lock, which is the contract.
	}

	firewall.Mutex.Unlock()
	unlocked = true
	wait()
}

// ReadLogs must take firewall.Mutex for WRITING before storing the trimmed
// DomainData back into the map. The test holds a READ lock: a real Lock() has
// to wait for it, an RLock() sails straight through. MaxLogLength is set below
// the log count so the overflow branch really runs.
func TestReadLogsTakesTheWriteLockBeforeStoringTheTrimmedLogs(t *testing.T) {
	saveColorsString(t)
	saveDomainsData(t)
	saveProxyTUIGlobals(t)
	ColorsString = "0;31"
	proxy.TWidth = 500
	proxy.MaxLogLength = 1 // 3 logs, overflow 2: the write branch runs

	domains.DomainsData["example.com"] = domains.DomainData{
		Name: "example.com",
		LastLogs: []domains.DomainLog{
			{Time: "1", IP: "1.1.1.1", BrowserFP: "Chrome", Useragent: "UA", Path: "/a"},
			{Time: "2", IP: "2.2.2.2", BrowserFP: "Chrome", Useragent: "UA", Path: "/b"},
			{Time: "3", IP: "3.3.3.3", BrowserFP: "Chrome", Useragent: "UA", Path: "/c"},
		},
	}
	muteStdout(t)

	// A read lock. The RLock at the top of ReadLogs is allowed to share it; only
	// a genuine writer has to wait.
	firewall.Mutex.RLock()
	unlocked := false
	defer func() {
		if !unlocked {
			firewall.Mutex.RUnlock()
		}
	}()

	done, wait := runReadLogsInBackground(t, "example.com")

	select {
	case <-done:
		t.Fatal("ReadLogs wrote domains.DomainsData while another reader held firewall.Mutex — the map WRITE is guarded by a read lock (or by nothing), which is a concurrent map write against the middleware and a fatal, unrecoverable runtime error in production")
	case <-time.After(blockWindow):
		// Still blocked acquiring the write lock, which is the contract.
	}

	firewall.Mutex.RUnlock()
	unlocked = true
	wait()

	// And it did do the trimming once it got the lock.
	if stored := domains.DomainsData["example.com"].LastLogs; len(stored) != 1 || stored[0].Path != "/c" {
		t.Errorf("stored LastLogs = %+v, want just the newest entry (/c)", stored)
	}
}

// ---------------------------------------------------------------------------
// InitPlaceholders (discord.go — the pure half; the network paths are not
// tested here by design).
// ---------------------------------------------------------------------------

func saveProxyUsageGlobals(t *testing.T) {
	t.Helper()
	prevCPU, prevRAM := proxy.CpuUsage(), proxy.RamUsage()
	t.Cleanup(func() {
		proxy.SetCpuUsage(prevCPU)
		proxy.SetRamUsage(prevRAM)
	})
}

func TestInitPlaceholders(t *testing.T) {
	saveProxyUsageGlobals(t)
	proxy.SetCpuUsage("42%")
	proxy.SetRamUsage("1.5GB")

	start := time.Date(2026, 8, 30, 13, 5, 9, 0, time.UTC)
	end := time.Date(2026, 8, 30, 14, 30, 0, 0, time.UTC)
	data := domains.DomainData{
		RequestLogger: []domains.RequestLog{
			{Time: start},
			{Time: time.Date(2026, 8, 30, 13, 50, 0, 0, time.UTC)},
			{Time: end},
		},
	}

	tests := []struct {
		name string
		msg  string
		want string
	}{
		{name: "domain name", msg: "{{domain.name}} is under attack", want: "example.com is under attack"},
		{name: "attack start uses the first log entry", msg: "started {{attack.start}}", want: "started 13:05:09"},
		{name: "attack end uses the last log entry", msg: "ended {{attack.end}}", want: "ended 14:30:00"},
		{name: "cpu", msg: "cpu {{proxy.cpu}}", want: "cpu 42%"},
		{name: "ram", msg: "ram {{proxy.ram}}", want: "ram 1.5GB"},
		{name: "all placeholders at once", msg: "{{domain.name}} {{attack.start}}-{{attack.end}} {{proxy.cpu}} {{proxy.ram}}", want: "example.com 13:05:09-14:30:00 42% 1.5GB"},
		{name: "repeated placeholders are all replaced", msg: "{{domain.name}}/{{domain.name}}", want: "example.com/example.com"},
		{name: "no placeholders is a passthrough", msg: "plain message", want: "plain message"},
		{name: "empty message", msg: "", want: ""},

		// Unknown placeholders are left verbatim — there is no validation, so a
		// typo in the operator's webhook template ships to Discord as-is.
		{name: "unknown placeholder is left alone", msg: "{{domain.nmae}}", want: "{{domain.nmae}}"},

		// Substitution is a plain string replace with no escaping. The result
		// is later marshalled into a webhook JSON body, so a domain name or a
		// CPU string containing a quote is a template-injection surface.
		{name: "replacement values are not escaped", msg: "{{proxy.cpu}}", want: `42%`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := InitPlaceholders(tt.msg, data, "example.com"); got != tt.want {
				t.Errorf("InitPlaceholders(%q) = %q, want %q", tt.msg, got, tt.want)
			}
		})
	}
}

func TestInitPlaceholdersSingleEntryLoggerUsesTheSameTimeForStartAndEnd(t *testing.T) {
	saveProxyUsageGlobals(t)
	proxy.SetCpuUsage("0%")
	proxy.SetRamUsage("0MB")

	data := domains.DomainData{
		RequestLogger: []domains.RequestLog{{Time: time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)}},
	}
	got := InitPlaceholders("{{attack.start}}..{{attack.end}}", data, "d")
	if want := "09:00:00..09:00:00"; got != want {
		t.Errorf("InitPlaceholders = %q, want %q", got, want)
	}
}

// WAVE 8 flipped: InitPlaceholders now guards the empty RequestLogger and
// renders the "-" placeholder instead of panicking (render assertions live in
// discord_test.go). Wave 3 pinned the old panic contract here; the fix landed,
// so the contract is now "no panic, webhook not silently dropped".
func TestInitPlaceholdersEmptyRequestLoggerNoLongerPanics(t *testing.T) {
	saveProxyUsageGlobals(t)
	proxy.SetCpuUsage("0%")
	proxy.SetRamUsage("0MB")

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("InitPlaceholders with an empty RequestLogger panicked: %v", r)
		}
	}()
	// No {{attack.*}} placeholder in the message, yet the index used to happen.
	_ = InitPlaceholders("{{domain.name}}", domains.DomainData{}, "example.com")
}
