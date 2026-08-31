package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/azferius/lancarsec/core/domains"
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

// ---------------------------------------------------------------------------
// InitPlaceholders (discord.go — the pure half; the network paths are not
// tested here by design).
// ---------------------------------------------------------------------------

func saveProxyUsageGlobals(t *testing.T) {
	t.Helper()
	prevCPU, prevRAM := proxy.CpuUsage, proxy.RamUsage
	t.Cleanup(func() {
		proxy.CpuUsage = prevCPU
		proxy.RamUsage = prevRAM
	})
}

func TestInitPlaceholders(t *testing.T) {
	saveProxyUsageGlobals(t)
	proxy.CpuUsage = "42%"
	proxy.RamUsage = "1.5GB"

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
	proxy.CpuUsage, proxy.RamUsage = "0%", "0MB"

	data := domains.DomainData{
		RequestLogger: []domains.RequestLog{{Time: time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)}},
	}
	got := InitPlaceholders("{{attack.start}}..{{attack.end}}", data, "d")
	if want := "09:00:00..09:00:00"; got != want {
		t.Errorf("InitPlaceholders = %q, want %q", got, want)
	}
}

// BUG (a later wave flips this): InitPlaceholders indexes RequestLogger[0] and
// RequestLogger[len-1] unconditionally, with no length check, even when the
// message contains no {{attack.*}} placeholder at all. An empty RequestLogger
// therefore panics. Its only caller is SendWebhook, which has a
// `defer pnc.PanicHndl()`, so today the panic is caught and the webhook is
// silently dropped rather than crashing the proxy — but the notification is
// lost and a crash.log entry is written. Pinned as the current contract.
func TestInitPlaceholdersPanicsOnAnEmptyRequestLogger(t *testing.T) {
	saveProxyUsageGlobals(t)
	proxy.CpuUsage, proxy.RamUsage = "0%", "0MB"

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("InitPlaceholders with an empty RequestLogger did not panic; today it indexes RequestLogger[0] unguarded")
		}
	}()
	// No {{attack.*}} placeholder in the message, yet the index still happens.
	_ = InitPlaceholders("{{domain.name}}", domains.DomainData{}, "example.com")
}
