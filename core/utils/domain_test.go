package utils

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/azferius/lancarsec/core/domains"
)

// ---------------------------------------------------------------------------
// AddDomain — the first-launch wizard.
//
// Everything AddDomain does is a side effect: it asks ~16 questions on the
// terminal, appends one domains.Domain to the domains.Config global, and writes
// config.json into the working directory at mode 0600. None of that is
// reachable through the file-backed stdin harness in terminal_test.go, because
// ReadTerminal builds a fresh bufio.Scanner per call and the first Scan against
// a regular file swallows the whole buffer — so every question after the first
// sees EOF and takes its default, and all the wizard's string answers come back
// identical ("").
//
// scriptedTerminal fixes that by driving the wizard the way an operator does:
// os.Stdin and os.Stdout become pipes, and a responder goroutine waits for each
// prompt to be printed before writing exactly one line of answer. Because the
// answer is written only after the prompt appears — and AddDomain prints prompt
// N+1 only after reading answer N — each ReadTerminal's single Read sees exactly
// one line. That makes per-question answers possible, which is what it takes to
// tell two same-typed struct fields apart.
// ---------------------------------------------------------------------------

// promptSuffix is what every AskString/AskInt/AskBool prompt ends with:
//
//	fmt.Print("[" + PrimaryColor("+") + "] [ " + PrimaryColor(question) + " ]: ")
const promptSuffix = " ]: "

// scriptedTerminal replaces os.Stdin/os.Stdout with pipes and answers each
// prompt with respond(prompt). Everything is restored via t.Cleanup.
func scriptedTerminal(t *testing.T, respond func(prompt string) string) {
	t.Helper()

	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating the stdin pipe: %v", err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating the stdout pipe: %v", err)
	}

	prevIn, prevOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inR, outW

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		var pending strings.Builder
		for {
			n, err := outR.Read(buf)
			if n > 0 {
				pending.Write(buf[:n])
				// A prompt is complete once the accumulated output ends with
				// " ]: ". Anything printed before it (banners, the rejection
				// notice) is carried along and handed to respond as context.
				if strings.HasSuffix(pending.String(), promptSuffix) {
					answer := respond(pending.String())
					pending.Reset()
					if _, werr := inW.Write([]byte(answer + "\n")); werr != nil {
						return
					}
				}
			}
			if err != nil {
				return
			}
		}
	}()

	t.Cleanup(func() {
		os.Stdin, os.Stdout = prevIn, prevOut
		outW.Close()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("the scripted-terminal responder did not shut down")
		}
		inW.Close()
		inR.Close()
		outR.Close()
	})
}

// inTempWorkingDir chdirs into a fresh temp directory for the duration of the
// test, so AddDomain's relative os.WriteFile("config.json", ...) lands somewhere
// disposable instead of over the repo's own config. Registered before t.TempDir's
// own cleanup can run, because a directory cannot be removed while it is the
// process working directory on Windows.
func inTempWorkingDir(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("reading the working directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(prev); err != nil {
			t.Errorf("restoring the working directory: %v", err)
		}
	})
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("entering the temp working directory: %v", err)
	}

	// t.TempDir can hand back a symlinked path (/var -> /private/var on macOS);
	// resolve it so comparisons against os.Getwd line up.
	resolved, err := os.Getwd()
	if err != nil {
		t.Fatalf("reading the temp working directory: %v", err)
	}
	return resolved
}

// saveDomainsConfig restores the domains.Config global, which AddDomain appends
// to. It is a nil *Configuration by default, and AddDomain dereferences it
// without a check, so it also has to be populated before the call.
func saveDomainsConfig(t *testing.T) {
	t.Helper()
	prev := domains.Config
	t.Cleanup(func() { domains.Config = prev })
	domains.Config = &domains.Configuration{}
}

// wizardAnswers is the script the responder plays back. The two SSL answers are
// deliberately distinguishable from each other and from everything else; the
// rest are just valid enough to keep the wizard moving.
//
// Note every answer is lowercase: ReadTerminal lowercases unconditionally, so an
// expectation containing an uppercase letter could never match.
func wizardAnswers(prompt string) string {
	switch {
	case strings.Contains(prompt, "SSL Certificate"):
		return "/etc/ssl/cert-answer.pem"
	case strings.Contains(prompt, "SSL Key"):
		return "/etc/ssl/key-answer.pem"
	// Every AskInt question — and only those — contains "How Many". An
	// unparseable answer here would make AskInt re-ask forever against a pipe
	// that only answers prompts, so these must be numbers.
	case strings.Contains(prompt, "How Many"):
		return "123"
	case strings.Contains(prompt, "Name Of Your Domain"):
		return "example.com"
	case strings.Contains(prompt, "Backed/Server"):
		return "10.0.0.1"
	case strings.Contains(prompt, "Scheme"):
		return "https"
	default:
		return "x"
	}
}

// runWizard drives one AddDomain to completion and returns the domain it
// appended plus the directory config.json was written into.
func runWizard(t *testing.T) (domains.Domain, string) {
	t.Helper()

	saveColorsString(t)
	ColorsString = "0;31"
	saveDomainsConfig(t)
	dir := inTempWorkingDir(t)
	scriptedTerminal(t, wizardAnswers)

	AddDomain()

	if len(domains.Config.Domains) != 1 {
		t.Fatalf("AddDomain appended %d domains, want 1", len(domains.Config.Domains))
	}
	return domains.Config.Domains[0], dir
}

// The wizard asks for the certificate path and then the key path. They are two
// adjacent string fields of the same type in one struct literal, filled from two
// positional calls whose only difference is the question text — the textbook
// setup for a same-type argument swap, and the natural outcome of reordering or
// reformatting the literal. Nothing else in the tree would notice: both fields
// are strings, both are optional (empty behind Cloudflare), and the mistake
// surfaces only at TLS handshake time on a production origin, as an opaque
// "failed to find any PEM data in certificate input".
//
// Every other AddDomain assertion is blind to it, so this pins the mapping
// explicitly: the answer to the CERTIFICATE question lands in Certificate, and
// the answer to the KEY question lands in Key.
func TestAddDomainAssignsTheCertificateAndKeyAnswersToTheirOwnFields(t *testing.T) {
	got, dir := runWizard(t)

	const (
		wantCert = "/etc/ssl/cert-answer.pem"
		wantKey  = "/etc/ssl/key-answer.pem"
	)

	if got.Certificate != wantCert {
		t.Errorf("Certificate = %q, want %q (the answer to the SSL Certificate question)", got.Certificate, wantCert)
	}
	if got.Key != wantKey {
		t.Errorf("Key = %q, want %q (the answer to the SSL Key question)", got.Key, wantKey)
	}
	if got.Certificate == wantKey && got.Key == wantCert {
		t.Error("Certificate and Key hold each other's answers — the two AskString results are swapped in the struct literal")
	}

	// The same mapping has to survive the round trip through config.json, since
	// that file is what the proxy actually loads on the next start.
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("reading the generated config.json: %v", err)
	}
	var cfg domains.Configuration
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("parsing the generated config.json: %v\n%s", err, raw)
	}
	if len(cfg.Domains) != 1 {
		t.Fatalf("config.json has %d domains, want 1", len(cfg.Domains))
	}
	if cfg.Domains[0].Certificate != wantCert || cfg.Domains[0].Key != wantKey {
		t.Errorf("config.json wrote certificate=%q key=%q, want certificate=%q key=%q", cfg.Domains[0].Certificate, cfg.Domains[0].Key, wantCert, wantKey)
	}
}

// The rest of the wizard's answers reach their own fields too. Kept separate so
// a failure here reads as "the whole literal is misaligned" rather than as a
// certificate/key swap.
func TestAddDomainAssignsEveryAnswerToItsOwnField(t *testing.T) {
	got, _ := runWizard(t)

	if got.Name != "example.com" {
		t.Errorf("Name = %q, want %q", got.Name, "example.com")
	}
	if got.Backend != "10.0.0.1" {
		t.Errorf("Backend = %q, want %q", got.Backend, "10.0.0.1")
	}
	if got.Scheme != "https" {
		t.Errorf("Scheme = %q, want %q", got.Scheme, "https")
	}
	if got.Webhook.URL != "x" {
		t.Errorf("Webhook.URL = %q, want %q", got.Webhook.URL, "x")
	}
	for _, f := range []struct {
		name string
		val  int
	}{
		{"BypassStage1", got.BypassStage1},
		{"BypassStage2", got.BypassStage2},
		{"DisableBypassStage3", got.DisableBypassStage3},
		{"DisableRawStage3", got.DisableRawStage3},
		{"DisableBypassStage2", got.DisableBypassStage2},
		{"DisableRawStage2", got.DisableRawStage2},
	} {
		if f.val != 123 {
			t.Errorf("%s = %d, want 123 — the AskInt answer did not reach this field", f.name, f.val)
		}
	}
	if got.FirewallRules == nil || len(got.FirewallRules) != 0 {
		t.Errorf("FirewallRules = %v, want an empty non-nil slice", got.FirewallRules)
	}
}

// config.json is written 0600 and that bit is load-bearing: the file holds
// AdminSecret, APISecret and all three challenge secrets, and it shipped
// world-readable at 0644 until wave 2 tightened it. A revert to 0644 is one
// character, survives review as "the mode the file always had", and is exactly
// what a merge conflict or a copy-paste from the pre-wave-2 file produces. Since
// nothing else asserts on the mode, the fix would silently come undone.
//
// Skipped on Windows, where Go maps the whole permission word onto the single
// read-only attribute: 0600 and 0644 produce byte-identical results there and no
// assertion can separate them. Verified to fail on the mutation under
// linux/amd64.
func TestAddDomainWritesConfigJsonOwnerReadableOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not carry POSIX permission bits; os.Stat cannot distinguish 0600 from 0644")
	}

	_, dir := runWizard(t)

	info, err := os.Stat(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("stat-ing the generated config.json: %v", err)
	}

	// The umask can only clear bits, never set them, so an exact comparison is
	// safe for 0600 and would still catch 0644 (which keeps 0600 and adds more).
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("config.json mode = %04o, want 0600 — the file holds AdminSecret, APISecret and the three challenge secrets", perm)
	}
	if perm := info.Mode().Perm(); perm&(fs.FileMode(0o077)) != 0 {
		t.Errorf("config.json mode = %04o, want no group or other bits set at all", perm)
	}
}
