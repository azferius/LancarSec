package utils

import (
	"strings"
	"testing"
	"time"

	"github.com/azferius/lancarsec/core/domains"
)

// WAVE 8: InitPlaceholders indexed RequestLogger[0] / [len-1] unguarded and
// panicked on an empty log. Pinned by this test: an empty log must render the
// "-" placeholder instead of crashing the webhook goroutine.
func TestInitPlaceholdersEmptyRequestLogger(t *testing.T) {
	out := InitPlaceholders(
		"start {{attack.start}} end {{attack.end}} name {{domain.name}} cpu {{proxy.cpu}}",
		domains.DomainData{},
		"example.com",
	)

	if out != "start - end - name example.com cpu 0" {
		t.Fatalf("unexpected render with empty log: %q", out)
	}
	if strings.Contains(out, "{{attack.") {
		t.Fatalf("unresolved attack placeholder left in output: %q", out)
	}
}

// Non-empty logs still render the real first/last timestamps (existing
// behaviour, guarded since wave 8).
func TestInitPlaceholdersWithRequests(t *testing.T) {
	domainData := domains.DomainData{
		RequestLogger: []domains.RequestLog{
			{Time: time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)},
			{Time: time.Date(2026, 8, 31, 10, 0, 5, 0, time.UTC)},
		},
	}

	out := InitPlaceholders("{{attack.start}}-{{attack.end}}", domainData, "example.com")
	if out != "10:00:00-10:00:05" {
		t.Fatalf("unexpected render with non-empty log: %q", out)
	}
}
