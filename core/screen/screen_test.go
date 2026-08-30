package screen

import (
	"bytes"
	"runtime"
	"testing"
)

// capture redirects the package's ANSI sink into a buffer for the duration of
// one test and restores it afterwards.
func capture(t *testing.T) *bytes.Buffer {
	t.Helper()

	var buf bytes.Buffer
	prev := out
	out = &buf
	t.Cleanup(func() { out = prev })

	return &buf
}

// TestANSIWriters pins the exact bytes of the two escape sequences. These are
// the sequences the non-Windows build of Clear and MoveTopLeft emits, and they
// must stay byte-identical to what github.com/inancgumus/screen wrote, because
// the surrounding TUI in core/server/monitor.go assumes CSI 2 J leaves the
// cursor alone and CSI H homes it.
func TestANSIWriters(t *testing.T) {
	tests := []struct {
		name string
		emit func()
		want []byte
	}{
		{
			name: "erase display",
			emit: writeEraseDisplay,
			want: []byte{0x1b, '[', '2', 'J'},
		},
		{
			name: "cursor home",
			emit: writeCursorHome,
			want: []byte{0x1b, '[', 'H'},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := capture(t)
			tt.emit()

			if got := buf.Bytes(); !bytes.Equal(got, tt.want) {
				t.Errorf("emitted %q (% x), want %q (% x)", got, got, tt.want, tt.want)
			}
		})
	}
}

// TestConstantsAreCSI pins the constants themselves against an independently
// spelled expectation. The octal escape in the constant and the hex escape
// here have to agree, which catches the classic typo of doubling the
// backslash -- that still compiles, but emits six printable characters
// instead of one control sequence.
func TestConstantsAreCSI(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"eraseDisplay", eraseDisplay, "\x1b[2J"},
		{"cursorHome", cursorHome, "\x1b[H"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("= %q, want %q", tt.got, tt.want)
			}
		})
	}
}

// TestExported checks that the exported entry points route to the right
// implementation for the platform being built.
//
// On everything but Windows they must produce the same bytes as the writers
// above. On Windows there are no bytes to assert -- Clear and MoveTopLeft go
// through kernel32's FillConsoleOutput*/SetConsoleCursorPosition and write
// nothing to stdout -- so the assertion there is that the sink stays empty and
// that both calls survive stdout not being a console, which is how they are
// reached under `go test` and under systemd in production.
func TestExported(t *testing.T) {
	tests := []struct {
		name     string
		call     func()
		wantANSI string
	}{
		{"Clear", Clear, "\x1b[2J"},
		{"MoveTopLeft", MoveTopLeft, "\x1b[H"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := capture(t)
			tt.call()

			want := tt.wantANSI
			if runtime.GOOS == "windows" {
				want = ""
			}

			if got := buf.String(); got != want {
				t.Errorf("%s wrote %q, want %q on %s", tt.name, got, want, runtime.GOOS)
			}
		})
	}
}
