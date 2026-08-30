// Package screen clears the terminal and homes the cursor for the LancarSec
// TUI.
//
// It replaces github.com/inancgumus/screen
// (v0.0.0-20190314163918-06e984b86ed3, the tip of that repository as of
// 2019-03-14 and the last commit it ever received). That module was three
// source files totalling 129 lines, of which LancarSec used exactly two
// six-line functions, Clear and MoveTopLeft. Its third exported function,
// Size, was never called here -- core/server/monitor.go reads the terminal
// dimensions from golang.org/x/term instead -- yet Size alone dragged
// golang.org/x/crypto/ssh/terminal, and therefore the whole of
// golang.org/x/crypto, into the build graph. Absorbing the two functions we
// actually use removes an unmaintained dependency and that transitive edge.
//
// The behaviour below is a faithful port of the upstream implementation: ANSI
// escapes everywhere except Windows, and the kernel32 console API on Windows.
// See screen_other.go and screen_windows.go.
//
// Upstream: https://github.com/inancgumus/screen
//
// Upstream licence (MIT) -- reproduced as required by its terms, which oblige
// any distribution of the software or a substantial portion of it to carry the
// copyright notice and the permission notice:
//
//	MIT License
//
//	Copyright (c) 2019 Inanc Gumus
//
//	Permission is hereby granted, free of charge, to any person obtaining a copy
//	of this software and associated documentation files (the "Software"), to deal
//	in the Software without restriction, including without limitation the rights
//	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//	copies of the Software, and to permit persons to whom the Software is
//	furnished to do so, subject to the following conditions:
//
//	The above copyright notice and this permission notice shall be included in all
//	copies or substantial portions of the Software.
//
//	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//	SOFTWARE.
//
// MIT and GPL v2 are compatible in this direction: MIT-licensed code may be
// incorporated into a GPL v2 work, and this notice satisfies the MIT
// attribution requirement while LancarSec as a whole remains GPL v2.
package screen

import (
	"io"
	"os"
)

// The two escape sequences the ANSI implementation emits. ESC is 0x1B; the
// octal \033 spelling is kept so these read the same as the upstream source.
const (
	// eraseDisplay is CSI 2 J, "erase the entire display". It does not move
	// the cursor.
	eraseDisplay = "\033[2J"

	// cursorHome is CSI H with no parameters, "move the cursor to row 1,
	// column 1 of the display".
	cursorHome = "\033[H"
)

// out is where the ANSI implementation writes. Upstream used fmt.Print, which
// is os.Stdout; writing the constant through io.WriteString puts the identical
// bytes on the identical file descriptor. It is a variable only so the tests
// can capture what was emitted -- nothing in LancarSec reassigns it.
var out io.Writer = os.Stdout

func writeEraseDisplay() { _, _ = io.WriteString(out, eraseDisplay) }
func writeCursorHome()   { _, _ = io.WriteString(out, cursorHome) }

// Clear clears the screen.
//
// Everywhere except Windows this writes CSI 2 J and leaves the cursor where it
// was, so callers pair it with MoveTopLeft. On Windows it blanks the console
// screen buffer through kernel32 and likewise leaves the cursor alone.
func Clear() { clearScreen() }

// MoveTopLeft moves the cursor to the top left position of the screen.
func MoveTopLeft() { moveCursorTopLeft() }
