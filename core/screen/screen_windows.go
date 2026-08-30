//go:build windows

package screen

import (
	"os"
	"syscall"
	"unsafe"
)

// Windows consoles do not interpret ANSI escapes unless the process turns on
// ENABLE_VIRTUAL_TERMINAL_PROCESSING (0x0004) with SetConsoleMode, and that
// bit is off in the mode a console hands a freshly started child. Measured on
// Windows 11 Pro 10.0.26100 with Go 1.25: the inherited mode is 0x0003
// (ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT), writing "\033[2J"
// advances the cursor four columns -- the escape is printed as literal text --
// and only after SetConsoleMode raises the mode to 0x0007 is it consumed.
//
// So the Windows path drives the console API directly, exactly as upstream
// did, and does not depend on virtual-terminal processing being enabled.
//
// (The rest of the LancarSec TUI does print raw ANSI, so on a VT-off Windows
// console it renders as garbage regardless of what this package does. Turning
// VT on at startup would fix that, but it is a behavioural change and belongs
// in a later wave, not in this dependency swap.)

// Clear blanks the whole console screen buffer, writing spaces in the current
// attribute over every cell, and leaves the cursor position untouched.
func clearScreen() {
	var (
		written dword
		h       = getScreen()
		origin  = coord{}
	)

	total := dword(h.info.size.x) * dword(h.info.size.y)

	_, _, _ = xFillConsoleOutputCharacterW.Call(
		uintptr(h.handle),
		uintptr(' '),
		uintptr(total),
		origin.pack(),
		uintptr(unsafe.Pointer(&written)),
	)

	_, _, _ = xFillConsoleOutputAttribute.Call(
		uintptr(h.handle),
		uintptr(h.info.attributes),
		uintptr(total),
		origin.pack(),
		uintptr(unsafe.Pointer(&written)),
	)
}

// moveCursorTopLeft puts the cursor at cell (0, 0) of the screen buffer.
func moveCursorTopLeft() {
	h := getScreen()

	_, _, _ = xSetConsoleCursorPosition.Call(
		uintptr(h.handle),
		coord{}.pack(),
	)
}

// getScreen reads the current screen-buffer state for stdout. Errors are
// ignored, as upstream ignored them: when stdout is not a console -- a pipe
// under systemd, say -- info stays zeroed, total comes out 0, and both Fill
// calls become no-ops.
func getScreen() screenHandle {
	h := screenHandle{handle: syscall.Handle(os.Stdout.Fd())}

	_, _, _ = xGetConsoleScreenBufferInfo.Call(
		uintptr(h.handle),
		uintptr(unsafe.Pointer(&h.info)),
	)

	return h
}

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	xGetConsoleScreenBufferInfo  = kernel32.NewProc("GetConsoleScreenBufferInfo")
	xSetConsoleCursorPosition    = kernel32.NewProc("SetConsoleCursorPosition")
	xFillConsoleOutputCharacterW = kernel32.NewProc("FillConsoleOutputCharacterW")
	xFillConsoleOutputAttribute  = kernel32.NewProc("FillConsoleOutputAttribute")
)

type (
	short int16
	dword uint32
	word  uint16
)

// coord mirrors the Win32 COORD struct.
type coord struct {
	x short
	y short
}

// pack returns the COORD as the single register-sized argument the Win32
// calling convention passes it in: y in the high 16 bits, x in the low 16.
//
// Upstream instead punned the address, *(*uintptr)(unsafe.Pointer(&c)), which
// reads eight bytes out of a four-byte struct on a 64-bit build. The callee
// only ever looks at the low 32 bits, so the extra four bytes were harmless in
// practice, but they were still a read past the value. Packing the halves
// explicitly passes the same low 32 bits with no out-of-bounds read and no
// unsafe conversion.
func (c coord) pack() uintptr {
	return uintptr(uint32(uint16(c.x)) | uint32(uint16(c.y))<<16)
}

type smallRect struct {
	left   short
	top    short
	right  short
	bottom short
}

// consoleScreenBufferInfo mirrors the Win32 CONSOLE_SCREEN_BUFFER_INFO struct.
type consoleScreenBufferInfo struct {
	size              coord
	cursorPosition    coord
	attributes        word
	window            smallRect
	maximumWindowSize coord
}

type screenHandle struct {
	handle syscall.Handle
	info   consoleScreenBufferInfo
}
