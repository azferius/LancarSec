//go:build !windows

package screen

// On every platform with a real terminal emulator the escapes are honoured
// unconditionally, so Clear and MoveTopLeft are just the two writes.

func clearScreen()       { writeEraseDisplay() }
func moveCursorTopLeft() { writeCursorHome() }
