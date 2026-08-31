package pnc

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"
	"time"
)

// logFile is crash.log. It is nil until InitHndl runs, and every write goes
// through writeCrashLog, which tolerates that: a nil *os.File would return
// ErrInvalid rather than panicking, but the guard makes the intent explicit and
// keeps the supervisor usable in tests and in tools that never call InitHndl.
//
// logMu guards the pointer itself. Before wave 4 InitHndl published it with a
// bare assignment while background goroutines read it, which is a data race the
// moment anything re-initialises the handler.
var (
	logMu   sync.Mutex
	logFile *os.File
)

func InitHndl() {
	f, err := os.OpenFile("crash.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		// log.Fatal calls os.Exit, so nothing after this line can run. Upstream
		// followed it with panic(err), which was dead code that read as a
		// second, stronger failure path and was not one.
		log.Fatal(err)
	}

	logMu.Lock()
	defer logMu.Unlock()
	logFile = f
}

// writeCrashLog appends one entry to crash.log. It never fails loudly: the
// callers are panic paths and a supervisor, and neither has anywhere better to
// report a logging error to.
func writeCrashLog(msg string) {
	logMu.Lock()
	defer logMu.Unlock()
	if logFile == nil {
		return
	}
	logFile.WriteString(msg)
}

// PanicHndl records a panic in crash.log and then re-raises it, so the process
// still dies. That is the right behaviour for main and for a request handler:
// the crash is recorded and the supervisor above (systemd) restarts a known-good
// process. It is the WRONG behaviour for a long-lived background goroutine,
// which is what Supervise is for.
func PanicHndl() {
	if r := recover(); r != nil {
		stackTrace := make([]byte, 4096000)
		runtime.Stack(stackTrace, false)

		errMsg := fmt.Sprintf("[ "+time.Now().Format("15:04:05")+" ]: Caught Panic: %v\n\n%s\n", r, bytes.TrimRight(stackTrace, "\x00"))
		writeCrashLog(errMsg)
		panic(r)
	}
}

func LogError(msg string) {
	errMsg := fmt.Sprintf("[ "+time.Now().Format("15:04:05")+" ]: Error: %s\n", msg)
	writeCrashLog(errMsg)
}
