package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/azferius/lancarsec/core/config"
	"github.com/azferius/lancarsec/core/pnc"
	"github.com/azferius/lancarsec/core/proxy"
	"github.com/azferius/lancarsec/core/server"
)

// Fingerprint identifies the build. Official releases stamp it at link time
// with `go build -ldflags "-X main.Fingerprint=<value>"`, so a binary still
// reporting the default below was built from source or patched after release.
// The released value is deliberately not recorded here: publishing it in the
// source file it is meant to protect lets anyone with a checkout stamp a
// modified build with the genuine value, which is the whole thing this guards
// against. It is distributed with the release artefacts instead.
var Fingerprint string = "S3LF_BU1LD_0R_M0D1F13D"

func main() {

	proxy.Fingerprint = Fingerprint

	// 0600 (CRYPTO-07): this create wins the mode if the file does not exist
	// yet; InitHndl's 0600 only applies at its own create, which never happens
	// after this line. Stack traces can embed request material.
	logFile, err := os.OpenFile("crash.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()

	pnc.InitHndl()

	defer pnc.PanicHndl()

	//Disable Error Logging
	log.SetOutput(io.Discard /*logFile*/) // if we ever need to log to a file

	fmt.Println("Starting Proxy ...")

	// The TUI's `add` command runs the same wizard config.Load uses when there
	// are no domains configured. It is wired here rather than called directly
	// from core/server so the dependency stays one-way.
	server.AddDomain = config.AddDomain

	// A configuration the proxy cannot serve is reported and exits non-zero.
	// It used to panic on a bad secret, and for a config.json with no domains
	// it did not even do that: it indexed domains.Domains[0] and died with a
	// nil-index stack trace.
	if err := config.Load(); err != nil {
		fmt.Println("[ ! ] [ Failed To Load Configuration: " + err.Error() + " ]")
		logFile.Close()
		os.Exit(1)
	}

	fmt.Println("Loaded Config ...")

	// Wait for everything to be initialised
	fmt.Println("Initialising ...")
	go server.Monitor()
	for !proxy.Initialised.Load() { // CONC-06: atomic poll, no data race
		time.Sleep(500 * time.Millisecond)
	}

	go server.Serve()

	// WAVE 13: shut down on a signal instead of blocking on a bare `select{}`.
	//
	// Nothing handled SIGINT or SIGTERM before, so every restart, redeploy and
	// `docker stop` killed the process mid-request: in-flight responses
	// truncated, keep-alive connections reset, and — because a challenged
	// client's clearance is issued and verified over separate requests — a
	// visitor part-way through the challenge sent back to stage 1. For a
	// mitigation proxy that is a self-inflicted outage during exactly the
	// operation an operator performs while under load.
	//
	// SIGTERM is what an init system and a container runtime send first, and
	// what they follow with SIGKILL after their own grace period; Windows never
	// delivers it, which is harmless — Interrupt covers Ctrl-C there.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	sig := <-stop

	fmt.Println("\n[ * ] [ " + sig.String() + " received - draining, up to " + shutdownGrace.String() + " ]")

	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		// The deadline passed with requests still running. Say so and exit
		// non-zero: the supervisor's own timer is what kills us next, and an
		// operator reading the exit code should know the drain did not finish.
		fmt.Println("[ ! ] [ Shutdown did not finish: " + err.Error() + " ]")
		logFile.Close()
		os.Exit(1)
	}

	fmt.Println("[ * ] [ Stopped cleanly ]")
}

// shutdownGrace is how long in-flight requests get to finish once a signal
// arrives. It sits under the 30s that systemd and Docker default to before
// SIGKILL, so the drain either completes or reports failure while we still
// control the exit.
const shutdownGrace = 20 * time.Second
