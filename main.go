package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/azferius/lancarsec/core/config"
	"github.com/azferius/lancarsec/core/pnc"
	"github.com/azferius/lancarsec/core/proxy"
	"github.com/azferius/lancarsec/core/server"
)

var Fingerprint string = "S3LF_BU1LD_0R_M0D1F13D" // 455b9300-0a6f-48f1-82ee-bb1f6cf43500

func main() {

	proxy.Fingerprint = Fingerprint

	logFile, err := os.OpenFile("crash.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
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
	for !proxy.Initialised {
		time.Sleep(500 * time.Millisecond)
	}

	go server.Serve()

	//Keep server running
	select {}
}
