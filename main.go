package main

import (
	"fmt"
	"github.com/azferius/lancarsec/core/config"
	"github.com/azferius/lancarsec/core/pnc"
	"github.com/azferius/lancarsec/core/proxy"
	"github.com/azferius/lancarsec/core/server"
	"io"
	"log"
	"os"
	"time"
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
	// from core/server because core/config imports core/server, so the reverse
	// import would be a cycle.
	server.AddDomain = config.AddDomain

	config.Load()

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
