package main

import (
	"context"
	"fmt"
	"io"
	"lancarsec/core/config"
	"lancarsec/core/dashboard"
	"lancarsec/core/pnc"
	"lancarsec/core/proxy"
	"lancarsec/core/server"
	"log"
	"os"
	"os/signal"
	"syscall"
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
	config.Load()
	fmt.Println("Loaded Config ...")

	// Dashboard credentials bootstrap runs after config load so dashboard.json
	// ends up in the same working directory as config.json. First run prints
	// a freshly generated password to the console; subsequent runs silently
	// reuse the stored hash.
	if err := dashboard.Bootstrap(); err != nil {
		log.Fatalf("dashboard bootstrap failed: %v", err)
	}

	fmt.Println("Initialising ...")
	go server.Monitor()
	for !proxy.IsInitialised() {
		time.Sleep(500 * time.Millisecond)
	}

	go server.Serve()

	// First SIGINT/SIGTERM: graceful drain with a 15 s deadline.
	// Second signal while draining: hard exit. Operators re-sending a signal
	// usually want the process gone now, not to keep waiting on a stuck
	// connection.
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nShutting down, draining in-flight requests (send signal again to force quit) ...")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		server.Shutdown(ctx)
		close(done)
	}()
	select {
	case <-done:
		fmt.Println("Bye.")
	case <-sigCh:
		fmt.Println("Forced exit.")
		os.Exit(1)
	}
}
