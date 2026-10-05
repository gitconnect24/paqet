package main

import (
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
)

// Setting PAQET_PPROF (e.g. "127.0.0.1:6060") exposes Go's pprof endpoints for profiling.
func init() {
	addr := os.Getenv("PAQET_PPROF")
	if addr == "" {
		return
	}
	go func() {
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Printf("pprof: %v", err)
		}
	}()
}
