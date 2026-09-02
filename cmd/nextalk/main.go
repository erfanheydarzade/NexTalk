package main

import (
	"fmt"
	"os"

	"github.com/erfanheydarzade/NexTalk/cmd"
	"github.com/erfanheydarzade/NexTalk/internal"
)

func main() {
	// Every command reports its own failures (human vs json formats) and
	// returns the error so we can set a non-zero exit code for scripts.
	// Errors that reach us UNreported (e.g. cobra's "required flag(s)
	// missing") are printed here — otherwise they would fail silently.
	if err := cmd.Execute(); err != nil {
		if !internal.IsReported(err) {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}
}
