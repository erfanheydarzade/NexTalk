package main

import (
	"github.com/erfanheydarzade/NexTalk/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		panic(err)
	}
}
