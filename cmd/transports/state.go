// cmd/transports/all.go
//
// Package transports is a pure side-effect import shim. Importing it (with a
// blank identifier) from main or root.go triggers every transport's init()
// function, which self-registers into the global registry.
//
// To add a new transport:
//  1. Create your transport package under cmd/<name>/
//  2. Add a register.go file that calls registry.Register(...) from init()
//  3. Add a blank import line here — nothing else needs to change.
package transports

import (
	_ "github.com/erfanheydarzade/NexTalk/cmd/offline"
	_ "github.com/erfanheydarzade/NexTalk/cmd/proxy"
	_ "github.com/erfanheydarzade/NexTalk/cmd/worker"
)
