// internal/session/session.go
package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
)

type state struct {
	ActiveClientID string `json:"active_client_id"`
}

func statePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".nextalk", "session.json")
}

// Save persists the active client ID after init.
func Save(clientID string) error {
	path := statePath()
	_ = os.MkdirAll(filepath.Dir(path), 0700)
	data, err := json.Marshal(state{ActiveClientID: clientID})
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// Load recovers the active client. Returns a clear error if init was never run.
func Load(engine *core.Engine) (*crypto.Client, error) {
	data, err := os.ReadFile(statePath())
	if err != nil {
		return nil, fmt.Errorf("no active session — run 'init' first")
	}
	var s state
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("corrupt session file: %w", err)
	}
	return engine.LoadClient(s.ActiveClientID)
}
