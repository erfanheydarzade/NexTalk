// cmd/offline/ingest.go — bridges the offline shell to the shared
// groupchat.Ingest standard: builds the identity's fanout/mailbox handles on
// demand and classifies pasted input.
package offline

import (
	"encoding/base64"
	"strings"

	"github.com/erfanheydarzade/NexTalk/internal/frame"
	"github.com/erfanheydarzade/NexTalk/internal/groupchat"
	"github.com/erfanheydarzade/NexTalk/internal/registry"
)

// ingestStandard tries to process input as a transfer container or framed
// payload. Returns groupchat.ErrNotFrame when the input predates framing
// (bare base64 SecureMessage) so the caller can fall back.
func ingestStandard(state *registry.State, input string) (*groupchat.IngestEvent, error) {
	raw := []byte(strings.TrimSpace(input))

	// Bare legacy b64 SecureMessage frames start with a length-prefixed
	// sender ID (first byte = 88 for real IDs), never a frame type — but a
	// single stray paste of "AAE=" style data could decode to anything, so
	// only treat it as framed when classification actually succeeds.
	if len(raw) > 0 && raw[0] != '{' && !isPlausibleFrameB64(raw) {
		return nil, groupchat.ErrNotFrame
	}

	fan := state.Fanout
	if fan == nil && state.ActiveClient != nil {
		state.InitFanout()
		fan = state.Fanout
	}

	return groupchat.Ingest(state.ActiveClient, state.MailboxStore, fan, raw)
}

// isPlausibleFrameB64 reports whether the token decodes (as b64) to something
// starting with a registered frame type byte.
func isPlausibleFrameB64(token []byte) bool {
	dec, err := base64.StdEncoding.DecodeString(string(token))
	if err != nil || len(dec) == 0 {
		return false
	}
	return frame.Valid(frame.Type(dec[0]))
}
