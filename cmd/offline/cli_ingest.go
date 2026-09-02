// cmd/offline/cli_ingest.go — CLI-side bridge to the shared groupchat.Ingest
// standard (the GUI shell has its own state-backed variant in ingest.go).
package offline

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/internal/frame"
	"github.com/erfanheydarzade/NexTalk/internal/groupchat"
	"github.com/erfanheydarzade/NexTalk/internal/mailbox"
	"github.com/erfanheydarzade/NexTalk/internal/multimsg"
)

func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// ingestStandardBytes processes container/framed input against the identity's
// persistent stores. Returns groupchat.ErrNotFrame for input that predates
// framing so callers can fall back to legacy decoding.
func ingestStandardBytes(localPeer string, raw []byte) (*groupchat.IngestEvent, error) {
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) == 0 {
		return nil, groupchat.ErrNotFrame
	}

	// Bare legacy b64 SecureMessage frames start with a length-prefixed
	// sender ID, never a registered frame byte — only treat input as framed
	// when it is a JSON container or decodes to a known type.
	isJSON := strings.HasPrefix(trimmed, "{")
	if !isJSON {
		dec, err := base64Decode(trimmed)
		if err != nil || len(dec) == 0 || !frame.Valid(frame.Type(dec[0])) {
			return nil, groupchat.ErrNotFrame
		}
	}

	cl, err := Client.LoadClient(localPeer)
	if err != nil {
		return nil, fmt.Errorf("load session: %w", err)
	}
	ctxStore, deliveryStore, err := multimsg.OpenIdentityStores(localPeer)
	if err != nil {
		return nil, fmt.Errorf("open stores: %w", err)
	}
	mb, err := mailbox.Load(localPeer)
	if err != nil {
		return nil, fmt.Errorf("open mailbox: %w", err)
	}

	fan := multimsg.NewFanout(cl, nil, ctxStore, deliveryStore, multimsg.DefaultFanoutConfig())
	ev, err := groupchat.Ingest(cl, mb, fan, []byte(trimmed))
	if err != nil && errors.Is(err, groupchat.ErrNotFrame) {
		return nil, groupchat.ErrNotFrame
	}
	return ev, err
}
