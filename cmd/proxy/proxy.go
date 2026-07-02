package proxy

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"

	// Assuming you placed your new storage code here:
	"github.com/erfanheydarzade/NexTalk/transport"
)

type PayloadEnvelope struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

func RunWorker(api *core.Engine, cfg config.Config) {
	activeClient := &Client.Client{}
	scanner := bufio.NewScanner(os.Stdin)

	// Initialize your new Proxy Storage instead of the old transport
	store := storage.NewProxyChatStorage(storage.ProxyConfig{
		ProxyUrl: cfg.WorkerURL,
	})

	fmt.Println("NexTalk Worker Mode (S3 Proxy Active)")

	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			return
		}

		parts := strings.Fields(scanner.Text())
		if len(parts) == 0 {
			continue
		}

		cmd := parts[0]

		switch cmd {

		case "init":
			activeClient = api.Initialize()
			fmt.Println("ID:", activeClient.Id)
			// Because S3/Proxy doesn't require "creating" an identity session
			// like the old worker, we just use the generated ID as our inbox name.
			fmt.Println("Identity initialized and ready for S3 proxy.")

		case "load":
			if len(parts) < 2 {
				fmt.Println("usage: load <id>")
				continue
			}

			cl, err := api.LoadClient(parts[1])
			if err != nil {
				fmt.Println("load failed:", err)
				continue
			}

			activeClient = cl
			fmt.Println("loaded:", cl.Id)

		case "connect":
			if activeClient.Id == "" {
				fmt.Println("init first")
				continue
			}
			if len(parts) < 2 {
				fmt.Println("usage: connect <peer>")
				continue
			}

			peerID := parts[1]

			offerBytes, err := api.CreateOffer(peerID)
			if err != nil {
				fmt.Println("offer failed:", err)
				continue
			}

			env := PayloadEnvelope{
				Type: "offer",
				Data: json.RawMessage(offerBytes),
			}

			send(store, peerID, env)

		case "listen":
			if activeClient.Id == "" {
				fmt.Println("init first")
				continue
			}

			// Read from your own ID's "inbox" folder
			payloads, err := store.ReadPayloads(activeClient.Id, "inbox")
			if err != nil {
				fmt.Println("receive failed:", err)
				continue
			}

			if len(payloads) == 0 {
				fmt.Println("no new messages")
				continue
			}

			for _, pBytes := range payloads {
				var env PayloadEnvelope
				if err := json.Unmarshal(pBytes, &env); err != nil {
					continue
				}

				switch env.Type {
				case "offer":
					handleOffer(api, store, env.Data)

				case "answer":
					peerID, err := api.FinishHandshake(env.Data)
					if err == nil {
						fmt.Println("session established with:", peerID)
					} else {
						fmt.Println("handshake failed:", err)
					}

				case "message":
					// Decrypt still expects Base64 for now as per your original design
					msgB64 := base64.StdEncoding.EncodeToString(env.Data)
					senderID, pt, err := api.Decrypt(msgB64)
					if err == nil {
						fmt.Printf("[msg] From %s: %s\n", senderID, pt)
					} else {
						fmt.Println("[-] failed to decrypt message:", err)
					}
				}
			}

		case "encrypt":
			if len(parts) < 3 {
				fmt.Println("usage: encrypt <peer> <msg>")
				continue
			}

			peer := parts[1]
			msg := strings.Join(parts[2:], " ")

			cipherBytes, err := api.Encrypt(peer, msg)
			if err != nil {
				fmt.Println("encrypt failed:", err)
				continue
			}

			env := PayloadEnvelope{
				Type: "message",
				Data: json.RawMessage(cipherBytes),
			}

			send(store, peer, env)

		case "exit":
			return
		default:
			fmt.Println("unknown command")
		}
	}
}

// Updated send function to use ProxyChatStorage
func send(store *storage.ProxyChatStorage, peerID string, env PayloadEnvelope) {
	// Write payload to the peer's "inbox" folder
	err := store.WritePayload(peerID, "inbox", env)
	if err != nil {
		fmt.Println("send failed:", err)
		return
	}
	fmt.Println("payload sent to", peerID)
}

// Updated handleOffer to use ProxyChatStorage
func handleOffer(api *core.Engine, store *storage.ProxyChatStorage, data json.RawMessage) {
	var offer Client.HandshakeOffer
	_ = json.Unmarshal(data, &offer)

	answerBytes, err := api.AcceptOffer(data)
	if err != nil {
		fmt.Println("accept offer failed:", err)
		return
	}

	env := PayloadEnvelope{
		Type: "answer",
		Data: json.RawMessage(answerBytes),
	}

	send(store, offer.SenderId, env)
}
