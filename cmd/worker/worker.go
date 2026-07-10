package worker

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
	workerrelay "github.com/erfanheydarzade/NexTalk/internal/relay/worker"
)

type ChatMessage struct {
	Body   string
	IsRead bool
}

func RunWorker(api *core.Engine, workerURL string) {
	scanner := bufio.NewScanner(os.Stdin)
	ctx := context.Background()

	w, err := workerrelay.New(workerURL)
	if err != nil {
		fmt.Println("[-] worker init failed:", err)
		return
	}

	var activeClient *client.Client
	mailbox := make(map[string][]ChatMessage)

	fmt.Println("=== NexTalk (Worker Transport) ===")
	fmt.Println("init | load <id> | connect <peer> | listen | send <peer> <msg> | mailbox [peer] | clear | exit")

	for {
		fmt.Print("\n> ")

		if !scanner.Scan() {
			break
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		cmd := strings.ToLower(parts[0])

		switch cmd {

		case "init":
			activeClient = api.Initialize()
			fmt.Println("[+] identity:", activeClient.Id)

			pubHex, err := w.Register(ctx, activeClient.IdentityPrivate)
			if err != nil {
				fmt.Println("[-] register failed:", err)
				continue
			}
			fmt.Println("[+] registered, relay pubkey:", pubHex)

		case "load":
			if len(parts) < 2 {
				fmt.Println("usage: load <id>")
				continue
			}
			cl, err := api.LoadClient(parts[1])
			if err != nil {
				fmt.Println("[-] load failed:", err)
				continue
			}
			activeClient = cl
			fmt.Println("[+] loaded:", cl.Id)

			if _, err := w.Register(ctx, cl.IdentityPrivate); err != nil {
				fmt.Println("[-] re-register failed:", err)
			} else {
				fmt.Println("[+] re-registered with relay.")
			}

		case "connect":
			if activeClient == nil {
				fmt.Println("[-] init or load an identity first")
				continue
			}
			if len(parts) < 2 {
				fmt.Println("usage: connect <peer>")
				continue
			}
			peerID := parts[1]

			offerBytes, err := api.CreateOffer(peerID)
			if err != nil {
				fmt.Println("[-] offer failed:", err)
				continue
			}

			recipientPub, err := ed25519PubFromID(peerID)
			if err != nil {
				fmt.Println("[-] invalid peer ID:", err)
				continue
			}
			if err := sendEnvelope(ctx, w, activeClient.IdentityPrivate, recipientPub, relay.TypeOffer, json.RawMessage(offerBytes)); err != nil {
				fmt.Println("[-] send offer failed:", err)
				continue
			}
			fmt.Println("[+] offer sent to", peerID)

		case "listen":
			if activeClient == nil {
				fmt.Println("[-] init or load an identity first")
				continue
			}

			msgs, err := w.Receive(ctx, activeClient.IdentityPrivate)
			if err != nil {
				fmt.Println("[-] receive failed:", err)
				continue
			}
			if len(msgs) == 0 {
				fmt.Println("[i] inbox empty.")
				continue
			}

			for _, m := range msgs {
				body := tryDecode(m.Body)
				var env relay.Envelope
				if err := json.Unmarshal(body, &env); err != nil {
					continue
				}

				switch env.Type {
				case relay.TypeOffer:
					var offer client.HandshakeOffer
					_ = json.Unmarshal(env.Data, &offer)

					ansBytes, err := api.AcceptOffer(env.Data)
					if err != nil {
						fmt.Println("[-] accept offer failed:", err)
						continue
					}

					senderPub, err := ed25519PubFromID(offer.SenderId)
					if err != nil {
						fmt.Println("[-] invalid sender ID:", err)
						continue
					}
					if err := sendEnvelope(ctx, w, activeClient.IdentityPrivate, senderPub, relay.TypeAnswer, json.RawMessage(ansBytes)); err != nil {
						fmt.Println("[-] send answer failed:", err)
						continue
					}
					fmt.Println("[+] auto-answered offer from", offer.SenderId)

				case relay.TypeAnswer:
					peerID, err := api.FinishHandshake(env.Data)
					if err != nil {
						fmt.Println("[-] finish handshake failed:", err)
					} else {
						fmt.Println("[+] session established:", peerID)
					}

				case relay.TypeMessage:
					senderID, pt, err := api.Decrypt(base64.StdEncoding.EncodeToString(env.Data))
					if err != nil {
						fmt.Println("[-] decrypt failed:", err)
						continue
					}
					mailbox[senderID] = append([]ChatMessage{{Body: pt}}, mailbox[senderID]...)
					fmt.Printf("[+] New message received from %s! Check your mailbox.\n", senderID)
				}
			}

		case "send":
			if activeClient == nil {
				fmt.Println("[-] init or load an identity first")
				continue
			}
			if len(parts) < 3 {
				fmt.Println("usage: send <peer> <msg>")
				continue
			}
			peer := parts[1]
			msg := strings.Join(parts[2:], " ")

			cipherBytes, err := api.Encrypt(peer, msg)
			if err != nil {
				fmt.Println("[-] encrypt failed:", err)
				continue
			}

			recipientPub, err := ed25519PubFromID(peer)
			if err != nil {
				fmt.Println("[-] invalid peer ID:", err)
				continue
			}
			if err := sendEnvelope(ctx, w, activeClient.IdentityPrivate, recipientPub, relay.TypeMessage, cipherBytes); err != nil {
				fmt.Println("[-] send failed:", err)
				continue
			}

			mailbox[peer] = append([]ChatMessage{{Body: "Me: " + msg, IsRead: true}}, mailbox[peer]...)
			fmt.Println("[+] sent to", peer)

		case "mailbox":
			if len(parts) == 1 {
				if len(mailbox) == 0 {
					fmt.Println("[i] mailbox empty.")
					continue
				}
				for peer, msgs := range mailbox {
					unread := 0
					for _, m := range msgs {
						if !m.IsRead {
							unread++
						}
					}
					fmt.Printf("  %s  (%d unread)\n", peer, unread)
				}
				continue
			}

			target := parts[1]
			fullPeer := target
			for peer := range mailbox {
				if strings.HasPrefix(peer, target) {
					fullPeer = peer
					break
				}
			}

			msgs, ok := mailbox[fullPeer]
			if !ok {
				fmt.Println("[-] no messages from", target)
				continue
			}
			fmt.Printf("=== messages with %s ===\n", fullPeer)
			for i, m := range msgs {
				mark := " "
				if !m.IsRead {
					mark = "*"
					mailbox[fullPeer][i].IsRead = true
				}
				fmt.Printf("[%s] %s\n", mark, m.Body)
			}

		case "help":
			fmt.Println("=== NexTalk (Worker Transport) ===")
			fmt.Println("Commands:")
			fmt.Println("  init                  Create a new identity")
			fmt.Println("  load <id>             Load an existing identity")
			fmt.Println("  connect <peer>        Start a secure session")
			fmt.Println("  listen                Receive offers and messages")
			fmt.Println("  send <peer> <msg>     Send an encrypted message")
			fmt.Println("  mailbox [peer]        Show mailbox or conversation")
			fmt.Println("  exit                  Quit")
		case "clear":
			fmt.Print("\033[H\033[2J")
			fmt.Println("=== NexTalk (Worker Transport) ===")
			fmt.Println("init | load <id> | connect <peer> | listen | send <peer> <msg> | mailbox [peer] | clear | exit")

		case "exit":
			fmt.Println("[+] bye.")
			return

		default:
			fmt.Println("[-] unknown command")
		}

	}
}
