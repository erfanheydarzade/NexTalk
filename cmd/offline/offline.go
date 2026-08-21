package offline

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/multimsg"
	"github.com/erfanheydarzade/NexTalk/internal/ui"
)

// PayloadEnvelope wraps raw payload bytes for REPL transport. It is
// marshalled as JSON, so Data is base64-encoded by encoding/json's []byte
// handling.
type PayloadEnvelope struct {
	Type string `json:"type"`
	Data []byte `json:"data"`
}

func wrapEnvelope(t string, data []byte) ([]byte, error) {
	env := PayloadEnvelope{
		Type: t,
		Data: data,
	}
	return json.Marshal(env)
}

func unwrapEnvelope(data []byte) (PayloadEnvelope, error) {
	var env PayloadEnvelope
	err := json.Unmarshal(data, &env)
	return env, err
}

func envelopeData(env PayloadEnvelope) []byte {
	return env.Data
}

func RunOffline(api *core.Engine) {
	scanner := bufio.NewScanner(os.Stdin)
	_ = context.Background()

	var activeClient *client.Client

	fmt.Println("=== NexTalk (Offline Transport) ===")
	fmt.Println("init | load | offer | accept | finish | encrypt | decrypt | help | clear | exit")

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
			activeClient = client.NewClient()
			fmt.Println("[+] Init:", activeClient.Id)

		case "load":
			if len(parts) < 2 {
				fmt.Println("usage: load <client_id>")
				continue
			}
			cl, err := client.LoadClient(parts[1])
			if err != nil {
				fmt.Println("[-] load failed:", err)
				continue
			}
			activeClient = cl
			fmt.Println("[+] loaded:", cl.Id)

		case "offer":

			if len(parts) < 2 {
				fmt.Println("usage: offer <client_id>")
				continue
			}
			if activeClient == nil {
				fmt.Println("[-] Please 'init' or 'load' an identity first.")
				continue
			}
			offerBytes, err := activeClient.CreateOffer(parts[1])

			if err != nil {
				fmt.Println("[-] offer failed:", err)
				continue
			}

			env, err := wrapEnvelope("offer", offerBytes)
			if err != nil {
				fmt.Println("[-] encode failed:", err)
				continue
			}
			out := base64.StdEncoding.EncodeToString(env)
			fmt.Println("[+] OFFER:\n", out)

		case "accept":
			scanner.Scan()

			envBytes, _ := base64.StdEncoding.DecodeString(scanner.Text())
			env, err := unwrapEnvelope(envBytes)
			if err != nil {
				fmt.Println("[-] invalid offer envelope")
				continue
			}

			if activeClient == nil {
				fmt.Println("[-] Please 'init' or 'load' an identity first.")
				continue
			}

			data := envelopeData(env)

			answerBytes, err := activeClient.AcceptOffer(data)
			if err != nil {
				fmt.Println("[-] accept failed:", err)
				continue
			}

			answerEnv, err := wrapEnvelope("answer", answerBytes)
			if err != nil {
				fmt.Println("[-] encode failed:", err)
				continue
			}
			fmt.Println("[+] ANSWER:\n", base64.StdEncoding.EncodeToString(answerEnv))

		case "finish":
			fmt.Print("answer: ")
			scanner.Scan()

			envBytes, _ := base64.StdEncoding.DecodeString(scanner.Text())
			env, err := unwrapEnvelope(envBytes)
			if err != nil {
				fmt.Println("[-] invalid answer envelope")
				continue
			}

			if activeClient == nil {
				fmt.Println("[-] Please 'init' or 'load' an identity first.")
				continue
			}

			data := envelopeData(env)

			peerID, err := activeClient.FinishHandshake(data)
			if err != nil {
				fmt.Println("[-] finish failed:", err)
				continue
			}

			fmt.Println("[+] session established:", peerID)

		case "encrypt":
			if len(parts) < 3 {
				fmt.Println("usage: encrypt <peer> <msg>")
				continue
			}

			peer := parts[1]
			message := strings.Join(parts[2:], " ")

			var plaintext []byte
			var err error
			if message != "" {
				plaintext = []byte(message)
			} else {
				plaintext, err = io.ReadAll(os.Stdin)
				if err != nil {
					fmt.Println("failed to read stdin: %w", err)
				}

				if len(plaintext) == 0 {
					fmt.Println("no codec provided")
				}
			}

			if activeClient == nil {
				fmt.Println("[-] Please 'init' or 'load' an identity first.")
				continue
			}

			cipherBytes, err := activeClient.Encrypt(peer, plaintext)

			if err != nil {
				fmt.Println("[-] encrypt failed:", err)
				continue
			}

			fmt.Println("[+] PACKAGE:\n", base64.StdEncoding.EncodeToString(cipherBytes))

		case "decrypt":
			fmt.Print("package: ")
			scanner.Scan()
			envBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(scanner.Text()))
			if err != nil {
				fmt.Println("[-] invalid base64 package:", err)
				continue
			}

			if activeClient == nil {
				fmt.Println("[-] Please 'init' or 'load' an identity first.")
				continue
			}

			senderID, plain, err := activeClient.Decrypt(envBytes)
			if err != nil {
				fmt.Println("[-] decrypt failed:", err)
				continue
			}

			fmt.Printf("[+] sender: %s\n", senderID)
			fmt.Printf("[+] message: %s\n", string(plain))

		case "help":
			fmt.Println("=== NexTalk (Offline Transport) ===")
			fmt.Println("Commands:")
			fmt.Println("  init                    Create a new identity")
			fmt.Println("  load <id>               Load an existing identity")
			fmt.Println("  offer                   Generate a handshake offer")
			fmt.Println("  accept                  Accept a handshake offer")
			fmt.Println("  finish                  Complete a handshake")
			fmt.Println("  encrypt <peer> <msg>    Encrypt a message")
			fmt.Println("  decrypt                 Decrypt a message package")
			fmt.Println("  context create <name>   Create a new message context")
			fmt.Println("  context list            List all contexts")
			fmt.Println("  context rename <id> <name>  Rename a context")
			fmt.Println("  context add <ctx> <peer>    Add recipient to context")
			fmt.Println("  context remove <ctx> <peer> Remove recipient from context")
			fmt.Println("  context mute <ctx> <peer>   Mute recipient in context")
			fmt.Println("  context block <ctx> <peer>  Block recipient in context")
			fmt.Println("  context policy <ctx> <peer> <policy> Set recipient policy")
			fmt.Println("  multisend <ctx> <peers...> <msg> Send multi-user message")
			fmt.Println("  clear                   Clear the screen")
			fmt.Println("  exit                    Quit")

		case "context":
			if len(parts) < 2 {
				fmt.Println("usage: context <create|list|rename|add|remove|mute|block|policy> ...")
				continue
			}
			subCmd := parts[1]
			switch subCmd {
			case "create":
				if len(parts) < 3 {
					fmt.Println("usage: context create <display_name>")
					continue
				}
				displayName := strings.Join(parts[2:], " ")
				if activeClient == nil {
					fmt.Println("[-] Please 'init' or 'load' an identity first.")
					continue
				}
				ctxStore := multimsg.NewMemoryContextStore()
				fanout := multimsg.NewFanout(activeClient, nil, ctxStore, multimsg.NewMemoryDeliveryStore(), multimsg.DefaultFanoutConfig())
				ctx, err := fanout.CreateContext(displayName, activeClient.IdentityPrivate)
				if err != nil {
					fmt.Println("[-] context create failed:", err)
					continue
				}
				fmt.Printf("[+] Context created: %s (ID: %s)\n", ctx.DisplayName, ctx.ContextID)

			case "list":
				if activeClient == nil {
					fmt.Println("[-] Please 'init' or 'load' an identity first.")
					continue
				}
				ctxStore := multimsg.NewMemoryContextStore()
				fanout := multimsg.NewFanout(activeClient, nil, ctxStore, multimsg.NewMemoryDeliveryStore(), multimsg.DefaultFanoutConfig())
				ctxs, err := fanout.CtxStore.ListContexts()
				if err != nil {
					fmt.Println("[-] context list failed:", err)
					continue
				}
				if len(ctxs) == 0 {
					fmt.Println("[+] No contexts")
					continue
				}
				fmt.Println("[+] Contexts:")
				for _, c := range ctxs {
					fmt.Printf("  %s  v%d  %s\n", c.ContextID, c.MetadataVersion, c.DisplayName)
				}

			case "rename":
				if len(parts) < 4 {
					fmt.Println("usage: context rename <context_id> <new_name>")
					continue
				}
				if activeClient == nil {
					fmt.Println("[-] Please 'init' or 'load' an identity first.")
					continue
				}
				ctxStore := multimsg.NewMemoryContextStore()
				fanout := multimsg.NewFanout(activeClient, nil, ctxStore, multimsg.NewMemoryDeliveryStore(), multimsg.DefaultFanoutConfig())
				ctxID := multimsg.ContextID(parts[2])
				newName := strings.Join(parts[3:], " ")
				ctx, err := fanout.UpdateContext(ctxID, newName, activeClient.IdentityPrivate)
				if err != nil {
					fmt.Println("[-] context rename failed:", err)
					continue
				}
				fmt.Printf("[+] Context renamed: %s (v%d)\n", ctx.DisplayName, ctx.MetadataVersion)

			case "add":
				if len(parts) < 4 {
					fmt.Println("usage: context add <context_id> <peer_id>")
					continue
				}
				if activeClient == nil {
					fmt.Println("[-] Please 'init' or 'load' an identity first.")
					continue
				}
				ctxStore := multimsg.NewMemoryContextStore()
				fanout := multimsg.NewFanout(activeClient, nil, ctxStore, multimsg.NewMemoryDeliveryStore(), multimsg.DefaultFanoutConfig())
				ctxID := multimsg.ContextID(parts[2])
				peerID := parts[3]
				if err := fanout.SetRecipientPolicy(ctxID, peerID, multimsg.PolicyEnabled); err != nil {
					fmt.Println("[-] context add failed:", err)
					continue
				}
				fmt.Printf("[+] Added %s to context %s\n", peerID, ctxID)

			case "remove":
				if len(parts) < 4 {
					fmt.Println("usage: context remove <context_id> <peer_id>")
					continue
				}
				if activeClient == nil {
					fmt.Println("[-] Please 'init' or 'load' an identity first.")
					continue
				}
				ctxStore := multimsg.NewMemoryContextStore()
				fanout := multimsg.NewFanout(activeClient, nil, ctxStore, multimsg.NewMemoryDeliveryStore(), multimsg.DefaultFanoutConfig())
				ctxID := multimsg.ContextID(parts[2])
				peerID := parts[3]
				if err := fanout.SetRecipientPolicy(ctxID, peerID, multimsg.PolicyExcluded); err != nil {
					fmt.Println("[-] context remove failed:", err)
					continue
				}
				fmt.Printf("[+] Removed %s from context %s (excluded)\n", peerID, ctxID)

			case "mute":
				if len(parts) < 4 {
					fmt.Println("usage: context mute <context_id> <peer_id>")
					continue
				}
				if activeClient == nil {
					fmt.Println("[-] Please 'init' or 'load' an identity first.")
					continue
				}
				ctxStore := multimsg.NewMemoryContextStore()
				fanout := multimsg.NewFanout(activeClient, nil, ctxStore, multimsg.NewMemoryDeliveryStore(), multimsg.DefaultFanoutConfig())
				ctxID := multimsg.ContextID(parts[2])
				peerID := parts[3]
				if err := fanout.SetRecipientPolicy(ctxID, peerID, multimsg.PolicyMuted); err != nil {
					fmt.Println("[-] context mute failed:", err)
					continue
				}
				fmt.Printf("[+] Muted %s in context %s\n", peerID, ctxID)

			case "block":
				if len(parts) < 4 {
					fmt.Println("usage: context block <context_id> <peer_id>")
					continue
				}
				if activeClient == nil {
					fmt.Println("[-] Please 'init' or 'load' an identity first.")
					continue
				}
				ctxStore := multimsg.NewMemoryContextStore()
				fanout := multimsg.NewFanout(activeClient, nil, ctxStore, multimsg.NewMemoryDeliveryStore(), multimsg.DefaultFanoutConfig())
				ctxID := multimsg.ContextID(parts[2])
				peerID := parts[3]
				if err := fanout.SetRecipientPolicy(ctxID, peerID, multimsg.PolicyBlocked); err != nil {
					fmt.Println("[-] context block failed:", err)
					continue
				}
				fmt.Printf("[+] Blocked %s in context %s\n", peerID, ctxID)

			case "policy":
				if len(parts) < 5 {
					fmt.Println("usage: context policy <context_id> <peer_id> <enabled|muted|blocked|excluded>")
					continue
				}
				if activeClient == nil {
					fmt.Println("[-] Please 'init' or 'load' an identity first.")
					continue
				}
				ctxStore := multimsg.NewMemoryContextStore()
				fanout := multimsg.NewFanout(activeClient, nil, ctxStore, multimsg.NewMemoryDeliveryStore(), multimsg.DefaultFanoutConfig())
				ctxID := multimsg.ContextID(parts[2])
				peerID := parts[3]
				policyStr := parts[4]
				var policy multimsg.RecipientPolicy
				switch policyStr {
				case "enabled":
					policy = multimsg.PolicyEnabled
				case "muted":
					policy = multimsg.PolicyMuted
				case "blocked":
					policy = multimsg.PolicyBlocked
				case "excluded":
					policy = multimsg.PolicyExcluded
				default:
					fmt.Println("[-] invalid policy:", policyStr)
					continue
				}
				if err := fanout.SetRecipientPolicy(ctxID, peerID, policy); err != nil {
					fmt.Println("[-] context policy failed:", err)
					continue
				}
				fmt.Printf("[+] Set policy for %s in context %s: %s\n", peerID, ctxID, policyStr)

			default:
				fmt.Println("[-] unknown context subcommand:", subCmd)
			}

		case "multisend":
			if len(parts) < 4 {
				fmt.Println("usage: multisend <context_id> <peer1,peer2,...> <message>")
				continue
			}
			if activeClient == nil {
				fmt.Println("[-] Please 'init' or 'load' an identity first.")
				continue
			}
			ctxStore := multimsg.NewMemoryContextStore()
			fanout := multimsg.NewFanout(activeClient, nil, ctxStore, multimsg.NewMemoryDeliveryStore(), multimsg.DefaultFanoutConfig())
			ctxID := multimsg.ContextID(parts[1])
			peerList := strings.Split(parts[2], ",")
			message := strings.Join(parts[3:], " ")
			msg, err := fanout.SendMultiMessage(context.Background(), ctxID, []byte(message), peerList)
			if err != nil {
				fmt.Println("[-] multisend failed:", err)
				continue
			}
			fmt.Printf("[+] Multi-message sent: %s (%d deliveries)\n", msg.MessageID, len(msg.Deliveries))
			for _, d := range msg.Deliveries {
				status := "encrypted"
				if d.Ciphertext == nil {
					status = "pending (no session)"
				}
				fmt.Printf("  -> %s: %s\n", d.Recipient, status)
			}

		case "clear":
			ui.ClearScreen()
			fmt.Println("=== NexTalk (Offline Transport) ===")
			fmt.Println("init | load | offer | accept | finish | encrypt | decrypt | help | clear | exit")

		case "exit":
			fmt.Println("[+] bye.")
			return

		default:
			fmt.Println("[-] unknown command")
		}
	}
}