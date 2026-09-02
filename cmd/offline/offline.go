package offline

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/erfanheydarzade/NexTalk/internal/groupchat"
	"github.com/erfanheydarzade/NexTalk/internal/registry"
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
			pasted := strings.TrimSpace(scanner.Text())
			if activeClient == nil {
				fmt.Println("[-] Please 'init' or 'load' an identity first.")
				continue
			}
			st := replState(activeClient)
			if ev, err := groupchat.Ingest(activeClient, st.MailboxStore, st.Fanout, []byte(pasted)); err == nil {
				switch ev.Kind {
				case "duplicate":
					fmt.Println("[+] already ingested — ignoring duplicate")
				case "group_message":
					fmt.Printf("[+] group [%s] from %s\n[+] message: %s\n", ev.Context, ev.Sender, ev.Message)
				default:
					fmt.Printf("[+] sender: %s\n[+] message: %s\n", ev.Sender, ev.Message)
				}
				continue
			}
			envBytes, err := base64.StdEncoding.DecodeString(pasted)
			if err != nil {
				fmt.Println("[-] invalid base64 package:", err)
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
			fmt.Println("  decrypt                 Decrypt a container / message package")
			fmt.Println("  context create|list|show|rename|add|remove|include|mute|block|members")
			fmt.Println("  send-multi <ctx> <msg>  Fan out a group message (exports containers)")
			fmt.Println("  contexts                List contexts")
			fmt.Println("  mailbox [peer|group]    Read stored conversations")
			fmt.Println("  clear                   Clear the screen")
			fmt.Println("  exit                    Quit")
		case "context", "send-multi", "multisend", "contexts", "mailbox":
			if activeClient == nil {
				fmt.Println("[-] Please 'init' or 'load' an identity first.")
				continue
			}
			st := replState(activeClient)
			args := parts[1:]
			target := cmd
			if cmd == "multisend" {
				target = "send-multi" // deprecated alias
			}
			if !groupchat.Execute(st, target, args) {
				fmt.Println("[-] unknown command:", cmd)
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

// replState builds a registry.State view over the REPL's active client so
// the shared groupchat layer can be driven with the same semantics as the
// GUI transport. Stores are reopened per command — matching CLI behavior.
func replState(cl *client.Client) *registry.State {
	st := registry.NewState(nil, config.Config{})
	st.ActiveClient = cl
	st.InitMailbox()
	st.InitFanout()
	return st
}

// parsePastedPayload extracts raw handshake wire bytes from pasted input.
// Accepted forms:
//
//  1. A wrapped envelope ("{"type":"offer","data":"base64..."}") — the
//     paste-safe container the shell itself prints.
//  2. A bare legacy JSON offer/answer — what older builds printed.
//  3. Raw nanopack bytes (e.g. piped from a file).
func parsePastedPayload(pasted string) ([]byte, error) {
	trimmed := []byte(strings.TrimSpace(pasted))
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("nothing pasted")
	}
	if trimmed[0] == '{' {
		if env, err := unwrapEnvelope(trimmed); err == nil && env.Data != nil {
			return env.Data, nil
		}
		// Not our envelope — legacy bare JSON; the engine's dual-format
		// decode handles it.
	}
	return trimmed, nil
}
