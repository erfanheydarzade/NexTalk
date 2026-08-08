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
			fmt.Println("  clear                   Clear the screen")
			fmt.Println("  exit                    Quit")

		case "clear":
			fmt.Print("\033[H\033[2J")
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
