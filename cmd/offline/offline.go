package offline

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
)

type PayloadEnvelope struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
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

func RunOffline(api *core.Engine) {
	scanner := bufio.NewScanner(os.Stdin)
	_ = context.Background()

	var activeClient *crypto.Client

	fmt.Println("=== NexTalk (Offline Transport) ===")
	fmt.Println("init | load | offer | accept | finish | encrypt | decrypt | exit")

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
			fmt.Println("[+] Init:", activeClient.Id)

		case "load":
			if len(parts) < 2 {
				fmt.Println("usage: load <client_id>")
				continue
			}
			cl, err := api.LoadClient(parts[1])
			if err != nil {
				fmt.Println("[-] load failed:", err)
				continue
			}
			activeClient = cl
			fmt.Println("[+] loaded:", cl.Id)

		case "offer":
			// FIXED: CreateOffer returns (bytes, error)
			offerBytes, err := api.CreateOffer("")
			if err != nil {
				fmt.Println("[-] offer failed:", err)
				continue
			}

			env, _ := wrapEnvelope("offer", offerBytes)
			out := base64.StdEncoding.EncodeToString(env)
			fmt.Println("[+] OFFER:\n", out)

		case "accept":
			fmt.Print("offer: ")
			scanner.Scan()

			envBytes, _ := base64.StdEncoding.DecodeString(scanner.Text())
			env, err := unwrapEnvelope(envBytes)
			if err != nil {
				fmt.Println("[-] invalid offer envelope")
				continue
			}

			// FIXED: AcceptOffer takes []byte (env.Data is already []byte)
			answerBytes, err := api.AcceptOffer(env.Data)
			if err != nil {
				fmt.Println("[-] accept failed:", err)
				continue
			}

			answerEnv, _ := wrapEnvelope("answer", answerBytes)
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

			// FIXED: FinishHandshake takes []byte
			peerID, err := api.FinishHandshake(env.Data)
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
			msg := strings.Join(parts[2:], " ")

			// 1. Get the Base64 string from the engine
			cipherBytes, err := api.Encrypt(peer, msg)
			if err != nil {
				fmt.Println("[-] encrypt failed:", err)
				continue
			}

			if err != nil {
				fmt.Println("[-] base64 decode failed:", err)
				continue
			}

			// 3. Wrap the raw bytes
			env, _ := wrapEnvelope("message", cipherBytes)
			fmt.Println("[+] PACKAGE:\n", base64.StdEncoding.EncodeToString(env))

		case "decrypt":
			fmt.Print("package: ")
			scanner.Scan()

			envBytes := []byte(scanner.Text())
			env, err := unwrapEnvelope(envBytes)
			if err != nil {
				fmt.Println("[-] invalid package")
				continue
			}

			senderID, plain, err := api.Decrypt(base64.StdEncoding.EncodeToString(env.Data))
			if err != nil {
				fmt.Println("[-] decrypt failed:", err)
				continue
			}

			fmt.Printf("[+] sender: %s\n", senderID)
			fmt.Printf("[+] message: %s\n", plain)

		case "exit":
			fmt.Println("[+] bye.")
			return

		default:
			fmt.Println("[-] unknown command")
		}
	}
}
