package offline

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/spf13/cobra"
)

func (c *Command) DecryptCommand() *cobra.Command {
	var localPeer string
	var cipherText string

	cmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Encrypt a message",
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunDecrypt(
				c.engine,
				localPeer,
				cipherText,
			)
		},
	}

	cmd.Flags().StringVarP(
		&localPeer,
		"id",
		"i",
		"",
		"Local peer ID",
	)
	cmd.Flags().StringVarP(
		&cipherText,
		"cipherText",
		"c",
		"",
		"Cybertext to decrypt",
	)

	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("cipherText")

	return cmd
}

func RunDecrypt(
	engine *core.Engine,
	localPeer string,
	cipherText string,
) error {

	if _, err := engine.LoadClient(localPeer); err != nil {
		return err
	}

	var env Envelope

	if err := json.Unmarshal([]byte(cipherText), &env); err != nil {
		return fmt.Errorf("invalid message json: %w", err)
	}

	cipherBytes, err := json.Marshal(env.Data)
	if err != nil {
		return err
	}

	cipherB64 := base64.StdEncoding.EncodeToString(cipherBytes)

	senderID, plain, err := engine.Decrypt(cipherB64)
	if err != nil {
		return err
	}

	response := map[string]any{
		"type": "message",
		"data": map[string]any{
			"sender":  senderID,
			"message": plain,
		},
	}

	output, err := json.Marshal(response)
	if err != nil {
		return err
	}

	fmt.Println(string(output))
	return nil
}
