package offline

import (
	"encoding/json"
	"fmt"

	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/spf13/cobra"
)

func (c *Command) EncryptCommand() *cobra.Command {
	var localPeer string
	var remotePeer string
	var message string

	cmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt a message",
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunEncrypt(
				c.engine,
				localPeer,
				remotePeer,
				message,
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
		&remotePeer,
		"remotePeer",
		"r",
		"",
		"Remote peer ID",
	)
	cmd.Flags().StringVarP(
		&message,
		"message",
		"m",
		"",
		"Message to encrypt",
	)

	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("remotePeer")
	_ = cmd.MarkFlagRequired("message")

	return cmd
}

func RunEncrypt(
	engine *core.Engine,
	localPeer string,
	remotePeer string,
	message string,
) error {

	if _, err := engine.LoadClient(localPeer); err != nil {
		return err
	}

	cipherBytes, err := engine.Encrypt(remotePeer, message)
	if err != nil {
		return err
	}

	var cipherMap map[string]any

	if err := json.Unmarshal(cipherBytes, &cipherMap); err != nil {
		return err
	}

	response := map[string]any{
		"type": "message",
		"data": cipherMap,
	}

	output, err := json.Marshal(response)
	if err != nil {
		return err
	}

	fmt.Println(string(output))
	return nil
}
