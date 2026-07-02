package offline

import (
	"encoding/json"
	"fmt"

	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/spf13/cobra"
)

func (c *Command) OfferCommand() *cobra.Command {
	var localPeer string
	var remotePeer string

	cmd := &cobra.Command{
		Use:   "offer",
		Short: "Generate a handshake offer",
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunOffer(
				c.engine,
				localPeer,
				remotePeer,
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

	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("remotePeer")

	return cmd
}

type Envelope struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

func RunOffer(
	engine *core.Engine,
	localPeer string,
	remotePeer string,
) error {

	if _, err := engine.LoadClient(localPeer); err != nil {
		return err
	}

	offerBytes, err := engine.CreateOffer(remotePeer)
	if err != nil {
		return err
	}

	var offerMap map[string]any

	if err := json.Unmarshal(offerBytes, &offerMap); err != nil {
		return err
	}

	response := map[string]any{
		"type": "offer",
		"data": offerMap,
	}

	output, err := json.Marshal(response)
	if err != nil {
		return err
	}

	fmt.Println(string(output))
	return nil
}
