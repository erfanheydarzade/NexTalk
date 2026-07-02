package offline

import (
	"encoding/json"
	"fmt"

	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/spf13/cobra"
)

func (c *Command) AcceptCommand() *cobra.Command {
	var localPeer string
	var offerEnvelope string

	cmd := &cobra.Command{
		Use:   "accept",
		Short: "Accept a handshake offer and generate an answer",
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAccept(
				c.engine,
				localPeer,
				offerEnvelope,
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
		&offerEnvelope,
		"offerEnvelope",
		"o",
		"",
		"Base64 encoded offer envelope",
	)

	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("offerEnvelope")

	return cmd
}

func RunAccept(
	engine *core.Engine,
	localPeer string,
	input string,
) error {

	if _, err := engine.LoadClient(localPeer); err != nil {
		return err
	}

	var env Envelope

	if err := json.Unmarshal([]byte(input), &env); err != nil {
		return err
	}

	dataBytes, err := json.Marshal(env.Data)
	if err != nil {
		return err
	}

	answerBytes, err := engine.AcceptOffer(dataBytes)
	if err != nil {
		return err
	}

	var answerMap map[string]any

	if err := json.Unmarshal(answerBytes, &answerMap); err != nil {
		return err
	}

	response := map[string]any{
		"type": "answer",
		"data": answerMap,
	}

	output, err := json.Marshal(response)
	if err != nil {
		return err
	}

	fmt.Println(string(output))
	return nil
}
