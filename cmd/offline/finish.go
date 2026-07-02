package offline

import (
	"encoding/json"
	"fmt"

	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/spf13/cobra"
)

func (c *Command) FinishCommand() *cobra.Command {
	var localPeer string
	var answerEnvelope string

	cmd := &cobra.Command{
		Use:   "finish",
		Short: "Finish handshake with an answer",
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunFinish(
				c.engine,
				localPeer,
				answerEnvelope,
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
		&answerEnvelope,
		"answerEnvelope",
		"a",
		"",
		"Base64 encoded offer envelope",
	)

	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("answerEnvelope")

	return cmd
}

func RunFinish(
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

	peerID, err := engine.FinishHandshake(dataBytes)
	if err != nil {
		return err
	}

	response := map[string]any{
		"type": "finish",
		"data": map[string]any{
			"peer_id": peerID,
		},
	}

	output, err := json.Marshal(response)
	if err != nil {
		return err
	}

	fmt.Println(string(output))
	return nil
}
