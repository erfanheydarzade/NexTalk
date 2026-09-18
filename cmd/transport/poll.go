// Poll/send/attach commands: thin frontends over internal/transportops.
// See transportops/frames.go for the shared implementations.
package transport

import (
	"github.com/erfanheydarzade/NexTalk/internal/transportops"
	"github.com/spf13/cobra"
)

func pollCommand() *cobra.Command {
	var localPeer, format, mailbox string
	var limit int
	c := &cobra.Command{
		Use:   "poll <id>",
		Short: "Poll an external transport and dispatch incoming frames",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d := openDeps(cmd)
			if format == "json" {
				d.JSON = true
			}
			return transportops.Poll(d, transportops.PollParams{
				TransportID: args[0], Identity: localPeer,
				Mailbox: mailbox, Limit: limit, Format: format,
			})
		},
	}
	c.Flags().StringVarP(&localPeer, "id", "i", "", "Local peer ID (required)")
	c.Flags().StringVar(&format, "format", "human", "Output format: human, json")
	c.Flags().StringVar(&mailbox, "mailbox", "", "Only poll this mailbox id (hex)")
	c.Flags().IntVar(&limit, "limit", 32, "Max frames per mailbox")
	_ = c.MarkFlagRequired("id")
	withDir(c)
	withJSON(c)
	return c
}

func sendFrameCommand() *cobra.Command {
	var peer, file, mailboxHex, shard string
	c := &cobra.Command{
		Use:   "send-frame <id>",
		Short: "Deliver one already-encrypted frame file to a peer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return transportops.SendFrame(openDeps(cmd), transportops.SendFrameParams{
				TransportID: args[0], Peer: peer,
				MailboxID: mailboxHex, ShardURL: shard, File: file,
			})
		},
	}
	c.Flags().StringVar(&peer, "to", "", "Recipient peer ID or 64-hex Ed25519 pubkey")
	c.Flags().StringVar(&mailboxHex, "mailbox", "", "Explicit recipient mailbox, 32 hex (for address-shared transports)")
	c.Flags().StringVar(&shard, "shard", "", "Shard URL for --mailbox")
	c.Flags().StringVarP(&file, "file", "f", "", "Frame file (required)")
	_ = c.MarkFlagRequired("file")
	withDir(c)
	withJSON(c)
	return c
}

func attachCommand() *cobra.Command {
	var mailbox, secret, shard, router string
	c := &cobra.Command{
		Use:   "attach <id>",
		Short: "Subscribe a mailbox for polling (stores a bearer, never a key)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return transportops.Attach(openDeps(cmd), transportops.AttachParams{
				TransportID: args[0], MailboxID: mailbox, ReadSecret: secret,
				ShardURL: shard, RouterURL: router,
			})
		},
	}
	c.Flags().StringVar(&mailbox, "mailbox", "", "Mailbox ID, 32 lowercase hex (required)")
	c.Flags().StringVar(&secret, "secret", "", "Read secret, 64 hex (required; omit in shell for hidden prompt)")
	c.Flags().StringVar(&shard, "shard", "", "Shard URL (required)")
	c.Flags().StringVar(&router, "router", "", "Router URL")
	_ = c.MarkFlagRequired("mailbox")
	_ = c.MarkFlagRequired("shard")
	withDir(c)
	withJSON(c)
	return c
}

func detachCommand() *cobra.Command {
	var mailbox string
	c := &cobra.Command{
		Use:   "detach <id>",
		Short: "Unsubscribe a mailbox",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return transportops.Detach(openDeps(cmd), args[0], mailbox)
		},
	}
	c.Flags().StringVar(&mailbox, "mailbox", "", "Mailbox ID (required)")
	_ = c.MarkFlagRequired("mailbox")
	withDir(c)
	withJSON(c)
	return c
}
