// Register/resolve/file commands: thin frontends over internal/transportops.
// See transportops/xfer.go for the shared implementations.
package transport

import (
	"github.com/erfanheydarzade/NexTalk/internal/transportops"
	"github.com/spf13/cobra"
)

// identityRegisterCommand is the command P2P messaging setup actually needs:
// it registers the identity's own pubkey with the Router, so peers resolving
// that pubkey reach a mailbox that exists. `register` (below) is the
// file-transfer scoped-credential path and does NOT do this.
func identityRegisterCommand() *cobra.Command {
	var identity, router string
	c := &cobra.Command{
		Use:     "register-identity <id>",
		Aliases: []string{"identity-register"},
		Short:   "Register the active identity's pubkey with the Router and attach its mailbox",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := transportops.IdentityRegister(openDeps(cmd), args[0], identity, router)
			return err
		},
	}
	c.Flags().StringVarP(&identity, "id", "i", "", "Local peer ID (required; or `use identity` in the shell)")
	c.Flags().StringVar(&router, "router", "", "Router URL (optional when `transport config` is set)")
	_ = c.MarkFlagRequired("id")
	withDir(c)
	withJSON(c)
	return c
}

func registerCommand() *cobra.Command {
	var identity, router string
	c := &cobra.Command{
		Use:     "xfer-register <id>",
		Aliases: []string{"register"},
		Short:   "Mint a file-transfer mailbox (scoped credential; NOT identity registration)",
		Long: "Mints a mailbox under the transport's scoped file-transfer credential.\n\n" +
			"This does NOT register your identity for messaging: the mailbox lives at\n" +
			"HMAC(scoped_pubkey), while peers address you at HMAC(identity_pubkey).\n" +
			"For `peer connect` / messaging, use `transport register-identity`.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return transportops.FilerelayRegister(openDeps(cmd), args[0], identity, router)
		},
	}
	c.Flags().StringVarP(&identity, "id", "i", "", "Local peer ID (required; or `use identity` in the shell)")
	c.Flags().StringVar(&router, "router", "", "Router URL (optional when `transport config` is set)")
	_ = c.MarkFlagRequired("id")

	withDir(c)
	withJSON(c)
	return c
}

func resolveCommand() *cobra.Command {
	var peer, router string
	c := &cobra.Command{
		Use:   "resolve <id>",
		Short: "Resolve a recipient to mailbox + shard",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return transportops.FilerelayResolve(openDeps(cmd), args[0], peer, router)
		},
	}
	c.Flags().StringVar(&peer, "to", "", "Recipient peer ID or 64-hex pubkey (required)")
	c.Flags().StringVar(&router, "router", "", "Router URL (required)")
	_ = c.MarkFlagRequired("to")
	_ = c.MarkFlagRequired("router")
	withDir(c)
	withJSON(c)
	return c
}

func xferSendCommand() *cobra.Command {
	var localPeer, peer, file, mailboxHex, shard string
	var chunkSize int
	c := &cobra.Command{
		Use:   "xfer-send <id>",
		Short: "Encrypt a file end-to-end and upload it in chunks",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return transportops.XferSend(openDeps(cmd), transportops.XferSendParams{
				TransportID: args[0], Identity: localPeer, Peer: peer,
				MailboxID: mailboxHex, ShardURL: shard, File: file, ChunkSize: chunkSize,
			})
		},
	}
	c.Flags().StringVarP(&localPeer, "id", "i", "", "Local peer ID (required)")
	c.Flags().StringVar(&peer, "to", "", "Recipient peer ID (required, needs a session)")
	c.Flags().StringVar(&mailboxHex, "mailbox", "", "Explicit mailbox, 32 hex: recipient address, or OWN mailbox for ticket shares (upload to your relay)")
	c.Flags().StringVar(&shard, "shard", "", "Shard URL for --mailbox")
	c.Flags().StringVarP(&file, "file", "f", "", "File to send (required)")
	c.Flags().IntVar(&chunkSize, "chunk-size", 32*1024, "Chunk size in bytes")
	_ = c.MarkFlagRequired("id")
	_ = c.MarkFlagRequired("to")
	_ = c.MarkFlagRequired("file")
	withDir(c)
	withJSON(c)
	return c
}

func xferRecvCommand() *cobra.Command {
	var localPeer, peer, transferHex, mailboxHex, secretHex, shard, manifestB64, ticketJSON, out string
	c := &cobra.Command{
		Use:   "xfer-recv <id>",
		Short: "Download, verify and decrypt a file transfer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return transportops.XferRecv(openDeps(cmd), transportops.XferRecvParams{
				TransportID: args[0], Identity: localPeer, Peer: peer,
				TicketB64: ticketJSON, TransferID: transferHex, MailboxID: mailboxHex,
				Secret: secretHex, ShardURL: shard, ManifestB64: manifestB64, Out: out,
			})
		},
	}
	c.Flags().StringVarP(&localPeer, "id", "i", "", "Local peer ID (required)")
	c.Flags().StringVar(&peer, "from", "", "Expected sender peer ID (required unless --ticket carries it)")
	c.Flags().StringVar(&transferHex, "transfer", "", "Transfer ID, 32 hex chars (mailbox mode)")
	c.Flags().StringVar(&mailboxHex, "mailbox", "", "Recipient mailbox ID, 32 hex (mailbox mode)")
	c.Flags().StringVar(&secretHex, "secret", "", "Read secret, 64 hex (mailbox mode)")
	c.Flags().StringVar(&shard, "shard", "", "Shard URL (informational in mailbox mode)")
	c.Flags().StringVar(&manifestB64, "manifest", "", "Transfer manifest, base64 (mailbox mode)")
	c.Flags().StringVar(&ticketJSON, "ticket", "", "Ticket base64 from a transfer message (ticket mode; replaces transfer/mailbox/secret/manifest)")
	c.Flags().StringVarP(&out, "out", "o", "", "Output file (required)")
	_ = c.MarkFlagRequired("id")
	_ = c.MarkFlagRequired("out")
	withDir(c)
	withJSON(c)
	return c
}

func xferResumeCommand() *cobra.Command {
	var transferHex, mailboxHex, secretHex, ticketB64, shard string
	c := &cobra.Command{
		Use:   "xfer-resume <id>",
		Short: "Show transfer progress without downloading",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return transportops.XferResume(openDeps(cmd), transportops.XferResumeParams{
				TransportID: args[0], TransferID: transferHex, MailboxID: mailboxHex,
				Secret: secretHex, TicketB64: ticketB64, ShardURL: shard,
			})
		},
	}
	c.Flags().StringVar(&transferHex, "transfer", "", "Transfer ID, 32 hex chars (mailbox mode; inside ticket otherwise)")
	c.Flags().StringVar(&mailboxHex, "mailbox", "", "Mailbox ID, 32 hex (mailbox mode)")
	c.Flags().StringVar(&secretHex, "secret", "", "Read secret, 64 hex (mailbox mode)")
	c.Flags().StringVar(&ticketB64, "ticket", "", "Ticket base64 (ticket mode)")
	c.Flags().StringVar(&shard, "shard", "", "Shard URL (ticket mode)")
	withDir(c)
	withJSON(c)
	return c
}

func xferCancelCommand() *cobra.Command {
	var transferHex, mailboxHex, secretHex string
	c := &cobra.Command{
		Use:   "xfer-cancel <id>",
		Short: "Abort a transfer (mailbox owner only; tickets never cancel)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return transportops.XferCancel(openDeps(cmd), transportops.XferCancelParams{
				TransportID: args[0], TransferID: transferHex,
				MailboxID: mailboxHex, Secret: secretHex,
			})
		},
	}
	c.Flags().StringVar(&transferHex, "transfer", "", "Transfer ID, 32 hex chars (required)")
	c.Flags().StringVar(&mailboxHex, "mailbox", "", "Mailbox ID, 32 hex (required)")
	c.Flags().StringVar(&secretHex, "secret", "", "Read secret, 64 hex (required; omit in shell for hidden prompt)")
	_ = c.MarkFlagRequired("transfer")
	_ = c.MarkFlagRequired("mailbox")
	withDir(c)
	withJSON(c)
	return c
}

func xferInspectCommand() *cobra.Command {
	var ticketB64 string
	c := &cobra.Command{
		Use:   "xfer-inspect <id>",
		Short: "Decode a ticket offline (no network): who, what, where",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return transportops.XferInspect(openDeps(cmd), ticketB64)
		},
	}
	c.Flags().StringVar(&ticketB64, "ticket", "", "Ticket base64 (required)")
	_ = c.MarkFlagRequired("ticket")
	withDir(c)
	withJSON(c)
	return c
}
