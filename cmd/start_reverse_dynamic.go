package cmd

import (
	"fmt"
	"os"

	"github.com/davrodpin/mole/mole"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	ReverseDynamicForwardDoc = `
Reverse Dynamic Forwarding turns the jump server into a SOCKS5 proxy served by
the source machine, giving any application on the remote network access to every
service this machine can reach, without a tunnel having to be set up for each one
of them upfront.

This could be particular useful for giving a computer on the outside access to a
whole set of internal services whose addresses are not known in advance.

Source endpoints are addresses on the jump server where SOCKS5 clients can
connect to. No destination endpoint is given: each client asks for the address it
wants to reach, which is then reached from the same machine where mole is getting
executed.

Host names are resolved by this machine rather than by the jump server, since
they name what only this side can reach.

Only the CONNECT command is supported, which is what a ssh tunnel is able to
carry, and anyone able to reach the source endpoint can reach anything this
machine can, so the proxy can be told to ask its clients for a user and a
password through the --socks-auth flag.

Which address the endpoint is bound to is decided by the jump server rather than
here, and the source address is only what gets asked for: a ssh server keeps it
on its loopback address unless it is configured otherwise (GatewayPorts), so by
default the proxy can only be reached from the jump server itself.
`
)

var startReverseDynamicCmd = &cobra.Command{
	Use:   "reverse-dynamic",
	Short: "Starts a ssh reverse dynamic port forwarding tunnel (SOCKS5 proxy)",
	Long:  fmt.Sprintf("Starts a ssh reverse dynamic port forwarding tunnel.\n%s", ReverseDynamicForwardDoc),
	Args: func(cmd *cobra.Command, args []string) error {
		conf.TunnelType = "reverse-dynamic"
		return nil
	},
	Run: func(cmd *cobra.Command, arg []string) {
		client := mole.New(conf)

		err := client.Start()
		if err != nil {
			log.WithError(err).Error("error starting mole")
			os.Exit(1)
		}
	},
}

func init() {
	err := bindFlags(conf, startReverseDynamicCmd)
	if err != nil {
		log.WithError(err).Error("error parsing command line arguments")
		os.Exit(1)
	}

	// a reverse dynamic tunnel has no destination to be given: each connection
	// carries the address it wants to reach.
	err = startReverseDynamicCmd.Flags().MarkHidden("destination")
	if err != nil {
		log.WithError(err).Error("error parsing command line arguments")
		os.Exit(1)
	}

	startCmd.AddCommand(startReverseDynamicCmd)
}
