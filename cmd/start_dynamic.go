package cmd

import (
	"fmt"
	"os"

	"github.com/davrodpin/mole/mole"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	DynamicForwardDoc = `
Dynamic Forwarding turns the source machine into a SOCKS5 proxy, giving any
application that speaks it access to every service the jump server can reach,
without a tunnel having to be set up for each one of them upfront.

This could be particular useful for browsing web sites only reachable from
inside a remote network, where the addresses are not known in advance.

Source endpoints are addresses on the same machine where mole is getting
executed where SOCKS5 clients can connect to. No destination endpoint is given:
each client asks for the address it wants to reach, which is then reached from
the jump server.

Host names are resolved by the jump server rather than locally, so names that
only exist in the remote network can be used.

Only the CONNECT command is supported, which is what a ssh tunnel is able to
carry, and no authentication is required to connect to the proxy, so the source
endpoint should be kept on an address reachable by trusted clients alone.
`
)

var startDynamicCmd = &cobra.Command{
	Use:   "dynamic",
	Short: "Starts a ssh dynamic port forwarding tunnel (SOCKS5 proxy)",
	Long:  fmt.Sprintf("Starts a ssh dynamic port forwarding tunnel.\n%s", DynamicForwardDoc),
	Args: func(cmd *cobra.Command, args []string) error {
		conf.TunnelType = "dynamic"
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
	err := bindFlags(conf, startDynamicCmd)
	if err != nil {
		log.WithError(err).Error("error parsing command line arguments")
		os.Exit(1)
	}

	// a dynamic tunnel has no destination to be given: each connection carries
	// the address it wants to reach.
	err = startDynamicCmd.Flags().MarkHidden("destination")
	if err != nil {
		log.WithError(err).Error("error parsing command line arguments")
		os.Exit(1)
	}

	startCmd.AddCommand(startDynamicCmd)
}
