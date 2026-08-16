package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Shows configuration details about ssh tunnel aliases",
	Args: func(cmd *cobra.Command, args []string) error {
		if err := cobra.MinimumNArgs(1)(cmd, args); err != nil {
			return err
		}

		// Anything reaching this point failed to match a subcommand, so it
		// would otherwise be silently accepted by the no-op Run below.
		return fmt.Errorf("unknown command %q for %q", args[0], cmd.CommandPath())
	},
	Run: func(cmd *cobra.Command, arg []string) {},
}

func init() {
	rootCmd.AddCommand(showCmd)
}
