package cmd

import (
	"testing"
	"time"

	"github.com/davrodpin/mole/mole"
	"github.com/spf13/cobra"
)

func TestTunnelFlagDefaults(t *testing.T) {
	conf := &mole.Configuration{}
	if err := bindFlags(conf, &cobra.Command{Use: "test"}); err != nil {
		t.Fatalf("could not bind tunnel flags: %v", err)
	}

	if conf.KeepAliveInterval != 10*time.Second || conf.ConnectionRetries != 3 ||
		conf.WaitAndRetry != 3*time.Second || conf.Timeout != 3*time.Second || conf.SshConfig != "$HOME/.ssh/config" {
		t.Errorf("unexpected tunnel defaults: %+v", conf)
	}
}
