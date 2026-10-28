package mole

import (
	"fmt"
	"time"

	"github.com/davrodpin/mole/alias"
)

// TunnelConfiguration holds what it takes to forward through one of the ssh
// servers an instance connects to.
type TunnelConfiguration struct {
	Server            AddressInput           `json:"server" mapstructure:"server" toml:"server"`
	Key               string                 `json:"key" mapstructure:"key" toml:"key"`
	KeepAliveInterval time.Duration          `json:"keep-alive-interval" mapstructure:"keep-alive-interval" toml:"keep-alive-interval"`
	ConnectionRetries int                    `json:"connection-retries" mapstructure:"connection-retries" toml:"connection-retries"`
	WaitAndRetry      time.Duration          `json:"wait-and-retry" mapstructure:"wait-and-retry" toml:"wait-and-retry"`
	SshAgent          string                 `json:"ssh-agent" mapstructure:"ssh-agent" toml:"ssh-agent"`
	Timeout           time.Duration          `json:"timeout" mapstructure:"timeout" toml:"timeout"`
	SshConfig         string                 `json:"ssh-config" mapstructure:"ssh-config" toml:"ssh-config"`
	Insecure          bool                   `json:"insecure" mapstructure:"insecure" toml:"insecure"`
	SocksAuth         string                 `json:"socks-auth" mapstructure:"socks-auth" toml:"socks-auth"`
	Forwards          []ForwardConfiguration `json:"forwards" mapstructure:"forwards" toml:"forwards"`
}

// ForwardConfiguration holds a group of channels of a single kind served
// through a tunnel.
type ForwardConfiguration struct {
	Type        string           `json:"type" mapstructure:"type" toml:"type"`
	Source      AddressInputList `json:"source" mapstructure:"source" toml:"source"`
	Destination AddressInputList `json:"destination" mapstructure:"destination" toml:"destination"`
}

// mergeTunnels overwrites the Configuration from an alias forwarding through
// several ssh servers. Each tunnel takes the settings it leaves out from the
// alias, and the insecure flag given on the command line, if any, over both.
func (c *Configuration) mergeTunnels(al *alias.Alias, insecureGiven bool) error {
	// the flat settings describe a tunnel of their own, which would have to be
	// either dropped without a word or started along with the others.
	if al.Server != "" || al.TunnelType != "" || len(al.Source) > 0 || len(al.Destination) > 0 {
		return fmt.Errorf("alias %s has tunnels along with a server, type, source or destination of its own: move them into a tunnel", al.Name)
	}

	tunnels := make([]TunnelConfiguration, len(al.Tunnels))

	for i, at := range al.Tunnels {
		tc, err := mergeTunnel(al, at)
		if err != nil {
			return fmt.Errorf("tunnel %d of alias %s: %v", i+1, al.Name, err)
		}

		if insecureGiven {
			tc.Insecure = c.Insecure
		}

		tunnels[i] = *tc
	}

	c.Tunnels = tunnels
	c.Rpc = al.Rpc
	c.RpcAddress = al.RpcAddress

	return nil
}

// mergeTunnel resolves the configuration of the given tunnel of an alias.
func mergeTunnel(al *alias.Alias, at alias.Tunnel) (*TunnelConfiguration, error) {
	if at.Server == "" {
		return nil, fmt.Errorf("no server given")
	}

	if len(at.Forwards) == 0 {
		return nil, fmt.Errorf("no forwards given for server %s", at.Server)
	}

	tc := &TunnelConfiguration{
		Key:               inherit(at.Key, al.Key),
		SshAgent:          inherit(at.SshAgent, al.SshAgent),
		SshConfig:         inherit(at.SshConfig, al.SshConfig),
		SocksAuth:         inherit(at.SocksAuth, al.SocksAuth),
		Insecure:          al.Insecure,
		ConnectionRetries: al.ConnectionRetries,
	}

	if at.Insecure != nil {
		tc.Insecure = *at.Insecure
	}

	if at.ConnectionRetries != nil {
		tc.ConnectionRetries = *at.ConnectionRetries
	}

	if err := tc.Server.Set(at.Server); err != nil {
		return nil, err
	}

	durations := []struct {
		name  string
		value string
		into  *time.Duration
	}{
		{"keep-alive-interval", inherit(at.KeepAliveInterval, al.KeepAliveInterval), &tc.KeepAliveInterval},
		{"wait-and-retry", inherit(at.WaitAndRetry, al.WaitAndRetry), &tc.WaitAndRetry},
		{"timeout", inherit(at.Timeout, al.Timeout), &tc.Timeout},
	}

	for _, d := range durations {
		v, err := time.ParseDuration(d.value)
		if err != nil {
			return nil, fmt.Errorf("invalid %s for server %s: %v", d.name, at.Server, err)
		}

		*d.into = v
	}

	for _, af := range at.Forwards {
		if af.Type == "" {
			return nil, fmt.Errorf("forward with no type for server %s", at.Server)
		}

		f := ForwardConfiguration{Type: af.Type}

		for _, src := range af.Source {
			if err := f.Source.Set(src); err != nil {
				return nil, err
			}
		}

		for _, dst := range af.Destination {
			if err := f.Destination.Set(dst); err != nil {
				return nil, err
			}
		}

		tc.Forwards = append(tc.Forwards, f)
	}

	return tc, nil
}

// inherit returns the value a tunnel gives to a setting, or the fallback the
// alias gives to it when the tunnel leaves it out.
func inherit(own, fallback string) string {
	if own != "" {
		return own
	}

	return fallback
}
