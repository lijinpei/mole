package mole

import (
	"errors"
	"fmt"
	"time"

	"github.com/davrodpin/mole/alias"
	"github.com/davrodpin/mole/tunnel"

	log "github.com/sirupsen/logrus"
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

// forward converts the configuration to what a tunnel serves, which needs every
// destination to carry the port to reach.
func (f ForwardConfiguration) forward() (tunnel.Forward, error) {
	destination := make([]string, len(f.Destination))

	for i, r := range f.Destination {
		if r.Port == "" {
			return tunnel.Forward{}, fmt.Errorf("missing port in destination address: %s", r.String())
		}

		destination[i] = r.String()
	}

	return tunnel.Forward{Type: f.Type, Source: f.Source.List(), Destination: destination}, nil
}

type flags []string

func (fs flags) lookup(flag string) bool {
	for _, f := range fs {
		if flag == f {
			return true
		}
	}

	return false
}

// Merge overwrites Configuration from the given Alias. Verbose, Insecure and
// Detach flags named in givenFlags take precedence over the alias settings.
func (c *Configuration) Merge(al *alias.Alias, givenFlags []string) error {
	var fl flags = givenFlags

	if !fl.lookup("verbose") {
		c.Verbose = al.Verbose
	}
	if !fl.lookup("insecure") {
		c.Insecure = al.Insecure
	}
	if !fl.lookup("detach") {
		c.Detach = al.Detach
	}
	c.Id = al.Name

	entries := al.Tunnels
	if len(entries) > 0 {
		if al.Server != "" || al.TunnelType != "" || len(al.Source) > 0 || len(al.Destination) > 0 {
			return fmt.Errorf("alias %s has tunnels along with a server, type, source or destination of its own: move them into a tunnel", al.Name)
		}
	} else {
		if al.Server == "" {
			return fmt.Errorf("alias %s has neither a server nor tunnels to forward through", al.Name)
		}

		// flat aliases keep the CLI's ssh config when they leave it out.
		entries = []alias.Tunnel{{
			Server:    al.Server,
			SshConfig: inherit(al.SshConfig, c.SshConfig),
			Forwards:  []alias.Forward{{Type: al.TunnelType, Source: al.Source, Destination: al.Destination}},
		}}
	}

	tunnels := make([]TunnelConfiguration, len(entries))
	for i, at := range entries {
		tc, err := mergeTunnel(al, at)
		if err != nil {
			return fmt.Errorf("tunnel %d of alias %s: %w", i+1, al.Name, err)
		}
		if fl.lookup("insecure") {
			tc.Insecure = c.Insecure
		}
		tunnels[i] = *tc
	}

	if len(al.Tunnels) > 0 {
		c.Tunnels = tunnels
	} else {
		tc := tunnels[0]
		c.Tunnels = nil
		c.TunnelType = al.TunnelType
		c.Server = tc.Server
		c.Source = append(AddressInputList{}, tc.Forwards[0].Source...)
		c.Destination = append(AddressInputList{}, tc.Forwards[0].Destination...)
		c.Key = tc.Key
		c.KeepAliveInterval = tc.KeepAliveInterval
		c.ConnectionRetries = tc.ConnectionRetries
		c.WaitAndRetry = tc.WaitAndRetry
		c.SshAgent = tc.SshAgent
		c.Timeout = tc.Timeout
		c.SshConfig = tc.SshConfig
		c.SocksAuth = tc.SocksAuth
	}
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

		// what createTunnels would refuse is refused here as well, since it runs
		// once a detached instance has already told its parent that it started.
		tf, err := f.forward()
		if err != nil {
			return nil, fmt.Errorf("%v for server %s", err, at.Server)
		}

		if err := tunnel.CheckForward(tf); err != nil {
			return nil, fmt.Errorf("%v for server %s", err, at.Server)
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

// tunnels returns the configuration of every tunnel the instance runs: the ones
// of an alias forwarding through several ssh servers, or else the single one
// the flat settings describe.
func (c *Configuration) tunnels() []TunnelConfiguration {
	if len(c.Tunnels) > 0 {
		return c.Tunnels
	}

	return []TunnelConfiguration{{
		Server:            c.Server,
		Key:               c.Key,
		KeepAliveInterval: c.KeepAliveInterval,
		ConnectionRetries: c.ConnectionRetries,
		WaitAndRetry:      c.WaitAndRetry,
		SshAgent:          c.SshAgent,
		Timeout:           c.Timeout,
		SshConfig:         c.SshConfig,
		Insecure:          c.Insecure,
		SocksAuth:         c.SocksAuth,
		Forwards: []ForwardConfiguration{{
			Type:        c.TunnelType,
			Source:      c.Source,
			Destination: c.Destination,
		}},
	}}
}

// runner is what runTunnels needs from a tunnel, which keeps how an instance
// runs several of them testable without a ssh server.
type runner interface {
	Start() error
	String() string
}

// runTunnels starts every given tunnel and waits for all of them to be over. A
// tunnel ending for good is reported along with what it was forwarding
// through, while the others keep going: an alias forwarding through several
// ssh servers is still of use for as long as any of them is.
func runTunnels(tunnels []runner) error {
	results := make(chan error, len(tunnels))

	for _, t := range tunnels {
		go func(t runner) {
			err := t.Start()
			if err != nil {
				log.WithFields(log.Fields{
					"tunnel": t.String(),
				}).WithError(err).Error("error while starting tunnel")

				err = fmt.Errorf("tunnel %s: %w", t, err)
			}

			results <- err
		}(t)
	}

	var errs []error

	for range tunnels {
		if err := <-results; err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
