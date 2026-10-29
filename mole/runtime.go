package mole

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/BurntSushi/toml"
	"github.com/davrodpin/mole/fsutils"
	"github.com/davrodpin/mole/tunnel"
)

type Formatter interface {
	Format(format string) (string, error)
}

// Runtime holds runtime data about an application instance.
type Runtime Configuration

// Format parses a Runtime object into a string representation based on the given
// format (i.e. toml).
func (rt Runtime) Format(format string) (string, error) {
	if format == "toml" {
		return rt.ToToml()
	} else {
		return "", fmt.Errorf("unknown %s format", format)
	}
}

func (rt Runtime) ToToml() (string, error) {
	var buf bytes.Buffer
	e := toml.NewEncoder(&buf)

	if err := e.Encode(rt); err != nil {
		return "", err
	}

	return buf.String(), nil
}

type InstancesRuntime []Runtime

func (ir InstancesRuntime) Format(format string) (string, error) {
	if format == "toml" {
		return ir.ToToml()
	} else {
		return "", fmt.Errorf("unknown %s format", format)
	}
}

func (ir InstancesRuntime) ToToml() (string, error) {
	rt := make(map[string]map[string]Runtime)
	rt["instances"] = make(map[string]Runtime)

	for _, instance := range ir {
		rt["instances"][instance.Id] = instance
	}

	var buf bytes.Buffer
	e := toml.NewEncoder(&buf)

	if err := e.Encode(rt); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func (c *Client) Runtime() (*Runtime, error) {
	runtime := Runtime(*c.Conf)

	// the credentials the socks proxy asks its clients for are not part of what
	// an instance tells about itself: whoever is looking at what it is doing has
	// no use for them.
	runtime.SocksAuth = ""

	tunnels, err := c.tunnelsRuntime()
	if err != nil {
		return nil, err
	}

	if len(c.Conf.Tunnels) > 0 {
		runtime.Tunnels = tunnels
	} else if len(c.Tunnels) > 0 {
		// flat output keeps its shape, but uses the same live interpretation.
		runtime.Source = AddressInputList{}
		runtime.Destination = AddressInputList{}
		for _, forward := range tunnels[0].Forwards {
			runtime.Source = append(runtime.Source, forward.Source...)
			runtime.Destination = append(runtime.Destination, forward.Destination...)
		}
	}

	return &runtime, nil
}

// tunnelsRuntime reports each tunnel's forwards with bound source endpoints
// and without SOCKS credentials, regardless of the alias format.
func (c *Client) tunnelsRuntime() ([]TunnelConfiguration, error) {
	// the tunnels are copied rather than changed in place: they are what the
	// instance keeps running with.
	configured := c.Conf.tunnels()
	tunnels := make([]TunnelConfiguration, len(configured))

	for i, tc := range configured {
		tc.SocksAuth = ""

		// the tunnels only exist once the instance has started.
		if i < len(c.Tunnels) {
			forwards, err := forwardsOf(c.Tunnels[i].Channels())
			if err != nil {
				return nil, err
			}

			tc.Forwards = forwards
		}

		tunnels[i] = tc
	}

	return tunnels, nil
}

// forwardsOf returns the forwards the given channels serve, with the source
// endpoints they are listening on. Channels of the same kind next to each other
// are told about together, the way they were given.
func forwardsOf(channels []*tunnel.SSHChannel) ([]ForwardConfiguration, error) {
	var forwards []ForwardConfiguration

	for _, channel := range channels {
		if len(forwards) == 0 || forwards[len(forwards)-1].Type != channel.ChannelType {
			forwards = append(forwards, ForwardConfiguration{Type: channel.ChannelType})
		}

		f := &forwards[len(forwards)-1]

		if err := f.Source.Set(channel.Source); err != nil {
			return nil, err
		}

		// a dynamic or reverse dynamic channel has no destination of its own.
		if channel.Destination == "" {
			continue
		}

		if err := f.Destination.Set(channel.Destination); err != nil {
			return nil, err
		}
	}

	return forwards, nil
}

// Running checks if an instance of mole is running on the system.
func (c *Client) Running() (bool, error) {
	d, err := fsutils.InstanceDir(c.Conf.Id)
	if err != nil {
		return false, err
	}

	if _, err := os.Stat(d.PidFile); os.IsNotExist(err) {
		return false, nil
	}

	pd, err := ioutil.ReadFile(d.PidFile)
	if err != nil {
		return false, err
	}

	pid, err := strconv.Atoi(string(pd))
	if err != nil {
		return false, err
	}

	return processExists(pid)
}
