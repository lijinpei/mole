package alias

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/davrodpin/mole/fsutils"
)

// Alias holds all attributes required to start a ssh port forwarding tunnel.
//
// An alias forwarding through several ssh servers has its Tunnels set instead
// of the type, source, destination and server of a single tunnel. The other
// tunnel settings are then the ones every tunnel takes unless it gives its own.
type Alias struct {
	Name              string   `toml:"name"`
	TunnelType        string   `toml:"type,omitempty"`
	Verbose           bool     `toml:"verbose"`
	Insecure          bool     `toml:"insecure"`
	Detach            bool     `toml:"detach"`
	Source            []string `toml:"source"`
	Destination       []string `toml:"destination"`
	Server            string   `toml:"server,omitempty"`
	Key               string   `toml:"key"`
	KeepAliveInterval string   `toml:"keep-alive-interval"`
	ConnectionRetries int      `toml:"connection-retries"`
	WaitAndRetry      string   `toml:"wait-and-retry"`
	SshAgent          string   `toml:"ssh-agent"`
	Timeout           string   `toml:"timeout"`
	SshConfig         string   `toml:"config"`
	SocksAuth         string   `toml:"socks-auth"`
	Rpc               bool     `toml:"rpc"`
	RpcAddress        string   `toml:"rpc-address"`
	Tunnels           []Tunnel `toml:"tunnels,omitempty"`
}

// Tunnel holds the attributes of one of the ssh servers an alias forwards
// through. A setting left empty is taken from the alias, which is why the ones
// whose zero value means something are pointers: no retries at all asks to
// never give up reconnecting.
type Tunnel struct {
	Server            string    `toml:"server"`
	Key               string    `toml:"key,omitempty"`
	KeepAliveInterval string    `toml:"keep-alive-interval,omitempty"`
	ConnectionRetries *int      `toml:"connection-retries,omitempty"`
	WaitAndRetry      string    `toml:"wait-and-retry,omitempty"`
	SshAgent          string    `toml:"ssh-agent,omitempty"`
	Timeout           string    `toml:"timeout,omitempty"`
	SshConfig         string    `toml:"config,omitempty"`
	Insecure          *bool     `toml:"insecure,omitempty"`
	SocksAuth         string    `toml:"socks-auth,omitempty"`
	Forwards          []Forward `toml:"forwards"`
}

// Forward holds a group of channels of a single kind served through a tunnel.
type Forward struct {
	Type        string   `toml:"type"`
	Source      []string `toml:"source,omitempty"`
	Destination []string `toml:"destination,omitempty"`
}

// The values the tunnel settings of an alias forwarding through several ssh
// servers take when the alias leaves them out, which are the ones the command
// line defaults to.
const (
	DefaultKeepAliveInterval = "10s"
	DefaultConnectionRetries = 3
	DefaultWaitAndRetry      = "3s"
	DefaultTimeout           = "3s"
	DefaultSshConfig         = "$HOME/.ssh/config"
)

// String parses a Alias object to a string representation.
func (a Alias) String() string {
	return fmt.Sprintf("[verbose: %t, insecure: %t, detach: %t, source: %s, destination: %s, server: %s, key: %s, keep-alive-interval: %s, connection-retries: %d, wait-and-retry: %s, ssh-agent: %s, timeout: %s, config: %s, rpc: %t, rpc-address: %s]",
		a.Verbose,
		a.Insecure,
		a.Detach,
		a.Source,
		a.Destination,
		a.Server,
		a.Key,
		a.KeepAliveInterval,
		a.ConnectionRetries,
		a.WaitAndRetry,
		a.SshAgent,
		a.Timeout,
		a.SshConfig,
		a.Rpc,
		a.RpcAddress,
	)
}

// Add persists an tunnel alias to the disk
func Add(alias *Alias) error {
	mp, err := fsutils.CreateHomeDir()
	if err != nil {
		return err
	}

	ap := filepath.Join(mp, fmt.Sprintf("%s.toml", alias.Name))

	f, err := os.Create(ap)
	if err != nil {
		return err
	}
	defer f.Close()

	e := toml.NewEncoder(f)

	if err = e.Encode(alias); err != nil {
		return err
	}

	return nil
}

// Delete destroys a alias configuration file.
func Delete(alias string) error {
	mp, err := fsutils.Dir()

	if err != nil {
		return err
	}

	afp := filepath.Join(mp, fmt.Sprintf("%s.toml", alias))

	if _, err := os.Stat(afp); os.IsNotExist(err) {
		return fmt.Errorf("alias %s does not exist", alias)
	}

	err = os.Remove(afp)
	if err != nil {
		return err
	}

	return nil
}

// Show displays the configuration parameters for the given alias name.
func Show(aliasName string) (string, error) {
	a, err := Get(aliasName)
	if err != nil {
		return "", fmt.Errorf("could not show alias %s configuration: %v", aliasName, err)
	}

	var aliases bytes.Buffer
	e := toml.NewEncoder(&aliases)

	if err = e.Encode(a); err != nil {
		return "", err
	}

	return aliases.String(), nil
}

// ShowAll displays the configuration parameters for all persisted aliases.
func ShowAll() (string, error) {
	mp, err := fsutils.Dir()
	if err != nil {
		return "", err
	}

	aliases := aliases{}
	aliases.Aliases = make(map[string]*Alias)

	err = filepath.Walk(mp, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			ext := filepath.Ext(path)
			if ext == ".toml" {
				var err error
				an := strings.TrimSuffix(filepath.Base(path), ".toml")
				al, err := Get(an)
				if err != nil {
					return err
				}

				aliases.Aliases[al.Name] = al
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}

	var buff bytes.Buffer

	e := toml.NewEncoder(&buff)

	if err = e.Encode(aliases); err != nil {
		return "", err
	}

	return buff.String(), nil
}

// Get returns an alias previously created
func Get(aliasName string) (*Alias, error) {
	mp, err := fsutils.Dir()
	if err != nil {
		return nil, err
	}

	p := filepath.Join(mp, fmt.Sprintf("%s.toml", aliasName))

	if _, err := os.Stat(p); os.IsNotExist(err) {
		return nil, fmt.Errorf("alias %s does not exist", aliasName)
	}

	a := &Alias{}
	md, err := toml.DecodeFile(p, a)
	if err != nil {
		return nil, err
	}
	a.Name = aliasName

	// an alias with a server of its own is the kind "mole add alias" writes,
	// which is read as it always was, whatever an older version wrote in it.
	// One with tunnels, or with no server at all, is written by hand, where a
	// misspelled setting would otherwise be dropped without a word, leaving an
	// alias that does not do what it says.
	if a.Server == "" || len(a.Tunnels) > 0 {
		if keys := md.Undecoded(); len(keys) > 0 {
			return nil, fmt.Errorf("alias %s has unknown settings: %v", aliasName, keys)
		}
	}

	if len(a.Tunnels) > 0 {
		a.applyDefaults(md)
	}

	return a, nil
}

// applyDefaults gives the tunnel settings an alias forwarding through several
// ssh servers leaves out the values the command line defaults to, so that a
// hand written alias only has to carry what sets it apart.
func (a *Alias) applyDefaults(md toml.MetaData) {
	if a.KeepAliveInterval == "" {
		a.KeepAliveInterval = DefaultKeepAliveInterval
	}

	// no retries at all asks to never give up reconnecting, so only a number
	// of retries left out altogether takes the default.
	if !md.IsDefined("connection-retries") {
		a.ConnectionRetries = DefaultConnectionRetries
	}

	if a.WaitAndRetry == "" {
		a.WaitAndRetry = DefaultWaitAndRetry
	}

	if a.Timeout == "" {
		a.Timeout = DefaultTimeout
	}

	if a.SshConfig == "" {
		a.SshConfig = DefaultSshConfig
	}
}

// FIXME terrible struct name. Change it.
type aliases struct {
	Aliases map[string]*Alias `toml:"aliases"`
}
