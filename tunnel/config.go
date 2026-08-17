package tunnel

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kevinburke/ssh_config"
	log "github.com/sirupsen/logrus"
)

const homeVar = "$HOME"

// SSHConfigFile finds specific attributes of a ssh server configured on a
// ssh config file.
type SSHConfigFile struct {
	sshConfig *ssh_config.Config
}

// NewSSHConfigFile creates a new instance of SSHConfigFile based on the
// ssh config file from configPath
func NewSSHConfigFile(configPath string) (*SSHConfigFile, error) {
	if strings.Contains(configPath, homeVar) {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}

		configPath = strings.ReplaceAll(configPath, homeVar, home)
	}

	f, err := os.Open(filepath.Clean(configPath))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfg, err := ssh_config.Decode(f)
	if err != nil {
		return nil, err
	}

	log.Debugf("using ssh config file from: %s", configPath)

	return &SSHConfigFile{sshConfig: cfg}, nil
}

func NewEmptySSHConfigStruct() *SSHConfigFile {
	log.Debugf("generating an empty config struct")
	return &SSHConfigFile{sshConfig: &ssh_config.Config{}}
}

// Get consults a ssh config file to extract some ssh server attributes
// from it, returning a SSHHost. Any attribute which its value is an empty
// string is an attribute that could not be found in the ssh config file.
func (r SSHConfigFile) Get(host string) *SSHHost {
	hostname := r.getHostname(host)

	port, err := r.sshConfig.Get(host, "Port")
	if err != nil {
		port = ""
	}

	user, err := r.sshConfig.Get(host, "User")
	if err != nil {
		user = ""
	}

	localForwards, err := r.getForwards("LocalForward", host)
	if err != nil {
		log.Warningf("error reading local forwarding configuration from ssh config file: %v", err)
	}

	remoteForwards, err := r.getForwards("RemoteForward", host)
	if err != nil {
		log.Warningf("error reading remote configuration from ssh config file: %v", err)
	}

	dynamicForwards, err := r.getDynamicForwards(host)
	if err != nil {
		log.Warningf("error reading dynamic forwarding configuration from ssh config file: %v", err)
	}

	reverseDynamicForwards, err := r.getReverseDynamicForwards(host)
	if err != nil {
		log.Warningf("error reading reverse dynamic forwarding configuration from ssh config file: %v", err)
	}

	key := r.getKey(host)

	identityAgent, err := r.sshConfig.Get(host, "IdentityAgent")
	if err != nil {
		identityAgent = ""
	}

	return &SSHHost{
		Hostname:               hostname,
		Port:                   port,
		User:                   user,
		Key:                    key,
		IdentityAgent:          identityAgent,
		LocalForwards:          localForwards,
		RemoteForwards:         remoteForwards,
		DynamicForwards:        dynamicForwards,
		ReverseDynamicForwards: reverseDynamicForwards,
	}
}

func (r SSHConfigFile) getHostname(host string) string {
	hostname, err := r.sshConfig.Get(host, "Hostname")
	if err != nil {
		return ""
	}

	return hostname
}

func (r SSHConfigFile) getForwards(forwardType, host string) ([]*ForwardConfig, error) {
	fwds, err := r.sshConfig.GetAll(host, forwardType)
	if err != nil {
		return nil, err
	}

	forwards := []*ForwardConfig{}

	for _, c := range fwds {
		if c == "" {
			continue
		}

		l := strings.Fields(c)

		// a RemoteForward carrying a source endpoint alone asks for a reverse
		// dynamic forward, which is read on its own.
		if forwardType == "RemoteForward" && len(l) == 1 {
			continue
		}

		if len(l) < 2 {
			return nil, fmt.Errorf("malformed forwarding configuration on ssh config file: %s", l)
		}

		forwards = append(forwards, &ForwardConfig{Source: sourceAddress(l[0]), Destination: l[1]})
	}

	if len(forwards) == 0 {
		return nil, nil
	}

	return forwards, nil

}

// getDynamicForwards reads the DynamicForward settings of the given host, which
// carry a source endpoint alone: the destination of every connection made to it
// is given by the client through the socks protocol.
func (r SSHConfigFile) getDynamicForwards(host string) ([]*ForwardConfig, error) {
	fwds, err := r.sshConfig.GetAll(host, "DynamicForward")
	if err != nil {
		return nil, err
	}

	forwards := []*ForwardConfig{}

	for _, c := range fwds {
		if c == "" {
			continue
		}

		l := strings.Fields(c)

		if len(l) != 1 || !endpoint(l[0]) {
			return nil, fmt.Errorf("malformed dynamic forwarding configuration on ssh config file: %s", l)
		}

		forwards = append(forwards, &ForwardConfig{Source: sourceAddress(l[0])})
	}

	if len(forwards) == 0 {
		return nil, nil
	}

	return forwards, nil
}

// getReverseDynamicForwards reads the RemoteForward settings of the given host
// that carry a source endpoint alone, which is what asks for a reverse dynamic
// forward: the ssh server listens on that endpoint and the destination of every
// connection made to it is given by the client that made it.
func (r SSHConfigFile) getReverseDynamicForwards(host string) ([]*ForwardConfig, error) {
	fwds, err := r.sshConfig.GetAll(host, "RemoteForward")
	if err != nil {
		return nil, err
	}

	forwards := []*ForwardConfig{}

	for _, c := range fwds {
		if c == "" {
			continue
		}

		l := strings.Fields(c)

		// a RemoteForward carrying a destination as well is a remote forward,
		// which is read on its own.
		if len(l) != 1 {
			continue
		}

		// what is left has to be an endpoint to listen on, since there is
		// nothing else a RemoteForward can carry on its own. Reporting it from
		// here is what keeps a malformed setting from being taken for one: the
		// reader of the remote forwards leaves every single field line to this
		// one.
		if !endpoint(l[0]) {
			return nil, fmt.Errorf("malformed reverse dynamic forwarding configuration on ssh config file: %s", l)
		}

		forwards = append(forwards, &ForwardConfig{Source: sourceAddress(l[0])})
	}

	if len(forwards) == 0 {
		return nil, nil
	}

	return forwards, nil
}

// endpoint tells whether the given source of a forwarding configuration names
// something that can be listened on, which is a port with an address in front
// of it or a port on its own.
func endpoint(source string) bool {
	_, port, err := net.SplitHostPort(sourceAddress(source))
	if err != nil {
		return false
	}

	_, err = strconv.ParseUint(port, 10, 16)

	return err == nil
}

// sourceAddress returns the source endpoint of a forwarding configuration as an
// address to listen on, which is what it already is unless the address was left
// out and only a port given.
func sourceAddress(source string) string {
	if strings.HasPrefix(source, ":") {
		return fmt.Sprintf("127.0.0.1%s", source)
	}

	if !strings.Contains(source, ":") {
		return fmt.Sprintf("127.0.0.1:%s", source)
	}

	return source
}

func (r SSHConfigFile) getKey(host string) string {
	id, err := r.sshConfig.Get(host, "IdentityFile")

	if err != nil {
		return ""
	}

	if id != "" {
		if strings.HasPrefix(id, "~") {
			return filepath.Join(os.Getenv("HOME"), id[1:])
		}

		return id
	}

	return ""
}

// SSHHost represents a host configuration extracted from a ssh config file.
type SSHHost struct {
	Hostname      string
	Port          string
	User          string
	Key           string
	IdentityAgent string
	LocalForwards []*ForwardConfig
	// RemoteForwards carries the RemoteForward settings that name a
	// destination, while ReverseDynamicForwards carries the ones that do not.
	RemoteForwards         []*ForwardConfig
	DynamicForwards        []*ForwardConfig
	ReverseDynamicForwards []*ForwardConfig
}

// String returns a string representation of a SSHHost.
func (h SSHHost) String() string {
	return fmt.Sprintf("[hostname=%s, port=%s, user=%s, key=%s, identity_agent=%s, local_forward=%v, remote_forward=%v, dynamic_forward=%v, reverse_dynamic_forward=%v]", h.Hostname, h.Port, h.User, h.Key, h.IdentityAgent, h.LocalForwards, h.RemoteForwards, h.DynamicForwards, h.ReverseDynamicForwards)
}

// ForwardConfig represents a LocalForward, a RemoteForward or a DynamicForward
// configuration for SSHHost. A DynamicForward, and a RemoteForward asking for a
// reverse dynamic forward, carry no destination.
type ForwardConfig struct {
	Source      string
	Destination string
}

// String returns a string representation of ForwardConfig.
func (f ForwardConfig) String() string {
	return fmt.Sprintf("[source=%s, destination=%s]", f.Source, f.Destination)
}
