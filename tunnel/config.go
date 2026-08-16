package tunnel

import (
	"fmt"
	"os"
	"path/filepath"
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

	key := r.getKey(host)

	identityAgent, err := r.sshConfig.Get(host, "IdentityAgent")
	if err != nil {
		identityAgent = ""
	}

	return &SSHHost{
		Hostname:        hostname,
		Port:            port,
		User:            user,
		Key:             key,
		IdentityAgent:   identityAgent,
		LocalForwards:   localForwards,
		RemoteForwards:  remoteForwards,
		DynamicForwards: dynamicForwards,
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

		if len(l) < 2 {
			return nil, fmt.Errorf("malformed forwarding configuration on ssh config file: %s", l)
		}

		source := l[0]
		destination := l[1]

		if strings.HasPrefix(source, ":") {
			source = fmt.Sprintf("127.0.0.1%s", source)
		}

		if source != "" && !strings.Contains(source, ":") {
			source = fmt.Sprintf("127.0.0.1:%s", source)
		}

		forwards = append(forwards, &ForwardConfig{Source: source, Destination: destination})
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

		if len(l) != 1 {
			return nil, fmt.Errorf("malformed dynamic forwarding configuration on ssh config file: %s", l)
		}

		source := l[0]

		if strings.HasPrefix(source, ":") {
			source = fmt.Sprintf("127.0.0.1%s", source)
		}

		if !strings.Contains(source, ":") {
			source = fmt.Sprintf("127.0.0.1:%s", source)
		}

		forwards = append(forwards, &ForwardConfig{Source: source})
	}

	if len(forwards) == 0 {
		return nil, nil
	}

	return forwards, nil
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
	Hostname        string
	Port            string
	User            string
	Key             string
	IdentityAgent   string
	LocalForwards   []*ForwardConfig
	RemoteForwards  []*ForwardConfig
	DynamicForwards []*ForwardConfig
}

// String returns a string representation of a SSHHost.
func (h SSHHost) String() string {
	return fmt.Sprintf("[hostname=%s, port=%s, user=%s, key=%s, identity_agent=%s, local_forward=%v, remote_forward=%v, dynamic_forward=%v]", h.Hostname, h.Port, h.User, h.Key, h.IdentityAgent, h.LocalForwards, h.RemoteForwards, h.DynamicForwards)
}

// ForwardConfig represents a LocalForward, a RemoteForward or a DynamicForward
// configuration for SSHHost. A DynamicForward carries no destination.
type ForwardConfig struct {
	Source      string
	Destination string
}

// String returns a string representation of ForwardConfig.
func (f ForwardConfig) String() string {
	return fmt.Sprintf("[source=%s, destination=%s]", f.Source, f.Destination)
}
