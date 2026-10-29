package mole

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/davrodpin/mole/alias"
	"github.com/davrodpin/mole/fsutils"
	"github.com/davrodpin/mole/rpc"
	"github.com/davrodpin/mole/tunnel"

	"github.com/awnumar/memguard"
	"github.com/go-viper/mapstructure/v2"
	"github.com/gofrs/uuid/v5"
	daemon "github.com/sevlyar/go-daemon"
	log "github.com/sirupsen/logrus"
	"golang.org/x/term"
)

const (
	// IdFlagName is the name of the flag that carries the unique idenfier for a
	// mole instance.
	IdFlagName = "id"
)

// cli keeps a reference to the latest Client object created.
// This is mostly needed to introspect client states during runtime (e.g. a
// remote procedure call that needs to check certain runtime information)
var cli *Client

type Configuration struct {
	Id                string           `json:"id" mapstructure:"id" toml:"id"`
	TunnelType        string           `json:"tunnel-type" mapstructure:"tunnel-type" toml:"tunnel-type"`
	Verbose           bool             `json:"verbose" mapstructure:"verbose" toml:"verbose"`
	Insecure          bool             `json:"insecure" mapstructure:"insecure" toml:"insecure"`
	Detach            bool             `json:"detach" mapstructure:"detach" toml:"detach"`
	Source            AddressInputList `json:"source" mapstructure:"source" toml:"source"`
	Destination       AddressInputList `json:"destination" mapstructure:"destination" toml:"destination"`
	Server            AddressInput     `json:"server" mapstructure:"server" toml:"server"`
	Key               string           `json:"key" mapstructure:"key" toml:"key"`
	KeepAliveInterval time.Duration    `json:"keep-alive-interval" mapstructure:"keep-alive-interva" toml:"keep-alive-interval"`
	ConnectionRetries int              `json:"connection-retries" mapstructure:"connection-retries" toml:"connection-retries"`
	WaitAndRetry      time.Duration    `json:"wait-and-retry" mapstructure:"wait-and-retry" toml:"wait-and-retry"`
	SshAgent          string           `json:"ssh-agent" mapstructure:"ssh-agent" toml:"ssh-agent"`
	Timeout           time.Duration    `json:"timeout" mapstructure:"timeout" toml:"timeout"`
	SshConfig         string           `json:"ssh-config" mapstructure:"ssh-config" toml:"ssh-config"`
	// SocksAuth carries the <user>:<password> the clients of the socks proxy
	// served by a dynamic or a reverse dynamic tunnel have to authenticate
	// with, or the name of the environment variable holding it.
	SocksAuth  string `json:"socks-auth" mapstructure:"socks-auth" toml:"socks-auth"`
	Rpc        bool   `json:"rpc" mapstructure:"rpc" toml:"rpc"`
	RpcAddress string `json:"rpc-address" mapstructure:"rpc-address" toml:"rpc-address"`

	// Tunnels holds the tunnels of an instance started from an alias
	// forwarding through several ssh servers. The flat settings describing a
	// single tunnel are not used then, and keep whatever they held, such as
	// the defaults given on the command line.
	Tunnels []TunnelConfiguration `json:"tunnels,omitempty" mapstructure:"tunnels" toml:"tunnels,omitempty"`
}

// ParseAlias translates a Configuration object to an Alias object.
func (c Configuration) ParseAlias(name string) *alias.Alias {
	return &alias.Alias{
		Name:              name,
		TunnelType:        c.TunnelType,
		Verbose:           c.Verbose,
		Insecure:          c.Insecure,
		Detach:            c.Detach,
		Source:            c.Source.List(),
		Destination:       c.Destination.List(),
		Server:            c.Server.String(),
		Key:               c.Key,
		KeepAliveInterval: c.KeepAliveInterval.String(),
		ConnectionRetries: c.ConnectionRetries,
		WaitAndRetry:      c.WaitAndRetry.String(),
		SshAgent:          c.SshAgent,
		Timeout:           c.Timeout.String(),
		SshConfig:         c.SshConfig,
		SocksAuth:         c.SocksAuth,
		Rpc:               c.Rpc,
		RpcAddress:        c.RpcAddress,
	}
}

// Client manages the overall state of the application based on its configuration.
type Client struct {
	Conf *Configuration
	// Tunnels holds a tunnel for each ssh server the instance forwards
	// through, in the order they are configured.
	Tunnels []*tunnel.Tunnel
	sigs    chan os.Signal
}

// New initializes a new mole's client.
func New(conf *Configuration) *Client {
	cli = &Client{
		Conf: conf,
		sigs: make(chan os.Signal, 1),
	}

	return cli
}

// Start kicks off mole's client, establishing the tunnel and its channels
// based on the client configuration attributes.
func (c *Client) Start() error {
	// memguard is used to securely keep sensitive information in memory.
	// This call makes sure all data will be destroy when the program exits.
	defer memguard.Purge()

	if c.Conf.Id == "" {
		u, err := uuid.NewV4()
		if err != nil {
			return fmt.Errorf("could not auto generate app instance id: %v", err)
		}
		c.Conf.Id = u.String()[:8]
	}

	r, err := c.Running()
	if err != nil {
		log.WithFields(log.Fields{
			"id": c.Conf.Id,
		}).WithError(err).Error("error while checking for another instance using the same id")

		return err
	}

	if r {
		log.WithFields(log.Fields{
			"id": c.Conf.Id,
		}).Error("can't start. Another instance is already using the same id")

		return fmt.Errorf("can't start. Another instance is already using the same id %s", c.Conf.Id)
	}

	log.Infof("instance identifier is %s", c.Conf.Id)

	if c.Conf.Detach {
		var err error

		ic, err := NewDetachedInstance(c.Conf.Id)
		if err != nil {
			log.WithError(err).Errorf("error while creating directory to store mole instance related files")
			return err
		}

		err = startDaemonProcess(ic)
		if err != nil {
			log.WithFields(log.Fields{
				"id": c.Conf.Id,
			}).WithError(err).Error("error starting ssh tunnel")

			return err
		}
	} else {
		go c.handleSignals()
	}

	if c.Conf.Verbose {
		log.SetLevel(log.DebugLevel)
	}

	d, err := fsutils.CreateInstanceDir(c.Conf.Id)
	if err != nil {
		log.WithFields(log.Fields{
			"id": c.Conf.Id,
		}).WithError(err).Error("error creating directory for mole instance")

		return err
	}

	// the tunnels are assigned before the rpc server starts, since it reads
	// them from its own goroutine.
	tunnels, err := createTunnels(c.Conf)
	if err != nil {
		log.WithFields(log.Fields{
			"id": c.Conf.Id,
		}).WithError(err).Error("error creating tunnel")

		return err
	}

	c.Tunnels = tunnels

	if c.Conf.Rpc {
		addr, err := rpc.Start(c.Conf.RpcAddress)
		if err != nil {
			return err
		}

		rd := filepath.Join(d.Dir, "rpc")

		err = ioutil.WriteFile(rd, []byte(addr.String()), 0644)
		if err != nil {
			log.WithFields(log.Fields{
				"id": c.Conf.Id,
			}).WithError(err).Error("error creating file with rpc address")

			return err
		}

		c.Conf.RpcAddress = addr.String()

		log.Infof("rpc server address saved on %s", rd)
	}

	runners := make([]runner, len(tunnels))
	for i, t := range tunnels {
		runners[i] = t
	}

	return runTunnels(runners)
}

// Stop shuts down a detached mole's application instance.
func (c *Client) Stop() error {
	pfp, err := fsutils.GetPidFileLocation(c.Conf.Id)
	if err != nil {
		return fmt.Errorf("error getting information about aliases directory: %v", err)
	}

	if _, err := os.Stat(pfp); os.IsNotExist(err) {
		return fmt.Errorf("no instance of mole with id %s is running", c.Conf.Id)
	}

	p, err := findInstanceProcess(pfp)
	if err != nil {
		return err
	}

	// an instance stopping itself, when it is interrupted, does not get past
	// killing itself, so its files are removed first.
	if p.Pid == os.Getpid() {
		err = c.removeInstanceFiles(pfp)
		if err != nil {
			return err
		}

		return p.Kill()
	}

	// any other instance is gone before its files are removed, since windows
	// refuses to remove a file a running process holds open, which a detached
	// instance does with its log file.
	err = p.Kill()
	if err != nil {
		return err
	}

	// waiting only works on windows, where it is needed: elsewhere the instance
	// is not a child of this process, and its files can be removed while it is
	// still going away.
	p.Wait() //nolint: errcheck

	return c.removeInstanceFiles(pfp)
}

// removeInstanceFiles removes the files kept about the instance: its pid file
// when it is detached, and its whole directory otherwise.
func (c *Client) removeInstanceFiles(pidFile string) error {
	if c.Conf.Detach {
		return os.RemoveAll(pidFile)
	}

	d, err := fsutils.InstanceDir(c.Conf.Id)
	if err != nil {
		return err
	}

	return os.RemoveAll(d.Dir)
}

// findInstanceProcess returns the process whose pid is kept in the given pid
// file, removing the file when that process is no longer running.
//
// go-daemon offers the same through Context.Search, but only on the systems it
// can detach a process on, which leaves windows out. An instance running in
// the foreground stops itself through here when it is interrupted, so the
// lookup has to work everywhere.
func findInstanceProcess(pidFile string) (*os.Process, error) {
	pid, err := daemon.ReadPidFile(pidFile)
	if err != nil {
		return nil, err
	}

	running, err := processExists(pid)
	if err != nil {
		return nil, err
	}

	if !running {
		os.Remove(pidFile)
		return nil, fmt.Errorf("process %d from %s is not running", pid, pidFile)
	}

	return os.FindProcess(pid)
}

func (c *Client) handleSignals() {
	signal.Notify(c.sigs, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	sig := <-c.sigs
	log.Debugf("process signal %s received", sig)
	err := c.Stop()
	if err != nil {
		log.WithError(err).Error("instance not properly stopped")
	}
}

// ShowInstances returns the runtime information about all instances of mole
// running on the system with rpc enabled.
func ShowInstances() (*InstancesRuntime, error) {
	ctx := context.Background()
	data, err := rpc.ShowAll(ctx)
	if err != nil {
		return nil, err
	}

	var instances []Runtime

	err = mapstructure.Decode(data, &instances)
	if err != nil {
		return nil, err
	}

	runtime := InstancesRuntime(instances)

	if len(runtime) == 0 {
		return nil, fmt.Errorf("no instances were found.")
	}

	return &runtime, nil
}

// ShowInstance returns the runtime information about an application instance
// from the given id or alias.
func ShowInstance(id string) (*Runtime, error) {
	ctx := context.Background()
	info, err := rpc.Show(ctx, id)
	if err != nil {
		return nil, err
	}

	var r Runtime
	err = mapstructure.Decode(info, &r)
	if err != nil {
		return nil, err
	}

	return &r, nil
}

// createTunnels creates every tunnel the instance runs, one after the other so
// that the passphrase of a key is never asked for while another one is. Any of
// them failing stops the instance before anything connects.
func createTunnels(conf *Configuration) ([]*tunnel.Tunnel, error) {
	var tunnels []*tunnel.Tunnel

	for _, tc := range conf.tunnels() {
		t, err := createTunnel(tc)
		if err != nil {
			return nil, fmt.Errorf("tunnel %s: %w", tc.Server.String(), err)
		}

		tunnels = append(tunnels, t)
	}

	return tunnels, nil
}

func createTunnel(tc TunnelConfiguration) (*tunnel.Tunnel, error) {
	s, err := tunnel.NewServer(tc.Server.User, tc.Server.Address(), tc.Key, tc.SshAgent, tc.SshConfig)
	if err != nil {
		log.Errorf("error processing server options: %v\n", err)
		return nil, err
	}

	s.Insecure = tc.Insecure
	s.Timeout = tc.Timeout

	err = s.Key.HandlePassphrase(func() ([]byte, error) {
		// an instance can connect to several servers, so the one the key is
		// for is named.
		fmt.Printf("The key provided for %s is secured by a password. Please provide it below:\n", tc.Server.String())
		fmt.Printf("Password: ")
		p, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Printf("\n")
		return p, err
	})

	if err != nil {
		log.WithError(err).Error("error setting up password handling function")
		return nil, err
	}

	log.Debugf("server: %s", s)

	forwards := make([]tunnel.Forward, len(tc.Forwards))

	for i, f := range tc.Forwards {
		var err error

		forwards[i], err = f.forward()
		if err != nil {
			log.Error(err)
			return nil, err
		}
	}

	t, err := tunnel.NewWithForwards(s, forwards, tc.SshConfig)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	t.SocksUser, t.SocksPassword, err = socksCredentials(tc.SocksAuth)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	//TODO need to find a way to require the attributes below to be always set
	// since they are not optional (functionality will break if they are not
	// set and CLI parsing is the one setting the default values).
	// That could be done by make them required in the constructor's signature or
	// by creating a configuration struct for a tunnel object.
	t.ConnectionRetries = tc.ConnectionRetries
	t.WaitAndRetry = tc.WaitAndRetry
	t.KeepAliveInterval = tc.KeepAliveInterval

	return t, nil
}

// socksCredentials splits the user name and the password the clients of a socks
// proxy have to authenticate with out of the value given to the socks-auth
// setting. Both are empty when no value was given, which asks for a proxy that
// serves whoever reaches it.
//
// A value naming an environment variable is read from it, the same way the ssh
// agent address is, so that a password does not have to be given on the command
// line, where anyone looking at the process list can read it, nor kept in the
// alias file.
func socksCredentials(auth string) (string, string, error) {
	if strings.HasPrefix(auth, "$") {
		auth = os.Getenv(auth[1:])
	}

	if auth == "" {
		return "", "", nil
	}

	user, password, given := strings.Cut(auth, ":")

	if !given || user == "" || password == "" {
		return "", "", fmt.Errorf("socks authentication has to be given as <user>:<password>")
	}

	return user, password, nil
}

// appendIdArg adds the id argument to the list of arguments passed by the user.
// This is helpful for scenarios where the process will be detached from the
// parent process and the new child process needs context about the instance.
func appendIdArg(id string, args []string) (newArgs []string) {
	idFlag := fmt.Sprintf("--%s", IdFlagName)

	for _, arg := range args {
		if arg == idFlag {
			return args
		}
	}

	newArgs = make([]string, len(args)+2)
	copy(newArgs, args)
	newArgs[len(args)] = idFlag
	newArgs[len(args)+1] = id

	return
}
