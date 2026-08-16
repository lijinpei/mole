package tunnel

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh/agent"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	HostMissing        = "server host has to be provided as part of the server address"
	RandomPortAddress  = "127.0.0.1:0"
	NoDestinationGiven = "cannot create a tunnel without at least one remote address"
)

// Server holds the SSH Server attributes used for the client to connect to it.
type Server struct {
	Name    string
	Address string
	User    string
	Key     *PemKey
	// Insecure is a flag to indicate if the host keys should be validated.
	Insecure bool
	Timeout  time.Duration
	// SSHAgent is the path to the unix socket where an ssh agent is listening
	SSHAgent string
}

// NewServer creates a new instance of Server using $HOME/.ssh/config to
// resolve the missing connection attributes (e.g. user, hostname, port, key
// and ssh agent) required to connect to the remote server, if any.
func NewServer(user, address, key, sshAgent, cfgPath string) (*Server, error) {
	var host string
	var hostname string
	var port string
	var c *SSHConfigFile
	var err error

	host = address
	if strings.Contains(host, ":") {
		args := strings.Split(host, ":")
		host = args[0]
		port = args[1]
	}

	if cfgPath == "" {
		c = NewEmptySSHConfigStruct()
	} else {
		c, err = NewSSHConfigFile(cfgPath)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("error accessing %s: %v", host, err)
			} else {
				c = NewEmptySSHConfigStruct()
			}
		}
	}

	h := c.Get(host)
	hostname = reconcile(h.Hostname, host)
	port = reconcile(port, h.Port)
	user = reconcile(user, h.User)
	key = reconcile(key, h.Key)
	sshAgent = reconcile(sshAgent, h.IdentityAgent)

	if host == "" {
		return nil, fmt.Errorf(HostMissing)
	}

	if hostname == "" {
		return nil, fmt.Errorf("no server hostname (ip) could be found for server %s", host)
	}

	if port == "" {
		port = "22"
	}

	if user == "" {
		return nil, fmt.Errorf("no user could be found for server %s", host)
	}

	if key == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("could not obtain user home directory: %v", err)
		}

		key = filepath.Join(home, ".ssh", "id_rsa")
	}

	pk, err := NewPemKey(key, "")
	if err != nil {
		return nil, fmt.Errorf("error while reading key %s: %v", key, err)
	}

	if strings.HasPrefix(sshAgent, "$") {
		sshAgent = os.Getenv(sshAgent[1:])
	}

	return &Server{
		Name:     host,
		Address:  fmt.Sprintf("%s:%s", hostname, port),
		User:     user,
		Key:      pk,
		SSHAgent: sshAgent,
	}, nil
}

// String provided a string representation of a Server.
func (s Server) String() string {
	return fmt.Sprintf("[name=%s, address=%s, user=%s]", s.Name, s.Address, s.User)
}

type SSHChannel struct {
	ChannelType string
	Source      string
	Destination string
	listener    net.Listener
}

// Listen creates tcp listeners for each channel defined.
func (ch *SSHChannel) Listen(serverClient *ssh.Client) error {
	var l net.Listener
	var err error

	if ch.listener == nil {
		if ch.ChannelType == "local" {
			l, err = net.Listen("tcp", ch.Source)
		} else if ch.ChannelType == "remote" {
			l, err = serverClient.Listen("tcp", ch.Source)
		} else {
			return fmt.Errorf("channel can't listen on endpoint: unknown channel type %s", ch.ChannelType)
		}

		if err != nil {
			return err
		}

		ch.listener = l

		// update the endpoint value with assigned port for the cases where the user
		// haven't explicitily specified one
		ch.Source = l.Addr().String()
	}

	return nil
}

// Accept waits for and returns the next connection to the SSHChannel. The
// caller owns the returned connection and is responsible for closing it.
func (ch *SSHChannel) Accept() (net.Conn, error) {
	conn, err := ch.listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("error while establishing connection: %v", err)
	}

	return conn, nil
}

// Close closes the channel listener, releasing the source endpoint and
// unblocking any Accept call in progress. Connections already accepted are
// owned by their caller and are not affected.
func (ch *SSHChannel) Close() error {
	if ch.listener == nil {
		return nil
	}

	return ch.listener.Close()
}

// String returns a string representation of a SSHChannel
func (ch SSHChannel) String() string {
	return fmt.Sprintf("[source=%s, destination=%s]", ch.Source, ch.Destination)
}

// Tunnel represents the ssh tunnel and the channels connecting local and
// remote endpoints.
type Tunnel struct {
	// Type tells what kind of port forwarding this tunnel will handle: local or remote
	Type string

	// Ready tells when the Tunnel is ready to accept connections
	Ready chan bool

	// KeepAliveInterval is the time period used to send keep alive packets to
	// the remote ssh server
	KeepAliveInterval time.Duration

	// ConnectionRetries is the number os attempts to reconnect to the ssh server
	// when the current connection fails
	ConnectionRetries int

	// WaitAndRetry is the time waited before trying to reconnect to the ssh
	// server
	WaitAndRetry time.Duration

	server   *Server
	channels []*SSHChannel
	done     chan error
	// client is replaced on every reconnection while the goroutines serving
	// the channels keep running, so it must only be reached through
	// sshClient and setSSHClient.
	client        *ssh.Client
	clientMutex   sync.RWMutex
	stopKeepAlive chan bool
	reconnect     chan error
	// stop is closed when the tunnel is shutting down, telling the channel
	// goroutines that any error they get from that point on is expected.
	stop chan struct{}
	// acceptOnce keeps the goroutines accepting connections from the channel
	// listeners from being started again on every reconnection.
	acceptOnce sync.Once
}

// New creates a new instance of Tunnel.
func New(tunnelType string, server *Server, source, destination []string, config string) (*Tunnel, error) {
	var channels []*SSHChannel
	var err error

	channels, err = buildSSHChannels(server.Name, tunnelType, source, destination, config)
	if err != nil {
		return nil, err
	}

	for _, channel := range channels {
		if channel.Source == "" || channel.Destination == "" {
			return nil, fmt.Errorf("invalid ssh channel: source=%s, destination=%s", channel.Source, channel.Destination)
		}
	}

	return &Tunnel{
		Type:          tunnelType,
		Ready:         make(chan bool, 1),
		channels:      channels,
		server:        server,
		reconnect:     make(chan error, 1),
		done:          make(chan error, 1),
		stopKeepAlive: make(chan bool, 1),
		stop:          make(chan struct{}),
	}, nil
}

// sshClient returns the connection to the ssh server currently in use, which
// is nil while the tunnel has none.
func (t *Tunnel) sshClient() *ssh.Client {
	t.clientMutex.RLock()
	defer t.clientMutex.RUnlock()

	return t.client
}

// setSSHClient sets the connection to the ssh server to be used from now on.
func (t *Tunnel) setSSHClient(client *ssh.Client) {
	t.clientMutex.Lock()
	defer t.clientMutex.Unlock()

	t.client = client
}

// Start creates the ssh tunnel and initialized all channels allowing data
// exchange between local and remote enpoints.
func (t *Tunnel) Start() error {
	log.Debugf("tunnel: %s", t)

	t.connect()

	for {
		select {
		case err := <-t.reconnect:
			if err == nil {
				continue
			}

			if t.reconnectionDisabled() {
				log.WithError(err).Error("connection to the ssh server is gone and reconnection is disabled")

				return t.shutdown(err)
			}

			log.WithError(err).Warnf("reconnecting to ssh server")

			t.stopKeepAlive <- true

			if client := t.sshClient(); client != nil {
				client.Close()
			}

			log.Debugf("restablishing the tunnel after disconnection: %s", t)

			// The reconnecion must happens on a goroutine to support the scenario
			// where tunnel.Stop() is called while the tunnel.connect() is getting
			// executed.
			//
			// In an event where tunnel.reconnect receives data from any point of the
			// code rather than tunnel.dial(), which is evoked by tunnel.connect()
			// this code needs to be updated to make sure tunnel.connect() is not
			// schedule in two goroutines at the same time.
			go t.connect()
		case err := <-t.done:
			return t.shutdown(err)
		}
	}
}

// shutdown tears down everything the tunnel has created, returning the error
// that caused it to stop, if any.
func (t *Tunnel) shutdown(err error) error {
	// signal the shutdown before closing the listeners so the channel
	// goroutines know the errors they are about to get from Accept are
	// expected.
	close(t.stop)

	// the listeners of remote channels live on the ssh connection, so they must
	// be closed before the ssh client.
	t.closeChannels()

	if client := t.sshClient(); client != nil {
		t.stopKeepAlive <- true
		client.Close()
	}

	return err
}

// reconnectionDisabled tells whether the tunnel should give up on the ssh
// server as soon as it cannot be reached, which is what a negative number of
// connection retries asks for.
func (t *Tunnel) reconnectionDisabled() bool {
	return t.ConnectionRetries < 0
}

// Listen creates tcp listeners for each channel defined.
func (t *Tunnel) Listen() error {
	client := t.sshClient()

	for _, ch := range t.channels {
		if err := ch.Listen(client); err != nil {
			return err
		}
	}

	return nil
}

// closeChannels closes the listener of every channel defined, releasing the
// source endpoints back to the system.
func (t *Tunnel) closeChannels() {
	for _, ch := range t.channels {
		if err := ch.Close(); err != nil {
			log.WithError(err).WithFields(log.Fields{
				"channel": ch,
			}).Debug("error while closing tunnel channel listener")
		}
	}
}

// startChannel forwards the given connection, which must have been accepted
// from the given channel, to the channel destination.
//
// On success both connections are handed over to copyConn, which closes them
// once either side is done. On error conn is left untouched and closing it is
// up to the caller.
func (t *Tunnel) startChannel(channel *SSHChannel, conn net.Conn) error {
	var err error

	log.WithFields(log.Fields{
		"channel": channel,
	}).Debug("connection established")

	client := t.sshClient()
	if client == nil {
		return fmt.Errorf("tunnel channel can't be established: missing connection to the ssh server")
	}

	var destinationConn net.Conn

	if t.Type == "local" {
		destinationConn, err = client.Dial("tcp", channel.Destination)
	} else if t.Type == "remote" {
		destinationConn, err = net.Dial("tcp", channel.Destination)
	} else {
		return fmt.Errorf("unknown tunnel type %s", t.Type)
	}

	if err != nil {
		return fmt.Errorf("dial error: %s", err)
	}

	go copyConn(conn, destinationConn)
	go copyConn(destinationConn, conn)

	log.WithFields(log.Fields{
		"channel": channel,
		"server":  t.server,
	}).Debug("tunnel channel has been established")

	return nil
}

// Stop cancels the tunnel, closing all connections.
func (t *Tunnel) Stop() {
	t.done <- nil
}

// String returns a string representation of a Tunnel.
func (t *Tunnel) String() string {
	return fmt.Sprintf("[channels:%s, server:%s]", t.channels, t.server.Address)
}

func (t *Tunnel) dial() error {
	if client := t.sshClient(); client != nil {
		client.Close()
		t.setSSHClient(nil)
	}

	c, err := sshClientConfig(*t.server)
	if err != nil {
		return fmt.Errorf("error generating ssh client config: %s", err)
	}

	var client *ssh.Client

	retries := 0
	for {
		if t.ConnectionRetries > 0 && retries == t.ConnectionRetries {
			log.WithFields(log.Fields{
				"server":  t.server,
				"retries": retries,
			}).Error("maximum number of connection retries to the ssh server reached")

			return fmt.Errorf("error while connecting to ssh server")
		}

		client, err = ssh.Dial("tcp", t.server.Address, c)
		if err != nil {
			log.WithError(err).WithFields(log.Fields{
				"server":  t.server,
				"retries": retries,
			}).Error("error while connecting to ssh server")

			if t.reconnectionDisabled() {
				return fmt.Errorf("error while connecting to ssh server: %v", err)
			}

			retries = retries + 1

			time.Sleep(t.WaitAndRetry)
			continue
		}

		break
	}

	t.setSSHClient(client)

	// both goroutines below are bound to the connection just established, so
	// they are given it instead of reaching for whatever connection the tunnel
	// happens to be using by the time they run.
	//
	// The connection is watched whatever the retry configuration is: the tunnel
	// can only forward anything while it is up, so its loss either starts a
	// reconnection or ends the tunnel.
	go t.keepAlive(client)
	go t.waitAndReconnect(client)

	log.WithFields(log.Fields{
		"server": t.server,
	}).Debug("connection to the ssh server is established")

	return nil
}

func (t *Tunnel) waitAndReconnect(client *ssh.Client) {
	t.reconnect <- client.Wait()
}

func (t *Tunnel) connect() {
	var err error

	err = t.dial()
	if err != nil {
		t.done <- err
		return
	}

	err = t.Listen()
	if err != nil {
		t.done <- err
		return
	}

	// The channel listeners are kept across reconnections, so the goroutines
	// serving them are started only once. Starting a new set on every
	// reconnection would pile them up on the very same listeners, leaving the
	// previous ones blocked on Accept for as long as the tunnel lives.
	t.acceptOnce.Do(func() {
		for _, ch := range t.channels {
			log.WithFields(log.Fields{
				"source":      ch.Source,
				"destination": ch.Destination,
			}).Info("tunnel channel is waiting for connection")

			go t.acceptConnections(ch)
		}
	})

	// The tunnel is ready as soon as the listeners are bound: connections
	// established before the goroutines above get to call Accept just wait on
	// the listener backlog.
	//
	// The signal is best effort, otherwise a tunnel reconnecting more than once
	// would get stuck here whenever no one is consuming Ready.
	select {
	case t.Ready <- true:
	default:
	}
}

// acceptConnections forwards every connection made to the source endpoint of
// the given channel until its listener is closed.
func (t *Tunnel) acceptConnections(channel *SSHChannel) {
	for {
		conn, err := channel.Accept()
		if err != nil {
			// the listener is gone, so this channel will never serve another
			// connection.
			select {
			case t.done <- err:
			case <-t.stop:
				// the tunnel is shutting down, which is what closed the
				// listener in the first place, so there is no one left to
				// report the error to.
				log.WithError(err).WithFields(log.Fields{
					"channel": channel,
				}).Debug("tunnel channel stopped accepting connections")
			}

			return
		}

		// failing to forward a single connection is not fatal to the channel:
		// the listener is still valid and the connection to the ssh server may
		// still be reestablished by the reconnection logic.
		if err := t.startChannel(channel, conn); err != nil {
			conn.Close()

			log.WithError(err).WithFields(log.Fields{
				"channel": channel,
			}).Error("error while establishing tunnel channel")
		}
	}
}

func (t *Tunnel) keepAlive(client *ssh.Client) {
	ticker := time.NewTicker(t.KeepAliveInterval)
	defer ticker.Stop()

	log.Debug("start sending keep alive packets")

	for {
		select {
		case <-ticker.C:
			_, _, err := client.SendRequest("keepalive@mole", true, nil)
			if err != nil {
				log.Warnf("error sending keep-alive request to ssh server: %v", err)
			}
		case <-t.stopKeepAlive:
			log.Debug("stop sending keep alive packets")
			return
		}
	}
}

// Channels returns a copy of all channels configured for the tunnel.
func (t *Tunnel) Channels() []*SSHChannel {
	channels := make([]*SSHChannel, len(t.channels))

	for i, c := range t.channels {
		cc := *c
		channels[i] = &cc
	}

	return channels
}

func sshClientConfig(server Server) (*ssh.ClientConfig, error) {
	var signers []ssh.Signer

	if server.Key == nil && server.SSHAgent == "" {
		return nil, fmt.Errorf("at least one authentication method (key or ssh agent) must be present.")
	}

	if server.Key != nil {
		signer, err := server.Key.Parse()
		if err != nil {
			log.WithError(err).Warn("invalid key. Skipping authentication using key.")
		} else {
			signers = append(signers, signer)
		}
	}

	if server.SSHAgent != "" {
		if _, err := os.Stat(server.SSHAgent); err == nil {
			agentSigners, err := getAgentSigners(server.SSHAgent)
			if err != nil {
				return nil, err
			}
			signers = append(signers, agentSigners...)
		} else {
			log.WithError(err).Warnf("%s cannot be read. Will not try to talk to ssh agent", server.SSHAgent)
		}
	}

	if len(signers) == 0 {
		return nil, fmt.Errorf("at least one working authentication method (key or ssh agent) must be present.")
	}

	clb, err := knownHostsCallback(server.Insecure)
	if err != nil {
		return nil, err
	}

	return &ssh.ClientConfig{
		User: server.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signers...),
		},
		HostKeyCallback: clb,
		Timeout:         server.Timeout,
	}, nil
}

func copyConn(writer, reader net.Conn) {
	_, err := io.Copy(writer, reader)
	defer writer.Close()
	defer reader.Close()
	if err != nil {
		log.Errorf("%v", err)
	}
}

func getAgentSigners(addr string) ([]ssh.Signer, error) {
	log.Debugf("ssh agent address: %s", addr)
	conn, err := net.Dial("unix", addr)
	if err != nil {
		return nil, err
	}
	client := agent.NewClient(conn)
	return client.Signers()
}

func knownHostsCallback(insecure bool) (ssh.HostKeyCallback, error) {
	var clb func(hostname string, remote net.Addr, key ssh.PublicKey) error

	if insecure {
		clb = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		}
	} else {
		var err error
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("could not obtain user home directory :%v", err)
		}

		knownHostFile := filepath.Join(home, ".ssh", "known_hosts")
		log.Debugf("known_hosts file used: %s", knownHostFile)

		clb, err = knownhosts.New(knownHostFile)
		if err != nil {
			return nil, fmt.Errorf("error while parsing 'known_hosts' file: %s: %v", knownHostFile, err)
		}
	}

	return clb, nil
}

func reconcile(precident, subsequent string) string {
	if precident != "" {
		return precident
	}

	return subsequent
}

func expandAddress(address string) string {
	if strings.HasPrefix(address, ":") {
		return fmt.Sprintf("127.0.0.1%s", address)
	}

	return address
}

func buildSSHChannels(serverName, channelType string, source, destination []string, cfgPath string) ([]*SSHChannel, error) {
	// if source and destination were not given, try to find the addresses from the
	// SSH configuration file.
	if len(source) == 0 && len(destination) == 0 {
		fwds, err := getForwards(channelType, serverName, cfgPath)
		if err != nil {
			return nil, err
		}

		source = []string{}
		destination = []string{}
		for _, f := range fwds {
			source = append(source, f.Source)
			destination = append(destination, f.Destination)
		}
	} else {

		lSize := len(source)
		rSize := len(destination)

		if lSize > rSize {
			// if there are more source than destination addresses given, the additional
			// addresses must be removed.
			if rSize == 0 {
				return nil, fmt.Errorf(NoDestinationGiven)
			}

			source = source[0:rSize]
		} else if lSize < rSize {
			// if there are more destination than source addresses given, the missing
			// source addresses should be configured as localhost with random ports.
			nl := make([]string, rSize)

			for i := range destination {
				if i < lSize {
					if source[i] != "" {
						nl[i] = source[i]
					} else {
						nl[i] = RandomPortAddress
					}
				} else {
					nl[i] = RandomPortAddress
				}
			}

			source = nl
		}
	}

	for i, addr := range source {
		source[i] = expandAddress(addr)
	}

	for i, addr := range destination {
		destination[i] = expandAddress(addr)
	}

	channels := make([]*SSHChannel, len(destination))
	for i, d := range destination {
		channels[i] = &SSHChannel{ChannelType: channelType, Source: source[i], Destination: d}
	}

	return channels, nil
}

func getForwards(channelType, serverName string, cfgPath string) ([]*ForwardConfig, error) {
	var fwds []*ForwardConfig

	cfg, err := NewSSHConfigFile(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("error reading ssh configuration file: %v", err)
	}

	sh := cfg.Get(serverName)

	if channelType == "local" {
		fwds = sh.LocalForwards
	} else if channelType == "remote" {
		fwds = sh.RemoteForwards
	} else {
		return nil, fmt.Errorf("could not retrieve forwarding information from ssh configuration file: unsupported channel type %s", channelType)
	}

	if fwds == nil {
		return nil, fmt.Errorf("forward config could not be found or has invalid syntax for host %s", serverName)
	}

	return fwds, nil
}
