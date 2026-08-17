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
	// DestinationNotAllowed is the error given when a dynamic or a reverse
	// dynamic tunnel is created with destination addresses, which it has no use
	// for: the destination of each of its connections is asked for by the client
	// that made it.
	DestinationNotAllowed = "cannot create a %s tunnel with destination addresses"
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

	// the listener of a channel that listens on the ssh server is replaced
	// whenever the tunnel reconnects to it, while everything else keeps running,
	// so the state below is only touched while holding the mutex.
	mutex    sync.Mutex
	listener net.Listener
	// client is the connection to the ssh server the listener of a remote or
	// reverse dynamic channel was created on.
	client *ssh.Client
}

// socksChannel tells whether the channels of the given type serve a socks proxy
// on the connections made to them, which is how a dynamic and a reverse dynamic
// channel are told the address each of those connections wants to reach: they
// have no destination of their own.
func socksChannel(channelType string) bool {
	return channelType == "dynamic" || channelType == "reverse-dynamic"
}

// serverListener tells whether the channels of the given type listen on the ssh
// server rather than on the machine the tunnel runs on, which is the case of a
// remote and of a reverse dynamic channel: their listeners are created on the
// connection to the ssh server and die with it.
func serverListener(channelType string) bool {
	return channelType == "remote" || channelType == "reverse-dynamic"
}

// Listen creates the listener the channel accepts connections from, unless it
// already has a usable one, and returns it.
//
// The listener of a remote or reverse dynamic channel is created on the given
// connection to the ssh server and dies with it, so a new one is created every
// time the tunnel connects to the server again. The listener of a local or
// dynamic channel does not depend on the ssh server and is kept for as long as
// the channel lives.
//
// A nil listener is returned, with no error, when the channel is already
// listening on a usable one.
func (ch *SSHChannel) Listen(serverClient *ssh.Client) (net.Listener, error) {
	ch.mutex.Lock()
	defer ch.mutex.Unlock()

	var l net.Listener
	var err error

	switch ch.ChannelType {
	case "local", "dynamic":
		if ch.listener != nil {
			return nil, nil
		}

		l, err = net.Listen("tcp", ch.Source)
	case "remote", "reverse-dynamic":
		if ch.listener != nil && ch.client == serverClient {
			return nil, nil
		}

		if serverClient == nil {
			return nil, fmt.Errorf("channel can't listen on endpoint: no connection to the ssh server")
		}

		l, err = serverClient.Listen("tcp", ch.Source)
	default:
		return nil, fmt.Errorf("channel can't listen on endpoint: unknown channel type %s", ch.ChannelType)
	}

	if err != nil {
		return nil, err
	}

	ch.listener = l
	ch.client = serverClient

	// update the endpoint value with assigned port for the cases where the user
	// haven't explicitily specified one
	ch.Source = boundSource(ch.Source, l.Addr())

	return l, nil
}

// boundSource returns the endpoint a channel listens on: the address it was
// given, carrying the port that was assigned to it when it asked for any.
//
// The address is kept as it was given because the listener of a channel
// listening on the ssh server reports the one it could make sense of rather
// than the one it asked for: a source naming a host comes back as 0.0.0.0,
// which would have every reconnection ask the server to listen on every
// interface instead of on the address it was told.
func boundSource(source string, bound net.Addr) string {
	host, port, err := net.SplitHostPort(source)
	if err != nil || port != "0" {
		return source
	}

	_, assigned, err := net.SplitHostPort(bound.String())
	if err != nil {
		return source
	}

	return net.JoinHostPort(host, assigned)
}

// Close closes the channel listener, releasing the source endpoint and
// unblocking any Accept call in progress. Connections already accepted are
// owned by their caller and are not affected.
func (ch *SSHChannel) Close() error {
	ch.mutex.Lock()
	defer ch.mutex.Unlock()

	if ch.listener == nil {
		return nil
	}

	return ch.listener.Close()
}

// source returns the endpoint the channel listens on, which carries the port
// assigned to it once it is listening.
func (ch *SSHChannel) source() string {
	ch.mutex.Lock()
	defer ch.mutex.Unlock()

	return ch.Source
}

// address returns the address the channel is listening on, which is empty
// while it has no listener.
func (ch *SSHChannel) address() string {
	ch.mutex.Lock()
	defer ch.mutex.Unlock()

	if ch.listener == nil {
		return ""
	}

	return ch.listener.Addr().String()
}

// copy returns a copy of the channel carrying its configuration alone, since
// the listener it is serving can't be handed over.
func (ch *SSHChannel) copy() *SSHChannel {
	ch.mutex.Lock()
	defer ch.mutex.Unlock()

	return &SSHChannel{
		ChannelType: ch.ChannelType,
		Source:      ch.Source,
		Destination: ch.Destination,
	}
}

// String returns a string representation of a SSHChannel
func (ch *SSHChannel) String() string {
	ch.mutex.Lock()
	defer ch.mutex.Unlock()

	// a dynamic or reverse dynamic channel has no destination to tell about:
	// every connection made to it carries the address it wants to reach.
	if ch.Destination == "" {
		return fmt.Sprintf("[source=%s]", ch.Source)
	}

	return fmt.Sprintf("[source=%s, destination=%s]", ch.Source, ch.Destination)
}

// Tunnel represents the ssh tunnel and the channels connecting local and
// remote endpoints.
//
// A Tunnel can only be started once: stopping it releases the source endpoints
// of its channels and the connection to the ssh server for good.
type Tunnel struct {
	// Type tells what kind of port forwarding this tunnel will handle: local,
	// remote, dynamic or reverse-dynamic
	Type string

	// Ready tells when the Tunnel is ready to accept connections, which is as
	// soon as its channels are listening on their source endpoints. A new
	// message is sent every time the tunnel reconnects to the ssh server, and
	// dropped whenever the previous one has not been consumed.
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
	// sshConnection and setSSHClient.
	client *ssh.Client
	// disconnected is closed as soon as the connection to the ssh server held
	// in client is gone, and is replaced along with it.
	disconnected <-chan struct{}
	clientMutex  sync.RWMutex
	reconnect    chan error
	// stop is closed when the tunnel is shutting down, telling the channel
	// goroutines that any error they get from that point on is expected.
	stop     chan struct{}
	stopOnce sync.Once
}

// New creates a new instance of Tunnel.
func New(tunnelType string, server *Server, source, destination []string, config string) (*Tunnel, error) {
	var channels []*SSHChannel
	var err error

	// the type is checked before anything is built from it so that a tunnel
	// asked for by a name that does not exist, as an alias carrying a typo does,
	// is told about it instead of failing on whatever the channels of an unknown
	// type end up missing.
	switch tunnelType {
	case "local", "remote", "dynamic", "reverse-dynamic":
	default:
		return nil, fmt.Errorf("unsupported tunnel type %s", tunnelType)
	}

	channels, err = buildSSHChannels(server.Name, tunnelType, source, destination, config)
	if err != nil {
		return nil, err
	}

	for _, channel := range channels {
		// a dynamic or reverse dynamic channel has no destination of its own:
		// every connection made to it carries the address it wants to reach.
		if channel.Source == "" || (channel.Destination == "" && !socksChannel(channel.ChannelType)) {
			return nil, fmt.Errorf("invalid ssh channel: source=%s, destination=%s", channel.Source, channel.Destination)
		}
	}

	t := &Tunnel{
		Type:      tunnelType,
		Ready:     make(chan bool, 1),
		channels:  channels,
		server:    server,
		reconnect: make(chan error, 1),
		done:      make(chan error, 1),
		stop:      make(chan struct{}),
	}

	return t, nil
}

// sshClient returns the connection to the ssh server currently in use, which
// is nil while the tunnel has none.
func (t *Tunnel) sshClient() *ssh.Client {
	client, _ := t.sshConnection()

	return client
}

// sshConnection returns the connection to the ssh server currently in use
// along with the channel that is closed as soon as that very connection is
// gone, which is how everything bound to it hears it has to stop. Both are nil
// while the tunnel has no connection.
func (t *Tunnel) sshConnection() (*ssh.Client, <-chan struct{}) {
	t.clientMutex.RLock()
	defer t.clientMutex.RUnlock()

	return t.client, t.disconnected
}

// setSSHClient sets the connection to the ssh server to be used from now on,
// together with the channel telling when that connection is gone.
func (t *Tunnel) setSSHClient(client *ssh.Client, disconnected <-chan struct{}) {
	t.clientMutex.Lock()
	defer t.clientMutex.Unlock()

	t.client = client
	t.disconnected = disconnected
}

// Start creates the ssh tunnel and initialized all channels allowing data
// exchange between local and remote enpoints.
func (t *Tunnel) Start() error {
	if t.stopping() {
		return fmt.Errorf("tunnel has been stopped and can't be started again")
	}

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
	t.stopOnce.Do(func() {
		close(t.stop)
	})

	// the listeners of remote channels live on the ssh connection, so they must
	// be closed before the ssh client.
	t.closeChannels()

	if client := t.sshClient(); client != nil {
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

// Listen creates the listeners the tunnel channels are missing and starts
// serving the connections made to them.
//
// It is called again on every reconnection to the ssh server: a local channel
// keeps the listener it already has, and with it the goroutine serving it,
// while a channel listening on the ssh server gets a new listener, and a
// goroutine to serve it, since the previous listener died with the connection
// it was created on.
func (t *Tunnel) Listen() error {
	client, disconnected := t.sshConnection()

	for _, ch := range t.channels {
		listener, err := ch.Listen(client)
		if err != nil {
			return err
		}

		if listener == nil {
			continue
		}

		fields := log.Fields{"source": ch.source()}

		// a dynamic or reverse dynamic channel has no destination to tell about:
		// every connection made to it carries the address it wants to reach.
		if ch.Destination != "" {
			fields["destination"] = ch.Destination
		}

		log.WithFields(fields).Info("tunnel channel is waiting for connection")

		// a connection accepted from a listener created on the ssh server lives
		// on the connection that listener was created on, which is the one just
		// used. The listener of a local or dynamic channel outlives every
		// connection to the ssh server, so nothing accepted from it is bound to
		// one before an address is reached through it.
		var listenerDisconnected <-chan struct{}
		if serverListener(ch.ChannelType) {
			listenerDisconnected = disconnected
		}

		go t.acceptConnections(ch, listener, listenerDisconnected)
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
// disconnected tells when the connection to the ssh server the given connection
// came from is gone, and is nil for a connection that came from a listener of
// its own rather than from the ssh server.
//
// On success the connection is handed over to whoever forwards it, which closes
// it once it is done with it. On error conn is left untouched and closing it is
// up to the caller.
func (t *Tunnel) startChannel(channel *SSHChannel, conn net.Conn, disconnected <-chan struct{}) error {
	var destinationConn net.Conn
	var err error

	log.WithFields(log.Fields{
		"channel": channel,
	}).Debug("connection established")

	switch t.Type {
	case "dynamic":
		// the destination is not known yet: the socks server reads it from the
		// connection itself and reaches it from the ssh server.
		//
		// Whether there is a connection to the ssh server is left for the socks
		// server to find out, so that a client asking for an address while the
		// tunnel is reconnecting is told the address could not be reached,
		// which is an answer it can act on, rather than having its connection
		// dropped in the middle of the protocol. Nothing carries the connection
		// until then, which is what the missing signal says.
		go t.serveSocks(channel, conn, nil, t.sshDial)

		return nil
	case "reverse-dynamic":
		// the destination is not known yet either, and is reached from the
		// machine the tunnel runs on rather than from the ssh server: the client
		// asking for it is the one on the other side.
		go t.serveSocks(channel, conn, disconnected, netDial)

		return nil
	case "local":
		var client *ssh.Client

		// the connection made to the source endpoint is a plain socket that
		// outlives any connection to the ssh server, so what carries it is the
		// one the destination is about to be dialed from.
		client, disconnected = t.sshConnection()
		if client == nil {
			return fmt.Errorf("tunnel channel can't be established: missing connection to the ssh server")
		}

		destinationConn, err = client.Dial("tcp", channel.Destination)
	case "remote":
		destinationConn, err = net.Dial("tcp", channel.Destination)
	default:
		return fmt.Errorf("unknown tunnel type %s", t.Type)
	}

	if err != nil {
		return fmt.Errorf("dial error: %s", err)
	}

	go t.forward(channel, conn, destinationConn, disconnected)

	log.WithFields(log.Fields{
		"channel": channel,
		"server":  t.server,
	}).Debug("tunnel channel has been established")

	return nil
}

// forward carries data both ways between the given connections, one of which
// lives on the connection to the ssh server whose loss is told by disconnected,
// until both directions are done, that connection is gone or the tunnel stops,
// whichever comes first, and closes both of them on its way out.
func (t *Tunnel) forward(channel *SSHChannel, conn, destinationConn net.Conn, disconnected <-chan struct{}) {
	// one of the two connections lives on the connection to the ssh server and
	// dies with it, which the direction reading from it sees as the end of the
	// stream, while the direction reading from the other one is left waiting on
	// a peer that has no reason to ever speak again. Releasing both ends as
	// soon as the ssh connection is gone, or the tunnel stops, is what keeps
	// that direction from outliving what it was forwarding.
	done := make(chan struct{})

	go func() {
		select {
		case <-t.stop:
		case <-disconnected:
		case <-done:
			return
		}

		conn.Close()
		destinationConn.Close()
	}()

	var wg sync.WaitGroup

	wg.Add(2)

	// conn is the connection the client made, whether it reached the source
	// endpoint of a local channel or the one a remote channel asked the ssh
	// server to listen on, so it is the one that can tell who is being served.
	client := conn.RemoteAddr()

	go func() { defer wg.Done(); t.copyConn(channel, client, conn, destinationConn) }()
	go func() { defer wg.Done(); t.copyConn(channel, client, destinationConn, conn) }()

	wg.Wait()
	close(done)

	conn.Close()
	destinationConn.Close()
}

// serveSocks hands the given connection over to the socks server, which reads
// the address the client wants to reach from it and forwards the connection to
// that address through the given dialer.
//
// disconnected tells when the connection to the ssh server the given connection
// came from is gone, and is nil for a connection that did not come from one: a
// dynamic channel only learns what carries a connection when the address it
// asked for is reached.
//
// The connection belongs to the socks server from this point on: it is closed
// as soon as the client is done with it, whether the forwarding succeeded or
// not, as soon as the connection to the ssh server carrying it is gone, or as
// soon as the tunnel stops, whichever comes first.
func (t *Tunnel) serveSocks(channel *SSHChannel, conn net.Conn, disconnected <-chan struct{}, dialer socksDialer) {
	served := make(chan struct{})
	defer close(served)

	// dialed carries what the socks server reached the address asked for with,
	// which only exists once it has been asked for one.
	dialed := make(chan dialedConn, 1)

	// a connection the socks server is still reading a request from has nothing
	// dialed on its behalf yet, so it is only released when the tunnel stops, or
	// when the connection to the ssh server it came from is gone, which keeps a
	// client that connects and says nothing from holding a socket, and the
	// goroutine serving it, for as long as the process lives. A client that
	// reached a dynamic channel is left alone while the tunnel reconnects, so
	// that it is still told the address could not be reached rather than having
	// its connection dropped in the middle of the protocol.
	//
	// Both ends of one already being forwarded are released as soon as the
	// connection to the ssh server carrying them is gone, since neither can be
	// carried any further: the direction reading from the ssh side sees the end
	// of its stream, while the opposite one would be left waiting on a peer that
	// has no reason to ever speak again.
	go func() {
		var target net.Conn

		select {
		case d := <-dialed:
			target = d.conn

			if disconnected == nil {
				disconnected = d.disconnected
			}
		case <-disconnected:
			conn.Close()
			return
		case <-t.stop:
			conn.Close()
			return
		case <-served:
			return
		}

		select {
		case <-disconnected:
		case <-t.stop:
		case <-served:
			return
		}

		conn.Close()
		target.Close()
	}()

	// the socks server is made for this connection alone, so that what it
	// reaches the address asked for with, and the connection to the ssh server
	// it was reached through, are known to whoever is serving this one.
	err := newSocksServer(dialer(dialed)).ServeConn(conn)
	if err == nil {
		return
	}

	// a connection released along with the tunnel, or along with the connection
	// to the ssh server carrying it, fails whatever the socks server was in the
	// middle of, which is this very code letting go of it rather than anything
	// worth reporting.
	if t.stopping() || errors.Is(err, net.ErrClosed) {
		return
	}

	// a single connection going wrong says nothing about the channel serving
	// it, which keeps accepting connections either way, so the error is only
	// worth reporting to whoever is looking into a client that misbehaved.
	log.WithError(err).WithFields(log.Fields{
		"channel": channel,
		"client":  conn.RemoteAddr(),
	}).Debug("error while serving socks connection")
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
		t.setSSHClient(nil, nil)
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

	// disconnected is closed as soon as the connection just established is
	// gone, so that everything bound to it stops with it rather than through a
	// signal a later connection could end up consuming. It is handed over along
	// with the connection so that whoever picks one up gets the signal that
	// belongs to it.
	disconnected := make(chan struct{})

	t.setSSHClient(client, disconnected)

	// both goroutines below are bound to the connection just established, so
	// they are given it instead of reaching for whatever connection the tunnel
	// happens to be using by the time they run.
	//
	// The connection is watched whatever the retry configuration is: the tunnel
	// can only forward anything while it is up, so its loss either starts a
	// reconnection or ends the tunnel.
	go t.keepAlive(client, disconnected)
	go t.watchConnection(client, disconnected)

	log.WithFields(log.Fields{
		"server": t.server,
	}).Debug("connection to the ssh server is established")

	return nil
}

// watchConnection waits for the given connection to be gone, telling everything
// bound to it to stop before reporting the loss to Start.
func (t *Tunnel) watchConnection(client *ssh.Client, disconnected chan<- struct{}) {
	err := client.Wait()

	close(disconnected)

	t.reconnect <- err
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

	// The tunnel is ready as soon as the listeners are bound: connections
	// established before the goroutines serving them get to call Accept just
	// wait on the listener backlog.
	//
	// The signal is best effort, otherwise a tunnel reconnecting more than once
	// would get stuck here whenever no one is consuming Ready.
	select {
	case t.Ready <- true:
	default:
	}
}

// acceptConnections forwards every connection made to the given listener, which
// must be the one the given channel is listening on, until it is closed.
//
// disconnected tells when the connection to the ssh server the listener was
// created on is gone, and is nil for a listener that was not created on one.
func (t *Tunnel) acceptConnections(channel *SSHChannel, listener net.Listener, disconnected <-chan struct{}) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			t.stopServing(channel, fmt.Errorf("error while establishing connection: %v", err))
			return
		}

		// failing to forward a single connection is not fatal to the channel:
		// the listener is still valid and the connection to the ssh server may
		// still be reestablished by the reconnection logic.
		if err := t.startChannel(channel, conn, disconnected); err != nil {
			conn.Close()

			log.WithError(err).WithFields(log.Fields{
				"channel": channel,
			}).Error("error while establishing tunnel channel")
		}
	}
}

// stopServing reports that a channel stopped accepting connections, ending the
// tunnel when it is not something the tunnel can recover from.
func (t *Tunnel) stopServing(channel *SSHChannel, err error) {
	if t.stopping() {
		// the tunnel is shutting down, which is what closed the listener in the
		// first place, so there is no one left to report the error to.
		log.WithError(err).WithFields(log.Fields{
			"channel": channel,
		}).Debug("tunnel channel stopped accepting connections")

		return
	}

	if serverListener(channel.ChannelType) {
		// the listener of a channel listening on the ssh server dies with the
		// connection it was created on, and a new one is created, and served, as
		// soon as the tunnel connects to the server again.
		log.WithError(err).WithFields(log.Fields{
			"channel": channel,
		}).Warn("tunnel channel stopped accepting connections until the tunnel reconnects to the ssh server")

		return
	}

	// the listener of a local channel is not replaced, so the channel is done
	// for and so is the tunnel.
	select {
	case t.done <- err:
	case <-t.stop:
		log.WithError(err).WithFields(log.Fields{
			"channel": channel,
		}).Debug("tunnel channel stopped accepting connections")
	}
}

// stopping tells whether the tunnel is shutting down.
func (t *Tunnel) stopping() bool {
	select {
	case <-t.stop:
		return true
	default:
		return false
	}
}

// keepAlive pings the given connection to the ssh server until it is gone.
func (t *Tunnel) keepAlive(client *ssh.Client, disconnected <-chan struct{}) {
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
		case <-disconnected:
			log.Debug("stop sending keep alive packets")
			return
		}
	}
}

// Channels returns a copy of all channels configured for the tunnel.
func (t *Tunnel) Channels() []*SSHChannel {
	channels := make([]*SSHChannel, len(t.channels))

	for i, c := range t.channels {
		channels[i] = c.copy()
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

// copyConn forwards data in a single direction, on behalf of the given client,
// signalling the end of the stream to the writer once the reader is done while
// leaving the opposite direction free to carry on. Closing both ends is up to
// forward.
func (t *Tunnel) copyConn(channel *SSHChannel, client net.Addr, writer, reader net.Conn) {
	_, err := io.Copy(writer, reader)

	// a half close tells the peer there is nothing else coming without
	// tearing down the connection, which the opposite direction may still
	// be using.
	if cw, ok := writer.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite() //nolint: errcheck
	} else {
		writer.Close() //nolint: errcheck
	}

	// a connection dying while the tunnel is shutting down is expected, and so
	// is the error a direction still reading gets once both ends are released,
	// which is what happens to every connection in flight when the tunnel
	// stops or loses the connection to the ssh server: the plain socket
	// reports that it has been closed, while a ssh channel reports the end of
	// the stream, only ever as the answer to a write since io.Copy takes it
	// for success on a read.
	if err == nil || t.stopping() || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return
	}

	log.WithError(err).WithFields(log.Fields{
		"channel": channel,
		"client":  client,
	}).Debug("error while forwarding connection")
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
	if socksChannel(channelType) {
		if len(destination) > 0 {
			return nil, fmt.Errorf(DestinationNotAllowed, channelType)
		}

		return buildDynamicSSHChannels(serverName, channelType, source, cfgPath)
	}

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

// buildDynamicSSHChannels creates the channels of a dynamic or of a reverse
// dynamic tunnel, which are made of a source endpoint alone: the destination of
// every connection made to them is given by the client through the socks
// protocol.
//
// If no source address is given, they are taken from the SSH configuration
// file.
func buildDynamicSSHChannels(serverName, channelType string, source []string, cfgPath string) ([]*SSHChannel, error) {
	if len(source) == 0 {
		fwds, err := getForwards(channelType, serverName, cfgPath)
		if err != nil {
			return nil, err
		}

		for _, f := range fwds {
			source = append(source, f.Source)
		}
	}

	channels := make([]*SSHChannel, len(source))
	for i, s := range source {
		channels[i] = &SSHChannel{ChannelType: channelType, Source: expandAddress(s)}
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
	} else if channelType == "dynamic" {
		fwds = sh.DynamicForwards
	} else if channelType == "reverse-dynamic" {
		fwds = sh.ReverseDynamicForwards
	} else {
		return nil, fmt.Errorf("could not retrieve forwarding information from ssh configuration file: unsupported channel type %s", channelType)
	}

	// the kind of forward is part of the message because a single setting can
	// hold more than one of them: a RemoteForward naming a destination is a
	// remote forward while one carrying a source endpoint alone is a reverse
	// dynamic forward, so a host can have what is being looked for missing while
	// its configuration is neither missing nor invalid.
	if fwds == nil {
		return nil, fmt.Errorf("%s forward config could not be found or has invalid syntax for host %s", channelType, serverName)
	}

	return fwds, nil
}
