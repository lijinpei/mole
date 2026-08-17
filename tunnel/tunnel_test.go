package tunnel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const NoSshRetries = -1

// addressesReached counts the addresses the test ssh servers have been asked to
// reach, which is what tells a connection made from the ssh server from one
// made from the machine the tunnel runs on.
var addressesReached atomic.Int64

var sshDir string
var keyPath string
var encryptedKeyPath string
var publicKeyPath string
var knownHostsPath string
var configPath string

func TestServerOptions(t *testing.T) {
	k1, _ := NewPemKey("testdata/.ssh/id_rsa", "")
	k2, _ := NewPemKey("testdata/.ssh/other_key", "")

	tests := []struct {
		user          string
		address       string
		key           string
		config        string
		expected      *Server
		expectedError error
	}{
		{
			"mole_user",
			"172.17.0.10:2222",
			"testdata/.ssh/id_rsa",
			"testdata/.ssh/config",
			&Server{
				Name:    "172.17.0.10",
				Address: "172.17.0.10:2222",
				User:    "mole_user",
				Key:     k1,
			},
			nil,
		},
		{
			"",
			"test",
			"",
			"testdata/.ssh/config",
			&Server{
				Name:    "test",
				Address: "127.0.0.1:2222",
				User:    "mole_test",
				Key:     k1,
			},
			nil,
		},
		{
			"",
			"test.something",
			"",
			"testdata/.ssh/config",
			&Server{
				Name:    "test.something",
				Address: "172.17.0.1:2223",
				User:    "mole_test2",
				Key:     k2,
			},
			nil,
		},
		{
			"mole_user",
			"test:3333",
			"testdata/.ssh/other_key",
			"testdata/.ssh/config",
			&Server{
				Name:    "test",
				Address: "127.0.0.1:3333",
				User:    "mole_user",
				Key:     k2,
			},
			nil,
		},
		{
			"",
			"",
			"",
			"testdata/.ssh/config",
			nil,
			errors.New(HostMissing),
		},
	}

	for _, test := range tests {
		s, err := NewServer(test.user, test.address, test.key, "", test.config)
		if err != nil {
			if test.expectedError != nil {
				if test.expectedError.Error() != err.Error() {
					t.Errorf("error '%v' was expected, but got '%v'", test.expectedError, err)
				}
			} else {
				t.Errorf("%v\n", err)
			}
		}

		if !reflect.DeepEqual(test.expected, s) {
			t.Errorf("unexpected result : expected: %s, result: %s", test.expected, s)
		}
	}
}

func TestLocalTunnel(t *testing.T) {
	c := &tunnelConfig{T: t, TunnelType: "local", Destinations: 1, Insecure: false, ConnectionRetries: NoSshRetries}
	tun, _, _ := prepareTunnel(c)

	select {
	case <-tun.Ready:
		t.Log("tunnel is ready to accept connections")
	case <-time.After(1 * time.Second):
		t.Errorf("error waiting for tunnel to be ready")
		return
	}

	err := validateTunnelConnectivity(t, "ABC", tun)
	if err != nil {
		t.Errorf("%v", err)
	}

	tun.Stop()
}

// A client that is done sending is not done receiving: half closing its side
// of the connection says nothing about the direction carrying the answer, which
// has to be left alone until the endpoint is done with it.
func TestLocalTunnelDoesNotTruncateAfterClientHalfClose(t *testing.T) {
	head := []byte("the first half of the answer|")
	tail := []byte("the second half, written after the client was done sending")

	// the answer is only finished once the client has nothing else to send,
	// which is the whole point: an endpoint that reads a request until the end
	// of the stream can only answer it after that.
	endpoint, err := createTCPServer(func(conn net.Conn) {
		conn.Write(head)

		io.Copy(io.Discard, conn)

		conn.Write(tail)
	})
	if err != nil {
		t.Fatalf("error while creating the endpoint: %v", err)
	}
	defer endpoint.Close()

	c := &tunnelConfig{T: t, TunnelType: "local", Destinations: 1, Destination: endpoint.Addr().String(), Insecure: false, ConnectionRetries: NoSshRetries}
	tun, _, _ := prepareTunnel(c)
	defer tun.Stop()

	select {
	case <-tun.Ready:
		t.Log("tunnel is ready to accept connections")
	case <-time.After(1 * time.Second):
		t.Fatalf("error waiting for tunnel to be ready")
	}

	conn, err := net.Dial("tcp", tun.channels[0].address())
	if err != nil {
		t.Fatalf("error while connecting to the tunnel: %v", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("error while setting a deadline on the connection to the tunnel: %v", err)
	}

	if _, err := conn.Write([]byte("request")); err != nil {
		t.Fatalf("error while sending a request through the tunnel: %v", err)
	}

	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("error while half closing the connection to the tunnel: %v", err)
	}

	expected := append(append([]byte{}, head...), tail...)
	answer := make([]byte, len(expected))

	if _, err := io.ReadFull(conn, answer); err != nil {
		t.Fatalf("the answer was cut short after the client was done sending: %v", err)
	}

	if !bytes.Equal(answer, expected) {
		t.Errorf("expected the answer %q, but got %q", expected, answer)
	}
}

// Half closing a connection leaves the socket alive, so the tunnel has to
// release every connection it is forwarding when it stops or the ones whose
// peer never speaks again would be left behind.
func TestLocalTunnelReleasesConnectionsOnStop(t *testing.T) {
	forwarded := make(chan struct{}, 1)
	release := make(chan struct{})
	defer close(release)

	// an endpoint that says nothing leaves the direction carrying the answer
	// waiting on it, just like the direction carrying the request waits on a
	// client that has nothing else to send.
	endpoint, err := createTCPServer(func(conn net.Conn) {
		forwarded <- struct{}{}

		<-release
	})
	if err != nil {
		t.Fatalf("error while creating the endpoint: %v", err)
	}
	defer endpoint.Close()

	c := &tunnelConfig{T: t, TunnelType: "local", Destinations: 1, Destination: endpoint.Addr().String(), Insecure: false, ConnectionRetries: NoSshRetries}
	tun, _, started := prepareTunnel(c)

	// giving up before the tunnel is stopped would leave it running for the
	// rest of the package, and every test counting goroutines after this one
	// would count the ones it owns.
	stop := sync.OnceFunc(tun.Stop)
	defer stop()

	select {
	case <-tun.Ready:
		t.Log("tunnel is ready to accept connections")
	case <-time.After(1 * time.Second):
		t.Fatalf("error waiting for tunnel to be ready")
	}

	conn, err := net.Dial("tcp", tun.channels[0].address())
	if err != nil {
		t.Fatalf("error while connecting to the tunnel: %v", err)
	}
	defer conn.Close()

	// the connection is only being forwarded, and so owned by the tunnel, once
	// it reached the endpoint.
	select {
	case <-forwarded:
	case <-time.After(5 * time.Second):
		t.Fatalf("the connection never reached the endpoint through the tunnel")
	}

	stop()

	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatalf("the tunnel never stopped")
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("error while setting a deadline on the connection to the tunnel: %v", err)
	}

	// nothing is ever sent to a client whose endpoint said nothing, so a read
	// can only end by the tunnel letting go of the connection. It ends the same
	// way whether it was closed or only half closed, though, so this catches a
	// connection left untouched while the goroutine count below is what tells a
	// released connection from a half closed one.
	if _, err := conn.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("expected the connection to be released when the tunnel stopped, but reading from it returned %v", err)
	}

	// a connection nobody is forwarding anymore must not leave the goroutines
	// that were carrying it behind either.
	if err := waitForGoroutines(forwardFrame, 0, 5*time.Second); err != nil {
		t.Errorf("the tunnel left connections behind when it stopped: %v", err)
	}
}

// The connections a tunnel is forwarding live on its connection to the ssh
// server: losing it leaves the direction reading from the ssh side at the end
// of its stream and the opposite one waiting on a client that has no reason to
// ever speak again, so both ends have to be released even though the tunnel
// itself carries on and reconnects.
func TestLocalTunnelReleasesConnectionsOnReconnection(t *testing.T) {
	forwarded := make(chan struct{}, 1)
	release := make(chan struct{})
	defer close(release)

	endpoint, err := createTCPServer(func(conn net.Conn) {
		forwarded <- struct{}{}

		<-release
	})
	if err != nil {
		t.Fatalf("error while creating the endpoint: %v", err)
	}
	defer endpoint.Close()

	c := &tunnelConfig{T: t, TunnelType: "local", Destinations: 1, Destination: endpoint.Addr().String(), Insecure: false, ConnectionRetries: 3}
	tun, ssh, _ := prepareTunnel(c)
	defer tun.Stop()

	select {
	case <-tun.Ready:
		t.Log("tunnel is ready to accept connections")
	case <-time.After(1 * time.Second):
		t.Fatalf("error waiting for tunnel to be ready")
	}

	conn, err := net.Dial("tcp", tun.channels[0].address())
	if err != nil {
		t.Fatalf("error while connecting to the tunnel: %v", err)
	}
	defer conn.Close()

	select {
	case <-forwarded:
	case <-time.After(5 * time.Second):
		t.Fatalf("the connection never reached the endpoint through the tunnel")
	}

	ssh.Close()

	if _, err := createSSHServer(t, ssh.Addr().String(), keyPath); err != nil {
		t.Fatalf("error while recreating ssh server: %v", err)
	}

	select {
	case <-tun.Ready:
		t.Log("tunnel is ready to accept connections")
	case <-time.After(10 * time.Second): // this is the maximum timeout based on the retries attempts
		t.Fatalf("error waiting for the tunnel to reconnect to the ssh server")
	}

	// the tunnel is serving again on a new connection to the ssh server, which
	// the connection made through the previous one can't be carried on.
	if err := waitForGoroutines(forwardFrame, 0, 5*time.Second); err != nil {
		t.Errorf("the tunnel kept forwarding a connection whose ssh channel is gone: %v", err)
	}
}

// The end of a connection is not an error: whichever direction finishes first
// tells the other end there is nothing else coming, which is the whole of it,
// and the opposite direction is left to finish on its own.
func TestLocalTunnelTeardownIsQuiet(t *testing.T) {
	request := []byte("request")
	answer := []byte("the whole answer")

	endpoint, err := createTCPServer(func(conn net.Conn) {
		// the request is taken before answering so that the connection is not
		// closed with data still waiting to be read on it, which sends a reset
		// that could take the answer with it.
		io.ReadFull(conn, make([]byte, len(request)))

		conn.Write(answer)
	})
	if err != nil {
		t.Fatalf("error while creating the endpoint: %v", err)
	}
	defer endpoint.Close()

	c := &tunnelConfig{T: t, TunnelType: "local", Destinations: 1, Destination: endpoint.Addr().String(), Insecure: false, ConnectionRetries: NoSshRetries}
	tun, _, _ := prepareTunnel(c)
	defer tun.Stop()

	select {
	case <-tun.Ready:
		t.Log("tunnel is ready to accept connections")
	case <-time.After(1 * time.Second):
		t.Fatalf("error waiting for tunnel to be ready")
	}

	// the hook records everything logged from this point on, on the logger the
	// whole package shares, so it is installed as late as possible, read as
	// soon as the connection it is watching is gone, and taken back out rather
	// than left recording every test that runs after this one.
	logger := log.StandardLogger()
	hooks := logger.ReplaceHooks(make(log.LevelHooks))
	defer logger.ReplaceHooks(hooks)

	hook := logtest.NewGlobal()

	conn, err := net.Dial("tcp", tun.channels[0].address())
	if err != nil {
		t.Fatalf("error while connecting to the tunnel: %v", err)
	}
	defer conn.Close()

	client := conn.LocalAddr().String()

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("error while setting a deadline on the connection to the tunnel: %v", err)
	}

	if _, err := conn.Write(request); err != nil {
		t.Fatalf("error while sending a request through the tunnel: %v", err)
	}

	// the endpoint is done as soon as it answered, which is what tears the
	// connection down, so reading it all is also waiting for the teardown to
	// reach the client.
	received, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("error while reading the answer through the tunnel: %v", err)
	}

	if !bytes.Equal(received, answer) {
		t.Fatalf("expected the answer %q, but got %q", answer, received)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("error while closing the connection to the tunnel: %v", err)
	}

	// the error a connection going away gives to whoever is reading from it is
	// reported by the goroutine carrying that direction, so all there is to do
	// is give it the chance to do so.
	time.Sleep(1 * time.Second)

	for _, entry := range hook.AllEntries() {
		if entry.Level != log.ErrorLevel {
			continue
		}

		// the tunnels of the tests that ran before are still being torn down
		// in the background, and complain about their own connections while
		// they are at it, so only what was said about this one counts.
		if !strings.Contains(fmt.Sprint(entry.Message, entry.Data), client) {
			continue
		}

		t.Errorf("closing a connection should be quiet, but it logged: %s %v", entry.Message, entry.Data)
	}
}

func TestRemoteTunnel(t *testing.T) {
	c := &tunnelConfig{T: t, TunnelType: "remote", Destinations: 1, Insecure: true, ConnectionRetries: NoSshRetries}
	tun, _, _ := prepareTunnel(c)

	select {
	case <-tun.Ready:
		t.Log("tunnel is ready to accept connections")
	case <-time.After(1 * time.Second):
		t.Errorf("error waiting for tunnel to be ready")
		return
	}

	err := validateTunnelConnectivity(t, "ABC", tun)
	if err != nil {
		t.Errorf("%v", err)
	}

	tun.Stop()
}

func TestTunnelInsecure(t *testing.T) {
	c := &tunnelConfig{T: t, TunnelType: "local", Destinations: 1, Insecure: true, ConnectionRetries: NoSshRetries}
	tun, _, _ := prepareTunnel(c)

	select {
	case <-tun.Ready:
		t.Log("tunnel is ready to accept connections")
	case <-time.After(1 * time.Second):
		t.Errorf("error waiting for tunnel to be ready")
		return
	}

	err := validateTunnelConnectivity(t, "ABC", tun)
	if err != nil {
		t.Errorf("%v", err)
	}

	tun.Stop()
}

func TestTunnelMultipleDestinations(t *testing.T) {
	c := &tunnelConfig{T: t, TunnelType: "local", Destinations: 2, Insecure: false, ConnectionRetries: NoSshRetries}
	tun, _, _ := prepareTunnel(c)

	select {
	case <-tun.Ready:
		t.Log("tunnel is ready to accept connections")
	case <-time.After(1 * time.Second):
		t.Errorf("error waiting for tunnel to be ready")
		return
	}

	err := validateTunnelConnectivity(t, "ABC", tun)
	if err != nil {
		t.Errorf("%v", err)
	}

	tun.Stop()
}

func TestTunnelStopReleasesSourceEndpoints(t *testing.T) {
	c := &tunnelConfig{T: t, TunnelType: "local", Destinations: 2, Insecure: false, ConnectionRetries: NoSshRetries}
	tun, _, _ := prepareTunnel(c)

	select {
	case <-tun.Ready:
		t.Log("tunnel is ready to accept connections")
	case <-time.After(1 * time.Second):
		t.Errorf("error waiting for tunnel to be ready")
		return
	}

	err := validateTunnelConnectivity(t, "ABC", tun)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	sources := []string{}
	for _, sshChan := range tun.channels {
		sources = append(sources, sshChan.address())
	}

	tun.Stop()

	// the tunnel is stopped asynchronously, so give it a chance to close the
	// listeners before checking the source endpoints have been released.
	for _, source := range sources {
		if err := waitForClosedEndpoint(source, 2*time.Second); err != nil {
			t.Errorf("%v", err)
		}
	}
}

// Stopping a tunnel gives up the source endpoints and the connection to the
// ssh server for good, so it can't be started again.
func TestTunnelCannotBeStartedAgain(t *testing.T) {
	c := &tunnelConfig{T: t, TunnelType: "local", Destinations: 1, Insecure: false, ConnectionRetries: NoSshRetries}
	tun, _, started := prepareTunnel(c)

	select {
	case <-tun.Ready:
		t.Log("tunnel is ready to accept connections")
	case <-time.After(1 * time.Second):
		t.Errorf("error waiting for tunnel to be ready")
		return
	}

	tun.Stop()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Errorf("the tunnel never stopped")
		return
	}

	restarted := make(chan error, 1)
	go func() { restarted <- tun.Start() }()

	select {
	case err := <-restarted:
		if err == nil {
			t.Errorf("a tunnel that has been stopped should not be able to start again")
		}
	case <-time.After(2 * time.Second):
		t.Errorf("a tunnel that has been stopped should not be able to start again")
	}
}

// waitForClosedEndpoint waits until no connection can be established to the
// given address anymore, returning an error if that does not happen within the
// given timeout.
func waitForClosedEndpoint(address string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err != nil {
			return nil
		}
		conn.Close()

		if time.Now().After(deadline) {
			return fmt.Errorf("endpoint %s is still accepting connections after the tunnel has been stopped", address)
		}

		time.Sleep(50 * time.Millisecond)
	}
}

func TestReconnectSSHServer(t *testing.T) {
	c := &tunnelConfig{T: t, TunnelType: "local", Destinations: 1, Insecure: false, ConnectionRetries: 3}
	tun, ssh, _ := prepareTunnel(c)

	select {
	case <-tun.Ready:
		t.Log("tunnel is ready to accept connections")
	case <-time.After(1 * time.Second):
		t.Errorf("error waiting for tunnel to be ready")
		return
	}

	err := validateTunnelConnectivity(t, "ABC", tun)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	ssh.Close()

	// http request should fail since ssh server is not running
	err = validateTunnelConnectivity(t, "DEF", tun)
	if err == nil {
		t.Errorf("%v", err)
		return
	}

	_, err = createSSHServer(t, ssh.Addr().String(), keyPath)
	if err != nil {
		t.Errorf("error while recreating ssh server: %s", err)
		return
	}

	select {
	case <-tun.Ready:
		t.Log("tunnel is ready to accept connections")
	case <-time.After(10 * time.Second): // this is the maximum timeout based on the retries attempts
		t.Errorf("error waiting for tunnel to be ready")
		return
	}

	err = validateTunnelConnectivity(t, "GHJ", tun)
	if err != nil {
		t.Errorf("%v", err)
	}

	tun.Stop()
}

func TestReconnectDoesNotPileUpGoroutines(t *testing.T) {
	c := &tunnelConfig{T: t, TunnelType: "local", Destinations: 2, Insecure: false, ConnectionRetries: 3}
	tun, ssh, _ := prepareTunnel(c)

	select {
	case <-tun.Ready:
		t.Log("tunnel is ready to accept connections")
	case <-time.After(1 * time.Second):
		t.Errorf("error waiting for tunnel to be ready")
		return
	}

	err := validateTunnelConnectivity(t, "ABC", tun)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	channels := len(tun.channels)

	if err := waitForGoroutines(acceptFrame, channels, 2*time.Second); err != nil {
		t.Errorf("%v", err)
		return
	}

	if err := waitForGoroutines(keepAliveFrame, 1, 2*time.Second); err != nil {
		t.Errorf("%v", err)
		return
	}

	ssh.Close()

	_, err = createSSHServer(t, ssh.Addr().String(), keyPath)
	if err != nil {
		t.Errorf("error while recreating ssh server: %s", err)
		return
	}

	select {
	case <-tun.Ready:
		t.Log("tunnel is ready to accept connections")
	case <-time.After(10 * time.Second): // this is the maximum timeout based on the retries attempts
		t.Errorf("error waiting for tunnel to be ready")
		return
	}

	err = validateTunnelConnectivity(t, "GHJ", tun)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	// the listeners survive the reconnection, so the goroutines serving them
	// must be the same ones, and the connection that has been replaced must not
	// have left its keep alive behind
	if err := waitForGoroutines(acceptFrame, channels, 2*time.Second); err != nil {
		t.Errorf("reconnection did not reuse the goroutines accepting connections: %v", err)
	}

	if err := waitForGoroutines(keepAliveFrame, 1, 2*time.Second); err != nil {
		t.Errorf("reconnection left more than one keep alive behind: %v", err)
	}

	tun.Stop()
}

// The listener of a remote channel is created on the connection to the ssh
// server and dies with it, so the tunnel has to create a new one, and serve it,
// every time it reconnects.
func TestRemoteChannelListensAgainAfterReconnection(t *testing.T) {
	c := &tunnelConfig{T: t, TunnelType: "remote", Destinations: 1, Insecure: true, ConnectionRetries: 3}
	tun, ssh, started := prepareTunnel(c)

	select {
	case <-tun.Ready:
		t.Log("tunnel is ready to accept connections")
	case <-time.After(1 * time.Second):
		t.Errorf("error waiting for tunnel to be ready")
		return
	}

	channel := tun.channels[0]
	listener, client := channelListener(channel)

	if listener == nil {
		t.Errorf("the remote channel is not listening")
		return
	}

	if err := waitForGoroutines(acceptFrame, 1, 2*time.Second); err != nil {
		t.Errorf("%v", err)
		return
	}

	ssh.Close()

	_, err := createSSHServer(t, ssh.Addr().String(), keyPath)
	if err != nil {
		t.Errorf("error while recreating ssh server: %s", err)
		return
	}

	select {
	case <-tun.Ready:
		t.Log("tunnel is ready to accept connections")
	case err := <-started:
		t.Errorf("the tunnel should have reconnected to the ssh server, but it stopped: %v", err)
		return
	case <-time.After(10 * time.Second): // this is the maximum timeout based on the retries attempts
		t.Errorf("error waiting for tunnel to be ready")
		return
	}

	newListener, newClient := channelListener(channel)

	if newClient == client {
		t.Errorf("the remote channel is still bound to the connection to the ssh server that is gone")
		return
	}

	if newClient != tun.sshClient() {
		t.Errorf("the remote channel should be listening on the connection to the ssh server the tunnel is using now")
	}

	if newListener == listener {
		t.Errorf("the remote channel is still listening on the listener that died with the previous connection to the ssh server")
	}

	// the goroutine serving the listener that is gone must have been replaced
	// by one serving the listener created on the new connection
	if err := waitForGoroutines(acceptFrame, 1, 2*time.Second); err != nil {
		t.Errorf("%v", err)
	}

	tun.Stop()
}

// channelListener returns what the given channel is listening on and the
// connection to the ssh server that listener was created on.
func channelListener(ch *SSHChannel) (net.Listener, *ssh.Client) {
	ch.mutex.Lock()
	defer ch.mutex.Unlock()

	return ch.listener, ch.client
}

// A negative number of connection retries asks the tunnel to give up on the
// ssh server as soon as it cannot be reached, which must be reported instead
// of leaving a tunnel behind that can't forward anything.
func TestTunnelFailsToStartWhenReconnectionIsDisabled(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Errorf("could not reserve an address for the test: %v", err)
		return
	}
	address := l.Addr().String()
	l.Close()

	srv, err := NewServer("mole", address, "", "", "testdata/.ssh/config")
	if err != nil {
		t.Errorf("could not create server: %v", err)
		return
	}
	srv.Insecure = true
	srv.Timeout = 1 * time.Second

	hl, _ := createHttpServer()

	tun, err := New("local", srv, []string{"127.0.0.1:0"}, []string{hl.Addr().String()}, configPath)
	if err != nil {
		t.Errorf("could not create tunnel: %v", err)
		return
	}
	tun.ConnectionRetries = NoSshRetries
	tun.WaitAndRetry = 100 * time.Millisecond
	tun.KeepAliveInterval = 100 * time.Millisecond

	started := make(chan error, 1)
	go func() { started <- tun.Start() }()

	select {
	case err := <-started:
		if err == nil {
			t.Errorf("the tunnel should not have started without a connection to the ssh server")
		}
	case <-time.After(5 * time.Second):
		t.Errorf("the tunnel should have given up on the ssh server instead of waiting for connections it can't forward")
	}
}

// A negative number of connection retries also means the tunnel must stop as
// soon as the connection it is using is lost.
func TestTunnelStopsWhenReconnectionIsDisabled(t *testing.T) {
	c := &tunnelConfig{T: t, TunnelType: "local", Destinations: 1, Insecure: false, ConnectionRetries: NoSshRetries}
	tun, ssh, started := prepareTunnel(c)

	select {
	case <-tun.Ready:
		t.Log("tunnel is ready to accept connections")
	case <-time.After(1 * time.Second):
		t.Errorf("error waiting for tunnel to be ready")
		return
	}

	err := validateTunnelConnectivity(t, "ABC", tun)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	ssh.Close()

	select {
	case err := <-started:
		if err == nil {
			t.Errorf("the tunnel should have reported the loss of the connection to the ssh server")
		}
	case <-time.After(5 * time.Second):
		t.Errorf("the tunnel should have stopped after losing the connection to the ssh server")
	}
}

// Zero connection retries asks the tunnel to never give up on the ssh server.
func TestTunnelNeverGivesUpReconnecting(t *testing.T) {
	c := &tunnelConfig{T: t, TunnelType: "local", Destinations: 1, Insecure: false, ConnectionRetries: 0}
	tun, ssh, started := prepareTunnel(c)

	select {
	case <-tun.Ready:
		t.Log("tunnel is ready to accept connections")
	case <-time.After(1 * time.Second):
		t.Errorf("error waiting for tunnel to be ready")
		return
	}

	err := validateTunnelConnectivity(t, "ABC", tun)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	ssh.Close()

	_, err = createSSHServer(t, ssh.Addr().String(), keyPath)
	if err != nil {
		t.Errorf("error while recreating ssh server: %s", err)
		return
	}

	select {
	case <-tun.Ready:
		t.Log("tunnel is ready to accept connections")
	case err := <-started:
		t.Errorf("the tunnel should have kept trying to reconnect, but it stopped: %v", err)
		return
	case <-time.After(10 * time.Second):
		t.Errorf("the tunnel never reconnected to the ssh server")
		return
	}

	err = validateTunnelConnectivity(t, "GHJ", tun)
	if err != nil {
		t.Errorf("%v", err)
	}

	tun.Stop()
}

const (
	acceptFrame     = "tunnel.(*Tunnel).acceptConnections("
	keepAliveFrame  = "tunnel.(*Tunnel).keepAlive("
	forwardFrame    = "tunnel.(*Tunnel).forward("
	serveSocksFrame = "tunnel.(*Tunnel).serveSocks("
)

// countGoroutines returns the number of goroutines currently running the
// function identified by the given stack frame.
func countGoroutines(frame string) int {
	for size := 1 << 16; ; size *= 2 {
		buf := make([]byte, size)

		// a truncated dump would leave goroutines out of the count, so the
		// buffer grows until it fits the whole thing.
		if n := runtime.Stack(buf, true); n < size {
			return strings.Count(string(buf[:n]), frame)
		}
	}
}

// waitForGoroutines waits until exactly the given number of goroutines is
// running the function identified by the given stack frame, which keeps the
// counting from being thrown off by goroutines of a previous test that have not
// been scheduled to finish yet.
func waitForGoroutines(frame string, expected int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for {
		goroutines := countGoroutines(frame)
		if goroutines == expected {
			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("expected %d goroutines running %s but %d are running", expected, frame, goroutines)
		}

		time.Sleep(20 * time.Millisecond)
	}
}

func validateTunnelConnectivity(t *testing.T, expected string, tun *Tunnel) error {
	for _, sshChan := range tun.channels {
		url := fmt.Sprintf("http://%s/%s", sshChan.address(), expected)
		timeout := time.Duration(500 * time.Millisecond)
		client := http.Client{
			Timeout: timeout,
		}
		resp, err := client.Get(url)
		if err != nil {
			return fmt.Errorf("error while making http request: %v", err)
		}
		defer resp.Body.Close()

		body, _ := ioutil.ReadAll(resp.Body)
		response := string(body)

		if expected != response {
			return fmt.Errorf("expected: %s, value: %s", expected, response)
		}
	}

	return nil
}

func TestMain(m *testing.M) {
	err := prepareTestEnv()
	if err != nil {
		fmt.Printf("could not start test suite: %v\n", err)
		os.RemoveAll(sshDir)
		os.Exit(1)
	}

	code := m.Run()

	os.RemoveAll(sshDir)

	os.Exit(code)
}

func TestBuildSSHChannels(t *testing.T) {
	tests := []struct {
		serverName    string
		source        []string
		destination   []string
		config        string
		expected      int
		expectedError error
	}{
		{
			serverName:    "test",
			source:        []string{":3360"},
			destination:   []string{":3360"},
			config:        "testdata/.ssh/config",
			expected:      1,
			expectedError: nil,
		},
		{
			serverName:    "test",
			source:        []string{":3360", ":8080"},
			destination:   []string{":3360", ":8080"},
			config:        "testdata/.ssh/config",
			expected:      2,
			expectedError: nil,
		},
		{
			serverName:    "test",
			source:        []string{},
			destination:   []string{":3360"},
			config:        "testdata/.ssh/config",
			expected:      1,
			expectedError: nil,
		},
		{
			serverName:    "test",
			source:        []string{":3360"},
			destination:   []string{":3360", ":8080"},
			config:        "testdata/.ssh/config",
			expected:      2,
			expectedError: nil,
		},
		{
			serverName:    "hostWithLocalForward",
			source:        []string{},
			destination:   []string{},
			config:        "testdata/.ssh/config",
			expected:      1,
			expectedError: nil,
		},
		{
			serverName:    "hostWithTwoLocalForwards",
			source:        []string{},
			destination:   []string{},
			config:        "testdata/.ssh/config",
			expected:      2,
			expectedError: nil,
		},
		{
			serverName:    "test",
			source:        []string{":3360", ":8080"},
			destination:   []string{":3360"},
			config:        "testdata/.ssh/config",
			expected:      1,
			expectedError: nil,
		},
		{
			serverName:    "test",
			source:        []string{":3360"},
			destination:   []string{},
			config:        "testdata/.ssh/config",
			expected:      0,
			expectedError: fmt.Errorf(NoDestinationGiven),
		},
	}

	for testId, test := range tests {
		sshChannels, err := buildSSHChannels(test.serverName, "local", test.source, test.destination, test.config)
		if err != nil {
			if test.expectedError != nil {
				if test.expectedError.Error() != err.Error() {
					t.Errorf("error '%v' was expected, but got '%v'", test.expectedError, err)
				}
			} else {
				t.Errorf("unable to build ssh channels objects for test %d: %v", testId, err)
			}
		}

		if test.expected != len(sshChannels) {
			t.Errorf("wrong number of ssh channel objects created for test %d: expected: %d, value: %d", testId, test.expected, len(sshChannels))
		}

		sourceSize := len(test.source)
		destinationSize := len(test.destination)

		// check if the source addresses match only if any address is given
		if sourceSize > 0 && destinationSize > 0 {
			for i, sshChannel := range sshChannels {
				source := ""
				if i < sourceSize {
					source = test.source[i]
				} else {
					source = RandomPortAddress
				}

				source = expandAddress(source)

				if sshChannel.Source != source {
					t.Errorf("source address don't match for test %d: expected: %s, value: %s", testId, sshChannel.Source, source)
				}

			}
		}
	}
}

type tunnelConfig struct {
	T          *testing.T
	TunnelType string

	// Destinations indicates how many endpoints should be available through the
	// tunnel.
	Destinations int

	// Destination is the address a local tunnel forwards to. An http server is
	// created for every destination, and the tunnel wired to it, when no
	// address is given.
	Destination string

	Insecure          bool
	ConnectionRetries int
}

// prepareTunnel creates a Tunnel object making sure all infrastructure
// dependencies (ssh and http servers) are ready.
//
// The 'remotes' argument tells how many remote endpoints will be available
// through the tunnel.
func prepareTunnel(config *tunnelConfig) (tun *Tunnel, ssh net.Listener, started <-chan error) {
	ssh, err := createSSHServer(config.T, "", keyPath)
	if err != nil {
		config.T.Errorf("error while creating ssh server: %s", err)
		return
	}

	srv, _ := NewServer("mole", ssh.Addr().String(), "", "", "testdata/.ssh/config")

	srv.Insecure = config.Insecure

	if !config.Insecure {
		err = generateKnownHosts(ssh.Addr(), publicKeyPath, knownHostsPath)
		if err != nil {
			config.T.Errorf("error generating known hosts file for tests: %v\n", err)
			return
		}

	}

	// only a local tunnel is wired to a destination given by the caller, so a
	// test giving one to any other kind would be reaching an endpoint the
	// tunnel is not forwarding to without ever hearing about it.
	if config.Destination != "" && config.TunnelType != "local" {
		config.T.Fatalf("a destination address can only be given to a local tunnel, not to a %s one", config.TunnelType)
		return
	}

	source := make([]string, config.Destinations)
	destination := make([]string, config.Destinations)

	for i := 0; i <= (config.Destinations - 1); i++ {
		if config.TunnelType == "local" {
			address := config.Destination

			if address == "" {
				l, _ := createHttpServer()
				address = l.Addr().String()
			}

			source[i] = "127.0.0.1:0"
			destination[i] = address
		} else if config.TunnelType == "remote" {
			l, _ := createHttpServer()

			// the source endpoint is listened on by the ssh server, which is
			// asked for any free port, while the destination is reached from
			// here.
			source[i] = "127.0.0.1:0"
			destination[i] = l.Addr().String()
		} else {
			config.T.Errorf("could not configure destination endpoints for testing: %v\n", err)
			return
		}
	}

	tun, _ = New(config.TunnelType, srv, source, destination, configPath)
	tun.ConnectionRetries = config.ConnectionRetries
	tun.WaitAndRetry = 3 * time.Second
	tun.KeepAliveInterval = 10 * time.Second

	// the value returned by Tunnel.Start can't be given to *testing.T from
	// here: it would be reported after the test that created the tunnel is
	// over, failing it. Tests that care about it read the channel instead.
	result := make(chan error, 1)

	go func(tun *Tunnel) {
		result <- tun.Start()
	}(tun)

	return tun, ssh, result
}

func prepareTestEnv() error {
	home := "testdata"
	fixtureDir := filepath.Join(home, "dotssh")
	testDir := filepath.Join(home, ".ssh")

	keyPath = filepath.Join(testDir, "id_rsa")
	encryptedKeyPath = filepath.Join(testDir, "id_rsa_encrypted")
	publicKeyPath = filepath.Join(testDir, "id_rsa.pub")
	knownHostsPath = filepath.Join(testDir, "known_hosts")
	configPath = filepath.Join(testDir, "config")
	sshDir = testDir

	fixtures := []map[string]string{
		{
			"from": filepath.Join(fixtureDir, "config"),
			"to":   filepath.Join(testDir, "config"),
		},
		{
			"from": filepath.Join(fixtureDir, "id_rsa.pub"),
			"to":   publicKeyPath,
		},
		{
			"from": filepath.Join(fixtureDir, "id_rsa"),
			"to":   keyPath,
		},
		{
			"from": filepath.Join(fixtureDir, "id_rsa"),
			"to":   filepath.Join(testDir, "other_key"),
		},
		{
			"from": filepath.Join(fixtureDir, "id_rsa_encrypted"),
			"to":   filepath.Join(testDir, "id_rsa_encrypted"),
		},
	}

	// the directory is entirely generated from the fixtures, and a test run
	// that died before cleaning up would otherwise keep every later run from
	// starting at all
	err := os.RemoveAll(testDir)
	if err != nil {
		return err
	}

	err = os.Mkdir(testDir, os.ModeDir|os.ModePerm)
	if err != nil {
		return err
	}

	for _, f := range fixtures {
		err = os.Link(f["from"], f["to"])
		if err != nil {
			return err
		}
	}

	os.Setenv("HOME", home)
	os.Setenv("USERPROFILE", home)

	return nil
}

// createHttpServer spawns a new http server, listening on a random port.
// The http server provided an endpoint, /XXX, that will respond, in plain
// text, with the very same given string.
//
// Example: If the request URI is /this-is-a-test, the response will be
// this-is-a-test
func createHttpServer() (net.Listener, *http.Server) {

	handler := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.URL.Path[1:])
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)

	server := &http.Server{
		Handler: mux,
	}

	l, _ := net.Listen("tcp", "127.0.0.1:0")

	go server.Serve(l)

	return l, server
}

// createTCPServer spawns a tcp server, listening on a random port, that hands
// every connection made to it over to the given handler and closes it once the
// handler is done with it.
//
// Unlike createHttpServer, it says nothing about how much data is coming, so a
// client can only tell a response is complete by reading all of it.
func createTCPServer(handler func(conn net.Conn)) (net.Listener, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}

			go func() {
				defer conn.Close()

				handler(conn)
			}()
		}
	}()

	return l, nil
}

// createSSHServer starts a SSH server that authenticates connections using
// the given keyPath, listens on a random user port and returns the SSH Server
// address.
//
// The SSH Server created by this function responds to "direct-tcpip", which is
// used to establish local port forwarding, and to "tcpip-forward", which is
// used to establish remote and reverse dynamic port forwarding: the endpoint
// asked for is listened on and every connection made to it is handed back over
// a "forwarded-tcpip" channel.
//
// References:
// https://gist.github.com/jpillora/b480fde82bff51a06238
// https://tools.ietf.org/html/rfc4254#section-7.2
func createSSHServer(t *testing.T, address string, keyPath string) (net.Listener, error) {
	conf := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}

	b, _ := ioutil.ReadFile(keyPath)
	p, _ := ssh.ParsePrivateKey(b)
	conf.AddHostKey(p)

	if address == "" {
		address = "127.0.0.1:0"
	}

	l, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("error while creating listener: %s", err)
	}

	go func(listener net.Listener) {
		var conns []ssh.Conn
		for {
			var err error

			conn, err := listener.Accept()
			if err != nil {
				// closing all ssh connections if a new client can't connect to the server
				for _, sc := range conns {
					sc.Close()
				}
				break
			}

			serverConn, chans, reqs, err := ssh.NewServerConn(conn, conf)
			if err != nil {
				// the client gave up in the middle of the handshake, which is
				// what happens to a tunnel reconnecting to a server that is
				// being taken down by a test
				conn.Close()
				continue
			}

			conns = append(conns, serverConn)

			// gone is closed as soon as the connection just accepted is over,
			// so that everything served on its behalf is released with it, the
			// same way a real ssh server does.
			gone := make(chan struct{})

			go func(serverConn ssh.Conn) {
				serverConn.Wait()

				close(gone)
			}(serverConn)

			// go routine to handle ssh client requests. All requests but the
			// ones asking for an endpoint to be listened on, and for one to be
			// given up, are discarded: the endpoint a tunnel names is listened
			// on here and the connections made to it are handed back to it over
			// "forwarded-tcpip" channels.
			go func(serverConn ssh.Conn, reqs <-chan *ssh.Request) {
				// the endpoints a connection asked for are released along with
				// it, unless they were given up before that.
				listeners := map[string]net.Listener{}

				defer func() {
					for _, listener := range listeners {
						listener.Close()
					}
				}()

				for newReq := range reqs {
					switch newReq.Type {
					case "tcpip-forward":
						listener, host, port, err := listenForward(newReq.Payload)
						if err != nil {
							newReq.Reply(false, nil) //nolint: errcheck
							continue
						}

						// the endpoint is kept under the address the client
						// knows it by, which is the host it asked for carrying
						// the port it was given, since that is what it names
						// when it gives the endpoint up.
						address := net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))

						listeners[address] = listener

						// the reply carries the port that was bound, which is
						// how a client that asked for any port hears about the
						// one it got.
						payload := make([]byte, 4)
						binary.BigEndian.PutUint32(payload, port)

						if err := newReq.Reply(true, payload); err != nil {
							listener.Close()
							delete(listeners, address)

							continue
						}

						go forwardConnections(serverConn, listener, host, port, gone)
					case "cancel-tcpip-forward":
						address, err := forwardAddress(newReq.Payload)
						if err != nil {
							newReq.Reply(false, nil) //nolint: errcheck
							continue
						}

						listener, listening := listeners[address]
						if !listening {
							newReq.Reply(false, nil) //nolint: errcheck
							continue
						}

						listener.Close()
						delete(listeners, address)

						newReq.Reply(true, nil) //nolint: errcheck
					default:
						newReq.Reply(false, nil) //nolint: errcheck
					}
				}
			}(serverConn, reqs)

			// go routine to handle requests to create new ssh channels. This particular
			// implementation only supports "direct-tcpip", which is the identifier used
			// for ssh port forwarding.
			go func(chans <-chan ssh.NewChannel) {
				for newChan := range chans {
					go func(newChan ssh.NewChannel) {
						var err error

						// a channel asking for an address is what reaching one
						// through the ssh server looks like, so counting them is
						// how a test tells that side apart from the one the
						// tunnel runs on.
						if newChan.ChannelType() == "direct-tcpip" {
							addressesReached.Add(1)
						}

						if ct := newChan.ChannelType(); ct != "direct-tcpip" {
							err = newChan.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", ct))
							if err != nil {
								t.Errorf("error rejecting unsupported channel: %v", err)
							}
							return
						}

						payload := newChan.ExtraData()
						pad := byte(4)
						l := payload[3]
						remoteIP := string(payload[pad : pad+l])
						remotePort := binary.BigEndian.Uint32(payload[pad+l : pad+l+4])

						// a channel opened while the connection is being taken
						// down can't be accepted, and neither the channel nor
						// the connection to the endpoint can be used before
						// knowing they are there: using them regardless takes
						// the whole test binary down with a nil dereference
						conn, _, err := newChan.Accept()
						if err != nil {
							return
						}

						remoteConn, err := net.Dial("tcp", net.JoinHostPort(remoteIP, strconv.FormatUint(uint64(remotePort), 10)))
						if err != nil {
							conn.Close()
							return
						}

						// the end of the stream is told to the other end of the
						// connection, as a real ssh server does, so that a
						// client whose endpoint is done, or an endpoint whose
						// client is done, hears about it instead of waiting
						// for data that is never coming.
						go func() {
							io.Copy(conn, remoteConn)

							conn.CloseWrite()
						}()

						go func() {
							io.Copy(remoteConn, conn)

							if tcp, ok := remoteConn.(*net.TCPConn); ok {
								tcp.CloseWrite()
							}
						}()
					}(newChan)
				}
			}(chans)
		}
	}(l)

	return l, nil
}

// forwardRequest is what a "tcpip-forward" request, and the one giving the
// endpoint it created back, carry: the endpoint to listen on.
type forwardRequest struct {
	Host string
	Port uint32
}

// forwardAddress returns the endpoint named by a "cancel-tcpip-forward"
// request, which is the address the client knows it by.
func forwardAddress(payload []byte) (string, error) {
	var request forwardRequest

	if err := ssh.Unmarshal(payload, &request); err != nil {
		return "", err
	}

	return net.JoinHostPort(request.Host, strconv.FormatUint(uint64(request.Port), 10)), nil
}

// listenForward creates the listener asked for by a "tcpip-forward" request,
// returning it along with the host and the port it was bound on.
//
// The host is the one carried by the request, rather than the address the
// listener ended up bound to, since that is what the client matches the
// connections handed back to it against.
func listenForward(payload []byte) (net.Listener, string, uint32, error) {
	var request forwardRequest

	if err := ssh.Unmarshal(payload, &request); err != nil {
		return nil, "", 0, err
	}

	address := net.JoinHostPort(request.Host, strconv.FormatUint(uint64(request.Port), 10))

	var listener net.Listener
	var err error

	// a tunnel that reconnects asks for the very same endpoint again, which the
	// connection that is gone may not have released yet, so the address is
	// waited for rather than refused right away.
	for deadline := time.Now().Add(5 * time.Second); ; {
		listener, err = net.Listen("tcp", address)
		if err == nil || time.Now().After(deadline) {
			break
		}

		time.Sleep(20 * time.Millisecond)
	}

	if err != nil {
		return nil, "", 0, err
	}

	return listener, request.Host, uint32(listener.Addr().(*net.TCPAddr).Port), nil
}

// forwardConnections hands every connection made to the given listener over to
// the given ssh connection as a "forwarded-tcpip" channel, which is how a ssh
// server serves the endpoints it was asked to listen on, until the listener is
// closed.
//
// The host and the port must be the ones asked for by the request the listener
// was created from: a channel carrying anything else is refused by the client.
//
// gone tells when the ssh connection is over, which releases the connections
// still being carried: one whose client is done sending waits for the peer it
// is half closed towards, and that peer is on the other side of a connection
// that is not coming back.
func forwardConnections(serverConn ssh.Conn, listener net.Listener, host string, port uint32, gone <-chan struct{}) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}

		go func(conn net.Conn) {
			defer conn.Close()

			origin, ok := conn.RemoteAddr().(*net.TCPAddr)
			if !ok {
				return
			}

			payload := ssh.Marshal(struct {
				Host       string
				Port       uint32
				OriginHost string
				OriginPort uint32
			}{host, port, origin.IP.String(), uint32(origin.Port)})

			channel, reqs, err := serverConn.OpenChannel("forwarded-tcpip", payload)
			if err != nil {
				return
			}
			defer channel.Close()

			go ssh.DiscardRequests(reqs)

			// the end of the stream is told to the other end of the connection,
			// as a real ssh server does, so that a client whose endpoint is
			// done, or an endpoint whose client is done, hears about it instead
			// of waiting for data that is never coming.
			done := make(chan struct{})

			go func() {
				io.Copy(channel, conn)

				channel.CloseWrite()

				close(done)
			}()

			io.Copy(conn, channel)

			if tcp, ok := conn.(*net.TCPConn); ok {
				tcp.CloseWrite()
			}

			// the opposite direction is left to finish on its own, unless the
			// connection carrying the channel it writes to is gone, in which
			// case it is waiting on a client that has nothing to reach anymore.
			select {
			case <-done:
			case <-gone:
			}
		}(conn)
	}
}

// generateKnownHosts creates a new "known_hosts" file on a given path with a
// single entry based on the given SSH server address and public key.
func generateKnownHosts(sshAddr net.Addr, pubKeyPath, knownHostsPath string) error {
	d, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		return err
	}

	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(d))
	if err != nil {
		return err
	}

	l := knownhosts.Line([]string{sshAddr.String()}, pk)
	ioutil.WriteFile(knownHostsPath, []byte(l), 0600)

	return nil
}
