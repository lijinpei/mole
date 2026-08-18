package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"testing"
	"time"
)

// elements of the socks5 protocol, as defined by RFC 1928, spelled out here so
// that what goes on the wire is checked against the specification rather than
// against the implementation serving it.
const (
	socksVersion      = byte(0x05)
	socksNoAuth       = byte(0x00)
	socksUserPassword = byte(0x02)
	socksNoAcceptable = byte(0xff)
	// the exchange carrying a user and a password has a version of its own, as
	// defined by RFC 1929.
	socksAuthVersion   = byte(0x01)
	socksAuthSucceeded = byte(0x00)
	socksConnect       = byte(0x01)
	socksAssociate     = byte(0x03)
	socksIPv4          = byte(0x01)
	socksDomainName    = byte(0x03)
	socksIPv6          = byte(0x04)
	socksSucceeded     = byte(0x00)
	socksNotAllowed    = byte(0x02)
	socksReplyHeader   = 4
)

func TestDynamicTunnel(t *testing.T) {
	tun, ssh, started := prepareDynamicTunnel(t, "dynamic", []string{"127.0.0.1:0"}, 3)
	defer ssh.Close()
	defer stopDynamicTunnel(t, tun, started)

	waitForDynamicTunnel(t, tun)

	endpoint, server := createHttpServer()
	defer server.Close()

	_, port, err := net.SplitHostPort(endpoint.Addr().String())
	if err != nil {
		t.Fatalf("error while reading the address of the http server: %v", err)
	}

	// the address is asked for both as an ip and as a name so that the two
	// kinds of address a socks client can send are covered.
	addresses := []string{
		endpoint.Addr().String(),
		net.JoinHostPort("localhost", port),
	}

	for _, address := range addresses {
		if err := validateDynamicTunnelConnectivity("ABC", address, tun); err != nil {
			t.Errorf("error while reaching %s through the tunnel: %v", address, err)
		}
	}
}

func TestDynamicTunnelMultipleSources(t *testing.T) {
	tun, ssh, started := prepareDynamicTunnel(t, "dynamic", []string{"127.0.0.1:0", "127.0.0.1:0"}, 3)
	defer ssh.Close()
	defer stopDynamicTunnel(t, tun, started)

	waitForDynamicTunnel(t, tun)

	if channels := len(tun.channels); channels != 2 {
		t.Fatalf("expected the tunnel to have 2 channels but it has %d", channels)
	}

	endpoint, server := createHttpServer()
	defer server.Close()

	// every channel serves its own socks proxy, and all of them reach the very
	// same endpoint through the same connection to the ssh server.
	if err := validateDynamicTunnelConnectivity("DEF", endpoint.Addr().String(), tun); err != nil {
		t.Errorf("error while reaching the endpoint through the tunnel: %v", err)
	}
}

func TestDynamicTunnelReconnectsToSSHServer(t *testing.T) {
	tun, ssh, started := prepareDynamicTunnel(t, "dynamic", []string{"127.0.0.1:0"}, 3)
	defer stopDynamicTunnel(t, tun, started)

	waitForDynamicTunnel(t, tun)

	endpoint, server := createHttpServer()
	defer server.Close()

	address := endpoint.Addr().String()

	if err := validateDynamicTunnelConnectivity("GHI", address, tun); err != nil {
		t.Fatalf("error while reaching the endpoint through the tunnel: %v", err)
	}

	ssh.Close()

	// nothing can be reached while the ssh server is gone, since every socks
	// request is forwarded through it.
	if err := validateDynamicTunnelConnectivity("JKL", address, tun); err == nil {
		t.Errorf("the endpoint was reached through the tunnel while the ssh server was down")
	}

	ssh, err := createSSHServer(t, ssh.Addr().String(), keyPath)
	if err != nil {
		t.Fatalf("error while recreating the ssh server: %v", err)
	}
	defer ssh.Close()

	waitForDynamicTunnel(t, tun)

	// the socks server dials from whatever connection to the ssh server the
	// tunnel currently has, so the connections made from this point on go
	// through the one just established rather than through the one that died.
	if err := validateDynamicTunnelConnectivity("MNO", address, tun); err != nil {
		t.Errorf("error while reaching the endpoint after the tunnel reconnected: %v", err)
	}
}

func TestDynamicTunnelRefusesUDPAssociate(t *testing.T) {
	tun, ssh, started := prepareDynamicTunnel(t, "dynamic", []string{"127.0.0.1:0"}, 3)
	defer ssh.Close()
	defer stopDynamicTunnel(t, tun, started)

	waitForDynamicTunnel(t, tun)

	conn, err := socksGreet(tun.channels[0].address())
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer conn.Close()

	// a ssh channel carries tcp alone, so there is no way to forward the udp
	// traffic an ASSOCIATE request asks for.
	request := []byte{socksVersion, socksAssociate, 0, socksIPv4, 127, 0, 0, 1, 0, 0}

	if _, err = conn.Write(request); err != nil {
		t.Fatalf("error while sending an associate request: %v", err)
	}

	reply := make([]byte, socksReplyHeader)
	if _, err = io.ReadFull(conn, reply); err != nil {
		t.Fatalf("error while reading the reply to an associate request: %v", err)
	}

	if reply[1] != socksNotAllowed {
		t.Errorf("expected an associate request to be refused with %d, but got %d", socksNotAllowed, reply[1])
	}
}

func TestDynamicTunnelReleasesIdleConnectionsOnStop(t *testing.T) {
	tun, ssh, started := prepareDynamicTunnel(t, "dynamic", []string{"127.0.0.1:0"}, 3)
	defer ssh.Close()

	waitForDynamicTunnel(t, tun)

	// a client that negotiates and then asks for nothing leaves the socks
	// server waiting for a request that never comes. Greeting the proxy, rather
	// than just connecting to it, is what tells the connection has been
	// accepted and is being served by the time the tunnel is stopped.
	conn, err := socksGreet(tun.channels[0].address())
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer conn.Close()

	stopDynamicTunnel(t, tun, started)

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("error while setting a deadline on the connection to the proxy: %v", err)
	}

	// nothing is ever sent to a client that made no request, so a read can only
	// end by the connection being closed, unless it was left behind.
	if _, err := conn.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("expected the connection to be released when the tunnel stopped, but reading from it returned %v", err)
	}
}

// The connections the socks server is forwarding are dialed from the connection
// to the ssh server the tunnel is using at the time: losing it leaves the
// direction bringing the answer back at the end of its stream and the opposite
// one waiting on a client that has no reason to ever speak again, so they have
// to be released even though the tunnel itself carries on and reconnects.
func TestDynamicTunnelReleasesConnectionsOnReconnection(t *testing.T) {
	forwarded := make(chan struct{}, 1)
	release := make(chan struct{})
	defer close(release)

	// an endpoint that says nothing leaves the connection idle both ways, which
	// is what a client holding one open without using it looks like.
	endpoint, err := createTCPServer(func(conn net.Conn) {
		forwarded <- struct{}{}

		<-release
	})
	if err != nil {
		t.Fatalf("error while creating the endpoint: %v", err)
	}
	defer endpoint.Close()

	tun, ssh, started := prepareDynamicTunnel(t, "dynamic", []string{"127.0.0.1:0"}, 3)
	defer ssh.Close()
	defer stopDynamicTunnel(t, tun, started)

	waitForDynamicTunnel(t, tun)

	conn, err := socksConnectTo(tun.channels[0].address(), endpoint.Addr().String())
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer conn.Close()

	// the connection is only being forwarded, and so bound to the connection to
	// the ssh server it was dialed from, once it reached the endpoint.
	select {
	case <-forwarded:
	case <-time.After(5 * time.Second):
		t.Fatalf("the connection never reached the endpoint through the tunnel")
	}

	// the connection to the ssh server is dropped rather than the server taken
	// down, so that the tunnel reconnects to it right away instead of waiting
	// out the retries: what the connection being served depends on is the one
	// it was dialed from, and the tunnel carrying on is what tells its release
	// apart from the one every connection gets when the tunnel stops.
	tun.sshClient().Close()

	waitForDynamicTunnel(t, tun)

	// the tunnel is serving again on a new connection to the ssh server, which
	// the connection made through the previous one can't be carried on.
	if err := waitForGoroutines(serveSocksFrame, 0, 5*time.Second); err != nil {
		t.Errorf("the tunnel kept serving a connection whose ssh channel is gone: %v", err)
	}
}

func TestDynamicTunnelRepliesWhileThereIsNoSSHConnection(t *testing.T) {
	tun, ssh, started := prepareDynamicTunnel(t, "dynamic", []string{"127.0.0.1:0"}, 3)
	defer ssh.Close()
	defer stopDynamicTunnel(t, tun, started)

	waitForDynamicTunnel(t, tun)

	// leave the tunnel without a connection to the ssh server, which is the
	// state it is in while reconnecting to it. The connection is given back
	// before the tunnel is stopped so that it is closed along with everything
	// else.
	server := tun.connection()
	defer tun.setConnection(server)
	tun.setConnection(nil)

	conn, err := socksGreet(tun.channels[0].address())
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer conn.Close()

	request := []byte{socksVersion, socksConnect, 0, socksIPv4, 127, 0, 0, 1, 0x1f, 0x90}

	if _, err = conn.Write(request); err != nil {
		t.Fatalf("error while sending a connect request: %v", err)
	}

	reply := make([]byte, socksReplyHeader)
	if _, err = io.ReadFull(conn, reply); err != nil {
		t.Fatalf("expected a socks reply saying the address could not be reached, but the connection was dropped instead: %v", err)
	}

	if reply[1] == socksSucceeded {
		t.Errorf("expected the connect request to fail while the tunnel has no connection to the ssh server")
	}
}

// A reverse dynamic tunnel serves its socks proxy on an endpoint of the ssh
// server, and reaches the addresses its clients ask for from the machine it
// runs on, which is the opposite of what a dynamic tunnel does.
func TestReverseDynamicTunnel(t *testing.T) {
	tun, ssh, started := prepareDynamicTunnel(t, "reverse-dynamic", []string{"127.0.0.1:0"}, 3)
	defer ssh.Close()
	defer stopDynamicTunnel(t, tun, started)

	waitForDynamicTunnel(t, tun)

	endpoint, server := createHttpServer()
	defer server.Close()

	_, port, err := net.SplitHostPort(endpoint.Addr().String())
	if err != nil {
		t.Fatalf("error while reading the address of the http server: %v", err)
	}

	// the address is asked for both as an ip and as a name so that the two
	// kinds of address a socks client can send are covered. The name is resolved
	// here, since it names what this side can reach.
	addresses := []string{
		endpoint.Addr().String(),
		net.JoinHostPort("localhost", port),
	}

	for _, address := range addresses {
		if err := validateDynamicTunnelConnectivity("PQR", address, tun); err != nil {
			t.Errorf("error while reaching %s through the tunnel: %v", address, err)
		}
	}
}

// The address a reverse dynamic tunnel is asked for is reached from the machine
// the tunnel runs on, which is the whole of what tells it apart from a dynamic
// one: the client sits on the other side of the ssh server, and what it is
// after is here, so the ssh server is asked for nothing beyond carrying the
// connection.
func TestReverseDynamicTunnelReachesTheAddressFromHere(t *testing.T) {
	endpoint, server := createHttpServer()
	defer server.Close()

	address := endpoint.Addr().String()

	tests := []struct {
		tunnelType string
		// reached tells how many addresses the ssh server is asked to reach on
		// behalf of a single connection made to the proxy.
		reached int64
	}{
		{tunnelType: "dynamic", reached: 1},
		{tunnelType: "reverse-dynamic", reached: 0},
	}

	for _, test := range tests {
		func() {
			tun, ssh, started := prepareDynamicTunnel(t, test.tunnelType, []string{"127.0.0.1:0"}, 3)
			defer ssh.Close()
			defer stopDynamicTunnel(t, tun, started)

			waitForDynamicTunnel(t, tun)

			asked := addressesReached.Load()

			if err := validateDynamicTunnelConnectivity("BCD", address, tun); err != nil {
				t.Errorf("error while reaching the endpoint through the %s tunnel: %v", test.tunnelType, err)
				return
			}

			if reached := addressesReached.Load() - asked; reached != test.reached {
				t.Errorf("expected the ssh server of a %s tunnel to be asked to reach %d addresses, but it was asked for %d", test.tunnelType, test.reached, reached)
			}
		}()
	}
}

// A source naming a host has to be kept the way it was given: the listener of a
// channel listening on the ssh server reports 0.0.0.0 for an address it could
// not parse, and a tunnel that took that for its endpoint would ask the server
// to listen on every interface as soon as it reconnected, turning a proxy meant
// for the jump server itself into one the whole network can reach.
func TestReverseDynamicTunnelKeepsTheSourceItWasGiven(t *testing.T) {
	tun, ssh, started := prepareDynamicTunnel(t, "reverse-dynamic", []string{"localhost:0"}, 3)
	defer ssh.Close()
	defer stopDynamicTunnel(t, tun, started)

	waitForDynamicTunnel(t, tun)

	source := tun.channels[0].source()

	host, port, err := net.SplitHostPort(source)
	if err != nil {
		t.Fatalf("error while reading the source endpoint of the channel: %v", err)
	}

	if host != "localhost" {
		t.Errorf("expected the channel to keep listening on localhost, but its source is %s", source)
	}

	if port == "0" {
		t.Errorf("expected the channel to carry the port it was assigned, but its source is %s", source)
	}

	// the endpoint the tunnel asks for again is the one it is already known by,
	// so the address has to survive the reconnection as well.
	tun.sshClient().Close()

	waitForDynamicTunnel(t, tun)

	if again := tun.channels[0].source(); again != source {
		t.Errorf("expected the tunnel to listen on %s again, but it is listening on %s", source, again)
	}
}

// The endpoint a reverse dynamic tunnel serves its proxy on is listened on by
// the ssh server, so it dies with the connection to it: a new listener is
// created on the same endpoint, and served, as soon as the tunnel connects to
// the server again.
func TestReverseDynamicTunnelListensAgainAfterReconnection(t *testing.T) {
	tun, ssh, started := prepareDynamicTunnel(t, "reverse-dynamic", []string{"127.0.0.1:0"}, 3)
	defer stopDynamicTunnel(t, tun, started)

	waitForDynamicTunnel(t, tun)

	endpoint, server := createHttpServer()
	defer server.Close()

	address := endpoint.Addr().String()
	proxy := tun.channels[0].address()

	if err := validateDynamicTunnelConnectivity("STU", address, tun); err != nil {
		t.Fatalf("error while reaching the endpoint through the tunnel: %v", err)
	}

	ssh.Close()

	ssh, err := createSSHServer(t, ssh.Addr().String(), keyPath)
	if err != nil {
		t.Fatalf("error while recreating the ssh server: %v", err)
	}
	defer ssh.Close()

	waitForDynamicTunnel(t, tun)

	// the endpoint is the one the clients of the proxy already know about, so
	// the tunnel has to ask the ssh server for it again rather than for whatever
	// it is given.
	if again := tun.channels[0].address(); again != proxy {
		t.Errorf("expected the tunnel to serve the proxy on %s again, but it is serving it on %s", proxy, again)
	}

	if err := validateDynamicTunnelConnectivity("VWX", address, tun); err != nil {
		t.Errorf("error while reaching the endpoint after the tunnel reconnected: %v", err)
	}
}

// The endpoint a tunnel listening on the ssh server asks for again after
// reconnecting may still be held by the connection that just died, which the
// server refuses. That is not the end of the tunnel: asking again a moment
// later is exactly what fixes it, and is what the retries it was given are for.
func TestReverseDynamicTunnelRetriesRefusedEndpoints(t *testing.T) {
	// the endpoint is refused twice, so the tunnel only gets it on the third
	// attempt, which is the last one it is allowed to make.
	forwardsDenied.Store(2)
	defer forwardsDenied.Store(0)

	tun, ssh, started := prepareDynamicTunnel(t, "reverse-dynamic", []string{"127.0.0.1:0"}, 3)
	defer ssh.Close()
	defer stopDynamicTunnel(t, tun, started)

	select {
	case <-tun.Ready:
	case err := <-started:
		t.Fatalf("the tunnel gave up on an endpoint it was about to be given: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatalf("error waiting for the tunnel to be ready")
	}

	endpoint, server := createHttpServer()
	defer server.Close()

	if err := validateDynamicTunnelConnectivity("EFG", endpoint.Addr().String(), tun); err != nil {
		t.Errorf("error while reaching the endpoint through the tunnel: %v", err)
	}

	// an endpoint that was refused is asked for again on a new connection to
	// the ssh server, and the one it was refused on has to be let go of rather
	// than left behind along with everything watching it.
	if err := waitForGoroutines(keepAliveFrame, 1, 5*time.Second); err != nil {
		t.Errorf("the tunnel left the connections it was refused an endpoint on behind: %v", err)
	}
}

// An endpoint on the machine the tunnel runs on is taken by whoever holds it,
// which asking for it again does not change, so a tunnel that cannot listen on
// one says so instead of retrying for as long as it was told to keep trying to
// reach the ssh server.
func TestTunnelFailsWhenTheSourceEndpointIsTaken(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("error while taking an endpoint: %v", err)
	}
	defer taken.Close()

	sshServer, err := createSSHServer(t, "", keyPath)
	if err != nil {
		t.Fatalf("error while creating ssh server: %v", err)
	}
	defer sshServer.Close()

	srv, err := NewServer("mole", sshServer.Addr().String(), "", "", "testdata/.ssh/config")
	if err != nil {
		t.Fatalf("error while creating the server configuration: %v", err)
	}

	srv.Insecure = true

	tun, err := New("dynamic", srv, []string{taken.Addr().String()}, nil, configPath)
	if err != nil {
		t.Fatalf("error while creating the tunnel: %v", err)
	}

	// the tunnel is told to never give up on the ssh server, which it has no
	// trouble reaching: what it cannot have is the endpoint.
	tun.ConnectionRetries = 0
	tun.WaitAndRetry = 100 * time.Millisecond
	tun.KeepAliveInterval = 10 * time.Second

	started := make(chan error, 1)
	go func() { started <- tun.Start() }()

	select {
	case err := <-started:
		if err == nil {
			t.Errorf("the tunnel should not have started while its source endpoint is taken")
		}
	case <-tun.Ready:
		t.Errorf("the tunnel became ready while its source endpoint is taken")
	case <-time.After(5 * time.Second):
		t.Errorf("the tunnel kept asking for an endpoint that is taken instead of giving up")
	}

	tun.Stop()
}

// Giving the endpoint back is how a channel listening on the ssh server stops
// listening, so the server has to hear about it: a listener closed without the
// server being told leaves the endpoint bound on the other side.
func TestReverseDynamicChannelGivesTheEndpointBack(t *testing.T) {
	tun, ssh, started := prepareDynamicTunnel(t, "reverse-dynamic", []string{"127.0.0.1:0"}, 3)
	defer ssh.Close()
	defer stopDynamicTunnel(t, tun, started)

	waitForDynamicTunnel(t, tun)

	endpoint := tun.channels[0].address()

	if err := tun.channels[0].Close(); err != nil {
		t.Fatalf("error while giving the endpoint back to the ssh server: %v", err)
	}

	if err := waitForClosedEndpoint(endpoint, 2*time.Second); err != nil {
		t.Errorf("%v", err)
	}
}

// The reply that tells a socks client its connection is established carries the
// address it was made from, which for a reverse dynamic tunnel is on the
// machine the tunnel runs on: a client on the other side of the ssh server would
// be told about a network it is not on, one address at a time.
func TestReverseDynamicTunnelDoesNotDiscloseWhereItDialsFrom(t *testing.T) {
	endpoint, server := createHttpServer()
	defer server.Close()

	tun, ssh, started := prepareDynamicTunnel(t, "reverse-dynamic", []string{"127.0.0.1:0"}, 3)
	defer ssh.Close()
	defer stopDynamicTunnel(t, tun, started)

	waitForDynamicTunnel(t, tun)

	conn, err := socksGreet(tun.channels[0].address())
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer conn.Close()

	host, portString, err := net.SplitHostPort(endpoint.Addr().String())
	if err != nil {
		t.Fatalf("error while reading the address of the http server: %v", err)
	}

	port, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatalf("error while reading the port of the http server: %v", err)
	}

	request := []byte{socksVersion, socksConnect, 0, socksIPv4}
	request = append(request, net.ParseIP(host).To4()...)
	request = append(request, byte(port>>8), byte(port))

	if _, err = conn.Write(request); err != nil {
		t.Fatalf("error while requesting a connection through the proxy: %v", err)
	}

	// the reply carries the address the connection was made from right after
	// its header, as an ip and a port of the kind the header names.
	reply := make([]byte, socksReplyHeader+net.IPv4len+2)
	if _, err = io.ReadFull(conn, reply); err != nil {
		t.Fatalf("error while reading the reply of the proxy: %v", err)
	}

	if reply[1] != socksSucceeded {
		t.Fatalf("the proxy refused to connect to the endpoint: %d", reply[1])
	}

	if reply[3] != socksIPv4 {
		t.Fatalf("expected the reply to carry an ipv4 address, but it carries %d", reply[3])
	}

	if bound := net.IP(reply[socksReplyHeader : socksReplyHeader+net.IPv4len]); !bound.IsUnspecified() {
		t.Errorf("the proxy told the client it dialed from %s", bound)
	}

	if boundPort := int(reply[socksReplyHeader+net.IPv4len])<<8 | int(reply[socksReplyHeader+net.IPv4len+1]); boundPort != 0 {
		t.Errorf("the proxy told the client it dialed from port %d", boundPort)
	}
}

// A client that is done sending is not done receiving, and the socks server
// says so by half closing the connection it reached the address with: that has
// to reach the endpoint, or an answer that only comes once the request is over
// never comes at all.
func TestReverseDynamicTunnelDoesNotTruncateAfterClientHalfClose(t *testing.T) {
	head := []byte("the first half of the answer|")
	tail := []byte("the second half, written after the client was done sending")

	endpoint, err := createTCPServer(func(conn net.Conn) {
		conn.Write(head)

		io.Copy(io.Discard, conn)

		conn.Write(tail)
	})
	if err != nil {
		t.Fatalf("error while creating the endpoint: %v", err)
	}
	defer endpoint.Close()

	tun, ssh, started := prepareDynamicTunnel(t, "reverse-dynamic", []string{"127.0.0.1:0"}, 3)
	defer ssh.Close()
	defer stopDynamicTunnel(t, tun, started)

	waitForDynamicTunnel(t, tun)

	conn, err := socksConnectTo(tun.channels[0].address(), endpoint.Addr().String())
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("error while setting a deadline on the connection to the proxy: %v", err)
	}

	if _, err := conn.Write([]byte("request")); err != nil {
		t.Fatalf("error while sending a request through the proxy: %v", err)
	}

	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("error while half closing the connection to the proxy: %v", err)
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

// The address a socks client asks for is reached on its behalf, so a client that
// asks for addresses that never answer would hold whatever is serving it for as
// long as the operating system takes to give up, which is a couple of minutes.
func TestSocksDialsAreBounded(t *testing.T) {
	defer func(timeout time.Duration) { socksDialTimeout = timeout }(socksDialTimeout)

	socksDialTimeout = 50 * time.Millisecond

	// an endpoint that is being listened on is reached right away, so the
	// deadline is the only thing that can end this dial: the address is asked
	// for through a context that is already over.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	endpoint, server := createHttpServer()
	defer server.Close()

	dialed := make(chan dialedConn, 1)

	if _, err := netDial(dialed)(ctx, "tcp", endpoint.Addr().String()); err == nil {
		t.Errorf("expected the dial to be given up on, but it went through")
	}
}

// The endpoint of a reverse dynamic tunnel is served by the ssh server, so
// whoever reaches that server reaches the proxy as well. A tunnel given
// credentials serves nobody who does not have them.
func TestReverseDynamicTunnelAuthenticatesItsClients(t *testing.T) {
	endpoint, server := createHttpServer()
	defer server.Close()

	tun, ssh, started := prepareDynamicTunnel(t, "reverse-dynamic", []string{"127.0.0.1:0"}, 3)
	defer ssh.Close()
	defer stopDynamicTunnel(t, tun, started)

	tun.SocksUser = "mole"
	tun.SocksPassword = "let me in"

	waitForDynamicTunnel(t, tun)

	proxy := tun.channels[0].address()

	// a client that offers to authenticate with nothing is told that none of
	// what it offers is good enough, and is not served at all.
	conn, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatalf("error while connecting to the socks proxy: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{socksVersion, 1, socksNoAuth}); err != nil {
		t.Fatalf("error while greeting the socks proxy: %v", err)
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("error while reading the greeting reply of the socks proxy: %v", err)
	}

	if reply[1] != socksNoAcceptable {
		t.Errorf("expected the proxy to refuse a client that does not authenticate, but it answered %d", reply[1])
	}

	tests := []struct {
		user     string
		password string
		served   bool
	}{
		{user: "mole", password: "let me in", served: true},
		{user: "mole", password: "guessing", served: false},
		{user: "somebody", password: "let me in", served: false},
	}

	for _, test := range tests {
		err := reachThroughAuthenticatedProxy(proxy, endpoint.Addr().String(), test.user, test.password)

		if test.served && err != nil {
			t.Errorf("the proxy refused to serve %s: %v", test.user, err)
		}

		if !test.served && err == nil {
			t.Errorf("the proxy served %s with the password %q", test.user, test.password)
		}
	}
}

// The connections a reverse dynamic tunnel serves come from the ssh server and
// live on the connection to it, while the addresses they ask for are reached
// from here: losing that connection leaves the direction reading from the ssh
// side at the end of its stream and the opposite one waiting on an endpoint
// that has no reason to ever speak again, so both have to be released even
// though the tunnel itself carries on and reconnects.
func TestReverseDynamicTunnelReleasesConnectionsOnReconnection(t *testing.T) {
	forwarded := make(chan struct{}, 1)
	release := make(chan struct{})
	defer close(release)

	// an endpoint that says nothing leaves the connection idle both ways, which
	// is what a client holding one open without using it looks like.
	endpoint, err := createTCPServer(func(conn net.Conn) {
		forwarded <- struct{}{}

		<-release
	})
	if err != nil {
		t.Fatalf("error while creating the endpoint: %v", err)
	}
	defer endpoint.Close()

	tun, ssh, started := prepareDynamicTunnel(t, "reverse-dynamic", []string{"127.0.0.1:0"}, 3)
	defer ssh.Close()
	defer stopDynamicTunnel(t, tun, started)

	waitForDynamicTunnel(t, tun)

	conn, err := socksConnectTo(tun.channels[0].address(), endpoint.Addr().String())
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer conn.Close()

	// the connection is only being forwarded, and so bound to both the endpoint
	// and the connection to the ssh server it came from, once it reached the
	// endpoint.
	select {
	case <-forwarded:
	case <-time.After(5 * time.Second):
		t.Fatalf("the connection never reached the endpoint through the tunnel")
	}

	// the connection to the ssh server is dropped rather than the server taken
	// down, so that the tunnel reconnects to it right away instead of waiting
	// out the retries: the tunnel carrying on is what tells this release apart
	// from the one every connection gets when the tunnel stops.
	tun.sshClient().Close()

	waitForDynamicTunnel(t, tun)

	// the tunnel is serving again on a new connection to the ssh server, which
	// the connection made through the previous one can't be carried on.
	if err := waitForGoroutines(serveSocksFrame, 0, 5*time.Second); err != nil {
		t.Errorf("the tunnel kept serving a connection whose ssh channel is gone: %v", err)
	}
}

func TestSocksServerResolvesNamesRemotely(t *testing.T) {
	dialed := make(chan string, 1)

	// the dial function stands for the connection to the ssh server, which is
	// the one that would resolve the name and reach the endpoint.
	server := newSocksServer(func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed <- address

		return nil, fmt.Errorf("the address asked for is all this test is after")
	}, nil)

	client, proxy := net.Pipe()
	defer client.Close()

	go func() {
		// ServeConn owns the connection it is given and closes it on the way
		// out, so the other end is the only one left to close here.
		_ = server.ServeConn(proxy)
	}()

	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("error while setting a deadline on the connection to the socks server: %v", err)
	}

	if _, err := client.Write([]byte{socksVersion, 1, socksNoAuth}); err != nil {
		t.Fatalf("error while greeting the socks server: %v", err)
	}

	greeting := make([]byte, 2)
	if _, err := io.ReadFull(client, greeting); err != nil {
		t.Fatalf("error while reading the greeting reply of the socks server: %v", err)
	}

	name := "endpoint.only.the.ssh.server.knows"

	request := []byte{socksVersion, socksConnect, 0, socksDomainName, byte(len(name))}
	request = append(request, name...)
	request = append(request, 0x1f, 0x90)

	if _, err := client.Write(request); err != nil {
		t.Fatalf("error while requesting a connection from the socks server: %v", err)
	}

	select {
	case address := <-dialed:
		// an address resolved before the dial would carry an ip rather than the
		// name the client asked for, leaving out every name that only exists in
		// the network the ssh server sits in.
		if expected := net.JoinHostPort(name, "8080"); address != expected {
			t.Errorf("expected the socks server to dial %s, but it dialed %s", expected, address)
		}
	case <-time.After(5 * time.Second):
		t.Errorf("the socks server never dialed the address asked for")
	}
}

func TestBuildDynamicSSHChannels(t *testing.T) {
	tests := []struct {
		channelType   string
		serverName    string
		source        []string
		destination   []string
		config        string
		expected      []string
		expectedError string
	}{
		{
			channelType: "dynamic",
			serverName:  "test",
			source:      []string{"127.0.0.1:1080"},
			config:      "testdata/.ssh/config",
			expected:    []string{"127.0.0.1:1080"},
		},
		{
			channelType: "dynamic",
			serverName:  "test",
			source:      []string{":1080", ":1081"},
			config:      "testdata/.ssh/config",
			expected:    []string{"127.0.0.1:1080", "127.0.0.1:1081"},
		},
		{
			channelType: "dynamic",
			serverName:  "hostWithDynamicForward",
			config:      "testdata/.ssh/config",
			expected:    []string{"127.0.0.1:1080"},
		},
		{
			channelType: "dynamic",
			serverName:  "hostWithTwoDynamicForwards",
			config:      "testdata/.ssh/config",
			expected:    []string{"127.0.0.1:1080", "192.168.1.1:1081"},
		},
		{
			channelType:   "dynamic",
			serverName:    "test",
			source:        []string{"127.0.0.1:1080"},
			destination:   []string{"172.17.0.1:8080"},
			config:        "testdata/.ssh/config",
			expectedError: fmt.Sprintf(DestinationNotAllowed, "dynamic"),
		},
		{
			channelType:   "dynamic",
			serverName:    "test",
			config:        "testdata/.ssh/config",
			expectedError: "dynamic forward config could not be found or has invalid syntax for host test",
		},
		{
			channelType: "reverse-dynamic",
			serverName:  "test",
			source:      []string{":1080"},
			config:      "testdata/.ssh/config",
			expected:    []string{"127.0.0.1:1080"},
		},
		// a RemoteForward carrying a source endpoint alone asks for a reverse
		// dynamic forward, while the ones naming a destination are remote
		// forwards and are left to a remote tunnel.
		{
			channelType: "reverse-dynamic",
			serverName:  "hostWithReverseDynamicForward",
			config:      "testdata/.ssh/config",
			expected:    []string{"127.0.0.1:1080"},
		},
		{
			channelType: "reverse-dynamic",
			serverName:  "hostWithReverseDynamicAndRemoteForwards",
			config:      "testdata/.ssh/config",
			expected:    []string{"127.0.0.1:1080", "192.168.1.1:1081"},
		},
		{
			channelType:   "reverse-dynamic",
			serverName:    "test",
			source:        []string{"127.0.0.1:1080"},
			destination:   []string{"172.17.0.1:8080"},
			config:        "testdata/.ssh/config",
			expectedError: fmt.Sprintf(DestinationNotAllowed, "reverse-dynamic"),
		},
		{
			channelType:   "reverse-dynamic",
			serverName:    "hostWithRemoteForward",
			config:        "testdata/.ssh/config",
			expectedError: "reverse-dynamic forward config could not be found or has invalid syntax for host hostWithRemoteForward",
		},
	}

	for id, test := range tests {
		channels, err := buildSSHChannels(test.serverName, test.channelType, test.source, test.destination, test.config)

		if test.expectedError != "" {
			if err == nil {
				t.Errorf("error '%s' was expected for test %d, but none was given", test.expectedError, id)
			} else if err.Error() != test.expectedError {
				t.Errorf("error '%s' was expected for test %d, but got '%v'", test.expectedError, id, err)
			}

			continue
		}

		if err != nil {
			t.Errorf("unable to build ssh channels for test %d: %v", id, err)
			continue
		}

		if len(channels) != len(test.expected) {
			t.Errorf("wrong number of ssh channels created for test %d: expected: %d, value: %d", id, len(test.expected), len(channels))
			continue
		}

		for i, channel := range channels {
			if channel.Source != test.expected[i] {
				t.Errorf("source address does not match for test %d: expected: %s, value: %s", id, test.expected[i], channel.Source)
			}

			if channel.Destination != "" {
				t.Errorf("a %s channel should have no destination, but got %s for test %d", test.channelType, channel.Destination, id)
			}

			if channel.ChannelType != test.channelType {
				t.Errorf("wrong channel type for test %d: expected: %s, value: %s", id, test.channelType, channel.ChannelType)
			}
		}
	}
}

func TestDynamicForwardConfig(t *testing.T) {
	cfg, err := NewSSHConfigFile("testdata/.ssh/config")
	if err != nil {
		t.Fatalf("error while reading the ssh config file: %v", err)
	}

	tests := []struct {
		host     string
		expected []string
	}{
		{host: "test", expected: []string{}},
		{host: "hostWithDynamicForward", expected: []string{"127.0.0.1:1080"}},
		{host: "hostWithTwoDynamicForwards", expected: []string{"127.0.0.1:1080", "192.168.1.1:1081"}},
	}

	for _, test := range tests {
		fwds := cfg.Get(test.host).DynamicForwards

		if len(fwds) != len(test.expected) {
			t.Errorf("wrong number of dynamic forwards for host %s: expected: %d, value: %d", test.host, len(test.expected), len(fwds))
			continue
		}

		for i, fwd := range fwds {
			if fwd.Source != test.expected[i] {
				t.Errorf("wrong dynamic forward source for host %s: expected: %s, value: %s", test.host, test.expected[i], fwd.Source)
			}

			if fwd.Destination != "" {
				t.Errorf("a dynamic forward should have no destination, but host %s got %s", test.host, fwd.Destination)
			}
		}
	}
}

// A RemoteForward carrying a source endpoint alone asks for a reverse dynamic
// forward, while the ones naming a destination are remote forwards: a host can
// have both, and neither kind can be taken for the other.
func TestReverseDynamicForwardConfig(t *testing.T) {
	cfg, err := NewSSHConfigFile("testdata/.ssh/config")
	if err != nil {
		t.Fatalf("error while reading the ssh config file: %v", err)
	}

	tests := []struct {
		host           string
		expected       []string
		expectedRemote []*ForwardConfig
	}{
		{host: "test"},
		{
			host:           "hostWithRemoteForward",
			expectedRemote: []*ForwardConfig{{Source: "127.0.0.1:8080", Destination: "172.17.0.1:8080"}},
		},
		{
			host:     "hostWithReverseDynamicForward",
			expected: []string{"127.0.0.1:1080"},
		},
		{
			host:           "hostWithReverseDynamicAndRemoteForwards",
			expected:       []string{"127.0.0.1:1080", "192.168.1.1:1081"},
			expectedRemote: []*ForwardConfig{{Source: "127.0.0.1:8080", Destination: "172.17.0.1:8080"}},
		},
	}

	for _, test := range tests {
		host := cfg.Get(test.host)

		fwds := host.ReverseDynamicForwards

		if len(fwds) != len(test.expected) {
			t.Errorf("wrong number of reverse dynamic forwards for host %s: expected: %d, value: %d", test.host, len(test.expected), len(fwds))
			continue
		}

		for i, fwd := range fwds {
			if fwd.Source != test.expected[i] {
				t.Errorf("wrong reverse dynamic forward source for host %s: expected: %s, value: %s", test.host, test.expected[i], fwd.Source)
			}

			if fwd.Destination != "" {
				t.Errorf("a reverse dynamic forward should have no destination, but host %s got %s", test.host, fwd.Destination)
			}
		}

		if !reflect.DeepEqual(host.RemoteForwards, test.expectedRemote) {
			t.Errorf("wrong remote forwards for host %s: expected: %v, value: %v", test.host, test.expectedRemote, host.RemoteForwards)
		}
	}
}

// prepareDynamicTunnel creates a dynamic or a reverse dynamic Tunnel object
// listening on the given source endpoints, making sure the ssh server it
// depends on is ready, and starts it.
func prepareDynamicTunnel(t *testing.T, tunnelType string, source []string, retries int) (tun *Tunnel, sshServer net.Listener, started <-chan error) {
	sshServer, err := createSSHServer(t, "", keyPath)
	if err != nil {
		t.Fatalf("error while creating ssh server: %v", err)
	}

	srv, err := NewServer("mole", sshServer.Addr().String(), "", "", "testdata/.ssh/config")
	if err != nil {
		t.Fatalf("error while creating the server configuration: %v", err)
	}

	srv.Insecure = true

	tun, err = New(tunnelType, srv, source, nil, configPath)
	if err != nil {
		t.Fatalf("error while creating the tunnel: %v", err)
	}

	tun.ConnectionRetries = retries
	tun.WaitAndRetry = 100 * time.Millisecond
	tun.KeepAliveInterval = 10 * time.Second

	// the value returned by Tunnel.Start can't be given to *testing.T from
	// here: it would be reported after the test that created the tunnel is
	// over, failing it.
	result := make(chan error, 1)

	go func(tun *Tunnel) {
		result <- tun.Start()
	}(tun)

	return tun, sshServer, result
}

// waitForDynamicTunnel waits for the given tunnel to be ready to accept
// connections, failing the test when it never gets there.
func waitForDynamicTunnel(t *testing.T, tun *Tunnel) {
	select {
	case <-tun.Ready:
	case <-time.After(10 * time.Second):
		t.Fatalf("error waiting for the tunnel to be ready")
	}
}

// stopDynamicTunnel stops the given tunnel and waits for it to be done, so that
// the goroutines it started are gone before the next test counts them.
func stopDynamicTunnel(t *testing.T, tun *Tunnel, started <-chan error) {
	tun.Stop()

	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Errorf("the tunnel never stopped")
	}
}

// validateDynamicTunnelConnectivity makes a http request to the given endpoint
// through the socks proxy served by every channel of the given tunnel, checking
// that the response carries the expected value.
func validateDynamicTunnelConnectivity(expected, endpoint string, tun *Tunnel) error {
	for _, sshChan := range tun.channels {
		proxy := sshChan.address()

		transport := &http.Transport{
			// a connection kept alive would outlive the request that created
			// it, leaving the socks server serving it behind.
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return socksConnectTo(proxy, address)
			},
		}

		client := http.Client{
			Timeout:   2 * time.Second,
			Transport: transport,
		}

		resp, err := client.Get(fmt.Sprintf("http://%s/%s", endpoint, expected))
		if err != nil {
			return fmt.Errorf("error while making a http request through %s: %v", proxy, err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("error while reading the http response from %s: %v", proxy, err)
		}

		if response := string(body); expected != response {
			return fmt.Errorf("expected: %s, value: %s", expected, response)
		}
	}

	return nil
}

// reachThroughAuthenticatedProxy asks the given socks5 proxy for a connection
// to the given address on behalf of a client authenticating with the given user
// and password, as defined by RFC 1929, and reports whether it was served.
func reachThroughAuthenticatedProxy(proxy, address, user, password string) error {
	conn, err := net.Dial("tcp", proxy)
	if err != nil {
		return fmt.Errorf("error while connecting to the socks proxy %s: %v", proxy, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fmt.Errorf("error while setting a deadline on the connection to the socks proxy: %v", err)
	}

	// a single authentication method is offered: a user and a password.
	if _, err = conn.Write([]byte{socksVersion, 1, socksUserPassword}); err != nil {
		return fmt.Errorf("error while greeting the socks proxy %s: %v", proxy, err)
	}

	greeting := make([]byte, 2)
	if _, err = io.ReadFull(conn, greeting); err != nil {
		return fmt.Errorf("error while reading the greeting reply of the socks proxy %s: %v", proxy, err)
	}

	if greeting[1] != socksUserPassword {
		return fmt.Errorf("socks proxy %s did not ask for a user and a password: %v", proxy, greeting)
	}

	credentials := []byte{socksAuthVersion, byte(len(user))}
	credentials = append(credentials, user...)
	credentials = append(credentials, byte(len(password)))
	credentials = append(credentials, password...)

	if _, err = conn.Write(credentials); err != nil {
		return fmt.Errorf("error while authenticating with the socks proxy %s: %v", proxy, err)
	}

	authenticated := make([]byte, 2)
	if _, err = io.ReadFull(conn, authenticated); err != nil {
		return fmt.Errorf("error while reading the authentication reply of the socks proxy %s: %v", proxy, err)
	}

	if authenticated[1] != socksAuthSucceeded {
		return fmt.Errorf("socks proxy %s refused the credentials of %s", proxy, user)
	}

	host, portString, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}

	port, err := strconv.Atoi(portString)
	if err != nil {
		return err
	}

	request := []byte{socksVersion, socksConnect, 0, socksIPv4}
	request = append(request, net.ParseIP(host).To4()...)
	request = append(request, byte(port>>8), byte(port))

	if _, err = conn.Write(request); err != nil {
		return fmt.Errorf("error while requesting a connection to %s: %v", address, err)
	}

	reply := make([]byte, socksReplyHeader)
	if _, err = io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("error while reading the reply of the socks proxy %s: %v", proxy, err)
	}

	if reply[1] != socksSucceeded {
		return fmt.Errorf("socks proxy %s refused to connect to %s: %d", proxy, address, reply[1])
	}

	return nil
}

// socksGreet connects to the given socks5 proxy and negotiates the use of no
// authentication with it, returning a connection ready to carry a request.
func socksGreet(proxy string) (net.Conn, error) {
	conn, err := net.Dial("tcp", proxy)
	if err != nil {
		return nil, fmt.Errorf("error while connecting to the socks proxy %s: %v", proxy, err)
	}

	// a single authentication method is offered: none.
	if _, err = conn.Write([]byte{socksVersion, 1, socksNoAuth}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("error while greeting the socks proxy %s: %v", proxy, err)
	}

	reply := make([]byte, 2)
	if _, err = io.ReadFull(conn, reply); err != nil {
		conn.Close()
		return nil, fmt.Errorf("error while reading the greeting reply of the socks proxy %s: %v", proxy, err)
	}

	if reply[0] != socksVersion || reply[1] != socksNoAuth {
		conn.Close()
		return nil, fmt.Errorf("socks proxy %s did not accept an unauthenticated connection: %v", proxy, reply)
	}

	return conn, nil
}

// socksConnectTo asks the given socks5 proxy for a connection to the given
// address, returning it ready to exchange data with the endpoint.
//
// A name is sent as a name rather than resolved here, so that it is the proxy
// the one deciding what it points at.
func socksConnectTo(proxy, address string) (net.Conn, error) {
	host, portString, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(portString)
	if err != nil {
		return nil, err
	}

	conn, err := socksGreet(proxy)
	if err != nil {
		return nil, err
	}

	request := []byte{socksVersion, socksConnect, 0}

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			request = append(request, socksIPv4)
			request = append(request, ip4...)
		} else {
			request = append(request, socksIPv6)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			conn.Close()
			return nil, fmt.Errorf("host name is too long to be sent to a socks proxy: %s", host)
		}

		request = append(request, socksDomainName, byte(len(host)))
		request = append(request, host...)
	}

	request = append(request, byte(port>>8), byte(port))

	if _, err = conn.Write(request); err != nil {
		conn.Close()
		return nil, fmt.Errorf("error while requesting a connection to %s from the socks proxy %s: %v", address, proxy, err)
	}

	reply := make([]byte, socksReplyHeader)
	if _, err = io.ReadFull(conn, reply); err != nil {
		conn.Close()
		return nil, fmt.Errorf("error while reading the reply of the socks proxy %s: %v", proxy, err)
	}

	if reply[1] != socksSucceeded {
		conn.Close()
		return nil, fmt.Errorf("socks proxy %s refused to connect to %s: %d", proxy, address, reply[1])
	}

	// the address the proxy bound is of no use to a client that asked for a
	// connection, but it has to be read for the connection to be left at the
	// start of the data the endpoint sends.
	bound := 0
	switch reply[3] {
	case socksIPv4:
		bound = net.IPv4len
	case socksIPv6:
		bound = net.IPv6len
	case socksDomainName:
		length := make([]byte, 1)
		if _, err = io.ReadFull(conn, length); err != nil {
			conn.Close()
			return nil, fmt.Errorf("error while reading the bound address length from the socks proxy %s: %v", proxy, err)
		}

		bound = int(length[0])
	default:
		conn.Close()
		return nil, fmt.Errorf("socks proxy %s replied with an unknown address type: %d", proxy, reply[3])
	}

	// the bound address is followed by the port it was bound on.
	if _, err = io.ReadFull(conn, make([]byte, bound+2)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("error while reading the bound address from the socks proxy %s: %v", proxy, err)
	}

	return conn, nil
}
