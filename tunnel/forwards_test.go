package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestNewWithForwards(t *testing.T) {
	server := &Server{Name: "example"}

	tests := []struct {
		name     string
		forwards []Forward
		kind     string
		channels []string
		fails    bool
	}{
		{
			name:  "no forwards",
			fails: true,
		},
		{
			name: "a single kind",
			forwards: []Forward{
				{Type: "local", Source: []string{"127.0.0.1:8080", "127.0.0.1:8081"}, Destination: []string{"db:5432", "db:5433"}},
			},
			kind:     "local",
			channels: []string{"local", "local"},
		},
		{
			name: "several forwards of the same kind",
			forwards: []Forward{
				{Type: "dynamic", Source: []string{"127.0.0.1:1080"}},
				{Type: "dynamic", Source: []string{"127.0.0.1:1081"}},
			},
			kind:     "dynamic",
			channels: []string{"dynamic", "dynamic"},
		},
		{
			name: "several kinds",
			forwards: []Forward{
				{Type: "local", Source: []string{"127.0.0.1:8080"}, Destination: []string{"db:5432"}},
				{Type: "dynamic", Source: []string{"127.0.0.1:1080"}},
				{Type: "remote", Source: []string{"127.0.0.1:9000"}, Destination: []string{"127.0.0.1:3000"}},
			},
			kind:     "",
			channels: []string{"local", "dynamic", "remote"},
		},
		{
			name: "an unknown kind after a valid one",
			forwards: []Forward{
				{Type: "local", Source: []string{"127.0.0.1:8080"}, Destination: []string{"db:5432"}},
				{Type: "locla", Source: []string{"127.0.0.1:8081"}, Destination: []string{"db:5433"}},
			},
			fails: true,
		},
		{
			name: "a destination given to a dynamic forward",
			forwards: []Forward{
				{Type: "dynamic", Source: []string{"127.0.0.1:1080"}, Destination: []string{"db:5432"}},
			},
			fails: true,
		},
		{
			name: "a local forward without destination",
			forwards: []Forward{
				{Type: "local", Source: []string{"127.0.0.1:8080"}},
			},
			fails: true,
		},
	}

	for _, test := range tests {
		tun, err := NewWithForwards(server, test.forwards, "")

		if test.fails {
			if err == nil {
				t.Errorf("a tunnel with %s should not be created", test.name)
			}

			continue
		}

		if err != nil {
			t.Errorf("error while creating a tunnel with %s: %v", test.name, err)
			continue
		}

		if tun.Type != test.kind {
			t.Errorf("expected a tunnel with %s to be of kind %q, but got %q", test.name, test.kind, tun.Type)
		}

		var channels []string
		for _, ch := range tun.channels {
			channels = append(channels, ch.ChannelType)
		}

		if fmt.Sprint(channels) != fmt.Sprint(test.channels) {
			t.Errorf("expected a tunnel with %s to have the channels %v, but got %v", test.name, test.channels, channels)
		}
	}
}

// A tunnel serves forwards of every kind on a single connection to the ssh
// server, each channel forwarding the way its own kind does.
func TestTunnelServesForwardsOfEveryKind(t *testing.T) {
	endpoint, httpServer := createHttpServer()
	defer httpServer.Close()

	tun, sshServer, started := prepareForwardsTunnel(t, []Forward{
		{Type: "local", Source: []string{"127.0.0.1:0"}, Destination: []string{endpoint.Addr().String()}},
		{Type: "remote", Source: []string{"127.0.0.1:0"}, Destination: []string{endpoint.Addr().String()}},
		{Type: "dynamic", Source: []string{"127.0.0.1:0"}},
		{Type: "reverse-dynamic", Source: []string{"127.0.0.1:0"}},
	}, 3)
	defer sshServer.Close()
	defer stopDynamicTunnel(t, tun, started)

	waitForDynamicTunnel(t, tun)

	if len(tun.channels) != 4 {
		t.Fatalf("expected a channel for each of the 4 forwards, but got %d", len(tun.channels))
	}

	for _, ch := range tun.channels {
		var body string
		var err error

		// the channels serving a socks proxy are asked for the endpoint, while
		// the others reach it on their own.
		if socksChannel(ch.ChannelType) {
			body, err = fetch(endpoint.Addr().String(), "ABC", ch.address())
		} else {
			body, err = fetch(ch.address(), "ABC", "")
		}

		if err != nil {
			t.Errorf("error while reaching the endpoint through the %s channel: %v", ch.ChannelType, err)
			continue
		}

		if body != "ABC" {
			t.Errorf("expected the %s channel to carry ABC, but got %q", ch.ChannelType, body)
		}
	}
}

// A source endpoint on this machine that is taken stays taken however many
// times it is asked for, so a tunnel that cannot have one gives up, even when
// its other channels listen on the ssh server and could be asked for again.
func TestTunnelWithForwardsFailsWhenALocalSourceIsTaken(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("error while taking an endpoint: %v", err)
	}
	defer taken.Close()

	endpoint, httpServer := createHttpServer()
	defer httpServer.Close()

	// the tunnel is told to never give up on the ssh server, which it has no
	// trouble reaching: what it cannot have is the endpoint.
	tun, sshServer, started := prepareForwardsTunnel(t, []Forward{
		{Type: "remote", Source: []string{"127.0.0.1:0"}, Destination: []string{endpoint.Addr().String()}},
		{Type: "local", Source: []string{taken.Addr().String()}, Destination: []string{endpoint.Addr().String()}},
	}, 0)
	defer sshServer.Close()

	select {
	case err := <-started:
		if err == nil {
			t.Errorf("the tunnel should not have started while one of its source endpoints is taken")
		}
	case <-tun.Ready:
		t.Errorf("the tunnel became ready while one of its source endpoints is taken")
		stopDynamicTunnel(t, tun, started)
	case <-time.After(5 * time.Second):
		t.Errorf("the tunnel kept asking for an endpoint that is taken instead of giving up")
		stopDynamicTunnel(t, tun, started)
	}
}

// An endpoint the ssh server refuses may still be held by the connection that
// just died, so asking for it again is what fixes it, while the channels
// listening on this machine keep the endpoints they already have.
func TestTunnelWithForwardsRetriesRefusedServerEndpoints(t *testing.T) {
	// the endpoint is refused twice, so the tunnel only gets it on the third
	// attempt, which is the last one it is allowed to make.
	forwardsDenied.Store(2)
	defer forwardsDenied.Store(0)

	endpoint, httpServer := createHttpServer()
	defer httpServer.Close()

	tun, sshServer, started := prepareForwardsTunnel(t, []Forward{
		{Type: "local", Source: []string{"127.0.0.1:0"}, Destination: []string{endpoint.Addr().String()}},
		{Type: "remote", Source: []string{"127.0.0.1:0"}, Destination: []string{endpoint.Addr().String()}},
	}, 3)
	defer sshServer.Close()
	defer stopDynamicTunnel(t, tun, started)

	select {
	case <-tun.Ready:
	case err := <-started:
		t.Fatalf("the tunnel gave up on an endpoint it was about to be given: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatalf("error waiting for the tunnel to be ready")
	}

	for _, ch := range tun.channels {
		body, err := fetch(ch.address(), "EFG", "")
		if err != nil {
			t.Errorf("error while reaching the endpoint through the %s channel: %v", ch.ChannelType, err)
			continue
		}

		if body != "EFG" {
			t.Errorf("expected the %s channel to carry EFG, but got %q", ch.ChannelType, body)
		}
	}
}

// prepareForwardsTunnel creates a tunnel serving the given forwards through a
// ssh server of its own, and starts it.
func prepareForwardsTunnel(t *testing.T, forwards []Forward, retries int) (tun *Tunnel, sshServer net.Listener, started <-chan error) {
	sshServer, err := createSSHServer(t, "", keyPath)
	if err != nil {
		t.Fatalf("error while creating ssh server: %v", err)
	}

	srv, err := NewServer("mole", sshServer.Addr().String(), "", "", "testdata/.ssh/config")
	if err != nil {
		t.Fatalf("error while creating the server configuration: %v", err)
	}

	srv.Insecure = true

	tun, err = NewWithForwards(srv, forwards, configPath)
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

	go func() {
		result <- tun.Start()
	}()

	return tun, sshServer, result
}

// fetch makes a http request for the given path to the given endpoint, through
// the socks proxy listening on proxy when one is given, and returns the body of
// the response.
func fetch(endpoint, path, proxy string) (string, error) {
	transport := &http.Transport{
		// a connection kept alive would outlive the request that created it,
		// leaving whatever serves it on the tunnel behind.
		DisableKeepAlives: true,
	}

	if proxy != "" {
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return socksConnectTo(proxy, address)
		}
	}

	client := http.Client{
		Timeout:   2 * time.Second,
		Transport: transport,
	}

	resp, err := client.Get(fmt.Sprintf("http://%s/%s", endpoint, path))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}
