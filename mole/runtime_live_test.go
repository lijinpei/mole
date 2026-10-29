package mole

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/davrodpin/mole/tunnel"
	"golang.org/x/crypto/ssh"
)

func TestRuntimeReportsBoundEndpointsAcrossReconnection(t *testing.T) {
	for _, kind := range []string{"flat", "nested"} {
		t.Run(kind, func(t *testing.T) {
			listener, accepted, resume := runtimeSSHServer(t)
			server, err := tunnel.NewServer("mole", listener.Addr().String(), testKey, "", "")
			if err != nil {
				t.Fatalf("could not configure SSH server: %v", err)
			}
			server.Insecure = true
			server.Timeout = 2 * time.Second

			tun, err := tunnel.New("dynamic", server, []string{"127.0.0.1:0"}, nil, "")
			if err != nil {
				t.Fatalf("could not create tunnel: %v", err)
			}
			tun.ConnectionRetries = 3
			tun.WaitAndRetry = 10 * time.Millisecond
			tun.KeepAliveInterval = time.Second

			conf := &Configuration{
				Id:         "live-runtime",
				TunnelType: "dynamic",
				Server:     address(t, "mole@"+listener.Addr().String()),
				Source:     addresses(t, "127.0.0.1:0"),
				SocksAuth:  "mole:runtime-secret",
			}
			if kind == "nested" {
				conf.Tunnels = []TunnelConfiguration{{
					Server:    conf.Server,
					SocksAuth: "mole:runtime-secret",
					Forwards:  []ForwardConfiguration{{Type: "dynamic", Source: addresses(t, "127.0.0.1:0")}},
				}}
			}
			client := &Client{Conf: conf, Tunnels: []*tunnel.Tunnel{tun}}

			finished := make(chan struct{})
			var startErr error
			go func() {
				startErr = tun.Start()
				close(finished)
			}()
			t.Cleanup(func() {
				tun.Stop()
				select {
				case <-finished:
					if startErr != nil {
						t.Errorf("tunnel did not stop cleanly: %v", startErr)
					}
				case <-time.After(5 * time.Second):
					t.Error("tunnel did not stop")
				}
			})

			connection := func() net.Conn {
				t.Helper()
				select {
				case conn := <-accepted:
					return conn
				case <-time.After(5 * time.Second):
					t.Fatal("SSH server did not accept a connection")
					return nil
				}
			}
			ready := func() {
				t.Helper()
				select {
				case <-tun.Ready:
				case <-finished:
					t.Fatalf("tunnel stopped before becoming ready: %v", startErr)
				case <-time.After(5 * time.Second):
					t.Fatal("tunnel did not become ready")
				}
			}
			source := func() string {
				t.Helper()
				rt, err := client.Runtime()
				if err != nil {
					t.Fatalf("could not report runtime: %v", err)
				}
				data, err := json.Marshal(rt)
				if err != nil {
					t.Fatalf("could not encode runtime: %v", err)
				}
				if strings.Contains(string(data), "runtime-secret") {
					t.Fatal("runtime disclosed SOCKS credentials")
				}
				sources, destinations := rt.Source, rt.Destination
				if kind == "nested" {
					if len(rt.Tunnels) != 1 || len(rt.Tunnels[0].Forwards) != 1 {
						t.Fatalf("expected one reported forward: %+v", rt.Tunnels)
					}
					sources = rt.Tunnels[0].Forwards[0].Source
					destinations = rt.Tunnels[0].Forwards[0].Destination
				}
				if len(sources) != 1 || sources[0].Host != "127.0.0.1" || sources[0].Port == "0" || sources[0].Port == "" || len(destinations) != 0 {
					t.Fatalf("expected a bound SOCKS endpoint without destination: sources=%v, destinations=%v", sources, destinations)
				}
				return sources[0].String()
			}

			first := connection()
			resume <- struct{}{}
			ready()
			bound := source()
			conn, err := net.DialTimeout("tcp", bound, time.Second)
			if err != nil {
				t.Fatalf("reported endpoint is not listening: %v", err)
			}
			conn.Close()

			first.Close()
			connection()
			// the next SSH handshake is held while reporting the surviving listener.
			if got := source(); got != bound {
				t.Errorf("endpoint changed during reconnection: got %s, want %s", got, bound)
			}
			resume <- struct{}{}
			ready()
			if got := source(); got != bound {
				t.Errorf("endpoint changed after reconnection: got %s, want %s", got, bound)
			}
			if conf.Source[0].Port != "0" || conf.SocksAuth != "mole:runtime-secret" {
				t.Errorf("reporting changed launch settings: %+v", conf)
			}
			if kind == "nested" && (conf.Tunnels[0].Forwards[0].Source[0].Port != "0" || conf.Tunnels[0].SocksAuth != "mole:runtime-secret") {
				t.Errorf("reporting changed tunnel settings: %+v", conf.Tunnels[0])
			}
		})
	}
}

// runtimeSSHServer permits handshakes one at a time so reporting can be checked
// while a real tunnel is reconnecting, without replacing its SSH implementation.
func runtimeSSHServer(t *testing.T) (net.Listener, <-chan net.Conn, chan<- struct{}) {
	t.Helper()
	key, err := tunnel.NewPemKey(testKey, "")
	if err != nil {
		t.Fatalf("could not read SSH key: %v", err)
	}
	signer, err := key.Parse()
	if err != nil {
		t.Fatalf("could not parse SSH key: %v", err)
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not listen for SSH: %v", err)
	}
	accepted := make(chan net.Conn, 1)
	resume := make(chan struct{})
	stop := make(chan struct{})
	finished := make(chan struct{})
	t.Cleanup(func() {
		close(stop)
		listener.Close()
		<-finished
	})
	go func() {
		defer close(finished)
		var conns []net.Conn
		defer func() {
			for _, conn := range conns {
				conn.Close()
			}
		}()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conns = append(conns, conn)
			select {
			case accepted <- conn:
			case <-stop:
				return
			}
			select {
			case <-resume:
			case <-stop:
				return
			}
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			_, _, requests, err := ssh.NewServerConn(conn, config)
			if err != nil {
				conn.Close()
				continue
			}
			conn.SetDeadline(time.Time{})
			go ssh.DiscardRequests(requests)
		}
	}()
	return listener, accepted, resume
}
