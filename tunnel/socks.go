package tunnel

import (
	"context"
	"fmt"
	"net"

	socks5 "github.com/things-go/go-socks5"
)

// newSocksServer creates a socks server to serve a single connection made to a
// channel of a dynamic tunnel, reaching the address asked for by its client
// through the given dial function.
//
// A server is made for every connection rather than shared by all of them so
// that the dial function can be the one of the connection being served, which
// is how the connection to the ssh server the address was reached through is
// known to whoever is serving it.
//
// The server is only given the connection already accepted by the tunnel, so it
// never listens on anything itself.
func newSocksServer(dial func(ctx context.Context, network, address string) (net.Conn, error)) *socks5.Server {
	return socks5.NewServer(
		socks5.WithDial(dial),
		socks5.WithResolver(remoteResolver{}),
		// CONNECT is the only command that can be served: a ssh direct-tcpip
		// channel carries tcp alone, leaving no way to forward the udp traffic
		// ASSOCIATE asks for, and BIND is not implemented by the socks server
		// to begin with. Both are refused before they reach a handler.
		socks5.WithRule(&socks5.PermitCommand{EnableConnect: true}),
	)
}

// socksDial returns the function a socks server reaches the address asked for
// by its client with, which is done from the ssh server the tunnel is connected
// to.
//
// The connection to the ssh server is looked up on every call rather than kept,
// so that the connections established after the tunnel reconnects are made on
// the connection currently in use instead of the one that is already gone. The
// one the address ends up being reached through is reported on dialed, so that
// whoever is serving the client can bind it to that connection and let go of
// both together.
func (t *Tunnel) socksDial(dialed chan<- <-chan struct{}) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		client, disconnected := t.sshConnection()
		if client == nil {
			return nil, fmt.Errorf("missing connection to the ssh server")
		}

		target, err := client.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}

		// the report is best effort: a socks server serves a single request,
		// and whoever asked for the address is gone by the time it is done
		// being served.
		select {
		case dialed <- disconnected:
		default:
		}

		return target, nil
	}
}

// remoteResolver leaves the resolution of the addresses asked for by the socks
// clients to the ssh server.
//
// The names a dynamic tunnel is given are meant to be resolved from the other
// side: they often only exist in the network the ssh server sits in, and
// resolving them here would both fail for those and tell the local resolver
// about every address reached through the tunnel.
type remoteResolver struct{}

// Resolve implements the socks5.NameResolver interface by resolving nothing: a
// request carrying no address resolved keeps the name it was created with all
// the way to the dial, which happens on the ssh server.
func (remoteResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}
