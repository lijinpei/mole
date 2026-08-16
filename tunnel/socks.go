package tunnel

import (
	"context"
	"fmt"
	"net"

	socks5 "github.com/things-go/go-socks5"
)

// newSocksServer creates the socks server used to serve the channels of a
// dynamic tunnel, reaching the addresses asked for by its clients through the
// given dial function.
//
// The server is only given the connections already accepted by the tunnel, so
// it never listens on anything itself.
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

// dialFromServer connects to the given address from the ssh server the tunnel
// is currently connected to.
//
// The connection to the ssh server is looked up on every call rather than kept,
// so that the connections established after the tunnel reconnects are made on
// the connection currently in use instead of the one that is already gone.
func (t *Tunnel) dialFromServer(ctx context.Context, network, address string) (net.Conn, error) {
	client := t.sshClient()
	if client == nil {
		return nil, fmt.Errorf("missing connection to the ssh server")
	}

	return client.DialContext(ctx, network, address)
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
