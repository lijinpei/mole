package tunnel

import (
	"context"
	"fmt"
	"net"

	socks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/bufferpool"
)

// socksDial reaches the address a socks server was asked for by its client.
type socksDial func(ctx context.Context, network, address string) (net.Conn, error)

// socksDialer creates the dial function used to serve a single connection,
// reporting what it reached the address with on the given channel so that
// whoever is serving that connection can let go of both ends together.
type socksDialer func(dialed chan<- dialedConn) socksDial

// dialedConn is what a socks server reached the address asked for by its client
// with: the connection it made and the signal telling when the connection to
// the ssh server that dial was made from is gone, which only exists when the
// address was reached through one.
type dialedConn struct {
	conn         net.Conn
	disconnected <-chan struct{}
}

// socksBuffers holds the buffers the socks servers carry data with, which are
// shared by all of them: a server is made for every connection served, and a
// pool of its own would be born and die with it, so every connection would
// allocate the two buffers it copies with and hand them straight to the garbage
// collector.
var socksBuffers = bufferpool.NewPool(32 * 1024)

// newSocksServer creates a socks server to serve a single connection made to a
// channel of a dynamic or of a reverse dynamic tunnel, reaching the address
// asked for by its client through the given dial function.
//
// A server is made for every connection rather than shared by all of them so
// that the dial function can be the one of the connection being served, which
// is how what the address was reached with is known to whoever is serving it.
//
// The server is only given the connection already accepted by the tunnel, so it
// never listens on anything itself.
func newSocksServer(dial socksDial) *socks5.Server {
	return socks5.NewServer(
		socks5.WithDial(dial),
		socks5.WithResolver(dialResolver{}),
		socks5.WithBufferPool(socksBuffers),
		// CONNECT is the only command that can be served: a ssh channel carries
		// tcp alone, leaving no way to forward the udp traffic ASSOCIATE asks
		// for, and BIND is not implemented by the socks server to begin with.
		// Both are refused before they reach a handler.
		socks5.WithRule(&socks5.PermitCommand{EnableConnect: true}),
	)
}

// sshDial returns the function a socks server serving a dynamic channel reaches
// the address asked for by its client with, which is done from the ssh server
// the tunnel is connected to.
//
// The connection to the ssh server is looked up on every call rather than kept,
// so that the connections established after the tunnel reconnects are made on
// the connection currently in use instead of the one that is already gone. The
// one the address ends up being reached through is reported on dialed, along
// with the connection made, so that whoever is serving the client can bind both
// to it and let go of them together.
func (t *Tunnel) sshDial(dialed chan<- dialedConn) socksDial {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		client, disconnected := t.sshConnection()
		if client == nil {
			return nil, fmt.Errorf("missing connection to the ssh server")
		}

		target, err := client.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}

		report(dialed, dialedConn{conn: target, disconnected: disconnected})

		return target, nil
	}
}

// netDial returns the function a socks server serving a reverse dynamic channel
// reaches the address asked for by its client with, which is done from the
// machine the tunnel runs on: the client sits on the other side of the ssh
// server and asks for what can only be reached from this one.
//
// The connection made is reported on dialed so that whoever is serving the
// client can let go of both ends once the connection to the ssh server the
// client came from is gone, which is not the one the address was reached
// through here.
func netDial(dialed chan<- dialedConn) socksDial {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		var dialer net.Dialer

		target, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}

		report(dialed, dialedConn{conn: target})

		return target, nil
	}
}

// report tells what the address asked for was reached with, if anyone is still
// listening: a socks server serves a single request, and whoever asked for the
// address may be gone by the time it is done being served.
func report(dialed chan<- dialedConn, d dialedConn) {
	select {
	case dialed <- d:
	default:
	}
}

// dialResolver leaves the resolution of the addresses asked for by the socks
// clients to whoever dials them, which is the ssh server for a dynamic channel
// and the machine the tunnel runs on for a reverse dynamic one.
//
// Either way the name is meant to be resolved from the side the address is
// reached from: the ones given to a dynamic tunnel often only exist in the
// network the ssh server sits in, and resolving them here would both fail for
// those and tell the local resolver about every address reached through the
// tunnel, while the ones given to a reverse dynamic tunnel name what only this
// side can reach.
type dialResolver struct{}

// Resolve implements the socks5.NameResolver interface by resolving nothing: a
// request carrying no address resolved keeps the name it was created with all
// the way to the dial.
func (dialResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}
