//go:build !windows

package tunnel

import (
	"io"
	"net"
)

// dialAgent connects to the ssh agent listening on the unix socket at the
// given address.
func dialAgent(addr string) (io.ReadWriteCloser, error) {
	return net.Dial("unix", addr)
}
