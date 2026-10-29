//go:build windows

package tunnel

import (
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

const (
	// pipePrefix starts the name of every named pipe.
	pipePrefix = `\\.\pipe\`

	// pipeBusyTimeout is how long a pipe with no instance free for a client is
	// waited on. Each client takes an instance of its own, and the agent only
	// creates the next one after handing one out, so for a moment after every
	// client the pipe is either busy or, once that client is gone, missing
	// altogether. Looking the pipe up is one such client already.
	pipeBusyTimeout = 2 * time.Second
)

// dialAgent connects to the ssh agent listening on the given address.
//
// The agent windows ships as part of its openssh port listens on a named pipe
// (\\.\pipe\openssh-ssh-agent) rather than on a unix socket, so an address
// naming a pipe is opened as one.
func dialAgent(addr string) (io.ReadWriteCloser, error) {
	if !strings.HasPrefix(strings.ToLower(addr), pipePrefix) {
		return net.Dial("unix", addr)
	}

	deadline := time.Now().Add(pipeBusyTimeout)

	for {
		f, err := openPipe(addr)
		if err == nil {
			return f, nil
		}

		between := errors.Is(err, windows.ERROR_PIPE_BUSY) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND)

		if !between || time.Now().After(deadline) {
			return nil, err
		}

		time.Sleep(10 * time.Millisecond)
	}
}

// openPipe opens the named pipe at the given address for overlapped i/o. The
// agent client waits on replies while it sends requests, and windows
// serializes every operation on a handle opened for synchronous i/o, so a read
// waiting on a reply would hold the request it waits on back for good.
func openPipe(addr string) (*os.File, error) {
	n, err := windows.UTF16PtrFromString(addr)
	if err != nil {
		return nil, err
	}

	h, err := windows.CreateFile(n,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OVERLAPPED,
		0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: addr, Err: err}
	}

	// a handle opened for overlapped i/o is served by the runtime poller.
	return os.NewFile(uintptr(h), addr), nil
}
