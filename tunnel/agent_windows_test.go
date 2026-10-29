//go:build windows

package tunnel

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/windows"
)

// TestSSHClientConfigWithAgentOnNamedPipe covers the ssh agent windows ships
// as part of its openssh port, which listens on a named pipe
// (\\.\pipe\openssh-ssh-agent) rather than on a unix socket.
func TestSSHClientConfigWithAgentOnNamedPipe(t *testing.T) {
	name := fmt.Sprintf(`\\.\pipe\mole-test-agent-%d`, os.Getpid())

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate a key for the ssh agent: %v", err)
	}

	keyring := agent.NewKeyring()

	err = keyring.Add(agent.AddedKey{PrivateKey: key})
	if err != nil {
		t.Fatalf("could not add a key to the ssh agent: %v", err)
	}

	serveAgentOnNamedPipe(t, name, keyring)

	_, err = sshClientConfig(Server{User: "mole", SSHAgent: name, Insecure: true})
	if err != nil {
		t.Errorf("could not use the ssh agent listening on %s: %v", name, err)
	}
}

// TestAgentOnNamedPipeTakesRequestsWhileReading covers the agent client
// waiting on replies while it sends requests: windows serializes every
// operation on a handle opened for synchronous i/o, so a read waiting on a
// reply would hold the request it waits on back for good.
func TestAgentOnNamedPipeTakesRequestsWhileReading(t *testing.T) {
	name := fmt.Sprintf(`\\.\pipe\mole-test-agent-reading-%d`, os.Getpid())

	serveAgentOnNamedPipe(t, name, agent.NewKeyring())

	conn, err := dialAgent(name)
	if err != nil {
		t.Fatalf("could not connect to the ssh agent listening on %s: %v", name, err)
	}
	defer conn.Close()

	c := agent.NewClient(conn)

	// gives the client the time to start waiting on a reply.
	time.Sleep(100 * time.Millisecond)

	listed := make(chan error, 1)

	go func() {
		_, err := c.List()
		listed <- err
	}()

	select {
	case err := <-listed:
		if err != nil {
			t.Errorf("could not list the keys of the ssh agent: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("request to the ssh agent was not sent while the client waited on a reply")
	}
}

// serveAgentOnNamedPipe serves the given agent on a named pipe until the test
// is over, the way the ssh agent of windows does: a new instance of the pipe is
// created for each client.
func serveAgentOnNamedPipe(t *testing.T, name string, a agent.Agent) {
	t.Helper()

	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatalf("invalid pipe name %s: %v", name, err)
	}

	newPipe := func() (windows.Handle, error) {
		return windows.CreateNamedPipe(n,
			windows.PIPE_ACCESS_DUPLEX,
			windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT,
			windows.PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, nil)
	}

	// the first instance is created before the pipe is handed out, so that a
	// client never finds it missing.
	h, err := newPipe()
	if err != nil {
		t.Fatalf("could not create pipe %s: %v", name, err)
	}

	var over atomic.Bool
	served := make(chan struct{})

	go func() {
		defer close(served)

		for {
			err := windows.ConnectNamedPipe(h, nil)

			if over.Load() {
				windows.CloseHandle(h)
				return
			}

			// a client that came and went before the instance was waited on
			// leaves it to be disconnected before it can take another one.
			if err == windows.ERROR_NO_DATA {
				windows.DisconnectNamedPipe(h)
				continue
			}

			if err != nil && err != windows.ERROR_PIPE_CONNECTED {
				windows.CloseHandle(h)
				return
			}

			f := os.NewFile(uintptr(h), name)

			go func() {
				defer f.Close()
				agent.ServeAgent(a, f) //nolint: errcheck
			}()

			h, err = newPipe()
			if err != nil {
				return
			}
		}
	}()

	t.Cleanup(func() {
		over.Store(true)

		// a client connecting is the only thing that wakes the loop up, and
		// it may find the pipe in between two instances like any other.
		if c, err := dialAgent(name); err == nil {
			c.Close()
		}

		<-served
	})
}
