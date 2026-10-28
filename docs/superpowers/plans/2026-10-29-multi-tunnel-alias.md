# Multi-tunnel Alias Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let one alias forward through several ssh servers at once, each carrying any mix of local, remote, dynamic and reverse-dynamic forwards, as a single mole instance.

**Architecture:** A `tunnel.Tunnel` learns to carry channels of mixed kinds on its one ssh connection. The alias file gains a nested `[[tunnels]]`/`[[tunnels.forwards]]` format whose tunnels inherit top-level settings. `mole.Configuration.Merge` resolves it into `[]TunnelConfiguration`, and `mole.Client` creates one `tunnel.Tunnel` per entry, runs them all, and waits for every one to end. Flat aliases keep today's code path and output.

**Tech Stack:** Go 1.25, `github.com/BurntSushi/toml` v1.6.0, `github.com/go-viper/mapstructure/v2`, `golang.org/x/crypto/ssh`, logrus.

**Spec:** `docs/superpowers/specs/2026-10-29-multi-tunnel-alias-design.md`

## Global Constraints

- No new dependencies; `go.mod` stays as is (`go 1.25.0`).
- `make test` must pass: it fails when `go fmt ./...` changes anything, and runs `go test github.com/davrodpin/mole/... -race`.
- CI runs the suite on Linux and Windows: no unix-only paths or calls in tests (forward slashes in relative paths are fine).
- Forward kinds are exactly `local`, `remote`, `dynamic`, `reverse-dynamic`.
- Defaults for tunnel settings a multi-tunnel alias leaves out: `timeout` 3s, `keep-alive-interval` 10s, `connection-retries` 3, `wait-and-retry` 3s, `config` `$HOME/.ssh/config`, `insecure` false.
- A flat alias (top-level `server`/`type`/`source`/`destination`, no `tunnels`) loads, starts, and shows exactly as today; the existing fixtures `show.alias.test-env.fixture`, `example.toml`, `test-env.toml` do not change.
- `mole add alias` keeps writing the flat format; `mole start local|remote|dynamic|reverse-dynamic` is unchanged.
- Process-wide settings (`verbose`, `detach`, `rpc`, `rpc-address`) live at the top level only.
- Comments follow the repo's style: full sentences that explain why, not what.
- Commit messages follow the repo's style: one imperative sentence, no `feat:` prefix, and end with the trailer `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`.

## Review Focus

1. A misspelled table or key in a hand-written alias (`[[tunnel]]`, `[[tunnels.forward]]`, `keep-alive`) must fail `mole start alias` naming the unknown setting, not be silently dropped. Test: Task 2 `TestGetRejectsUnknownSettingsOfHandWrittenAliases`.
2. A configuration error in any one tunnel (local forward without destination, destination without port, unknown kind) must stop the whole instance before anything connects, and must not crash. Today a destination without port returns `(nil, nil)` from `createTunnel` and panics. Test: Task 4 `TestCreateTunnelsFailsWhenAnyTunnelIsInvalid`.
3. An alias naming no server at all (e.g. `tunnels = []`) must fail with an error naming the alias, not a "server host has to be provided" from deep inside. Test: Task 3 `TestMergeRejectsAliasesWithoutServer`.
4. `mole show instances` reads runtime data as JSON over rpc, decoded with mapstructure: the tunnels and forwards of a multi-tunnel instance must survive that trip. Test: Task 5 `TestRuntimeOfSeveralTunnelsThroughRpc`.
5. A tunnel overriding a setting with its zero value (`connection-retries = 0` meaning "never give up", `insecure = false`) must keep it rather than fall back to the alias value. Test: Task 3 `TestMergeTunnelsKeepsZeroOverrides`.

---

### Task 1: Tunnels carrying forwards of several kinds

**Files:**
- Modify: `tunnel/tunnel.go` (const block ~line 21-30, `Tunnel.Type` doc ~line 302, `New` ~line 383-421, `Listen` ~line 571-607, `startChannel` ~line 632-689, `connect` ~line 902-950)
- Create test: `tunnel/forwards_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `type Forward struct { Type string; Source []string; Destination []string }`
  - `func NewWithForwards(server *Server, forwards []Forward, config string) (*Tunnel, error)`
  - `const NoForwardGiven = "cannot create a tunnel without at least one forward"`
  - `New(tunnelType string, server *Server, source, destination []string, config string) (*Tunnel, error)` keeps its signature and behavior.
  - `Tunnel.Type` is the shared kind of all forwards, `""` when they differ.

- [ ] **Step 1: Write the failing tests**

Create `tunnel/forwards_test.go`:

```go
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./tunnel -run 'TestNewWithForwards|TestTunnelServesForwardsOfEveryKind|TestTunnelWithForwards' -v`
Expected: build failure, `undefined: Forward` and `undefined: NewWithForwards`.

- [ ] **Step 3: Add `Forward`, `NewWithForwards` and `NoForwardGiven`**

In `tunnel/tunnel.go`, add to the `const (...)` block after `DestinationNotAllowed`:

```go
	// NoForwardGiven is the error given when a tunnel is created with nothing
	// to forward.
	NoForwardGiven = "cannot create a tunnel without at least one forward"
```

Replace the doc comment of `Tunnel.Type`:

```go
	// Type tells what kind of port forwarding this tunnel handles: local,
	// remote, dynamic or reverse-dynamic. It is empty for a tunnel whose
	// channels are not all of the same kind, each of which tells its own.
	Type string
```

Replace the whole `New` function (from `// New creates a new instance of Tunnel.` to the end of the function) with:

```go
// Forward is a group of channels of a single kind, given the same way the
// channels of a tunnel of that kind are: a dynamic or reverse dynamic forward
// takes no destination, and a forward with neither source nor destination
// reads the ones of its kind from the ssh configuration file.
type Forward struct {
	Type        string
	Source      []string
	Destination []string
}

// New creates a new instance of Tunnel whose channels are all of the given
// kind.
func New(tunnelType string, server *Server, source, destination []string, config string) (*Tunnel, error) {
	return NewWithForwards(server, []Forward{{Type: tunnelType, Source: source, Destination: destination}}, config)
}

// NewWithForwards creates a new instance of Tunnel serving the channels of
// every given forward, whatever their kind, on a single connection to the ssh
// server.
func NewWithForwards(server *Server, forwards []Forward, config string) (*Tunnel, error) {
	if len(forwards) == 0 {
		return nil, fmt.Errorf(NoForwardGiven)
	}

	var channels []*SSHChannel

	for _, forward := range forwards {
		// the type is checked before anything is built from it so that a
		// forward asked for by a name that does not exist, as an alias carrying
		// a typo does, is told about it instead of failing on whatever the
		// channels of an unknown type end up missing.
		switch forward.Type {
		case "local", "remote", "dynamic", "reverse-dynamic":
		default:
			return nil, fmt.Errorf("unsupported tunnel type %s", forward.Type)
		}

		chs, err := buildSSHChannels(server.Name, forward.Type, forward.Source, forward.Destination, config)
		if err != nil {
			return nil, err
		}

		for _, channel := range chs {
			// a dynamic or reverse dynamic channel has no destination of its
			// own: every connection made to it carries the address it wants to
			// reach.
			if channel.Source == "" || (channel.Destination == "" && !socksChannel(channel.ChannelType)) {
				return nil, fmt.Errorf("invalid ssh channel: source=%s, destination=%s", channel.Source, channel.Destination)
			}
		}

		channels = append(channels, chs...)
	}

	t := &Tunnel{
		Type:     sharedType(forwards),
		Ready:    make(chan bool, 1),
		channels: channels,
		server:   server,
		done:     make(chan error, 1),
		stop:     make(chan struct{}),
	}

	return t, nil
}

// sharedType returns the kind shared by every given forward, which is empty
// when they are not all of the same kind.
func sharedType(forwards []Forward) string {
	for _, forward := range forwards[1:] {
		if forward.Type != forwards[0].Type {
			return ""
		}
	}

	return forwards[0].Type
}
```

- [ ] **Step 4: Run `TestNewWithForwards` to verify it passes**

Run: `go test ./tunnel -run TestNewWithForwards -v`
Expected: PASS. (`TestTunnelServesForwardsOfEveryKind` still fails at this point: the channels are dispatched on `t.Type`, which is empty.)

- [ ] **Step 5: Dispatch each connection on the kind of its channel**

In `startChannel`, change `switch t.Type {` to:

```go
	switch channel.ChannelType {
```

and its `default` branch to:

```go
	default:
		return fmt.Errorf("unknown channel type %s", channel.ChannelType)
```

- [ ] **Step 6: Decide on retrying a listen failure from the channel that failed**

In `tunnel/tunnel.go`, add right before `// Listen creates the listeners the tunnel channels are missing`:

```go
// listenError tells which channel could not listen on its source endpoint,
// since whether asking for it again can fix it depends on where that endpoint
// lives.
type listenError struct {
	channel *SSHChannel
	err     error
}

func (e *listenError) Error() string {
	return e.err.Error()
}

func (e *listenError) Unwrap() error {
	return e.err
}
```

In `Tunnel.Listen`, change:

```go
		listener, err := ch.Listen(conn.sshClient())
		if err != nil {
			return err
		}
```

to:

```go
		listener, err := ch.Listen(conn.sshClient())
		if err != nil {
			return &listenError{channel: ch, err: err}
		}
```

In `connect`, replace:

```go
			if !serverListener(t.Type) {
				return err
			}
```

with:

```go
			var le *listenError
			if errors.As(err, &le) && !serverListener(le.channel.ChannelType) {
				return err
			}
```

(`errors` is already imported by `tunnel/tunnel.go`.)

- [ ] **Step 7: Run the new tests to verify they pass**

Run: `go test ./tunnel -run 'TestNewWithForwards|TestTunnelServesForwardsOfEveryKind|TestTunnelWithForwards' -v -race`
Expected: PASS for all four.

- [ ] **Step 8: Run the whole tunnel package and check formatting**

Run: `gofmt -l tunnel; go vet ./tunnel && go test ./tunnel -race`
Expected: no file listed by `gofmt -l`, `ok  github.com/davrodpin/mole/tunnel`.

- [ ] **Step 9: Commit**

```bash
git add tunnel/tunnel.go tunnel/forwards_test.go
git commit -m "Let a tunnel serve forwards of several kinds on one ssh connection" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Alias files describing tunnels through several ssh servers

**Files:**
- Modify: `alias/alias.go` (struct `Alias` ~line 15-34, `Get` ~line 176-196)
- Create: `alias/testdata/multi.toml`, `alias/testdata/show.alias.multi.fixture`
- Modify: `alias/testdata/show.alias.fixture`
- Modify test: `alias/alias_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `alias.Alias.Tunnels []alias.Tunnel` (toml `tunnels`)
  - `type Tunnel struct { Server, Key, KeepAliveInterval string; ConnectionRetries *int; WaitAndRetry, SshAgent, Timeout, SshConfig string; Insecure *bool; SocksAuth string; Forwards []Forward }`
  - `type Forward struct { Type string; Source, Destination []string }`
  - `const DefaultKeepAliveInterval = "10s"`, `DefaultConnectionRetries = 3`, `DefaultWaitAndRetry = "3s"`, `DefaultTimeout = "3s"`, `DefaultSshConfig = "$HOME/.ssh/config"`
  - `alias.Get` fills those defaults into the top-level settings of an alias with tunnels, and rejects unknown keys in hand-written aliases (any alias with tunnels or without a server).

- [ ] **Step 1: Add the fixtures**

Create `alias/testdata/multi.toml`:

```toml
verbose = true
key = "path/to/key"
timeout = "5s"
rpc = true
rpc-address = "127.0.0.1:0"

[[tunnels]]
server = "mole@bastion-a"

  [[tunnels.forwards]]
  type = "local"
  source = [":8080"]
  destination = ["db:5432"]

  [[tunnels.forwards]]
  type = "dynamic"
  source = [":1080"]

[[tunnels]]
server = "mole@bastion-b:2222"
key = "path/to/other/key"
insecure = true
connection-retries = 0

  [[tunnels.forwards]]
  type = "remote"
  source = ["0.0.0.0:9000"]
  destination = ["127.0.0.1:3000"]
```

Create `alias/testdata/show.alias.multi.fixture` (ends with a single newline after the last line):

```toml
name = "multi"
verbose = true
insecure = false
detach = false
key = "path/to/key"
keep-alive-interval = "10s"
connection-retries = 3
wait-and-retry = "3s"
ssh-agent = ""
timeout = "5s"
config = "$HOME/.ssh/config"
socks-auth = ""
rpc = true
rpc-address = "127.0.0.1:0"

[[tunnels]]
  server = "mole@bastion-a"

  [[tunnels.forwards]]
    type = "local"
    source = [":8080"]
    destination = ["db:5432"]

  [[tunnels.forwards]]
    type = "dynamic"
    source = [":1080"]

[[tunnels]]
  server = "mole@bastion-b:2222"
  key = "path/to/other/key"
  connection-retries = 0
  insecure = true

  [[tunnels.forwards]]
    type = "remote"
    source = ["0.0.0.0:9000"]
    destination = ["127.0.0.1:3000"]
```

In `alias/testdata/show.alias.fixture`, insert the following between the line `    rpc-address = "127.0.0.1:0"` that ends the `[aliases.example]` block and the line `  [aliases.test-env]` (no blank line before `  [aliases.test-env]`):

```toml
  [aliases.multi]
    name = "multi"
    verbose = true
    insecure = false
    detach = false
    key = "path/to/key"
    keep-alive-interval = "10s"
    connection-retries = 3
    wait-and-retry = "3s"
    ssh-agent = ""
    timeout = "5s"
    config = "$HOME/.ssh/config"
    socks-auth = ""
    rpc = true
    rpc-address = "127.0.0.1:0"

    [[aliases.multi.tunnels]]
      server = "mole@bastion-a"

      [[aliases.multi.tunnels.forwards]]
        type = "local"
        source = [":8080"]
        destination = ["db:5432"]

      [[aliases.multi.tunnels.forwards]]
        type = "dynamic"
        source = [":1080"]

    [[aliases.multi.tunnels]]
      server = "mole@bastion-b:2222"
      key = "path/to/other/key"
      connection-retries = 0
      insecure = true

      [[aliases.multi.tunnels.forwards]]
        type = "remote"
        source = ["0.0.0.0:9000"]
        destination = ["127.0.0.1:3000"]
```

- [ ] **Step 2: Write the failing tests**

In `alias/alias_test.go`:

1. Add `"strings"` to the imports.
2. In `TestShow`, change `ids := []string{"test-env"}` to `ids := []string{"test-env", "multi"}`.
3. In `setup`, change `fixtures := []string{"test-env.toml", "example.toml"}` to `fixtures := []string{"test-env.toml", "example.toml", "multi.toml"}`.
4. Append:

```go
func TestGetMultiTunnelAlias(t *testing.T) {
	insecure := true
	never := 0

	// the settings the alias leaves out take the values the command line
	// defaults to.
	expected := &alias.Alias{
		Name:              "multi",
		Verbose:           true,
		Key:               "path/to/key",
		KeepAliveInterval: alias.DefaultKeepAliveInterval,
		ConnectionRetries: alias.DefaultConnectionRetries,
		WaitAndRetry:      alias.DefaultWaitAndRetry,
		Timeout:           "5s",
		SshConfig:         alias.DefaultSshConfig,
		Rpc:               true,
		RpcAddress:        "127.0.0.1:0",
		Tunnels: []alias.Tunnel{
			{
				Server: "mole@bastion-a",
				Forwards: []alias.Forward{
					{Type: "local", Source: []string{":8080"}, Destination: []string{"db:5432"}},
					{Type: "dynamic", Source: []string{":1080"}},
				},
			},
			{
				Server:            "mole@bastion-b:2222",
				Key:               "path/to/other/key",
				Insecure:          &insecure,
				ConnectionRetries: &never,
				Forwards: []alias.Forward{
					{Type: "remote", Source: []string{"0.0.0.0:9000"}, Destination: []string{"127.0.0.1:3000"}},
				},
			},
		},
	}

	al, err := alias.Get("multi")
	if err != nil {
		t.Fatalf("error while reading the alias: %v", err)
	}

	if !reflect.DeepEqual(expected, al) {
		t.Errorf("expected: %+v, actual: %+v", expected, al)
	}
}

// No retries at all asks to never give up reconnecting, so only a number of
// retries left out altogether takes the default.
func TestGetMultiTunnelAliasKeepsZeroRetries(t *testing.T) {
	writeAlias(t, "never-give-up", `connection-retries = 0

[[tunnels]]
server = "mole@bastion-a"

  [[tunnels.forwards]]
  type = "dynamic"
`)

	al, err := alias.Get("never-give-up")
	if err != nil {
		t.Fatalf("error while reading the alias: %v", err)
	}

	if al.ConnectionRetries != 0 {
		t.Errorf("expected the alias to never give up reconnecting, but it gives up after %d retries", al.ConnectionRetries)
	}
}

// An alias with tunnels, or without a server, is written by hand, where a
// misspelled setting would otherwise be dropped without a word.
func TestGetRejectsUnknownSettingsOfHandWrittenAliases(t *testing.T) {
	tests := []struct {
		name    string
		content string
		unknown string
	}{
		{
			name:    "misspelled-tunnels",
			content: "[[tunnel]]\nserver = \"mole@bastion-a\"\n",
			unknown: "tunnel",
		},
		{
			name:    "misspelled-setting",
			content: "keep-alive = \"5s\"\n\n[[tunnels]]\nserver = \"mole@bastion-a\"\n\n  [[tunnels.forwards]]\n  type = \"dynamic\"\n",
			unknown: "keep-alive",
		},
		{
			name:    "misspelled-forwards",
			content: "[[tunnels]]\nserver = \"mole@bastion-a\"\n\n  [[tunnels.forward]]\n  type = \"dynamic\"\n",
			unknown: "tunnels.forward",
		},
	}

	for _, test := range tests {
		writeAlias(t, test.name, test.content)

		_, err := alias.Get(test.name)
		if err == nil || !strings.Contains(err.Error(), test.unknown) {
			t.Errorf("expected reading alias %s to fail on the unknown setting %s, but got %v", test.name, test.unknown, err)
		}
	}
}

// An alias with a server of its own is the kind "mole add alias" writes, which
// is read as it always was: whatever an older version wrote in it is left
// alone, and nothing it leaves out is filled in.
func TestGetLeavesFlatAliasesAlone(t *testing.T) {
	writeAlias(t, "flat", "type = \"local\"\nserver = \"mole@bastion-a\"\nlocal = [\":8080\"]\n")

	al, err := alias.Get("flat")
	if err != nil {
		t.Fatalf("error while reading the alias: %v", err)
	}

	if al.KeepAliveInterval != "" || al.ConnectionRetries != 0 || al.SshConfig != "" {
		t.Errorf("expected the settings the alias leaves out to be left empty, but got %s", al)
	}
}

func TestAddThenGetMultiTunnelAlias(t *testing.T) {
	expected, err := alias.Get("multi")
	if err != nil {
		t.Fatalf("error while reading the alias: %v", err)
	}

	expected.Name = "multi-copy"

	if err := alias.Add(expected); err != nil {
		t.Fatalf("error while adding the alias: %v", err)
	}
	defer alias.Delete(expected.Name)

	al, err := alias.Get(expected.Name)
	if err != nil {
		t.Fatalf("error while reading the alias back: %v", err)
	}

	if !reflect.DeepEqual(expected, al) {
		t.Errorf("expected: %+v, actual: %+v", expected, al)
	}
}

// writeAlias saves an alias file with the given content, which is removed once
// the test is over so that it does not show up in what the other tests read.
func writeAlias(t *testing.T, name, content string) {
	t.Helper()

	p := filepath.Join(home, ".mole", fmt.Sprintf("%s.toml", name))

	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("error while writing alias %s: %v", name, err)
	}

	t.Cleanup(func() { os.Remove(p) })
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./alias -v`
Expected: build failure, `undefined: alias.DefaultKeepAliveInterval`, `undefined: alias.Tunnel`, `undefined: alias.Forward`.

- [ ] **Step 4: Implement the nested format**

In `alias/alias.go`, replace the `Alias` struct with:

```go
// Alias holds all attributes required to start a ssh port forwarding tunnel.
//
// An alias forwarding through several ssh servers has its Tunnels set instead
// of the type, source, destination and server of a single tunnel. The other
// tunnel settings are then the ones every tunnel takes unless it gives its own.
type Alias struct {
	Name              string   `toml:"name"`
	TunnelType        string   `toml:"type,omitempty"`
	Verbose           bool     `toml:"verbose"`
	Insecure          bool     `toml:"insecure"`
	Detach            bool     `toml:"detach"`
	Source            []string `toml:"source,omitempty"`
	Destination       []string `toml:"destination,omitempty"`
	Server            string   `toml:"server,omitempty"`
	Key               string   `toml:"key"`
	KeepAliveInterval string   `toml:"keep-alive-interval"`
	ConnectionRetries int      `toml:"connection-retries"`
	WaitAndRetry      string   `toml:"wait-and-retry"`
	SshAgent          string   `toml:"ssh-agent"`
	Timeout           string   `toml:"timeout"`
	SshConfig         string   `toml:"config"`
	SocksAuth         string   `toml:"socks-auth"`
	Rpc               bool     `toml:"rpc"`
	RpcAddress        string   `toml:"rpc-address"`
	Tunnels           []Tunnel `toml:"tunnels,omitempty"`
}

// Tunnel holds the attributes of one of the ssh servers an alias forwards
// through. A setting left empty is taken from the alias, which is why the ones
// whose zero value means something are pointers: no retries at all asks to
// never give up reconnecting.
type Tunnel struct {
	Server            string    `toml:"server"`
	Key               string    `toml:"key,omitempty"`
	KeepAliveInterval string    `toml:"keep-alive-interval,omitempty"`
	ConnectionRetries *int      `toml:"connection-retries,omitempty"`
	WaitAndRetry      string    `toml:"wait-and-retry,omitempty"`
	SshAgent          string    `toml:"ssh-agent,omitempty"`
	Timeout           string    `toml:"timeout,omitempty"`
	SshConfig         string    `toml:"config,omitempty"`
	Insecure          *bool     `toml:"insecure,omitempty"`
	SocksAuth         string    `toml:"socks-auth,omitempty"`
	Forwards          []Forward `toml:"forwards"`
}

// Forward holds a group of channels of a single kind served through a tunnel.
type Forward struct {
	Type        string   `toml:"type"`
	Source      []string `toml:"source,omitempty"`
	Destination []string `toml:"destination,omitempty"`
}

// The values the tunnel settings of an alias forwarding through several ssh
// servers take when the alias leaves them out, which are the ones the command
// line defaults to.
const (
	DefaultKeepAliveInterval = "10s"
	DefaultConnectionRetries = 3
	DefaultWaitAndRetry      = "3s"
	DefaultTimeout           = "3s"
	DefaultSshConfig         = "$HOME/.ssh/config"
)
```

Replace the whole `Get` function with:

```go
// Get returns an alias previously created
func Get(aliasName string) (*Alias, error) {
	mp, err := fsutils.Dir()
	if err != nil {
		return nil, err
	}

	p := filepath.Join(mp, fmt.Sprintf("%s.toml", aliasName))

	if _, err := os.Stat(p); os.IsNotExist(err) {
		return nil, fmt.Errorf("alias %s does not exist", aliasName)
	}

	a := &Alias{}
	md, err := toml.DecodeFile(p, a)
	if err != nil {
		return nil, err
	}
	a.Name = aliasName

	// an alias with a server of its own is the kind "mole add alias" writes,
	// which is read as it always was, whatever an older version wrote in it.
	// One with tunnels, or with no server at all, is written by hand, where a
	// misspelled setting would otherwise be dropped without a word, leaving an
	// alias that does not do what it says.
	if a.Server == "" || len(a.Tunnels) > 0 {
		if keys := md.Undecoded(); len(keys) > 0 {
			return nil, fmt.Errorf("alias %s has unknown settings: %v", aliasName, keys)
		}
	}

	if len(a.Tunnels) > 0 {
		a.applyDefaults(md)
	}

	return a, nil
}

// applyDefaults gives the tunnel settings an alias forwarding through several
// ssh servers leaves out the values the command line defaults to, so that a
// hand written alias only has to carry what sets it apart.
func (a *Alias) applyDefaults(md toml.MetaData) {
	if a.KeepAliveInterval == "" {
		a.KeepAliveInterval = DefaultKeepAliveInterval
	}

	// no retries at all asks to never give up reconnecting, so only a number
	// of retries left out altogether takes the default.
	if !md.IsDefined("connection-retries") {
		a.ConnectionRetries = DefaultConnectionRetries
	}

	if a.WaitAndRetry == "" {
		a.WaitAndRetry = DefaultWaitAndRetry
	}

	if a.Timeout == "" {
		a.Timeout = DefaultTimeout
	}

	if a.SshConfig == "" {
		a.SshConfig = DefaultSshConfig
	}
}
```

- [ ] **Step 5: Run the alias tests to verify they pass**

Run: `go test ./alias -v -race`
Expected: PASS for every test, including the unchanged `TestAddThenGetThenDeleteAlias`, `TestShow` (now covering `test-env` and `multi`) and `TestShowAll`.

If `TestShow` or `TestShowAll` fail on whitespace only, diff the actual output (`alias.Show("multi")` / `alias.ShowAll()`) against the fixture and fix the fixture's whitespace. Do not change the encoder or the field order to match the fixture.

- [ ] **Step 6: Run the whole suite and check formatting**

Run: `gofmt -l alias; go vet ./... && go test ./... -race`
Expected: nothing listed by `gofmt -l`; all packages `ok`.

- [ ] **Step 7: Commit**

```bash
git add alias/alias.go alias/alias_test.go alias/testdata/multi.toml alias/testdata/show.alias.multi.fixture alias/testdata/show.alias.fixture
git commit -m "Let an alias file describe tunnels through several ssh servers" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Resolving the tunnels of an alias

**Files:**
- Create: `mole/tunnels.go`
- Modify: `mole/mole.go` (`Configuration` struct ~line 39-62, `Merge` ~line 273-357)
- Create test: `mole/tunnels_test.go`

**Interfaces:**
- Consumes: `alias.Alias.Tunnels`, `alias.Tunnel`, `alias.Forward` from Task 2.
- Produces:
  - `type TunnelConfiguration struct { Server AddressInput; Key string; KeepAliveInterval time.Duration; ConnectionRetries int; WaitAndRetry time.Duration; SshAgent string; Timeout time.Duration; SshConfig string; Insecure bool; SocksAuth string; Forwards []ForwardConfiguration }`
  - `type ForwardConfiguration struct { Type string; Source AddressInputList; Destination AddressInputList }`
  - `Configuration.Tunnels []TunnelConfiguration` (json/mapstructure/toml key `tunnels`, omitted when empty)
  - `Configuration.Merge` fills `Tunnels` for an alias with tunnels, leaves it nil for a flat alias, and rejects an alias with neither.
  - Test helpers in `mole/tunnels_test.go` (package `mole`), reused by Tasks 4-5: `address(t, value string) AddressInput`, `addresses(t, values ...string) AddressInputList`, `multiTunnelAlias() *alias.Alias`.

- [ ] **Step 1: Write the failing tests**

Create `mole/tunnels_test.go`:

```go
package mole

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/davrodpin/mole/alias"
)

func TestMergeTunnels(t *testing.T) {
	conf := &Configuration{}

	if err := conf.Merge(multiTunnelAlias(), []string{}); err != nil {
		t.Fatalf("error while merging the alias: %v", err)
	}

	expected := []TunnelConfiguration{
		{
			Server:            address(t, "mole@bastion-a"),
			Key:               "path/to/key",
			KeepAliveInterval: 10 * time.Second,
			ConnectionRetries: 3,
			WaitAndRetry:      3 * time.Second,
			SshAgent:          "path/to/agent",
			Timeout:           5 * time.Second,
			SshConfig:         "path/to/config",
			Insecure:          false,
			SocksAuth:         "mole:let me in",
			Forwards: []ForwardConfiguration{
				{Type: "local", Source: addresses(t, ":8080"), Destination: addresses(t, "db:5432")},
				{Type: "dynamic", Source: addresses(t, ":1080")},
			},
		},
		{
			Server:            address(t, "mole@bastion-b:2222"),
			Key:               "path/to/other/key",
			KeepAliveInterval: 2 * time.Second,
			ConnectionRetries: 5,
			WaitAndRetry:      1 * time.Second,
			SshAgent:          "path/to/other/agent",
			Timeout:           1 * time.Second,
			SshConfig:         "path/to/other/config",
			Insecure:          true,
			SocksAuth:         "other:let me in",
			Forwards: []ForwardConfiguration{
				{Type: "remote", Source: addresses(t, "0.0.0.0:9000"), Destination: addresses(t, "127.0.0.1:3000")},
			},
		},
	}

	if !reflect.DeepEqual(expected, conf.Tunnels) {
		t.Errorf("expected tunnels:\n%+v\nbut got:\n%+v", expected, conf.Tunnels)
	}

	if conf.Id != "multi" || !conf.Rpc || conf.RpcAddress != "127.0.0.1:0" {
		t.Errorf("the process wide settings were not taken from the alias: id=%s, rpc=%t, rpc-address=%s", conf.Id, conf.Rpc, conf.RpcAddress)
	}
}

// A tunnel giving a setting its zero value means it: no retries at all asks to
// never give up reconnecting, and a tunnel can validate the host key of its
// server while the others don't.
func TestMergeTunnelsKeepsZeroOverrides(t *testing.T) {
	al := multiTunnelAlias()
	al.Insecure = true

	secure := false
	never := 0
	al.Tunnels[1].Insecure = &secure
	al.Tunnels[1].ConnectionRetries = &never

	conf := &Configuration{}
	if err := conf.Merge(al, []string{}); err != nil {
		t.Fatalf("error while merging the alias: %v", err)
	}

	if !conf.Tunnels[0].Insecure || conf.Tunnels[0].ConnectionRetries != 3 {
		t.Errorf("expected the first tunnel to take the settings of the alias, but got insecure=%t, retries=%d", conf.Tunnels[0].Insecure, conf.Tunnels[0].ConnectionRetries)
	}

	if conf.Tunnels[1].Insecure || conf.Tunnels[1].ConnectionRetries != 0 {
		t.Errorf("expected the second tunnel to keep its own settings, but got insecure=%t, retries=%d", conf.Tunnels[1].Insecure, conf.Tunnels[1].ConnectionRetries)
	}
}

// The insecure flag given on the command line is about every server the
// instance connects to, whatever each tunnel says.
func TestMergeTunnelsInsecureFlag(t *testing.T) {
	al := multiTunnelAlias()

	secure := false
	al.Tunnels[1].Insecure = &secure

	conf := &Configuration{Insecure: true}
	if err := conf.Merge(al, []string{"insecure"}); err != nil {
		t.Fatalf("error while merging the alias: %v", err)
	}

	for i, tc := range conf.Tunnels {
		if !tc.Insecure {
			t.Errorf("tunnel %d should skip the host key validation as asked on the command line", i)
		}
	}
}

func TestMergeTunnelsRejectsInvalidAliases(t *testing.T) {
	tests := []struct {
		name   string
		change func(al *alias.Alias)
	}{
		{"a server of its own", func(al *alias.Alias) { al.Server = "mole@bastion-c" }},
		{"a type of its own", func(al *alias.Alias) { al.TunnelType = "local" }},
		{"a source of its own", func(al *alias.Alias) { al.Source = []string{":8081"} }},
		{"a destination of its own", func(al *alias.Alias) { al.Destination = []string{"db:5433"} }},
		{"a tunnel without server", func(al *alias.Alias) { al.Tunnels[1].Server = "" }},
		{"a tunnel without forwards", func(al *alias.Alias) { al.Tunnels[1].Forwards = nil }},
		{"a forward without type", func(al *alias.Alias) { al.Tunnels[0].Forwards[1].Type = "" }},
		{"an invalid duration", func(al *alias.Alias) { al.Tunnels[1].Timeout = "soon" }},
	}

	for _, test := range tests {
		al := multiTunnelAlias()
		test.change(al)

		conf := &Configuration{}
		if err := conf.Merge(al, []string{}); err == nil {
			t.Errorf("an alias with %s should not be accepted", test.name)
		}
	}
}

// An alias that names no server at all, as one whose tunnels were all left out
// does, has nothing to forward through, which is better told right away than
// found out when connecting to a server with no address.
func TestMergeRejectsAliasesWithoutServer(t *testing.T) {
	conf := &Configuration{}

	err := conf.Merge(&alias.Alias{Name: "nowhere", KeepAliveInterval: "10s", WaitAndRetry: "3s", Timeout: "3s"}, []string{})
	if err == nil || !strings.Contains(err.Error(), "nowhere") {
		t.Errorf("expected an error naming the alias without server, but got %v", err)
	}
}

func TestMergeLeavesFlatAliasesWithoutTunnels(t *testing.T) {
	conf := &Configuration{}

	al := &alias.Alias{
		Name:              "flat",
		TunnelType:        "local",
		Server:            "mole@bastion-a",
		Source:            []string{":8080"},
		Destination:       []string{"db:5432"},
		KeepAliveInterval: "10s",
		WaitAndRetry:      "3s",
		Timeout:           "3s",
	}

	if err := conf.Merge(al, []string{}); err != nil {
		t.Fatalf("error while merging the alias: %v", err)
	}

	if conf.Tunnels != nil {
		t.Errorf("expected a flat alias to describe its single tunnel through the flat settings, but got tunnels %+v", conf.Tunnels)
	}

	if conf.TunnelType != "local" || conf.Server.String() != "mole@bastion-a" {
		t.Errorf("expected the flat settings to be taken from the alias, but got type=%s, server=%s", conf.TunnelType, conf.Server)
	}
}

// address parses the given string representation of an address, failing the
// test when it can't.
func address(t *testing.T, value string) AddressInput {
	t.Helper()

	var a AddressInput
	if err := a.Set(value); err != nil {
		t.Fatalf("error while parsing address %s: %v", value, err)
	}

	return a
}

// addresses parses the given string representations of addresses into a list,
// which is nil when none is given, as it is in a configuration that never had
// one set.
func addresses(t *testing.T, values ...string) AddressInputList {
	t.Helper()

	var l AddressInputList
	for _, value := range values {
		if err := l.Set(value); err != nil {
			t.Fatalf("error while parsing address %s: %v", value, err)
		}
	}

	return l
}

// multiTunnelAlias returns an alias forwarding through two ssh servers, the
// first taking every tunnel setting from the alias and the second giving each
// of them a value of its own.
func multiTunnelAlias() *alias.Alias {
	insecure := true
	retries := 5

	return &alias.Alias{
		Name:              "multi",
		Key:               "path/to/key",
		KeepAliveInterval: "10s",
		ConnectionRetries: 3,
		WaitAndRetry:      "3s",
		SshAgent:          "path/to/agent",
		Timeout:           "5s",
		SshConfig:         "path/to/config",
		SocksAuth:         "mole:let me in",
		Rpc:               true,
		RpcAddress:        "127.0.0.1:0",
		Tunnels: []alias.Tunnel{
			{
				Server: "mole@bastion-a",
				Forwards: []alias.Forward{
					{Type: "local", Source: []string{":8080"}, Destination: []string{"db:5432"}},
					{Type: "dynamic", Source: []string{":1080"}},
				},
			},
			{
				Server:            "mole@bastion-b:2222",
				Key:               "path/to/other/key",
				KeepAliveInterval: "2s",
				ConnectionRetries: &retries,
				WaitAndRetry:      "1s",
				SshAgent:          "path/to/other/agent",
				Timeout:           "1s",
				SshConfig:         "path/to/other/config",
				Insecure:          &insecure,
				SocksAuth:         "other:let me in",
				Forwards: []alias.Forward{
					{Type: "remote", Source: []string{"0.0.0.0:9000"}, Destination: []string{"127.0.0.1:3000"}},
				},
			},
		},
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./mole -run 'TestMerge' -v`
Expected: build failure, `undefined: TunnelConfiguration`, `undefined: ForwardConfiguration`, `conf.Tunnels undefined`.

- [ ] **Step 3: Add the tunnel configuration types and their resolution**

Create `mole/tunnels.go`:

```go
package mole

import (
	"fmt"
	"time"

	"github.com/davrodpin/mole/alias"
)

// TunnelConfiguration holds what it takes to forward through one of the ssh
// servers an instance connects to.
type TunnelConfiguration struct {
	Server            AddressInput           `json:"server" mapstructure:"server" toml:"server"`
	Key               string                 `json:"key" mapstructure:"key" toml:"key"`
	KeepAliveInterval time.Duration          `json:"keep-alive-interval" mapstructure:"keep-alive-interval" toml:"keep-alive-interval"`
	ConnectionRetries int                    `json:"connection-retries" mapstructure:"connection-retries" toml:"connection-retries"`
	WaitAndRetry      time.Duration          `json:"wait-and-retry" mapstructure:"wait-and-retry" toml:"wait-and-retry"`
	SshAgent          string                 `json:"ssh-agent" mapstructure:"ssh-agent" toml:"ssh-agent"`
	Timeout           time.Duration          `json:"timeout" mapstructure:"timeout" toml:"timeout"`
	SshConfig         string                 `json:"ssh-config" mapstructure:"ssh-config" toml:"ssh-config"`
	Insecure          bool                   `json:"insecure" mapstructure:"insecure" toml:"insecure"`
	SocksAuth         string                 `json:"socks-auth" mapstructure:"socks-auth" toml:"socks-auth"`
	Forwards          []ForwardConfiguration `json:"forwards" mapstructure:"forwards" toml:"forwards"`
}

// ForwardConfiguration holds a group of channels of a single kind served
// through a tunnel.
type ForwardConfiguration struct {
	Type        string           `json:"type" mapstructure:"type" toml:"type"`
	Source      AddressInputList `json:"source" mapstructure:"source" toml:"source"`
	Destination AddressInputList `json:"destination" mapstructure:"destination" toml:"destination"`
}

// mergeTunnels overwrites the Configuration from an alias forwarding through
// several ssh servers. Each tunnel takes the settings it leaves out from the
// alias, and the insecure flag given on the command line, if any, over both.
func (c *Configuration) mergeTunnels(al *alias.Alias, insecureGiven bool) error {
	// the flat settings describe a tunnel of their own, which would have to be
	// either dropped without a word or started along with the others.
	if al.Server != "" || al.TunnelType != "" || len(al.Source) > 0 || len(al.Destination) > 0 {
		return fmt.Errorf("alias %s has tunnels along with a server, type, source or destination of its own: move them into a tunnel", al.Name)
	}

	tunnels := make([]TunnelConfiguration, len(al.Tunnels))

	for i, at := range al.Tunnels {
		tc, err := mergeTunnel(al, at)
		if err != nil {
			return fmt.Errorf("tunnel %d of alias %s: %v", i+1, al.Name, err)
		}

		if insecureGiven {
			tc.Insecure = c.Insecure
		}

		tunnels[i] = *tc
	}

	c.Tunnels = tunnels
	c.Rpc = al.Rpc
	c.RpcAddress = al.RpcAddress

	return nil
}

// mergeTunnel resolves the configuration of the given tunnel of an alias.
func mergeTunnel(al *alias.Alias, at alias.Tunnel) (*TunnelConfiguration, error) {
	if at.Server == "" {
		return nil, fmt.Errorf("no server given")
	}

	if len(at.Forwards) == 0 {
		return nil, fmt.Errorf("no forwards given for server %s", at.Server)
	}

	tc := &TunnelConfiguration{
		Key:               inherit(at.Key, al.Key),
		SshAgent:          inherit(at.SshAgent, al.SshAgent),
		SshConfig:         inherit(at.SshConfig, al.SshConfig),
		SocksAuth:         inherit(at.SocksAuth, al.SocksAuth),
		Insecure:          al.Insecure,
		ConnectionRetries: al.ConnectionRetries,
	}

	if at.Insecure != nil {
		tc.Insecure = *at.Insecure
	}

	if at.ConnectionRetries != nil {
		tc.ConnectionRetries = *at.ConnectionRetries
	}

	if err := tc.Server.Set(at.Server); err != nil {
		return nil, err
	}

	durations := []struct {
		name  string
		value string
		into  *time.Duration
	}{
		{"keep-alive-interval", inherit(at.KeepAliveInterval, al.KeepAliveInterval), &tc.KeepAliveInterval},
		{"wait-and-retry", inherit(at.WaitAndRetry, al.WaitAndRetry), &tc.WaitAndRetry},
		{"timeout", inherit(at.Timeout, al.Timeout), &tc.Timeout},
	}

	for _, d := range durations {
		v, err := time.ParseDuration(d.value)
		if err != nil {
			return nil, fmt.Errorf("invalid %s for server %s: %v", d.name, at.Server, err)
		}

		*d.into = v
	}

	for _, af := range at.Forwards {
		if af.Type == "" {
			return nil, fmt.Errorf("forward with no type for server %s", at.Server)
		}

		f := ForwardConfiguration{Type: af.Type}

		for _, src := range af.Source {
			if err := f.Source.Set(src); err != nil {
				return nil, err
			}
		}

		for _, dst := range af.Destination {
			if err := f.Destination.Set(dst); err != nil {
				return nil, err
			}
		}

		tc.Forwards = append(tc.Forwards, f)
	}

	return tc, nil
}

// inherit returns the value a tunnel gives to a setting, or the fallback the
// alias gives to it when the tunnel leaves it out.
func inherit(own, fallback string) string {
	if own != "" {
		return own
	}

	return fallback
}
```

- [ ] **Step 4: Wire it into `Configuration` and `Merge`**

In `mole/mole.go`, add as the last field of `Configuration` (after `RpcAddress`):

```go
	// Tunnels holds the tunnels of an instance started from an alias
	// forwarding through several ssh servers, which leaves the flat settings
	// describing a single tunnel empty.
	Tunnels []TunnelConfiguration `json:"tunnels,omitempty" mapstructure:"tunnels" toml:"tunnels,omitempty"`
```

In `Merge`, replace:

```go
	c.Id = al.Name
	c.TunnelType = al.TunnelType
```

with:

```go
	c.Id = al.Name

	if len(al.Tunnels) > 0 {
		return c.mergeTunnels(al, fl.lookup("insecure"))
	}

	if al.Server == "" {
		return fmt.Errorf("alias %s has neither a server nor tunnels to forward through", al.Name)
	}

	c.TunnelType = al.TunnelType
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./mole -run 'TestMerge|TestAliasMerge' -v -race`
Expected: PASS for all, including the unchanged `TestAliasMerge`.

- [ ] **Step 6: Run the whole suite and check formatting**

Run: `gofmt -l mole; go vet ./... && go test ./... -race`
Expected: nothing listed by `gofmt -l`; all packages `ok`.

- [ ] **Step 7: Commit**

```bash
git add mole/tunnels.go mole/tunnels_test.go mole/mole.go
git commit -m "Resolve the tunnels of an alias forwarding through several ssh servers" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Running every tunnel of an instance

**Files:**
- Modify: `mole/tunnels.go` (append)
- Modify: `mole/mole.go` (`Client` struct ~line 86-91, end of `Start` ~line 193-213, `createTunnel` ~line 455-518)
- Modify: `mole/runtime.go` (`Runtime` ~line 78-82)
- Modify test: `mole/runtime_test.go` (~line 115)
- Modify test: `mole/tunnels_test.go` (append)

**Interfaces:**
- Consumes: `tunnel.Forward`, `tunnel.NewWithForwards` (Task 1); `TunnelConfiguration`, `ForwardConfiguration`, `Configuration.Tunnels`, test helpers `address`, `addresses` (Task 3).
- Produces:
  - `Client.Tunnels []*tunnel.Tunnel` (replaces `Client.Tunnel`)
  - `func (c *Configuration) tunnels() []TunnelConfiguration`
  - `func createTunnel(tc TunnelConfiguration) (*tunnel.Tunnel, error)`
  - `func createTunnels(conf *Configuration) ([]*tunnel.Tunnel, error)`
  - `type runner interface { Start() error; String() string }`
  - `func runTunnels(tunnels []runner) error`

- [ ] **Step 1: Write the failing tests**

In `mole/tunnels_test.go`, add `"errors"` to the imports, then append:

```go
// testKey is a key without passphrase for the tunnels created by the tests,
// which never connect to anything.
const testKey = "../tunnel/testdata/dotssh/id_rsa"

func TestFlatConfigurationIsASingleTunnel(t *testing.T) {
	conf := &Configuration{
		TunnelType:        "local",
		Source:            addresses(t, ":8080"),
		Destination:       addresses(t, "db:5432"),
		Server:            address(t, "mole@bastion-a"),
		Key:               "path/to/key",
		KeepAliveInterval: 1 * time.Second,
		ConnectionRetries: 5,
		WaitAndRetry:      2 * time.Second,
		SshAgent:          "path/to/agent",
		Timeout:           3 * time.Second,
		SshConfig:         "path/to/config",
		Insecure:          true,
		SocksAuth:         "mole:let me in",
	}

	expected := []TunnelConfiguration{
		{
			Server:            address(t, "mole@bastion-a"),
			Key:               "path/to/key",
			KeepAliveInterval: 1 * time.Second,
			ConnectionRetries: 5,
			WaitAndRetry:      2 * time.Second,
			SshAgent:          "path/to/agent",
			Timeout:           3 * time.Second,
			SshConfig:         "path/to/config",
			Insecure:          true,
			SocksAuth:         "mole:let me in",
			Forwards: []ForwardConfiguration{
				{Type: "local", Source: addresses(t, ":8080"), Destination: addresses(t, "db:5432")},
			},
		},
	}

	if tunnels := conf.tunnels(); !reflect.DeepEqual(expected, tunnels) {
		t.Errorf("expected tunnels:\n%+v\nbut got:\n%+v", expected, tunnels)
	}
}

func TestCreateTunnelsCreatesOneTunnelPerServer(t *testing.T) {
	conf := &Configuration{
		Tunnels: []TunnelConfiguration{
			{
				Server:            address(t, "mole@127.0.0.1:2222"),
				Key:               testKey,
				ConnectionRetries: 3,
				Forwards: []ForwardConfiguration{
					{Type: "local", Source: addresses(t, "127.0.0.1:8080"), Destination: addresses(t, "db:5432")},
					{Type: "dynamic", Source: addresses(t, "127.0.0.1:1080")},
				},
			},
			{
				Server:            address(t, "mole@127.0.0.1:2223"),
				Key:               testKey,
				ConnectionRetries: 0,
				Forwards: []ForwardConfiguration{
					{Type: "remote", Source: addresses(t, "0.0.0.0:9000"), Destination: addresses(t, "127.0.0.1:3000")},
				},
			},
		},
	}

	tunnels, err := createTunnels(conf)
	if err != nil {
		t.Fatalf("error while creating the tunnels: %v", err)
	}

	if len(tunnels) != 2 {
		t.Fatalf("expected a tunnel for each of the 2 servers, but got %d", len(tunnels))
	}

	expected := [][]string{{"local", "dynamic"}, {"remote"}}

	for i, tun := range tunnels {
		var kinds []string
		for _, ch := range tun.Channels() {
			kinds = append(kinds, ch.ChannelType)
		}

		if !reflect.DeepEqual(expected[i], kinds) {
			t.Errorf("expected tunnel %d to have channels %v, but got %v", i, expected[i], kinds)
		}
	}

	if tunnels[0].ConnectionRetries != 3 || tunnels[1].ConnectionRetries != 0 {
		t.Errorf("expected each tunnel to keep its own connection retries, but got %d and %d", tunnels[0].ConnectionRetries, tunnels[1].ConnectionRetries)
	}
}

// A tunnel that can't be created stops the instance before any of them
// connects: an alias is started as a whole or not at all.
func TestCreateTunnelsFailsWhenAnyTunnelIsInvalid(t *testing.T) {
	tests := []struct {
		name    string
		forward ForwardConfiguration
	}{
		{"a local forward without destination", ForwardConfiguration{Type: "local", Source: addresses(t, "127.0.0.1:8080")}},
		{"a destination without port", ForwardConfiguration{Type: "local", Source: addresses(t, "127.0.0.1:8080"), Destination: addresses(t, "db")}},
		{"an unknown kind", ForwardConfiguration{Type: "locla", Source: addresses(t, "127.0.0.1:8080"), Destination: addresses(t, "db:5432")}},
	}

	for _, test := range tests {
		conf := &Configuration{
			Tunnels: []TunnelConfiguration{
				{
					Server:   address(t, "mole@127.0.0.1:2222"),
					Key:      testKey,
					Forwards: []ForwardConfiguration{{Type: "dynamic", Source: addresses(t, "127.0.0.1:1080")}},
				},
				{
					Server:   address(t, "mole@127.0.0.1:2223"),
					Key:      testKey,
					Forwards: []ForwardConfiguration{test.forward},
				},
			},
		}

		tunnels, err := createTunnels(conf)
		if err == nil {
			t.Errorf("the tunnels should not be created along with one with %s", test.name)
		}

		if tunnels != nil {
			t.Errorf("no tunnel should be handed over along with one with %s, but got %d", test.name, len(tunnels))
		}
	}
}

// fakeTunnel stands for a tunnel whose Start returns the given error, right
// away or once it is told to stop when it blocks.
type fakeTunnel struct {
	name    string
	err     error
	stop    chan struct{}
	started chan struct{}
}

func newFakeTunnel(name string, err error, blocks bool) *fakeTunnel {
	f := &fakeTunnel{name: name, err: err, started: make(chan struct{})}

	if blocks {
		f.stop = make(chan struct{})
	}

	return f
}

func (f *fakeTunnel) Start() error {
	close(f.started)

	if f.stop != nil {
		<-f.stop
	}

	return f.err
}

func (f *fakeTunnel) String() string {
	return f.name
}

// A tunnel ending for good leaves the others running: the instance is only over
// once every one of them is, and tells about each one that failed.
func TestRunTunnelsKeepsTheOthersRunning(t *testing.T) {
	failure := errors.New("source endpoint taken")
	failing := newFakeTunnel("bastion-a", failure, false)
	serving := newFakeTunnel("bastion-b", nil, true)

	done := make(chan error, 1)
	go func() { done <- runTunnels([]runner{failing, serving}) }()

	<-failing.started
	<-serving.started

	select {
	case err := <-done:
		t.Fatalf("the tunnels stopped running while one of them still was: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	close(serving.stop)

	select {
	case err := <-done:
		if !errors.Is(err, failure) {
			t.Errorf("expected the failure of the tunnel to be reported, but got %v", err)
		}

		if err != nil && !strings.Contains(err.Error(), "bastion-a") {
			t.Errorf("expected the failure to name the tunnel it came from, but got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("the tunnels kept running after every one of them stopped")
	}
}

func TestRunTunnelsReportsNothingWhenEveryTunnelStopsCleanly(t *testing.T) {
	err := runTunnels([]runner{newFakeTunnel("bastion-a", nil, false), newFakeTunnel("bastion-b", nil, false)})
	if err != nil {
		t.Errorf("expected no error from tunnels that stopped cleanly, but got %v", err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./mole -run 'TestFlatConfigurationIsASingleTunnel|TestCreateTunnels|TestRunTunnels' -v`
Expected: build failure, `conf.tunnels undefined`, `undefined: createTunnels`, `undefined: runner`, `undefined: runTunnels`.

- [ ] **Step 3: Add `tunnels`, `runner` and `runTunnels`**

In `mole/tunnels.go`, replace the import block with:

```go
import (
	"errors"
	"fmt"
	"time"

	"github.com/davrodpin/mole/alias"

	log "github.com/sirupsen/logrus"
)
```

and append:

```go
// tunnels returns the configuration of every tunnel the instance runs: the ones
// of an alias forwarding through several ssh servers, or else the single one
// the flat settings describe.
func (c *Configuration) tunnels() []TunnelConfiguration {
	if len(c.Tunnels) > 0 {
		return c.Tunnels
	}

	return []TunnelConfiguration{{
		Server:            c.Server,
		Key:               c.Key,
		KeepAliveInterval: c.KeepAliveInterval,
		ConnectionRetries: c.ConnectionRetries,
		WaitAndRetry:      c.WaitAndRetry,
		SshAgent:          c.SshAgent,
		Timeout:           c.Timeout,
		SshConfig:         c.SshConfig,
		Insecure:          c.Insecure,
		SocksAuth:         c.SocksAuth,
		Forwards: []ForwardConfiguration{{
			Type:        c.TunnelType,
			Source:      c.Source,
			Destination: c.Destination,
		}},
	}}
}

// runner is what runTunnels needs from a tunnel, which keeps how an instance
// runs several of them testable without a ssh server.
type runner interface {
	Start() error
	String() string
}

// runTunnels starts every given tunnel and waits for all of them to be over. A
// tunnel ending for good is reported along with what it was forwarding
// through, while the others keep going: an alias forwarding through several
// ssh servers is still of use for as long as any of them is.
func runTunnels(tunnels []runner) error {
	results := make(chan error, len(tunnels))

	for _, t := range tunnels {
		go func(t runner) {
			err := t.Start()
			if err != nil {
				log.WithFields(log.Fields{
					"tunnel": t.String(),
				}).WithError(err).Error("error while starting tunnel")

				err = fmt.Errorf("tunnel %s: %w", t, err)
			}

			results <- err
		}(t)
	}

	var errs []error

	for range tunnels {
		if err := <-results; err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
```

- [ ] **Step 4: Create one tunnel per configuration**

In `mole/mole.go`, replace the `Client` struct with:

```go
// Client manages the overall state of the application based on its configuration.
type Client struct {
	Conf *Configuration
	// Tunnels holds a tunnel for each ssh server the instance forwards
	// through, in the order they are configured.
	Tunnels []*tunnel.Tunnel
	sigs    chan os.Signal
}
```

In `Start`, replace everything from `t, err := createTunnel(c.Conf)` to the end of the function with:

```go
	tunnels, err := createTunnels(c.Conf)
	if err != nil {
		log.WithFields(log.Fields{
			"id": c.Conf.Id,
		}).WithError(err).Error("error creating tunnel")

		return err
	}

	c.Tunnels = tunnels

	runners := make([]runner, len(tunnels))
	for i, t := range tunnels {
		runners[i] = t
	}

	return runTunnels(runners)
}
```

Replace the whole `createTunnel` function with:

```go
// createTunnels creates every tunnel the instance runs, one after the other so
// that the passphrase of a key is never asked for while another one is. Any of
// them failing stops the instance before anything connects.
func createTunnels(conf *Configuration) ([]*tunnel.Tunnel, error) {
	var tunnels []*tunnel.Tunnel

	for _, tc := range conf.tunnels() {
		t, err := createTunnel(tc)
		if err != nil {
			return nil, err
		}

		tunnels = append(tunnels, t)
	}

	return tunnels, nil
}

func createTunnel(tc TunnelConfiguration) (*tunnel.Tunnel, error) {
	s, err := tunnel.NewServer(tc.Server.User, tc.Server.Address(), tc.Key, tc.SshAgent, tc.SshConfig)
	if err != nil {
		log.Errorf("error processing server options: %v\n", err)
		return nil, err
	}

	s.Insecure = tc.Insecure
	s.Timeout = tc.Timeout

	err = s.Key.HandlePassphrase(func() ([]byte, error) {
		// an instance can connect to several servers, so the one the key is
		// for is named.
		fmt.Printf("The key provided for %s is secured by a password. Please provide it below:\n", tc.Server.String())
		fmt.Printf("Password: ")
		p, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Printf("\n")
		return p, err
	})

	if err != nil {
		log.WithError(err).Error("error setting up password handling function")
		return nil, err
	}

	log.Debugf("server: %s", s)

	forwards := make([]tunnel.Forward, len(tc.Forwards))

	for i, f := range tc.Forwards {
		destination := make([]string, len(f.Destination))

		for j, r := range f.Destination {
			if r.Port == "" {
				err := fmt.Errorf("missing port in destination address: %s", r.String())
				log.Error(err)
				return nil, err
			}

			destination[j] = r.String()
		}

		forwards[i] = tunnel.Forward{Type: f.Type, Source: f.Source.List(), Destination: destination}
	}

	t, err := tunnel.NewWithForwards(s, forwards, tc.SshConfig)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	t.SocksUser, t.SocksPassword, err = socksCredentials(tc.SocksAuth)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	//TODO need to find a way to require the attributes below to be always set
	// since they are not optional (functionality will break if they are not
	// set and CLI parsing is the one setting the default values).
	// That could be done by make them required in the constructor's signature or
	// by creating a configuration struct for a tunnel object.
	t.ConnectionRetries = tc.ConnectionRetries
	t.WaitAndRetry = tc.WaitAndRetry
	t.KeepAliveInterval = tc.KeepAliveInterval

	return t, nil
}
```

- [ ] **Step 5: Follow the rename in the runtime**

In `mole/runtime.go`, replace:

```go
	if c.Tunnel != nil {
```

with:

```go
	// an instance with flat settings runs a single tunnel.
	if len(c.Tunnels) > 0 {
```

and replace `for _, channel := range c.Tunnel.Channels() {` with `for _, channel := range c.Tunnels[0].Channels() {`.

In `mole/runtime_test.go`, replace:

```go
		client := mole.Client{Conf: &mole.Configuration{Id: "dynamic-runtime"}, Tunnel: tun}
```

with:

```go
		client := mole.Client{Conf: &mole.Configuration{Id: "dynamic-runtime"}, Tunnels: []*tunnel.Tunnel{tun}}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./mole -v -race`
Expected: PASS for every test in the package.

- [ ] **Step 7: Run the whole suite, vet, and build**

Run: `gofmt -l mole; go vet ./... && go test ./... -race && go build -o /tmp/mole-bin github.com/davrodpin/mole`
Expected: nothing listed by `gofmt -l`; all packages `ok`; the build succeeds.

- [ ] **Step 8: Commit**

```bash
git add mole/tunnels.go mole/tunnels_test.go mole/mole.go mole/runtime.go mole/runtime_test.go
git commit -m "Run every tunnel of an alias until the last one is over" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Reporting the tunnels of a running instance, and docs

**Files:**
- Modify: `mole/runtime.go` (`Runtime` function, new `tunnelsRuntime` and `forwardsOf`)
- Modify test: `mole/tunnels_test.go` (append)
- Modify: `docs/index.md` (highlighted features ~line 17, table of contents ~line 46, new section after "Start mole in background" ~line 415)
- Modify: `CHANGELOG.md` (`## [Unreleased]` → `### Added` and `### Fixed`)

**Interfaces:**
- Consumes: `Client.Tunnels`, `Configuration.Tunnels`, `TunnelConfiguration`, `ForwardConfiguration`, `tunnel.NewWithForwards`, test helpers `address`, `addresses` (Tasks 1, 3, 4).
- Produces: `Client.Runtime()` fills `Runtime.Tunnels` for a multi-tunnel instance, with each tunnel's forwards built from its channels (bound sources) and its socks credentials removed. Flat instances report exactly as before.

- [ ] **Step 1: Write the failing tests**

In `mole/tunnels_test.go`, add `"encoding/json"`, `"github.com/davrodpin/mole/tunnel"` and `"github.com/go-viper/mapstructure/v2"` to the imports, then append:

```go
func TestRuntimeOfSeveralTunnels(t *testing.T) {
	client := runtimeClient(t)

	rt, err := client.Runtime()
	if err != nil {
		t.Fatalf("error while reading the runtime information: %v", err)
	}

	// the sources are the ones the channels are listening on, rather than the
	// ones they were asked for, and the socks credentials are left out.
	expected := []TunnelConfiguration{
		{
			Server:            address(t, "mole@bastion-a"),
			KeepAliveInterval: 10 * time.Second,
			Forwards: []ForwardConfiguration{
				{Type: "local", Source: addresses(t, "127.0.0.1:8080"), Destination: addresses(t, "db:5432")},
				{Type: "dynamic", Source: addresses(t, "127.0.0.1:1080")},
			},
		},
		{
			Server:   address(t, "mole@bastion-b:2222"),
			Insecure: true,
			Forwards: []ForwardConfiguration{
				{Type: "remote", Source: addresses(t, "0.0.0.0:9000"), Destination: addresses(t, "127.0.0.1:3000")},
			},
		},
	}

	if !reflect.DeepEqual(expected, rt.Tunnels) {
		t.Errorf("expected tunnels:\n%+v\nbut got:\n%+v", expected, rt.Tunnels)
	}

	// what the instance is running with is left alone: only what it reports is.
	if client.Conf.Tunnels[0].SocksAuth != "mole:let me in" {
		t.Errorf("the configuration of the instance lost its socks credentials")
	}

	if len(client.Conf.Tunnels[0].Forwards[0].Source) != 1 || client.Conf.Tunnels[0].Forwards[0].Source[0].Port != "0" {
		t.Errorf("the configuration of the instance had its sources replaced: %+v", client.Conf.Tunnels[0].Forwards)
	}
}

func TestRuntimeOfSeveralTunnelsToToml(t *testing.T) {
	rt, err := runtimeClient(t).Runtime()
	if err != nil {
		t.Fatalf("error while reading the runtime information: %v", err)
	}

	out, err := rt.Format("toml")
	if err != nil {
		t.Fatalf("error while formatting the runtime information: %v", err)
	}

	for _, expected := range []string{"[[tunnels]]", "[[tunnels.forwards]]", `type = "dynamic"`, `host = "bastion-b"`} {
		if !strings.Contains(out, expected) {
			t.Errorf("expected the runtime information to carry %s, but got:\n%s", expected, out)
		}
	}

	if strings.Contains(out, "let me in") {
		t.Errorf("the runtime information carries the socks credentials:\n%s", out)
	}
}

// "mole show instances" reads what an instance tells about itself through the
// rpc server, which carries it as json, so the tunnels have to make it through.
func TestRuntimeOfSeveralTunnelsThroughRpc(t *testing.T) {
	rt, err := runtimeClient(t).Runtime()
	if err != nil {
		t.Fatalf("error while reading the runtime information: %v", err)
	}

	data, err := json.Marshal(rt)
	if err != nil {
		t.Fatalf("error while encoding the runtime information: %v", err)
	}

	var message interface{}
	if err := json.Unmarshal(data, &message); err != nil {
		t.Fatalf("error while decoding the rpc message: %v", err)
	}

	var received Runtime
	if err := mapstructure.Decode(message, &received); err != nil {
		t.Fatalf("error while reading the runtime information from the rpc message: %v", err)
	}

	if !reflect.DeepEqual(rt.Tunnels, received.Tunnels) {
		t.Errorf("expected tunnels:\n%+v\nbut got:\n%+v", rt.Tunnels, received.Tunnels)
	}
}

// runtimeClient returns a client forwarding through two ssh servers whose
// tunnels are never started: the sources they were created with stand for the
// ones they would be listening on, which differ from the configured ones.
func runtimeClient(t *testing.T) *Client {
	t.Helper()

	conf := &Configuration{
		Id: "multi",
		Tunnels: []TunnelConfiguration{
			{
				Server:            address(t, "mole@bastion-a"),
				KeepAliveInterval: 10 * time.Second,
				SocksAuth:         "mole:let me in",
				Forwards: []ForwardConfiguration{
					{Type: "local", Source: addresses(t, "127.0.0.1:0"), Destination: addresses(t, "db:5432")},
					{Type: "dynamic", Source: addresses(t, "127.0.0.1:0")},
				},
			},
			{
				Server:   address(t, "mole@bastion-b:2222"),
				Insecure: true,
				Forwards: []ForwardConfiguration{
					{Type: "remote", Source: addresses(t, "0.0.0.0:0"), Destination: addresses(t, "127.0.0.1:3000")},
				},
			},
		},
	}

	first, err := tunnel.NewWithForwards(&tunnel.Server{Name: "bastion-a"}, []tunnel.Forward{
		{Type: "local", Source: []string{"127.0.0.1:8080"}, Destination: []string{"db:5432"}},
		{Type: "dynamic", Source: []string{"127.0.0.1:1080"}},
	}, "")
	if err != nil {
		t.Fatalf("error while creating the first tunnel: %v", err)
	}

	second, err := tunnel.NewWithForwards(&tunnel.Server{Name: "bastion-b"}, []tunnel.Forward{
		{Type: "remote", Source: []string{"0.0.0.0:9000"}, Destination: []string{"127.0.0.1:3000"}},
	}, "")
	if err != nil {
		t.Fatalf("error while creating the second tunnel: %v", err)
	}

	return &Client{Conf: conf, Tunnels: []*tunnel.Tunnel{first, second}}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./mole -run 'TestRuntimeOfSeveralTunnels' -v`
Expected: FAIL. `TestRuntimeOfSeveralTunnels` reports the configured `127.0.0.1:0` sources and the socks credentials instead of the expected tunnels, and `TestRuntimeOfSeveralTunnelsToToml` reports `let me in` in the output.

- [ ] **Step 3: Report each tunnel from its channels**

In `mole/runtime.go`, add `"github.com/davrodpin/mole/tunnel"` to the imports, and replace the `Runtime` method with:

```go
func (c *Client) Runtime() (*Runtime, error) {
	runtime := Runtime(*c.Conf)

	// the credentials the socks proxy asks its clients for are not part of what
	// an instance tells about itself: whoever is looking at what it is doing has
	// no use for them.
	runtime.SocksAuth = ""

	if len(c.Conf.Tunnels) > 0 {
		tunnels, err := c.tunnelsRuntime()
		if err != nil {
			return nil, err
		}

		runtime.Tunnels = tunnels

		return &runtime, nil
	}

	// an instance with flat settings runs a single tunnel.
	if len(c.Tunnels) > 0 {
		source := &AddressInputList{}
		destination := &AddressInputList{}

		for _, channel := range c.Tunnels[0].Channels() {
			var err error

			err = source.Set(channel.Source)
			if err != nil {
				return nil, err
			}

			// a dynamic or reverse dynamic channel has no destination of its
			// own: every connection made to it carries the address it wants to
			// reach, so there is nothing to report other than the endpoint it
			// listens on.
			if channel.Destination == "" {
				continue
			}

			err = destination.Set(channel.Destination)
			if err != nil {
				return nil, err
			}

		}

		runtime.Source = *source
		runtime.Destination = *destination
	}

	return &runtime, nil
}

// tunnelsRuntime returns what each tunnel of an instance forwarding through
// several ssh servers is doing: the forwards it serves, with the source
// endpoints its channels are listening on, and without the credentials its
// socks proxies ask their clients for.
func (c *Client) tunnelsRuntime() ([]TunnelConfiguration, error) {
	// the tunnels are copied rather than changed in place: they are what the
	// instance keeps running with.
	tunnels := make([]TunnelConfiguration, len(c.Conf.Tunnels))

	for i, tc := range c.Conf.Tunnels {
		tc.SocksAuth = ""

		// the tunnels only exist once the instance has started.
		if i < len(c.Tunnels) {
			forwards, err := forwardsOf(c.Tunnels[i].Channels())
			if err != nil {
				return nil, err
			}

			tc.Forwards = forwards
		}

		tunnels[i] = tc
	}

	return tunnels, nil
}

// forwardsOf returns the forwards the given channels serve, with the source
// endpoints they are listening on. Channels of the same kind next to each other
// are told about together, the way they were given.
func forwardsOf(channels []*tunnel.SSHChannel) ([]ForwardConfiguration, error) {
	var forwards []ForwardConfiguration

	for _, channel := range channels {
		if len(forwards) == 0 || forwards[len(forwards)-1].Type != channel.ChannelType {
			forwards = append(forwards, ForwardConfiguration{Type: channel.ChannelType})
		}

		f := &forwards[len(forwards)-1]

		if err := f.Source.Set(channel.Source); err != nil {
			return nil, err
		}

		// a dynamic or reverse dynamic channel has no destination of its own.
		if channel.Destination == "" {
			continue
		}

		if err := f.Destination.Set(channel.Destination); err != nil {
			return nil, err
		}
	}

	return forwards, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./mole -v -race`
Expected: PASS for every test, including the unchanged `TestFormatRuntimeToML`, `TestRuntimeOfDynamicTunnel` and `TestRuntimeDoesNotReportSocksCredentials`.

If `TestRuntimeOfSeveralTunnelsThroughRpc` fails on the durations or the addresses, the mapstructure tags of `TunnelConfiguration`/`ForwardConfiguration` disagree with their json tags. Make them equal; do not change the test.

- [ ] **Step 5: Document the feature**

In `docs/index.md`, add to **Highlighted Features**, right after the `[Aliases](...)` bullet:

```markdown
  * [Aliases through several servers](#forward-through-several-ssh-servers-with-a-single-alias): a single alias can forward through several ssh servers at once, each with any mix of local, remote, dynamic and reverse dynamic forwards, started and stopped together.
```

Add to the **Table of Contents**, right after the `[Start mole in background](#start-mole-in-background)` entry:

```markdown
  * [Forward through several ssh servers with a single alias](#forward-through-several-ssh-servers-with-a-single-alias)
```

Add this section right after the "Start mole in background" section (before `### Leveraging LocalForward from SSH configuration file`):

````markdown
### Forward through several ssh servers with a single alias

An alias can forward through several ssh servers at once, each with any mix of
local, remote, dynamic and reverse dynamic forwards. Such an alias is written by
hand in `$HOME/.mole/<alias>.toml`: every `[[tunnels]]` entry is a connection to
a ssh server, serving the `[[tunnels.forwards]]` listed under it.

The settings at the top of the file are used by every tunnel, which can give
its own `key`, `ssh-agent`, `config`, `insecure`, `timeout`,
`keep-alive-interval`, `connection-retries`, `wait-and-retry` and `socks-auth`.
`verbose`, `detach`, `rpc` and `rpc-address` are about the whole instance.

```sh
$ cat ~/.mole/example.toml
key = "/home/user/.ssh/id_ed25519"
connection-retries = 3

[[tunnels]]
server = "user@bastion-a.example.com"

  [[tunnels.forwards]]
  type = "local"
  source = [":8080"]
  destination = ["172.17.0.100:80"]

  [[tunnels.forwards]]
  type = "dynamic"
  source = [":1080"]

[[tunnels]]
server = "user@bastion-b.example.com:2222"
key = "/home/user/.ssh/other_key"

  [[tunnels.forwards]]
  type = "remote"
  source = ["127.0.0.1:9000"]
  destination = ["127.0.0.1:3000"]
$ mole start alias example
INFO[0000] tunnel channel is waiting for connection      destination="172.17.0.100:80" source="127.0.0.1:8080"
INFO[0000] tunnel channel is waiting for connection      source="127.0.0.1:1080"
INFO[0000] tunnel channel is waiting for connection      destination="127.0.0.1:3000" source="127.0.0.1:9000"
```

A tunnel that stops for good, e.g. after running out of connection retries, is
reported and leaves the others running. `mole stop example` stops all of them.
````

- [ ] **Step 6: Record the change**

In `CHANGELOG.md`, append to the `### Added` list under `## [Unreleased]`:

```markdown
- Aliases forwarding through several ssh servers at once, each with any mix of
  local, remote, dynamic and reverse dynamic forwards, written by hand as
  `[[tunnels]]` entries of the alias file. The settings at the top of the file
  are used by every tunnel unless it gives its own, a tunnel that stops for
  good leaves the others running, and `show instances` lists the forwards of
  each tunnel
```

and append to the `### Fixed` list under `## [Unreleased]`:

```markdown
- A destination address without a port no longer crashes `start`. The error
  was logged but not returned, so mole went on to start a tunnel that did not
  exist
```

- [ ] **Step 7: Run the whole suite the way CI does**

Run: `make test`
Expected: no formatting error; every package `ok`.

- [ ] **Step 8: Commit**

```bash
git add mole/runtime.go mole/tunnels_test.go docs/index.md CHANGELOG.md
git commit -m "Report the forwards of each tunnel an instance runs" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```
