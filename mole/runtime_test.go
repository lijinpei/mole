package mole_test

import (
	"strings"
	"testing"

	"github.com/davrodpin/mole/fsutils"
	"github.com/davrodpin/mole/mole"
	"github.com/davrodpin/mole/tunnel"

	"github.com/andreyvit/diff"
)

const expectedInstance string = `id = "id1"
tunnel-type = ""
verbose = false
insecure = false
detach = false
key = ""
keep-alive-interval = "0s"
connection-retries = 0
wait-and-retry = "0s"
ssh-agent = ""
timeout = "0s"
ssh-config = ""
socks-auth = ""
rpc = false
rpc-address = ""

[server]
  user = ""
  host = ""
  port = ""`

const expectedMultipleInstances string = `[instances]
  [instances.id1]
    id = "id1"
    tunnel-type = ""
    verbose = false
    insecure = false
    detach = false
    key = ""
    keep-alive-interval = "0s"
    connection-retries = 0
    wait-and-retry = "0s"
    ssh-agent = ""
    timeout = "0s"
    ssh-config = ""
    socks-auth = ""
    rpc = false
    rpc-address = ""
    [instances.id1.server]
      user = ""
      host = ""
      port = ""
  [instances.id2]
    id = "id2"
    tunnel-type = ""
    verbose = false
    insecure = false
    detach = false
    key = ""
    keep-alive-interval = "0s"
    connection-retries = 0
    wait-and-retry = "0s"
    ssh-agent = ""
    timeout = "0s"
    ssh-config = ""
    socks-auth = ""
    rpc = false
    rpc-address = ""
    [instances.id2.server]
      user = ""
      host = ""
      port = ""`

func TestFormatRuntimeToML(t *testing.T) {
	instances := []mole.Runtime{
		mole.Runtime{Id: "id1"},
		mole.Runtime{Id: "id2"},
	}

	runtimes := mole.InstancesRuntime(instances)

	tests := []struct {
		formatter mole.Formatter
		expected  string
	}{
		{formatter: mole.Runtime{Id: "id1"}, expected: expectedInstance},
		{formatter: runtimes, expected: expectedMultipleInstances},
	}

	for _, test := range tests {
		out, err := test.formatter.Format("toml")

		if err != nil {
			t.Errorf("%v", err)
		}

		if a, e := strings.TrimSpace(out), strings.TrimSpace(test.expected); a != e {
			t.Errorf("Result not as expected:\n%v", diff.LineDiff(e, a))
		}
	}
}

func TestRuntimeOfDynamicTunnel(t *testing.T) {
	for _, tunnelType := range []string{"dynamic", "reverse-dynamic"} {
		// the tunnel is never started: Channels reports what it was configured
		// with, which is all the runtime information is built from.
		tun, err := tunnel.New(tunnelType, &tunnel.Server{Name: "example"}, []string{"127.0.0.1:1080"}, nil, "")
		if err != nil {
			t.Fatalf("error while creating the %s tunnel: %v", tunnelType, err)
		}

		client := mole.Client{Conf: &mole.Configuration{Id: "dynamic-runtime"}, Tunnel: tun}

		rt, err := client.Runtime()
		if err != nil {
			t.Fatalf("error while reading the runtime information of the %s tunnel: %v", tunnelType, err)
		}

		if len(rt.Source) != 1 || rt.Source[0].String() != "127.0.0.1:1080" {
			t.Errorf("expected the source endpoint of the %s tunnel to be reported, but got %v", tunnelType, rt.Source.List())
		}

		// a dynamic or reverse dynamic channel has no destination, so reporting
		// one would mean making an address up.
		if len(rt.Destination) != 0 {
			t.Errorf("expected no destination to be reported for a %s tunnel, but got %d: %q", tunnelType, len(rt.Destination), rt.Destination.List())
		}
	}
}

// What an instance tells about itself is asked for through the rpc server and
// printed by "mole show", so the credentials its socks proxy asks its clients
// for have no place in it.
func TestRuntimeDoesNotReportSocksCredentials(t *testing.T) {
	conf := &mole.Configuration{Id: "socks-runtime", SocksAuth: "mole:let me in"}
	client := mole.Client{Conf: conf}

	rt, err := client.Runtime()
	if err != nil {
		t.Fatalf("error while reading the runtime information: %v", err)
	}

	if rt.SocksAuth != "" {
		t.Errorf("the runtime information carries the socks credentials: %s", rt.SocksAuth)
	}

	// what the instance is running with is left alone: only what it reports is.
	if conf.SocksAuth == "" {
		t.Errorf("the configuration of the instance lost its socks credentials")
	}
}

func TestClientRunning(t *testing.T) {
	id := "test-client-running"

	// Mock the pid file using the process id of the program running the test
	_, err := fsutils.CreateInstanceDir(id)
	if err != nil {
		t.Errorf("%v", err)
	}

	conf := &mole.Configuration{Id: id}
	client := mole.Client{Conf: conf}

	running, err := client.Running()
	if err != nil {
		t.Errorf("%v", err)
	}

	if !running {
		t.Errorf("client was supposed to be running")
	}
}
