package mole

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/davrodpin/mole/alias"
	"github.com/davrodpin/mole/tunnel"
	"github.com/go-viper/mapstructure/v2"
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
