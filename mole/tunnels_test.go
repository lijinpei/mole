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
