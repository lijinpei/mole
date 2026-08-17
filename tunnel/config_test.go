package tunnel

import (
	"reflect"
	"strings"
	"testing"

	"github.com/kevinburke/ssh_config"
)

func TestSSHConfigFile(t *testing.T) {

	var config = `
Host example1
  Hostname 172.17.0.1
	Port 3306
	User john
	IdentityFile /path/.ssh/id_rsa
Host example2
	LocalForward 8080 127.0.0.1:8080
Host example3
	LocalForward 9090 127.0.0.1:9090
	LocalForward 9091 127.0.0.1:9091
Host example4
	RemoteForward 80 127.0.0.1:8080
Host example5
	RemoteForward 192.168.1.100:80 my-server:8080
Host example6
	DynamicForward 1080
Host example7
	RemoteForward 1080
	RemoteForward 80 127.0.0.1:8080
`

	c, _ := ssh_config.Decode(strings.NewReader(config))
	cfg := &SSHConfigFile{sshConfig: c}

	tests := []struct {
		host     string
		expected *SSHHost
	}{
		{
			"example1",
			&SSHHost{
				Hostname:      "172.17.0.1",
				Port:          "3306",
				User:          "john",
				Key:           "/path/.ssh/id_rsa",
				LocalForwards: nil,
			},
		},
		{
			"example2",
			&SSHHost{
				Hostname:      "",
				Port:          "",
				User:          "",
				Key:           "",
				LocalForwards: []*ForwardConfig{&ForwardConfig{Source: "127.0.0.1:8080", Destination: "127.0.0.1:8080"}},
			},
		},
		{
			"example3",
			&SSHHost{
				Hostname: "",
				Port:     "",
				User:     "",
				Key:      "",
				LocalForwards: []*ForwardConfig{
					&ForwardConfig{Source: "127.0.0.1:9090", Destination: "127.0.0.1:9090"},
					&ForwardConfig{Source: "127.0.0.1:9091", Destination: "127.0.0.1:9091"},
				},
			},
		},
		{
			"example4",
			&SSHHost{
				Hostname:       "",
				Port:           "",
				User:           "",
				Key:            "",
				RemoteForwards: []*ForwardConfig{&ForwardConfig{Source: "127.0.0.1:80", Destination: "127.0.0.1:8080"}},
			},
		},
		{
			"example5",
			&SSHHost{
				Hostname:       "",
				Port:           "",
				User:           "",
				Key:            "",
				RemoteForwards: []*ForwardConfig{&ForwardConfig{Source: "192.168.1.100:80", Destination: "my-server:8080"}},
			},
		},
		{
			"example6",
			&SSHHost{
				Hostname:        "",
				Port:            "",
				User:            "",
				Key:             "",
				DynamicForwards: []*ForwardConfig{&ForwardConfig{Source: "127.0.0.1:1080"}},
			},
		},
		// a RemoteForward carrying a source endpoint alone asks for a reverse
		// dynamic forward, and says nothing about the remote forwards of the
		// same host.
		{
			"example7",
			&SSHHost{
				Hostname:               "",
				Port:                   "",
				User:                   "",
				Key:                    "",
				RemoteForwards:         []*ForwardConfig{&ForwardConfig{Source: "127.0.0.1:80", Destination: "127.0.0.1:8080"}},
				ReverseDynamicForwards: []*ForwardConfig{&ForwardConfig{Source: "127.0.0.1:1080"}},
			},
		},
	}

	var value *SSHHost
	for _, test := range tests {
		value = cfg.Get(test.host)

		if !reflect.DeepEqual(test.expected, value) {
			t.Errorf("unexpected result for %s:\n\texpected: %s\n\tvalue   : %s", test.host, test.expected, value)
		}
	}
}

// A forwarding configuration that names neither a destination nor an endpoint
// to listen on is malformed: reading it as a dynamic or a reverse dynamic
// forward would turn it into an address nothing can listen on, and the tunnel
// would only fail once it tried to use it.
func TestMalformedForwardConfig(t *testing.T) {
	var config = `
Host example1
	RemoteForward /run/mole.sock
Host example2
	RemoteForward 1080x
Host example3
	DynamicForward /run/mole.sock
Host example4
	RemoteForward 1080
	RemoteForward /run/mole.sock
`

	c, _ := ssh_config.Decode(strings.NewReader(config))
	cfg := &SSHConfigFile{sshConfig: c}

	// a single malformed setting is enough to leave the host without any
	// forward of that kind, the same way a malformed LocalForward already does.
	for _, host := range []string{"example1", "example2", "example3", "example4"} {
		value := cfg.Get(host)

		if value.ReverseDynamicForwards != nil {
			t.Errorf("expected no reverse dynamic forward to be read for host %s, but got %v", host, value.ReverseDynamicForwards)
		}

		if value.DynamicForwards != nil {
			t.Errorf("expected no dynamic forward to be read for host %s, but got %v", host, value.DynamicForwards)
		}
	}
}
