package mole_test

import (
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/davrodpin/mole/alias"
	"github.com/davrodpin/mole/fsutils"
	"github.com/davrodpin/mole/mole"
)

func TestAliasMerge(t *testing.T) {
	tests := []struct {
		alias      *alias.Alias
		givenFlags []string
		conf       mole.Configuration
		expected   mole.Configuration
	}{
		{
			&alias.Alias{
				Verbose:           false,
				Insecure:          false,
				Detach:            false,
				Source:            []string{"127.0.0.1:80"},
				Destination:       []string{"172.17.0.100:8080"},
				Server:            "user@example.com:22",
				Key:               "path/to/key/1",
				KeepAliveInterval: "3s",
				ConnectionRetries: 3,
				WaitAndRetry:      "10s",
				SshAgent:          "path/to/sshagent",
				Timeout:           "3s",
			},
			[]string{},
			mole.Configuration{
				Verbose:  true,
				Insecure: true,
				Detach:   true,
			},
			mole.Configuration{
				Verbose:  false,
				Insecure: false,
				Detach:   false,
			},
		},
		{
			&alias.Alias{
				Verbose:           false,
				Insecure:          false,
				Detach:            false,
				Source:            []string{"127.0.0.1:80"},
				Destination:       []string{"172.17.0.100:8080"},
				Server:            "user@example.com:22",
				Key:               "path/to/key/1",
				KeepAliveInterval: "3s",
				ConnectionRetries: 3,
				WaitAndRetry:      "10s",
				SshAgent:          "path/to/sshagent",
				Timeout:           "3s",
			},
			[]string{"verbose", "insecure", "detach"},
			mole.Configuration{
				Verbose:  true,
				Insecure: true,
				Detach:   true,
			},
			mole.Configuration{
				Verbose:  true,
				Insecure: true,
				Detach:   true,
			},
		},
		{
			&alias.Alias{
				Verbose:           false,
				Insecure:          false,
				Detach:            false,
				Source:            []string{"127.0.0.1:80"},
				Destination:       []string{"172.17.0.100:8080"},
				Server:            "user@example.com:22",
				Key:               "path/to/key/1",
				KeepAliveInterval: "3s",
				ConnectionRetries: 3,
				WaitAndRetry:      "10s",
				SshAgent:          "path/to/sshagent",
				Timeout:           "3s",
			},
			[]string{},
			mole.Configuration{
				SshConfig: "path/to/config",
			},
			mole.Configuration{
				SshConfig: "path/to/config",
			},
		},
	}

	for id, test := range tests {
		test.alias.TunnelType = "local"
		conf := test.conf
		if err := conf.Merge(test.alias, test.givenFlags); err != nil {
			t.Fatalf("could not merge alias on test %d: %v", id, err)
		}

		if test.expected.Verbose != conf.Verbose {
			t.Errorf("verbose doesn't match on test %d: expected: %t, value: %t", id, test.expected.Verbose, conf.Verbose)
		}

		if test.expected.Insecure != conf.Insecure {
			t.Errorf("insecure doesn't match on test %d: expected: %t, value: %t", id, test.expected.Insecure, conf.Insecure)
		}

		if test.expected.Detach != conf.Detach {
			t.Errorf("detach doesn't match on test %d: expected: %t, value: %t", id, test.expected.Detach, conf.Detach)
		}
		if test.expected.SshConfig != conf.SshConfig {
			t.Errorf("sshConfig doesn't match on test %d: expected: %s, value: %s", id, test.expected.SshConfig, conf.SshConfig)
		}
	}

}

// TestHelperProcessRunning is not a test on its own: it stands in for a running
// mole instance when TestClientStop starts the test binary as a separate
// process, and is skipped otherwise.
func TestHelperProcessRunning(t *testing.T) {
	if os.Getenv("MOLE_TEST_HELPER_PROCESS") != "1" {
		t.Skip("only runs as a helper process")
	}

	time.Sleep(time.Minute)
}

// TestClientStop covers what both "mole stop" and an interrupt (ctrl-c) on an
// instance running in the foreground go through: the process named by the pid
// file of the instance has to be killed, wherever it runs.
func TestClientStop(t *testing.T) {
	testClientStop(t, "test-client-stop", false)
}

// TestClientStopDetached covers stopping an instance that holds its log file
// open, the way a detached one does. Windows refuses to remove a file a running
// process holds open.
func TestClientStopDetached(t *testing.T) {
	testClientStop(t, "test-client-stop-detached", true)
}

func testClientStop(t *testing.T, id string, detached bool) {
	d, err := fsutils.CreateInstanceDir(id)
	if err != nil {
		t.Fatalf("could not create the instance directory: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcessRunning$")
	cmd.Env = append(os.Environ(), "MOLE_TEST_HELPER_PROCESS=1")

	var lf *os.File

	if detached {
		lfl, err := fsutils.GetLogFileLocation(id)
		if err != nil {
			t.Fatalf("could not find the log file of the instance: %v", err)
		}

		lf, err = os.Create(lfl)
		if err != nil {
			t.Fatalf("could not create the log file of the instance: %v", err)
		}

		cmd.Stdout = lf
		cmd.Stderr = lf
	}

	err = cmd.Start()

	// only the helper holds the log file open from here on.
	if lf != nil {
		lf.Close()
	}

	if err != nil {
		t.Fatalf("could not start the helper process: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	exited := false
	defer func() {
		if !exited {
			cmd.Process.Kill()
			<-done
		}
	}()

	err = os.WriteFile(d.PidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0644)
	if err != nil {
		t.Fatalf("could not write the pid of the helper process: %v", err)
	}

	client := mole.New(&mole.Configuration{Id: id})

	if err := client.Stop(); err != nil {
		t.Fatalf("instance was not stopped: %v", err)
	}

	select {
	case <-done:
		exited = true
	case <-time.After(10 * time.Second):
		t.Fatalf("helper process %d is still running after being stopped", cmd.Process.Pid)
	}

	if _, err := os.Stat(d.Dir); !os.IsNotExist(err) {
		t.Errorf("instance directory %s was not removed: %v", d.Dir, err)
	}
}
