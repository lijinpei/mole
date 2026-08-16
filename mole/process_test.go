package mole

import (
	"os"
	"os/exec"
	"testing"
)

func TestProcessExists(t *testing.T) {
	running, err := processExists(os.Getpid())
	if err != nil {
		t.Fatalf("unexpected error looking up the process running the test: %v", err)
	}

	if !running {
		t.Error("the process running the test was reported as not running")
	}
}

func TestProcessExistsTerminated(t *testing.T) {
	// Runs the test binary itself with a filter that matches no test, so it
	// exits right away and leaves behind a pid that is known to be dead. This
	// is what a stale pid file left by a crashed instance looks like.
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	if err := cmd.Start(); err != nil {
		t.Fatalf("could not start the helper process: %v", err)
	}

	pid := cmd.Process.Pid

	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper process %d did not exit cleanly: %v", pid, err)
	}

	running, err := processExists(pid)
	if err != nil {
		t.Fatalf("unexpected error looking up terminated process %d: %v", pid, err)
	}

	if running {
		t.Errorf("terminated process %d was reported as running", pid)
	}
}
