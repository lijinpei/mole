//go:build windows

package mole

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

// TestProcessExistsTerminatedWithOpenHandle covers the windows specific reason
// a dead pid keeps resolving: a process object, and with it the pid, is only
// destroyed once the process has exited and the last handle to it is closed.
// Anything still holding a handle keeps OpenProcess succeeding long after the
// process is gone, which is what a stale pid file left behind by a crashed
// instance runs into.
//
// TestProcessExistsTerminated only reaches that state when something outside
// the test happens to hold a handle, since cmd.Wait closes the one go itself
// holds. Here the handle is held by the test, so the check is made against the
// same state on every machine.
func TestProcessExistsTerminatedWithOpenHandle(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	if err := cmd.Start(); err != nil {
		t.Fatalf("could not start the helper process: %v", err)
	}

	pid := cmd.Process.Pid

	// Stands in for whatever else on the system may be holding a handle to a
	// process mole started: the shell it was launched from, a monitoring
	// agent, an antivirus.
	h, err := syscall.OpenProcess(syscall.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		t.Fatalf("could not open a second handle to helper process %d: %v", pid, err)
	}
	defer syscall.CloseHandle(h)

	// Returns only once the helper has exited, so there is no race between the
	// process going away and the check below.
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
