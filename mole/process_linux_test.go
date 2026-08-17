//go:build linux

package mole

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
	"unsafe"
)

// TestProcessExistsZombie covers the linux counterpart of a dead pid that keeps
// resolving: a process that has exited but has not been reaped by its parent
// yet stays in the process table, so kill(pid, 0) keeps succeeding for it. An
// instance started by something that never waits on its children - a
// supervisor, a CI runner, an editor task runner - is left in exactly that
// state when it dies, and the stale pid file it leaves behind then blocks every
// later start.
//
// TestProcessExistsTerminated cannot reach this state: cmd.Wait reaps the
// helper, which releases the pid before the check runs.
func TestProcessExistsZombie(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	if err := cmd.Start(); err != nil {
		t.Fatalf("could not start the helper process: %v", err)
	}

	pid := cmd.Process.Pid

	// WNOWAIT returns once the helper has exited but leaves it waitable, so it
	// is still a zombie by the time the check below runs. cmd.Wait would reap
	// it and release the pid instead. waitid is used rather than wait4, which
	// rejects WNOWAIT with EINVAL on linux.
	const pPid = 1 // P_PID

	var info [128]byte // siginfo_t
	for {
		_, _, errno := syscall.Syscall6(syscall.SYS_WAITID,
			pPid,
			uintptr(pid),
			uintptr(unsafe.Pointer(&info[0])),
			syscall.WEXITED|syscall.WNOWAIT,
			0,
			0)
		if errno == syscall.EINTR {
			continue
		}

		if errno != 0 {
			t.Fatalf("could not wait for helper process %d: %v", pid, errno)
		}

		break
	}

	running, err := processExists(pid)
	if err != nil {
		t.Fatalf("unexpected error looking up terminated process %d: %v", pid, err)
	}

	if running {
		t.Errorf("terminated process %d was reported as running", pid)
	}

	if err := cmd.Wait(); err != nil {
		t.Errorf("helper process %d did not exit cleanly: %v", pid, err)
	}
}
