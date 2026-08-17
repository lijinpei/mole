//go:build !windows

package mole

import (
	"errors"
	"os"
	"syscall"
)

// processExists tells whether a process with the given pid is running.
//
// On unix os.FindProcess never fails, so the process is probed with signal 0,
// which runs the kernel's error checking without delivering anything. That
// check on its own is not enough: a process that has exited but has not been
// reaped by its parent yet stays in the process table and accepts the signal
// just like a running one, so it is ruled out separately.
func processExists(pid int) (bool, error) {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false, nil
	}

	err = p.Signal(syscall.Signal(0))

	switch {
	case err == nil:
		defunct, err := processIsDefunct(pid)
		if err != nil {
			return false, err
		}

		return !defunct, nil
	case errors.Is(err, os.ErrProcessDone), errors.Is(err, syscall.ESRCH):
		return false, nil
	case errors.Is(err, syscall.EPERM):
		// The process is alive but owned by another user.
		return true, nil
	}

	return false, err
}
