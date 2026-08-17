//go:build windows

package mole

import (
	"errors"
	"syscall"
)

// processExists tells whether a process with the given pid is running.
//
// On windows OpenProcess keeps succeeding for a process that has already
// exited, for as long as anything still holds a handle to it: the process
// object, and with it the pid, is only destroyed once the last handle is
// closed. So the lookup alone is not enough and the handle is waited on with a
// zero timeout, which reports a process that is already gone as signaled.
func processExists(pid int) (bool, error) {
	// Waiting on the handle is all this does with it, so SYNCHRONIZE is all it
	// asks for. Every right beyond that is one more reason for OpenProcess to
	// come back with ERROR_ACCESS_DENIED, where a running process can only be
	// assumed rather than observed.
	h, err := syscall.OpenProcess(syscall.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		if errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
			// The process is alive but owned by another user.
			return true, nil
		}

		return false, nil
	}
	defer syscall.CloseHandle(h)

	ev, err := syscall.WaitForSingleObject(h, 0)
	if err != nil {
		return false, err
	}

	return ev == uint32(syscall.WAIT_TIMEOUT), nil
}
