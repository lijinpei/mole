//go:build windows

package mole

import "os"

// processExists tells whether a process with the given pid is running.
//
// On windows os.FindProcess opens a handle to the process and fails when no
// process holds the pid, so the lookup alone is enough.
func processExists(pid int) (bool, error) {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false, nil
	}
	defer p.Release()

	return true, nil
}
