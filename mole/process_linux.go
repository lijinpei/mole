//go:build linux

package mole

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// processIsDefunct tells whether the given pid no longer belongs to a running
// process, either because the process has exited and is still waiting on its
// parent to reap it, or because it went away entirely.
//
// A process in the first state keeps its entry in the process table, so it
// takes signal 0 without error exactly like a running one does.
func processIsDefunct(pid int) (bool, error) {
	sf := fmt.Sprintf("/proc/%d/stat", pid)

	d, err := os.ReadFile(sf)
	if err != nil {
		// Reaped in between the two checks, so it is gone rather than defunct,
		// but either way it is not running. Which of the two errors comes back
		// depends on how far the read got: the file is only filled in when it
		// is read, so a process that goes away after the open is reported
		// through ESRCH rather than as a missing file.
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			return true, nil
		}

		return false, err
	}

	// The state is the field right after the executable name, which is wrapped
	// in parentheses and may itself contain both spaces and parentheses, so it
	// is located from the last closing one.
	i := strings.LastIndex(string(d), ")")
	if i < 0 || i+2 >= len(d) {
		return false, fmt.Errorf("could not parse the state of process %d from %s", pid, sf)
	}

	return d[i+2] == 'Z', nil
}
