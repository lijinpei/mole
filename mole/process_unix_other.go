//go:build !windows && !linux

package mole

// processIsDefunct always reports false. Telling a process that has exited but
// has not been reaped yet apart from a running one needs the process state,
// which is read in a platform specific way and is only implemented for linux.
func processIsDefunct(pid int) (bool, error) {
	return false, nil
}
