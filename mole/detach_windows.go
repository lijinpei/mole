//go:build windows

package mole

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	daemon "github.com/sevlyar/go-daemon"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

// startDaemonProcess detaches the instance from the console it was started
// from.
//
// go-daemon only detaches a process on the systems it can fork one on, which
// leaves windows out, so a copy of mole is started here the way go-daemon
// starts one: marked as the detached copy, which goes through Start again and
// carries on as the instance once it gets here, while the one that started it
// exits.
func startDaemonProcess(instanceConf *DetachedInstance) error {
	if daemon.WasReborn() {
		return nil
	}

	p, err := detach(instanceConf.LogFile, appendIdArg(instanceConf.Id, os.Args))
	if err != nil {
		return err
	}

	err = p.Release()
	if err != nil {
		return err
	}

	log.Infof("execute \"mole stop %s\" if you like to stop it at any time", instanceConf.Id)

	os.Exit(0)

	return nil
}

// detach starts the running executable again with the given arguments, the
// first of them being the name it is run by, in a process with no console:
// neither a ctrl-c nor closing the window it was started from reaches it.
// Whatever it writes goes to the given log file.
func detach(logFile string, args []string) (*os.Process, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}

	lf, err := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0640)
	if err != nil {
		return nil, err
	}
	defer lf.Close()

	cmd := &exec.Cmd{
		Path:   exe,
		Args:   args,
		Env:    append(os.Environ(), fmt.Sprintf("%s=%s", daemon.MARK_NAME, daemon.MARK_VALUE)),
		Stdout: lf,
		Stderr: lf,
		SysProcAttr: &syscall.SysProcAttr{
			CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
		},
	}

	err = cmd.Start()
	if err != nil {
		return nil, err
	}

	return cmd.Process, nil
}
