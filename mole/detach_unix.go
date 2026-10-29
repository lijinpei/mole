//go:build !windows

package mole

import (
	"os"

	daemon "github.com/sevlyar/go-daemon"
	log "github.com/sirupsen/logrus"
)

func startDaemonProcess(instanceConf *DetachedInstance) error {
	args := appendIdArg(instanceConf.Id, os.Args)

	cntxt := &daemon.Context{
		PidFileName: instanceConf.PidFile,
		PidFilePerm: 0644,
		LogFileName: instanceConf.LogFile,
		LogFilePerm: 0640,
		Umask:       027,
		Args:        args,
	}

	d, err := cntxt.Reborn()
	if err != nil {
		return err
	}

	if d != nil {
		err = os.Rename(instanceConf.PidFile, instanceConf.PidFile)
		if err != nil {
			return err
		}

		err = os.Rename(instanceConf.LogFile, instanceConf.LogFile)
		if err != nil {
			return err
		}

		log.Infof("execute \"mole stop %s\" if you like to stop it at any time", instanceConf.Id)

		os.Exit(0)
	}

	defer func() {
		err := cntxt.Release()
		if err != nil {
			log.WithFields(log.Fields{
				"id": instanceConf.Id,
			}).WithError(err).Error("error detaching the mole instance")
		}
	}()

	return nil
}
