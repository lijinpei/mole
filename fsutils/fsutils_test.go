package fsutils_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/davrodpin/mole/fsutils"
)

var (
	// home is a temporary directory that acts as the user home directory.
	// It is used on most tests to validates files created by Mole and their
	// contents.
	home string
)

func TestCreateInstanceDir(t *testing.T) {
	tests := []struct {
		id        string
		preCreate bool
	}{
		{id: "f00d", preCreate: false},
		{id: "d34dbeef", preCreate: true},
	}

	for idx, test := range tests {
		instanceDir := filepath.Join(home, ".mole", test.id)
		pidFileLocation := filepath.Join(home, ".mole", test.id, fsutils.InstancePidFile)

		if test.preCreate {
			os.MkdirAll(instanceDir, 0755)
			ioutil.WriteFile(pidFileLocation, []byte("1234"), 0644)
		}

		dirInfo, err := fsutils.CreateInstanceDir(test.id)

		if err != nil {
			t.Errorf("item %d: expected: nil; got %v", idx, err)
		}

		if test.id != dirInfo.Id {
			t.Errorf("item %d: expected: %s; got: %s", idx, test.id, dirInfo.Id)
		}

		if instanceDir != dirInfo.Dir {
			t.Errorf("item %d: expected: %s; got: %s", idx, instanceDir, dirInfo.Dir)
		}

		if pidFileLocation != dirInfo.PidFile {
			t.Errorf("item %d: expected: %s; got: %s", idx, pidFileLocation, dirInfo.PidFile)
		}

		if _, err := os.Stat(dirInfo.Dir); os.IsNotExist(err) {
			t.Errorf("item %d: no such instance directory %s", idx, dirInfo.Dir)
		}

		if _, err := os.Stat(dirInfo.PidFile); os.IsNotExist(err) {
			t.Errorf("item %d: no such pid file %s", idx, dirInfo.PidFile)
		}

	}

}

func TestPid(t *testing.T) {
	expectedPid := 1234
	id := strconv.Itoa(expectedPid)

	pid, err := fsutils.Pid(id)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if expectedPid != pid {
		t.Errorf("pid does not match: want %d, got %d", expectedPid, pid)
	}
}

func TestPidAlias(t *testing.T) {
	expectedPid := 1234
	id := "test-env"

	err := createPidFile(id, expectedPid)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	pid, err := fsutils.Pid(id)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if expectedPid != pid {
		t.Errorf("pid does not match: want %d, got %d", expectedPid, pid)
	}
}

func TestLogFileLocation(t *testing.T) {
	instanceId := "id"
	instanceDir, err := fsutils.InstanceDir(instanceId)
	if err != nil {
		t.Errorf("%v", err)
	}

	expected := filepath.Join(instanceDir.Dir, fsutils.InstanceLogFile)
	lfp, err := fsutils.GetLogFileLocation(instanceId)
	if err != nil {
		t.Errorf("%v", err)
	}

	if lfp != expected {
		t.Errorf("expected: %s; got: %s", expected, lfp)
	}
}

func TestRpcAddress(t *testing.T) {
	instanceId := "id"
	expectedRpcAddress := "127.0.0.1:8181"
	instanceDir := filepath.Join(home, ".mole", instanceId)
	rpcFileLocation := filepath.Join(instanceDir, "rpc")

	// create RPC address file
	os.MkdirAll(instanceDir, 0755)
	ioutil.WriteFile(rpcFileLocation, []byte(expectedRpcAddress), 0644)

	rpcAddress, err := fsutils.RpcAddress(instanceId)
	if err != nil {
		t.Errorf("%s", err)
	}

	if expectedRpcAddress != rpcAddress {
		t.Errorf("expected: %s; got: %s", expectedRpcAddress, rpcAddress)
	}
}

func TestMain(m *testing.M) {
	testDir, err := setup()
	if err != nil {
		fmt.Printf("error while setting up tests: %v", err)
		os.RemoveAll(testDir)
		os.Exit(1)
	}

	code := m.Run()

	os.RemoveAll(testDir)

	os.Exit(code)

}

// setup prepares the system environment to run the tests by creating a temp
// directory and making it the user home directory, returning it so that the
// caller can remove it once the tests are over.
func setup() (string, error) {
	testDir, err := ioutil.TempDir("", "mole-fsutils")
	if err != nil {
		return "", fmt.Errorf("error while setting up tests: %v", err)
	}

	err = os.Setenv("HOME", testDir)
	if err != nil {
		return testDir, fmt.Errorf("error while setting up tests: %v", err)
	}

	err = os.Setenv("USERPROFILE", testDir)
	if err != nil {
		return testDir, fmt.Errorf("error while setting up tests: %v", err)
	}

	home = testDir

	return testDir, nil
}

func createPidFile(id string, pid int) error {
	dir := filepath.Join(home, ".mole", id)

	// the directory is not necessarily missing: its parent is only created by
	// whichever test gets there first, and the test itself runs again on every
	// repetition asked for through -count
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return err
	}

	d := []byte(strconv.Itoa(pid))
	err = ioutil.WriteFile(filepath.Join(dir, fsutils.InstancePidFile), d, 0644)
	if err != nil {
		return err
	}

	if err != nil {
		return err
	}

	return nil
}
