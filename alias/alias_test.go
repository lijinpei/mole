package alias_test

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/davrodpin/mole/alias"
)

const (
	FixtureDir = "./testdata"
)

var home string

func TestAddThenGetThenDeleteAlias(t *testing.T) {
	expectedAlias, err := addAlias()
	if err != nil {
		t.Errorf("error creating alias file %v", err)
	}

	expectedAliasFilePath := filepath.Join(home, ".mole", fmt.Sprintf("%s.toml", expectedAlias.Name))

	if _, err := os.Stat(expectedAliasFilePath); os.IsNotExist(err) {
		t.Errorf("alias file could not be found after the attempt to create it")
	}

	al, err := alias.Get(expectedAlias.Name)
	if err != nil {
		t.Errorf("%v", err)
	}

	if !reflect.DeepEqual(expectedAlias, al) {
		t.Errorf("expected: %s, actual: %s", expectedAlias, al)
	}

	err = alias.Delete(expectedAlias.Name)
	if err != nil {
		t.Errorf("error while deleting %s alias file: %v", expectedAlias.Name, err)
	}

	if _, err := os.Stat(expectedAliasFilePath); !os.IsNotExist(err) {
		t.Errorf("alias file found after the attempt to delete it")
	}

}

func TestShow(t *testing.T) {
	ids := []string{"test-env", "multi"}
	fx, err := filepath.Abs(FixtureDir)
	if err != nil {
		t.Errorf("error while loading data for TestShow: %v", err)
	}

	for _, id := range ids {
		fixturePath := filepath.Join(fx, fmt.Sprintf("show.alias.%s.fixture", id))
		expectedBytes, err := ioutil.ReadFile(fixturePath)
		if err != nil {
			t.Errorf("error while loading data for TestShow: %v", err)
		}

		expected := string(expectedBytes)

		output, err := alias.Show(id)
		if err != nil {
			t.Errorf("error showing alias %s: %v", id, err)
		}

		if output != expected {
			t.Errorf("output doesn't match. Failing the test.")
		}
	}
}

func TestShowAll(t *testing.T) {
	fx, err := filepath.Abs(FixtureDir)
	if err != nil {
		t.Errorf("error while loading data for TestShow: %v", err)
	}

	fixturePath := filepath.Join(fx, "show.alias.fixture")
	expectedBytes, err := ioutil.ReadFile(fixturePath)
	if err != nil {
		t.Errorf("error while loading data for TestShow: %v", err)
	}

	expected := string(expectedBytes)

	output, err := alias.ShowAll()
	if output != expected {
		t.Errorf("output doesn't match. Failing the test.")
	}
}

func TestMain(m *testing.M) {
	home, err := setup()
	if err != nil {
		fmt.Printf("error while loading data for TestShow: %v", err)
		os.RemoveAll(home)
		os.Exit(1)
	}

	code := m.Run()

	os.RemoveAll(home)

	os.Exit(code)
}

func addAlias() (*alias.Alias, error) {
	a := &alias.Alias{
		Name:              "alias",
		TunnelType:        "local",
		Verbose:           true,
		Insecure:          true,
		Detach:            true,
		Source:            []string{":1234"},
		Destination:       []string{"192.168.1.1:80"},
		Server:            "server.com",
		Key:               "path/to/key",
		KeepAliveInterval: "5s",
		ConnectionRetries: 3,
		WaitAndRetry:      "10s",
		SshAgent:          "path/to/agent",
		Timeout:           "1m",
		SshConfig:         "/home/user/.ssh/config",
	}

	err := alias.Add(a)
	if err != nil {
		return nil, err
	}

	return a, nil
}

// setup prepares the system environment to run the tests by:
// 1. Create temp dir and <dir>/.mole
// 2. Copy fixtures to <dir>/.mole
// 3. Set temp dir as the user testDir dir
func setup() (string, error) {
	testDir, err := ioutil.TempDir("", "mole-alias")
	if err != nil {
		return "", fmt.Errorf("error while setting up tests: %v", err)
	}

	moleAliasDir := filepath.Join(testDir, ".mole")
	err = os.Mkdir(moleAliasDir, 0755)
	if err != nil {
		return "", fmt.Errorf("error while setting up tests: %v", err)
	}

	err = os.Setenv("HOME", testDir)
	if err != nil {
		return "", fmt.Errorf("error while setting up tests: %v", err)
	}

	err = os.Setenv("USERPROFILE", testDir)
	if err != nil {
		return "", fmt.Errorf("error while setting up tests: %v", err)
	}

	fx, err := filepath.Abs(FixtureDir)
	if err != nil {
		return "", err
	}

	fixtures := []string{"test-env.toml", "example.toml", "multi.toml"}
	for _, fixture := range fixtures {
		err = CopyFile(filepath.Join(fx, fixture), filepath.Join(moleAliasDir, fixture))
		if err != nil {
			return "", err
		}
	}

	home = testDir

	return moleAliasDir, nil
}

// GoLang: os.Rename() give error "invalid cross-device link" for Docker container with Volumes.
// CopyFile(source, destination) will work moving file between folders
// Source: https://gist.github.com/var23rav/23ae5d0d4d830aff886c3c970b8f6c6b
func CopyFile(sourcePath, destPath string) error {
	inputFile, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("Couldn't open source file: %s", err)
	}

	outputFile, err := os.Create(destPath)
	if err != nil {
		inputFile.Close()
		return fmt.Errorf("Couldn't open dest file: %s", err)
	}
	defer outputFile.Close()

	_, err = io.Copy(outputFile, inputFile)
	inputFile.Close()
	if err != nil {
		return fmt.Errorf("Writing to output file failed: %s", err)
	}

	return nil
}

func TestGetMultiTunnelAlias(t *testing.T) {
	insecure := true
	never := 0

	// the settings the alias leaves out take the values the command line
	// defaults to.
	expected := &alias.Alias{
		Name:              "multi",
		Verbose:           true,
		Key:               "path/to/key",
		KeepAliveInterval: "10s",
		ConnectionRetries: 3,
		WaitAndRetry:      "3s",
		Timeout:           "5s",
		SshConfig:         alias.DefaultSshConfig,
		Rpc:               true,
		RpcAddress:        "127.0.0.1:0",
		Tunnels: []alias.Tunnel{
			{
				Server: "mole@bastion-a",
				Forwards: []alias.Forward{
					{Type: "local", Source: []string{":8080"}, Destination: []string{"db:5432"}},
					{Type: "dynamic", Source: []string{":1080"}},
				},
			},
			{
				Server:            "mole@bastion-b:2222",
				Key:               "path/to/other/key",
				Insecure:          &insecure,
				ConnectionRetries: &never,
				Forwards: []alias.Forward{
					{Type: "remote", Source: []string{"0.0.0.0:9000"}, Destination: []string{"127.0.0.1:3000"}},
				},
			},
		},
	}

	al, err := alias.Get("multi")
	if err != nil {
		t.Fatalf("error while reading the alias: %v", err)
	}

	if !reflect.DeepEqual(expected, al) {
		t.Errorf("expected: %+v, actual: %+v", expected, al)
	}
}

// No retries at all asks to never give up reconnecting, so only a number of
// retries left out altogether takes the default.
func TestGetMultiTunnelAliasKeepsZeroRetries(t *testing.T) {
	writeAlias(t, "never-give-up", `connection-retries = 0

[[tunnels]]
server = "mole@bastion-a"

  [[tunnels.forwards]]
  type = "dynamic"
`)

	al, err := alias.Get("never-give-up")
	if err != nil {
		t.Fatalf("error while reading the alias: %v", err)
	}

	if al.ConnectionRetries != 0 {
		t.Errorf("expected the alias to never give up reconnecting, but it gives up after %d retries", al.ConnectionRetries)
	}
}

// An alias with tunnels, or without a server, is written by hand, where a
// misspelled setting would otherwise be dropped without a word.
func TestGetRejectsUnknownSettingsOfHandWrittenAliases(t *testing.T) {
	tests := []struct {
		name    string
		content string
		unknown string
	}{
		{
			name:    "misspelled-tunnels",
			content: "[[tunnel]]\nserver = \"mole@bastion-a\"\n",
			unknown: "tunnel",
		},
		{
			name:    "misspelled-setting",
			content: "keep-alive = \"5s\"\n\n[[tunnels]]\nserver = \"mole@bastion-a\"\n\n  [[tunnels.forwards]]\n  type = \"dynamic\"\n",
			unknown: "keep-alive",
		},
		{
			name:    "misspelled-forwards",
			content: "[[tunnels]]\nserver = \"mole@bastion-a\"\n\n  [[tunnels.forward]]\n  type = \"dynamic\"\n",
			unknown: "tunnels.forward",
		},
	}

	for _, test := range tests {
		writeAlias(t, test.name, test.content)

		_, err := alias.Get(test.name)
		if err == nil || !strings.Contains(err.Error(), test.unknown) {
			t.Errorf("expected reading alias %s to fail on the unknown setting %s, but got %v", test.name, test.unknown, err)
		}
	}
}

// An alias with a server of its own is the kind "mole add alias" writes, which
// is read as it always was: whatever an older version wrote in it is left
// alone, and nothing it leaves out is filled in.
func TestGetLeavesFlatAliasesAlone(t *testing.T) {
	writeAlias(t, "flat", "type = \"local\"\nserver = \"mole@bastion-a\"\nlocal = [\":8080\"]\n")

	al, err := alias.Get("flat")
	if err != nil {
		t.Fatalf("error while reading the alias: %v", err)
	}

	if al.KeepAliveInterval != "" || al.ConnectionRetries != 0 || al.SshConfig != "" {
		t.Errorf("expected the settings the alias leaves out to be left empty, but got %s", al)
	}
}

func TestAddThenGetMultiTunnelAlias(t *testing.T) {
	expected, err := alias.Get("multi")
	if err != nil {
		t.Fatalf("error while reading the alias: %v", err)
	}

	expected.Name = "multi-copy"

	if err := alias.Add(expected); err != nil {
		t.Fatalf("error while adding the alias: %v", err)
	}
	defer alias.Delete(expected.Name)

	al, err := alias.Get(expected.Name)
	if err != nil {
		t.Fatalf("error while reading the alias back: %v", err)
	}

	if !reflect.DeepEqual(expected, al) {
		t.Errorf("expected: %+v, actual: %+v", expected, al)
	}
}

// writeAlias saves an alias file with the given content, which is removed once
// the test is over so that it does not show up in what the other tests read.
func writeAlias(t *testing.T, name, content string) {
	t.Helper()

	p := filepath.Join(home, ".mole", fmt.Sprintf("%s.toml", name))

	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("error while writing alias %s: %v", name, err)
	}

	t.Cleanup(func() { os.Remove(p) })
}

// A flat alias is shown as it always was, which includes the empty lists a
// dynamic alias or one reading its forwards from the ssh config carries.
func TestShowKeepsEmptyListsOfFlatAliases(t *testing.T) {
	a := &alias.Alias{
		Name:        "flat-dynamic",
		TunnelType:  "dynamic",
		Source:      []string{":1080"},
		Destination: []string{},
		Server:      "server.com",
	}

	if err := alias.Add(a); err != nil {
		t.Fatalf("error while adding the alias: %v", err)
	}
	defer alias.Delete(a.Name)

	output, err := alias.Show(a.Name)
	if err != nil {
		t.Fatalf("error showing alias: %v", err)
	}

	if !strings.Contains(output, "destination = []") {
		t.Errorf("expected the empty destination to be shown, but got:\n%s", output)
	}
}
