//go:build windows

package mole

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	daemon "github.com/sevlyar/go-daemon"
)

// TestHelperProcessDetached is not a test on its own: it stands in for the
// instance TestDetach starts, and is skipped otherwise. What it finds about
// itself goes to its log file.
func TestHelperProcessDetached(t *testing.T) {
	if os.Getenv("MOLE_TEST_HELPER_DETACHED") != "1" {
		t.Skip("only runs as a helper process")
	}

	w, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleWindow").Call()

	fmt.Fprintf(os.Stderr, "reborn=%t console=%t\n", daemon.WasReborn(), w != 0)

	time.Sleep(time.Minute)
}

// TestDetach covers what a detached instance relies on: it is started knowing
// it is the detached copy, with no console that a ctrl-c or closing the window
// it was started from could reach it through, and with its output going to its
// log file.
func TestDetach(t *testing.T) {
	t.Setenv("MOLE_TEST_HELPER_DETACHED", "1")

	lf := filepath.Join(t.TempDir(), "mole.log")

	p, err := detach(lf, []string{os.Args[0], "-test.run=^TestHelperProcessDetached$"})
	if err != nil {
		t.Fatalf("could not detach the helper process: %v", err)
	}

	// the log file is removed along with the temporary directory, which is
	// only possible once the helper is gone.
	defer func() {
		p.Kill()
		p.Wait()
	}()

	expected := "reborn=true console=false"
	deadline := time.Now().Add(10 * time.Second)

	for {
		l, err := os.ReadFile(lf)
		if err != nil {
			t.Fatalf("could not read the log file of the helper process: %v", err)
		}

		if strings.Contains(string(l), "reborn=") {
			if !strings.Contains(string(l), expected) {
				t.Errorf("unexpected state of the helper process: expected: %s, log:\n%s", expected, l)
			}

			return
		}

		if time.Now().After(deadline) {
			t.Fatalf("helper process %d did not log anything:\n%s", p.Pid, l)
		}

		time.Sleep(50 * time.Millisecond)
	}
}
