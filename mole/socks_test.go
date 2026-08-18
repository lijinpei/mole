package mole

import "testing"

// The credentials the clients of a socks proxy have to authenticate with can be
// named by an environment variable, so that a password is neither given on the
// command line, where anyone looking at the process list can read it, nor kept
// in the alias file.
func TestSocksCredentials(t *testing.T) {
	t.Setenv("MOLE_TEST_SOCKS_AUTH", "mole:let me in")
	t.Setenv("MOLE_TEST_SOCKS_EMPTY", "")

	tests := []struct {
		auth     string
		user     string
		password string
		fails    bool
	}{
		{auth: ""},
		{auth: "mole:let me in", user: "mole", password: "let me in"},
		{auth: "mole:pass:word", user: "mole", password: "pass:word"},
		{auth: "$MOLE_TEST_SOCKS_AUTH", user: "mole", password: "let me in"},
		{auth: "$MOLE_TEST_SOCKS_EMPTY"},
		{auth: "$MOLE_TEST_SOCKS_MISSING"},
		{auth: "mole", fails: true},
		{auth: "mole:", fails: true},
		{auth: ":let me in", fails: true},
	}

	for _, test := range tests {
		user, password, err := socksCredentials(test.auth)

		if test.fails {
			if err == nil {
				t.Errorf("%q should not be accepted as socks credentials", test.auth)
			}

			continue
		}

		if err != nil {
			t.Errorf("error while reading the socks credentials from %q: %v", test.auth, err)
			continue
		}

		if user != test.user || password != test.password {
			t.Errorf("expected %q to carry the user %q and the password %q, but got %q and %q", test.auth, test.user, test.password, user, password)
		}
	}
}
