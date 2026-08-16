package mole

import (
	"reflect"
	"testing"
)

func TestAppendIdArg(t *testing.T) {
	tests := []struct {
		args     []string
		expected []string
	}{
		{
			[]string{"mole", "start", "alias", "prod", "--detach"},
			[]string{"mole", "start", "alias", "prod", "--detach", "--id", "afb046da"},
		},
		{
			[]string{"mole", "start", "local", "--server", "example", "-x"},
			[]string{"mole", "start", "local", "--server", "example", "-x", "--id", "afb046da"},
		},
	}

	for id, test := range tests {
		value := appendIdArg("afb046da", test.args)

		if !reflect.DeepEqual(test.expected, value) {
			t.Errorf("args don't match on test %d: expected: %q, value: %q", id, test.expected, value)
		}
	}
}

// TestAppendIdArgKeepsGivenId makes sure the id is not appended twice for
// scenarios where the arguments already carry one.
func TestAppendIdArgKeepsGivenId(t *testing.T) {
	args := []string{"mole", "start", "alias", "prod", "--id", "afb046da"}

	value := appendIdArg("cc7b1a11", args)

	if !reflect.DeepEqual(args, value) {
		t.Errorf("args carrying an id should not change: expected: %q, value: %q", args, value)
	}
}
