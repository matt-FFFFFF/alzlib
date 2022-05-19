package alzlib

import (
	"testing"

	"gotest.tools/v3/assert"
)

// TestNewAlzLib tests the valid creation of a new AlzLib from a valid source directory
func TestNewAlzLib(t *testing.T) {
	az, err := NewAlzLib("./testdata/lib")
	assert.NilError(t, err)
	assert.Equal(t, len(az.PolicyAssignments), 35)
	assert.Equal(t, len(az.PolicyDefinitions), 104)
	assert.Equal(t, len(az.PolicySetDefinitions), 7)
	assert.Equal(t, len(az.libArchetypeDefinitions), 12)
}

// TestNewAlzLibNoDir tests the creation of a new AlzLib when supplied with a path
// that does not exist.
// The error details are checked for the expected error message.
func TestNewAlzLibNoDir(t *testing.T) {
	_, err := NewAlzLib("./testdata/doesnotexist")
	assert.ErrorContains(t, err, "the supplied lib directory does not exist")
}

// TestNewAlzLibNotADir tests the creation of a new AlzLib when supplied with a valid
// path that is not a directory.
// The error details are checked for the expected error message.
func TestNewAlzLibNotADir(t *testing.T) {
	_, err := NewAlzLib("./testdata/notadirectory")
	assert.ErrorContains(t, err, "is not a directory and it should be")
}

// BenchmarkNewAlzLib benchmarks the creation of a new AlzLib based on the test data set
func BenchmarkNewAlzLib(b *testing.B) {
	_, e := NewAlzLib("./testdata/lib")
	if e != nil {
		b.Error(e)
	}
}
