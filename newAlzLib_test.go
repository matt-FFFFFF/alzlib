package alzlib

import (
	"testing"

	"gotest.tools/v3/assert"
)

// Test_NewAlzLib tests the valid creation of a new AlzLib from a valid source directory
func Test_NewAlzLib(t *testing.T) {
	az, err := NewAlzLib("./testdata/lib")
	assert.NilError(t, err)
	assert.Equal(t, len(az.PolicyAssignments), 35)
	assert.Equal(t, len(az.PolicyDefinitions), 104)
	assert.Equal(t, len(az.PolicySetDefinitions), 7)
	assert.Equal(t, len(az.libArchetypeDefinitions), 12)
}

// Test_NewAlzLib_noDir tests the creation of a new AlzLib when supplied with a path
// that does not exist.
// The error details are checked for the expected error message.
func Test_NewAlzLib_noDir(t *testing.T) {
	_, err := NewAlzLib("./testdata/doesnotexist")
	assert.ErrorContains(t, err, "the supplied lib directory does not exist")
}

// Test_NewAlzLib_notADir tests the creation of a new AlzLib when supplied with a valid
// path that is not a directory.
// The error details are checked for the expected error message.
func Test_NewAlzLib_notADir(t *testing.T) {
	_, err := NewAlzLib("./testdata/notadirectory")
	assert.ErrorContains(t, err, "is not a directory and it should be")
}

// Benchmark_NewAlzLib benchmarks the creation of a new AlzLib based on the test data set
func Benchmark_NewAlzLib(b *testing.B) {
	_, e := NewAlzLib("./testdata/lib")
	if e != nil {
		b.Error(e)
	}
}

// Test_NewAlzLibDuplicateArchetypeDefinition tests the creation of a new AlzLib from a invalid source directory
func Test_NewAlzLibDuplicateArchetypeDefinition(t *testing.T) {
	_, err := NewAlzLib("./testdata/badlib-duplicatearchetypedef")
	assert.ErrorContains(t, err, "duplicate archetype id: duplicate")
}

// Test_NewAlzLibBadMgFiles tests the creation of a new AlzLib from a valid source directory with no root MG defined
func Test_NewAlzLibBadMgFiles(t *testing.T) {
	_, err := NewAlzLib("./testdata/badlib-norootmg")
	assert.ErrorContains(t, err, "error generating management groups")
}
