package alzlib

import (
	"testing"

	"gotest.tools/v3/assert"
)

func Test_NewAlzLib(t *testing.T) {
	az, err := NewAlzLib("./testdata/lib")
	assert.NilError(t, err)
	assert.Equal(t, len(az.PolicyAssignments), 35)
	assert.Equal(t, len(az.PolicyDefinitions), 104)
	assert.Equal(t, len(az.PolicySetDefinitions), 7)
	assert.Equal(t, len(az.libArchetypeDefinitions), 12)
}

func Benchmark_NewAlzLib(b *testing.B) {
	NewAlzLib("./testdata/lib")
}
