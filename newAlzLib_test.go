package alzlib

import (
	"testing"

	"gotest.tools/v3/assert"
)

func Test_newAlzLib(t *testing.T) {
	az, err := New("./testdata/lib")
	assert.NilError(t, err)
	assert.Equal(t, len(az.PolicyAssignments), 35)
	assert.Equal(t, len(az.PolicyDefinitions), 104)
	assert.Equal(t, len(az.PolicySetDefinitions), 7)
	assert.Equal(t, len(az.libArchetypeDefinitions), 12)
}
