package alzlib

import (
	"testing"

	"gotest.tools/v3/assert"
)

func Test_newAlzLib(t *testing.T) {
	a, err := New("./testdata/lib")
	assert.NilError(t, err)
	assert.Equal(t, len(a.PolicyAssignments), 35)
	assert.Equal(t, len(a.PolicyDefinitions), 104)
	assert.Equal(t, len(a.PolicySetDefinitions), 7)
}
