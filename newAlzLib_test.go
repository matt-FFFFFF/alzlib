package alzlib

import (
	"testing"

	"gotest.tools/v3/assert"
)

func Test_newAlzLib(t *testing.T) {
	a, err := New("./testdata/lib")
	assert.NilError(t, err)
	assert.Equal(t, len(a.policyDefinitions), 104)
}
