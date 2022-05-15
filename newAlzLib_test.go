package alzlib

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
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

func Test_generateArchetypes_policyParameterOverride(t *testing.T) {
	aname := "testassignment1"
	tdname := "testdefinition1"
	pname := "testparameter1"
	ptype := armpolicy.ParameterTypeString

	az := AlzLib{
		libArchetypeDefinitions: []*libArchetypeDefinition{
			&libArchetypeDefinition{
				id:                "testarchetype",
				PolicyAssignments: []string{aname},
				PolicyDefinitions: []string{tdname},
				Config: &libArchetypeDefinitionConfig{
					Parameters: map[string]interface{}{
						aname: map[string]interface{}{
							pname: "replaced by archetype config",
						},
					},
				},
			},
		},
		PolicyDefinitions: map[string]*armpolicy.Definition{
			tdname: &armpolicy.Definition{
				Name: &tdname,
				Properties: &armpolicy.DefinitionProperties{
					Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
						pname: {
							DefaultValue: "default value",
							Type:         &ptype,
						},
					},
				},
			},
		},
		PolicyAssignments: map[string]*armpolicy.Assignment{
			aname: &armpolicy.Assignment{
				Name: &aname,
				Properties: &armpolicy.AssignmentProperties{
					Parameters: map[string]*armpolicy.ParameterValuesValue{
						pname: {
							Value: "value in assignment",
						},
					},
				},
			},
		},
		PolicySetDefinitions: map[string]*armpolicy.SetDefinition{},
		Archetypes:           map[string]*ArchetypeDefinition{},
	}

	assert.NilError(t, az.generateArchetypes())
	assert.Equal(t, az.Archetypes["testarchetype"].PolicyAssignments[aname].Properties.Parameters[pname].Value, "replaced by archetype config")
}

func Benchmark_NewAlzLib(b *testing.B) {
	NewAlzLib("./testdata/lib")
}
