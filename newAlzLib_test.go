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

// Test_generateArchetypes_policyParameterOverride tests that the resultant policy assignments
// overridden by the archetype definition
func Test_generateArchetypes_policyParameterOverride(t *testing.T) {
	aname := "testassignment1"
	pdname := "testdefinition1"
	pname := "testparameter1"
	ptype := armpolicy.ParameterTypeString

	az := AlzLib{
		libArchetypeDefinitions: []*LibArchetypeDefinition{
			{
				Id:                "testarchetype",
				PolicyAssignments: []string{aname},
				PolicyDefinitions: []string{pdname},
				Config: &libArchetypeDefinitionConfig{
					Parameters: map[string]interface{}{
						aname: map[string]interface{}{
							pname: "value replaced by archetype config",
						},
					},
				},
			},
		},
		PolicyDefinitions: map[string]*armpolicy.Definition{
			pdname: {
				Name: &pdname,
				Properties: &armpolicy.DefinitionProperties{
					Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
						pname: {
							Type: &ptype,
						},
					},
				},
			},
		},
		PolicyAssignments: map[string]*armpolicy.Assignment{
			aname: {
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
	assert.Equal(t, az.Archetypes["testarchetype"].PolicyAssignments[aname].Properties.Parameters[pname].Value, "value replaced by archetype config")
}

func Test_generateArchetypes_archetypeExtension(t *testing.T) {
	aname := "testassignment1"
	pdname := "testdefinition1"
	psname := "testsetdefinition1"

	az := AlzLib{
		libArchetypeDefinitions: []*LibArchetypeDefinition{
			{
				Id:                "testarchetype",
				PolicyAssignments: []string{},
				PolicyDefinitions: []string{},
				Config:            &libArchetypeDefinitionConfig{},
			},
		},
		PolicyDefinitions: map[string]*armpolicy.Definition{
			pdname: {
				Name: &pdname,
			},
		},
		PolicyAssignments: map[string]*armpolicy.Assignment{
			aname: {
				Name:       &aname,
				Properties: &armpolicy.AssignmentProperties{},
			},
		},
		PolicySetDefinitions: map[string]*armpolicy.SetDefinition{
			psname: {
				Name: &psname,
			},
		},
		libArchetypeExtensions: []*LibArchetypeDefinition{
			{
				Id:                   "testarchetype",
				PolicyAssignments:    []string{aname},
				PolicyDefinitions:    []string{pdname},
				PolicySetDefinitions: []string{psname},
			},
		},
		Archetypes: map[string]*ArchetypeDefinition{},
	}

	assert.NilError(t, az.generateArchetypes())
}

func Benchmark_NewAlzLib(b *testing.B) {
	_, e := NewAlzLib("./testdata/lib")
	if e != nil {
		b.Error(e)
	}
}
