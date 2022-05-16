package alzlib

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"gotest.tools/v3/assert"
)

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

// Test_generateArchetypes_policyParameterOverride_invalidParameterName tests that the correct
// error is returned when an invalid parameter name is used in the archetype_config parameters section.
func Test_generateArchetypes_policyParameterOverride_invalidParameterName(t *testing.T) {
	aname := "testassignment1"
	pdname := "testdefinition1"
	pname := "testparameter1"
	pname2 := "testparameter2"
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
							pname2: "value replaced by archetype config",
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

	assert.ErrorContains(t, az.generateArchetypes(), "archetype_config.parameters error: cannot modify policy parameter")
}

// Test_generateArchetypes_policyParameterOverride_invalidAssignmentName tests that the correct
// error is returned when an invalid parameter name is used in the archetype_config parameters section.
func Test_generateArchetypes_policyParameterOverride_invalidAssignmentName(t *testing.T) {
	aname := "testassignment1"
	aname2 := "testassignment2"
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
						aname2: map[string]interface{}{
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

	assert.ErrorContains(t, az.generateArchetypes(), "archetype_config.parameters error: cannot modify policy assignment")
}

// Test_generateArchetypes_archetypeExtension tests the archetype extension process.
// It starts with an empty archetype that is extended by adding a policy assignment,
// policy definition, and policy set definition.
func Test_generateArchetypes_archetypeExtension(t *testing.T) {
	archetype := "testarchetype"
	aname := "testassignment1"
	pdname := "testdefinition1"
	psname := "testsetdefinition1"

	// The rather unwieldy literals that we use for the testing are:
	pa := &armpolicy.Assignment{
		Name:       &aname,
		Properties: &armpolicy.AssignmentProperties{},
	}
	pd := &armpolicy.Definition{
		Name: &pdname,
	}
	psd := &armpolicy.SetDefinition{
		Name: &psname,
	}

	az := AlzLib{
		libArchetypeDefinitions: []*LibArchetypeDefinition{
			{
				Id:                   archetype,
				PolicyAssignments:    []string{},
				PolicyDefinitions:    []string{},
				PolicySetDefinitions: []string{},
				Config:               &libArchetypeDefinitionConfig{},
			},
		},
		PolicyDefinitions: map[string]*armpolicy.Definition{
			pdname: pd,
		},
		PolicyAssignments: map[string]*armpolicy.Assignment{
			aname: pa,
		},
		PolicySetDefinitions: map[string]*armpolicy.SetDefinition{
			psname: psd,
		},
		libArchetypeExtensions: []*LibArchetypeDefinition{
			{
				Id:                   archetype,
				PolicyAssignments:    []string{aname},
				PolicyDefinitions:    []string{pdname},
				PolicySetDefinitions: []string{psname},
			},
		},
		Archetypes: map[string]*ArchetypeDefinition{},
	}

	// Test the function doesn't return an error and then deep compare to ensure the expected
	// values are correct.
	assert.NilError(t, az.generateArchetypes())
	assert.DeepEqual(t, az.Archetypes[archetype].PolicyAssignments[aname], *pa)
	assert.DeepEqual(t, az.Archetypes[archetype].PolicyDefinitions[pdname], *pd)
	assert.DeepEqual(t, az.Archetypes[archetype].PolicySetDefinitions[psname], *psd)
}

// Test_generateArchetypes_archetypeExclusion tests the archetype exclusion process.
// It starts with an archetype that has one each of policy assignment, policy definition
// and policy set definition.
// This is excluded by removing the policy assignment policy definition, and policy set definition.
// The resulting archetype should have no policy assignments, no policy definitions, and no policy set definitions.
func Test_generateArchetypes_archetypeExclusion(t *testing.T) {
	archetype := "testarchetype"
	aname := "testassignment1"
	pdname := "testdefinition1"
	psname := "testsetdefinition1"

	// The rather unwieldy literals that we use for the testing are:
	pa := &armpolicy.Assignment{
		Name:       &aname,
		Properties: &armpolicy.AssignmentProperties{},
	}
	pd := &armpolicy.Definition{
		Name: &pdname,
	}
	psd := &armpolicy.SetDefinition{
		Name: &psname,
	}

	az := AlzLib{
		libArchetypeDefinitions: []*LibArchetypeDefinition{
			{
				Id:                   archetype,
				PolicyAssignments:    []string{aname},
				PolicyDefinitions:    []string{pdname},
				PolicySetDefinitions: []string{psname},
				Config:               &libArchetypeDefinitionConfig{},
			},
		},
		PolicyDefinitions: map[string]*armpolicy.Definition{
			pdname: pd,
		},
		PolicyAssignments: map[string]*armpolicy.Assignment{
			aname: pa,
		},
		PolicySetDefinitions: map[string]*armpolicy.SetDefinition{
			psname: psd,
		},
		libArchetypeExclusions: []*LibArchetypeDefinition{
			{
				Id:                   archetype,
				PolicyAssignments:    []string{aname},
				PolicyDefinitions:    []string{pdname},
				PolicySetDefinitions: []string{psname},
			},
		},
		Archetypes: map[string]*ArchetypeDefinition{},
	}

	assert.NilError(t, az.generateArchetypes())
	assert.Equal(t, len(az.Archetypes[archetype].PolicyAssignments), 0)
	assert.Equal(t, len(az.Archetypes[archetype].PolicyDefinitions), 0)
	assert.Equal(t, len(az.Archetypes[archetype].PolicySetDefinitions), 0)
}

func Test_generateArchetypes_duplicateDefinitions(t *testing.T) {
	archetype := "testarchetype"
	aname := "testassignment1"
	pdname := "testdefinition1"
	psname := "testsetdefinition1"

	// The rather unwieldy literals that we use for the testing are:
	pa := &armpolicy.Assignment{
		Name:       &aname,
		Properties: &armpolicy.AssignmentProperties{},
	}
	pd := &armpolicy.Definition{
		Name: &pdname,
	}
	psd := &armpolicy.SetDefinition{
		Name: &psname,
	}

	az := AlzLib{
		libArchetypeDefinitions: []*LibArchetypeDefinition{
			{
				Id:                   archetype,
				PolicyAssignments:    []string{aname, aname},
				PolicyDefinitions:    []string{pdname, pdname},
				PolicySetDefinitions: []string{psname, psname},
				Config:               &libArchetypeDefinitionConfig{},
			},
		},
		PolicyDefinitions: map[string]*armpolicy.Definition{
			pdname: pd,
		},
		PolicyAssignments: map[string]*armpolicy.Assignment{
			aname: pa,
		},
		PolicySetDefinitions: map[string]*armpolicy.SetDefinition{
			psname: psd,
		},
		Archetypes: map[string]*ArchetypeDefinition{},
	}

	assert.ErrorContains(t, az.generateArchetypes(), "duplicate policy set definition in archetype testarchetype")
}
