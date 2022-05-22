package alzlib

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"gotest.tools/v3/assert"
)

// Test_generateArchetypes_policyParameterOverride tests that the resultant policy assignments
// overridden by the archetype definition
func TestGenerateArchetypesPolicyParameterOverride(t *testing.T) {
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
func TestGenerateArchetypes_policyParameterOverrideInvalidParameterName(t *testing.T) {
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
func TestGenerateArchetypesPolicyParameterOverrideInvalidAssignmentName(t *testing.T) {
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
func TestGenerateArchetypesArchetypeExtension(t *testing.T) {
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
func TestGenerateArchetypesArchetypeExclusion(t *testing.T) {
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

// TestGenerateArchetypesDuplicateSetDefinitions tests the scenario that there are duplicate policy
// set definitions in the archetype_definition file.
func TestGenerateArchetypesDuplicateSetDefinitions(t *testing.T) {
	archetype := "testarchetype"
	psname := "testsetdefinition1"

	// The rather unwieldy literals that we use for the testing are:
	psd := &armpolicy.SetDefinition{
		Name: &psname,
	}

	az := AlzLib{
		libArchetypeDefinitions: []*LibArchetypeDefinition{
			{
				Id:                   archetype,
				PolicySetDefinitions: []string{psname, psname},
				Config:               &libArchetypeDefinitionConfig{},
			},
		},
		PolicySetDefinitions: map[string]*armpolicy.SetDefinition{
			psname: psd,
		},
		Archetypes: map[string]*ArchetypeDefinition{},
	}

	assert.ErrorContains(t, az.generateArchetypes(), "duplicate policy set definition in archetype testarchetype")
}

// TestGenerateArchetypesNotFoundSetDefinitions tests the scenario where a policy set definition is specified in
// an archetype_definition file, but is not found in the policy set definitions.
func TestGenerateArchetypesNotFoundSetDefinitions(t *testing.T) {
	archetype := "testarchetype"
	psname := "testsetdefinition1"

	// The rather unwieldy literals that we use for the testing are:
	az := AlzLib{
		libArchetypeDefinitions: []*LibArchetypeDefinition{
			{
				Id:                   archetype,
				PolicyAssignments:    []string{},
				PolicyDefinitions:    []string{},
				PolicySetDefinitions: []string{psname, psname},
				Config:               &libArchetypeDefinitionConfig{},
			},
		},
		PolicySetDefinitions: map[string]*armpolicy.SetDefinition{},
		Archetypes:           map[string]*ArchetypeDefinition{},
	}

	assert.ErrorContains(t, az.generateArchetypes(), "policy set definition testsetdefinition1 not found for archetype testarchetype")
}

// TestGenerateArchetypesDuplicateDefinitions tests the scenario that there are duplicate policy
// definitions in the archetype_definition file.
func TestGenerateArchetypesDuplicateDefinitions(t *testing.T) {
	archetype := "testarchetype"
	pdname := "testdefinition1"

	// The rather unwieldy literals that we use for the testing are:
	pd := &armpolicy.Definition{
		Name: &pdname,
	}

	az := AlzLib{
		libArchetypeDefinitions: []*LibArchetypeDefinition{
			{
				Id:                   archetype,
				PolicyAssignments:    []string{},
				PolicyDefinitions:    []string{pdname, pdname},
				PolicySetDefinitions: []string{},
				Config:               &libArchetypeDefinitionConfig{},
			},
		},
		PolicyDefinitions: map[string]*armpolicy.Definition{
			pdname: pd,
		},
		Archetypes: map[string]*ArchetypeDefinition{},
	}

	assert.ErrorContains(t, az.generateArchetypes(), "duplicate policy definition in archetype testarchetype")
}

// TestGenerateArchetypesNotFoundSetDefinitions tests the scenario where a policy definition is specified in
// an archetype_definition file, but is not found in the policy definitions.
func TestGenerateArchetypesNotFoundDefinitions(t *testing.T) {
	archetype := "testarchetype"
	pdname := "testdefinition1"

	// The rather unwieldy literals that we use for the testing are:
	az := AlzLib{
		libArchetypeDefinitions: []*LibArchetypeDefinition{
			{
				Id:                   archetype,
				PolicyAssignments:    []string{},
				PolicyDefinitions:    []string{pdname},
				PolicySetDefinitions: []string{},
				Config:               &libArchetypeDefinitionConfig{},
			},
		},
		PolicyDefinitions: map[string]*armpolicy.Definition{},
		Archetypes:        map[string]*ArchetypeDefinition{},
	}

	assert.ErrorContains(t, az.generateArchetypes(), "policy definition testdefinition1 not found for archetype testarchetype")
}

// TestGenerateArchetypesDuplicateAssignment tests the scenario that there are duplicate policy
// assignments in the archetype_definition file.
func TestGenerateArchetypesDuplicateAssignment(t *testing.T) {
	archetype := "testarchetype"
	aname := "testassignment1"

	// The rather unwieldy literals that we use for the testing are:
	pa := &armpolicy.Assignment{
		Name:       &aname,
		Properties: &armpolicy.AssignmentProperties{},
	}

	az := AlzLib{
		libArchetypeDefinitions: []*LibArchetypeDefinition{
			{
				Id:                   archetype,
				PolicyAssignments:    []string{aname, aname},
				PolicyDefinitions:    []string{},
				PolicySetDefinitions: []string{},
				Config:               &libArchetypeDefinitionConfig{},
			},
		},
		PolicyAssignments: map[string]*armpolicy.Assignment{
			aname: pa,
		},
		Archetypes: map[string]*ArchetypeDefinition{},
	}

	assert.ErrorContains(t, az.generateArchetypes(), "duplicate policy assignment in archetype testarchetype")
}

// TestGenerateArchetypesNotFoundAssignment tests the scenario where a policy assignment is specified in
// an archetype_definition file, but is not found in the assignments.
func TestGenerateArchetypesNotFoundAssignment(t *testing.T) {
	archetype := "testarchetype"
	aname := "testassignment1"

	// The rather unwieldy literals that we use for the testing are:

	az := AlzLib{
		libArchetypeDefinitions: []*LibArchetypeDefinition{
			{
				Id:                   archetype,
				PolicyAssignments:    []string{aname},
				PolicyDefinitions:    []string{},
				PolicySetDefinitions: []string{},
				Config:               &libArchetypeDefinitionConfig{},
			},
		},
		PolicyAssignments: map[string]*armpolicy.Assignment{},
		Archetypes:        map[string]*ArchetypeDefinition{},
	}

	assert.ErrorContains(t, az.generateArchetypes(), "policy assignment testassignment1 not found for archetype testarchetype")
}

// TestGenerateArchetypesDuplicateArchetype tests the scenario where there is a duplicate archetype definition
// in the archetype_definition files.
func TestGenerateArchetypesDuplicateArchetype(t *testing.T) {
	archetype := "testarchetype"

	// The rather unwieldy literals that we use for the testing are:
	az := AlzLib{
		libArchetypeDefinitions: []*LibArchetypeDefinition{
			{
				Id:                   archetype,
				PolicyAssignments:    []string{},
				PolicyDefinitions:    []string{},
				PolicySetDefinitions: []string{},
				Config:               &libArchetypeDefinitionConfig{},
			},
			{
				Id:                   archetype,
				PolicyAssignments:    []string{},
				PolicyDefinitions:    []string{},
				PolicySetDefinitions: []string{},
				Config:               &libArchetypeDefinitionConfig{},
			},
		},
		Archetypes: map[string]*ArchetypeDefinition{},
	}

	assert.ErrorContains(t, az.generateArchetypes(), "duplicate archetype id: testarchetype")
}
